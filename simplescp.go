package main

import (
	"log"
	"net"
	"os"

	"github.com/FranGM/simplelog"
	"github.com/flynn/go-shlex"
	"golang.org/x/crypto/ssh"
)

type scpOptions struct {
	To           bool
	From         bool
	TargetIsDir  bool
	Recursive    bool
	PreserveMode bool
	fileNames    []string
}

type simpleScpConfig struct {
	User           string
	passwords      map[string]string
	Dir            string
	privateKey     ssh.Signer
	PrivateKeyFile string
	Port           string
	AuthKeys       map[string][]ssh.PublicKey
	AuthKeysFile   string
}

func newSimpleScpConfig() *simpleScpConfig {

	workingDir, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	return &simpleScpConfig{Port: "2222", User: "scpuser", Dir: workingDir}
}

var globalConfig *simpleScpConfig

// Allows us to send to the client the exit status code of the command they asked as to run
func sendExitStatusCode(channel ssh.Channel, status uint8) {
	exitStatusBuffer := make([]byte, 4)
	exitStatusBuffer[3] = status
	_, err := channel.SendRequest("exit-status", false, exitStatusBuffer)
	if err != nil {
		simplelog.Error.Printf("Failed to forward exit-status to client: %v", err)
	}
}

// Handle requests received through a channel
func handleRequest(channel ssh.Channel, req *ssh.Request) {
	ok := true
	simplelog.Debug.Printf("Payload before splitting is %v", string(req.Payload[4:]))
	s, err := shlex.Split(string(req.Payload[4:]))
	if err != nil {
		// TODO: Shouldn't we do something with this error?
		simplelog.Error.Printf("Error when splitting payload: %v", err)
	}

	// Ignore everything that's not scp
	if s[0] != "scp" {
		ok = false
		req.Reply(ok, []byte("Only scp is supported"))
		channel.Write([]byte("Only scp is supported\n"))
		channel.Close()
		return
	}

	opts := scpOptions{}
	// TODO: Do a sanity check of options (like needing to have either -f or -t defined)
	// TODO: Define what happens if both -t and -f are specified?
	// TODO: If we have more than one filename with -t defined it's an error: "ambiguous target"

	// At the very least we expect either -t or -f
	// UNDOCUMENTED scp OPTIONS:
	//  -t: "TO", our server will be receiving files
	//  -f: "FROM", our server will be sending files
	//  -d: Target is expected to be a directory
	// DOCUMENTED scp OPTIONS:
	//  -r: Recursively copy entire directories (follows symlinks)
	//  -p: Preserve modification mtime, atime and mode of files
	parseOpts := true
	opts.fileNames = make([]string, 0)
	for _, elem := range s[1:] {
		if parseOpts {
			switch elem {
			case "-f":
				opts.From = true
			case "-t":
				opts.To = true
			case "-d":
				opts.TargetIsDir = true
			case "-p":
				opts.PreserveMode = true
			case "-r":
				opts.Recursive = true
			case "-v":
				// Verbose mode, this is more of a local client thing
			case "--":
				// After finding a "--" we stop parsing for flags
				if parseOpts {
					parseOpts = false
				} else {
					opts.fileNames = append(opts.fileNames, elem)
				}
			default:
				opts.fileNames = append(opts.fileNames, elem)
			}
		}
	}

	simplelog.Debug.Printf("Called scp with %v", s[1:])
	simplelog.Debug.Printf("Options: %v", opts)
	simplelog.Debug.Printf("Filenames: %v", opts.fileNames)

	// We're acting as source
	if opts.From {
		err := startSCPSource(channel, opts)
		ok := true
		if err != nil {
			ok = false
			req.Reply(ok, []byte(err.Error()))
		} else {
			req.Reply(ok, nil)
		}
	}

	// We're acting as sink
	if opts.To {
		var statusCode uint8
		ok := true
		if len(opts.fileNames) != 1 {
			simplelog.Error.Printf("Error in number of targets (ambiguous target)")
			statusCode = 1
			ok = false
			sendErrorToClient("scp: ambiguous target", channel)
		} else {
			startSCPSink(channel, opts)
		}
		sendExitStatusCode(channel, statusCode)
		channel.Close()
		req.Reply(ok, nil)
		return
	}
}

func handleNewChannel(newChannel ssh.NewChannel) {
	// There are different channel types, depending on what's done at the application level.
	// scp is done over a "session" channel (as it's just used to execute "scp" on the remote side)
	// We reject any other kind of channel as we only care about scp
	simplelog.Debug.Printf("Channel type is %v", newChannel.ChannelType())
	if newChannel.ChannelType() != "session" {
		simplelog.Debug.Printf("Rejecting channel request for type %v", newChannel.ChannelType)
		newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
		return
	}
	channel, requests, err := newChannel.Accept()
	if err != nil {
		// TODO: Don't panic here, just clean up and log error
		panic("could not accept channel.")
	}

	// Inside our channel there are several kinds of requests.
	// We can have a request to open a shell or to set environment variables
	// Again, we only care about "exec" as we will just want to execute scp over ssh
	for req := range requests {
		// scp does an exec, so that's all we care about
		switch req.Type {
		case "exec":
			go handleRequest(channel, req)
		case "shell":
			channel.Write([]byte("Opening a shell is not supported by this server\n"))
			req.Reply(false, nil)
		case "env":
			// Ignore these for now
			// TODO: Is there any kind of env settings we want to honor?
			req.Reply(true, nil)
		default:
			simplelog.Debug.Printf("Req type: %v, req payload: %v", req.Type, string(req.Payload))
			req.Reply(true, nil)
		}
	}
}

// Handle new connections
func handleConn(nConn net.Conn, config *ssh.ServerConfig) {
	_, chans, _, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		simplelog.Error.Printf("Error during handshake: %v", err)
		return
	}

	// Handle any new channels
	for newChannel := range chans {
		go handleNewChannel(newChannel)
	}
}

// Parse and return a ssh public key as found in an authorized keys file
func parsePubKey(pktext string) (ssh.PublicKey, error) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pktext))
	return pub, err
}

func main() {

	// An SSH server is represented by a ServerConfig, which holds
	// certificate details and handles authentication of ServerConns.
	// Setting NoClientAuth to true would allow users to connect without needing to authenticate
	config := &ssh.ServerConfig{
		PasswordCallback:  passwordAuth,
		PublicKeyCallback: keyAuth,
	}

	config.AddHostKey(globalConfig.privateKey)

	listener, err := net.Listen("tcp", "0.0.0.0:"+globalConfig.Port)
	if err != nil {
		log.Fatal("Failed to listen for connections: ", err)
	}
	simplelog.Info.Printf("Listening on port %v. Accepting connections", globalConfig.Port)
	for {
		nConn, err := listener.Accept()
		if err != nil {
			log.Fatal("Failed to accept incoming connection: ", err)
		}
		simplelog.Info.Printf("Accepted connection from %v", nConn.RemoteAddr())
		go handleConn(nConn, config)
	}
}
