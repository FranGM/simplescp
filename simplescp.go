package main

import (
	"crypto/rand"
	"crypto/rsa"
	"github.com/flynn/go-shlex"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"log"
	"net"
	"os"
)

var basedir string // Base directory we will be sharing.

func sendExitStatusCode(channel ssh.Channel, status uint8) {
	exitStatusBuffer := make([]byte, 4)
	exitStatusBuffer[3] = status
	_, err := channel.SendRequest("exit-status", false, exitStatusBuffer)
	if err != nil {
		log.Println("Failed to forward exit-status to client:", err)
	}
}

type scpOptions struct {
	To           bool
	From         bool
	TargetIsDir  bool
	Recursive    bool
	PreserveMode bool
	fileNames    []string
}

// Handle requests received through a channel
func handleRequest(channel ssh.Channel, req *ssh.Request) {
	ok := true
	log.Println("Payload before splitting is", string(req.Payload[4:]))
	// This strips globs that aren't the standard * stuff in the standard shlex
	// See https://github.com/flynn/go-shlex/pull/4
	s, err := shlex.Split(string(req.Payload[4:]))
	if err != nil {
		log.Println("Error when splitting payload", err)
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
	// POSSIBLE UNDOCUMENTED OPTIONS:
	//  -t: "TO", our server will be receiving files
	//  -f: "FROM", our server will be sending files
	//  -d: Target is expected to be a directory
	// POSSIBLE DOCUMENTED OPTIONS:
	//  -r: Recursively copy entire directories (follows symlinks)
	//  -p: Preserve modification mtime, atime and mode of files
	parseOpts := true
	opts.fileNames = make([]string, 0)
	for _, elem := range s[1:] {
		log.Println("________", elem, "_________")
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
				// TODO: Maybe we shouldn't ignore this?
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

	log.Println("Called scp with", s[1:])
	log.Println("Options: ", opts)
	log.Println("Filenames: ", opts.fileNames)

	// We're acting as source
	if opts.From {
		err := startSCPSource(channel, opts)
		var ok bool = true
		if err != nil {
			ok = false
			req.Reply(ok, []byte(err.Error()))
		} else {
			req.Reply(ok, nil)
		}
	}

	// We're acting as sink
	// TODO: Implement
	if opts.To {
		if len(opts.fileNames) != 1 {
			// TODO: Inform of the error
			log.Println("Error in number of targets")

			sendExitStatusCode(channel, 0)
			channel.Close()
			req.Reply(false, nil)
			return
		}
		startSCPSink(channel, opts)
		//		channel.Write([]byte("Sink mode not implemented"))
		sendExitStatusCode(channel, 0)
		channel.Close()
		req.Reply(true, nil)
		return
	}

}

func handleNewChannel(newChannel ssh.NewChannel) {
	// There are different channel types, depending on what's done at the application level.
	// scp is done over a "session" channel (as it's used to execute "scp" on the remote side)
	// We reject any other kind of channel as we only care about scp
	log.Println("Channel type is ", newChannel.ChannelType())
	if newChannel.ChannelType() != "session" {
		log.Println("Rejecting channel request for type", newChannel.ChannelType)
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
			channel.Write([]byte("Opening a shell is not supported by the server\n"))
			req.Reply(false, nil)
		case "env":
			// Ignore these for now
			// TODO: Is there any kind of env we want to honor?
			req.Reply(true, nil)
		default:
			log.Println("__", req.Type, "__", string(req.Payload))
			req.Reply(true, nil)
		}
	}
}

// Handle new connections
func handleConn(nConn net.Conn, config *ssh.ServerConfig) {
	// Before use, a handshake must be performed on the incoming
	// net.Conn.
	_, chans, _, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		// If the key changes this is considered a handshake failure
		log.Println("failed to handshake")
	}

	// Service the incoming Channel channel.
	for newChannel := range chans {
		go handleNewChannel(newChannel)
	}
}

// Environment variables:
//   SIMPLESCP_DIR: Directory to share. Nothing outside of it will be accessible. Defaults to working directory
//   SIMPLESCP_PORT: Port we'll be listening in. Default: 2222
//   SIMPLESCP_USER: Username for connecting to this server. Default: scpuser
//   SIMPLESCP_PASS: Password used for connecting to this server. Will be generated randomly by default. TODO: Implement
//   SIMPLESCP_PRIVATEKEY: Location for the private key that will identify this server. By default a random key will be generated

func main() {

	if sharedDirenv := os.Getenv("SIMPLESCP_DIR"); len(sharedDirenv) > 0 {
		basedir = sharedDirenv
	} else {
		basedir = os.Getenv("PWD")
	}

	log.Println("Sharing files out of ", basedir)

	// An SSH server is represented by a ServerConfig, which holds
	// certificate details and handles authentication of ServerConns.
	config := &ssh.ServerConfig{
		PasswordCallback:  passwordAuth,
		PublicKeyCallback: keyAuth,
	}

	privateKeyLocation := os.Getenv("SIMPLESCP_PRIVATEKEY")
	privateBytes, err := ioutil.ReadFile(privateKeyLocation)
	var private ssh.Signer
	if err != nil {
		if len(privateKeyLocation) > 0 {
			log.Fatal("Can't load private key: ", err)
		}
		log.Print("Generating random private key...")
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		private, _ = ssh.NewSignerFromKey(key)
		log.Print("Done")
	} else {
		private, err = ssh.ParsePrivateKey(privateBytes)
		if err != nil {
			log.Fatal("Failed to parse private key: ", err)
		}
	}

	config.AddHostKey(private)

	// TODO: Do sanity checking and ensure port is valid
	port := os.Getenv("SIMPLESCP_PORT")
	if len(port) == 0 {
		port = "2222"
	}

	listener, err := net.Listen("tcp", "0.0.0.0:"+port)
	if err != nil {
		log.Fatal("Failed to listen for connection: ", err)
	}
	log.Println("Listening on port", port)

	for {
		nConn, err := listener.Accept()
		if err != nil {
			log.Fatal("Failed to accept incoming connection: ", err)
		}
		go handleConn(nConn, config)
	}
}
