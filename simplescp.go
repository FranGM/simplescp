package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"fmt"
	"github.com/flynn/go-shlex"
	"golang.org/x/crypto/ssh"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os/exec"
)

// Handle requests received through a channel
func handleRequest(channel ssh.Channel, req *ssh.Request) {
	ok := true
	s, _ := shlex.Split(string(req.Payload[4:]))

	// We only do scp, so ignore everything after a ";" or "&&"
	commandStop := len(s)
	for i := 1; i < len(s); i++ {
		if s[i] == ";" || s[i] == "&&" {
			commandStop = i
		}
	}

	// Ignore everything that's not scp
	if s[0] != "scp" {
		ok = false
		req.Reply(ok, []byte("Only scp is supported"))
		channel.Write([]byte("Only scp is supported\n"))
		channel.Close()
		return
	}

	cmd := exec.Command(s[0], s[1:commandStop]...)

	cerr, _ := cmd.StderrPipe()
	cout, _ := cmd.StdoutPipe()
	cin, _ := cmd.StdinPipe()

	go io.Copy(channel.Stderr(), cerr)
	go io.Copy(channel, cout)
	go io.Copy(cin, channel)

	log.Printf("Starting command")
	cmd.Start()

	log.Printf("Waiting")
	var exitStatus uint64 = 0
	err := cmd.Wait()
	if err != nil {
		log.Printf("Error when running command (%s)", err)
		// TODO: Get the actual exit status and store it here
		exitStatus = 1
	}

	log.Printf("Waited")

	exitStatusBuffer := make([]byte, 4)
	binary.PutUvarint(exitStatusBuffer, uint64(exitStatus))
	_, err = channel.SendRequest("exit-status", false, exitStatusBuffer)
	if err != nil {
		log.Println("Failed to forward exit-status to client:", err)
	}

	channel.Close()
	log.Printf("session closed")
	fmt.Println(ok)
	req.Reply(ok, nil)
}

func handleNewChannel(newChannel ssh.NewChannel) {
	fmt.Println("Channel type is ", newChannel.ChannelType())
	// Channels have a type, depending on the application level
	// protocol intended. In the case of a shell, the type is
	// "session" and ServerShell may be used to present a simple
	// terminal interface.
	// TODO: Is there any other channel type we want to accept?
	if newChannel.ChannelType() != "session" {
		newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
		return
	}
	channel, requests, err := newChannel.Accept()
	if err != nil {
		// TODO: Don't panic here, just clean up and log error
		panic("could not accept channel.")
	}

	// We just handle "exec" requests
	for req := range requests {
		// scp does an exec, so that's all we care about
		switch req.Type {
		case "exec":
			go handleRequest(channel, req)
		case "shell":
			channel.Write([]byte("Opening a shell is not supported by the server\n"))
			req.Reply(false, nil)
		case "env":
			// Ignore these
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

func passwordAuth(conn ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
	// TODO: Everything!!
	// Should use constant-time compare (or better, salt+hash) in
	// a production setting.
	if conn.User() == "testuser" && string(pass) == "" {
		return nil, nil
	}
	return nil, fmt.Errorf("password rejected for %q", conn.User())
}

func keyAuth(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	// TODO: Improve log message
	log.Println(conn.RemoteAddr(), "authenticating with", key.Type())
	// TODO: Actually do authentication here
	return nil, fmt.Errorf("key rejected for %q", conn.User())
}

func main() {
	// An SSH server is represented by a ServerConfig, which holds
	// certificate details and handles authentication of ServerConns.
	config := &ssh.ServerConfig{
		PasswordCallback:  passwordAuth,
		PublicKeyCallback: keyAuth,
	}

	// TODO: Tidy up a bit, allow to specify keys on startup
	privateBytes, err := ioutil.ReadFile("id_rsa")
	var private ssh.Signer
	if err != nil {
		fmt.Println("Failed to load private key, generating one")
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		private, _ = ssh.NewSignerFromKey(key)
	} else {
		private, err = ssh.ParsePrivateKey(privateBytes)
		if err != nil {
			panic("Failed to parse private key")
		}
	}

	config.AddHostKey(private)

	// Once a ServerConfig has been configured, connections can be
	// accepted.
	listener, err := net.Listen("tcp", "0.0.0.0:2222")
	if err != nil {
		panic("failed to listen for connection")
	}

	for {
		nConn, err := listener.Accept()
		if err != nil {
			panic("failed to accept incoming connection")
		}
		go handleConn(nConn, config)
	}
}