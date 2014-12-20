package main

import (
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
	go io.Copy(channel, cerr)
	cout, _ := cmd.StdoutPipe()
	go io.Copy(channel, cout)
	cin, _ := cmd.StdinPipe()
	go io.Copy(cin, channel)

	log.Printf("Starting command")
	cmd.Start()

	log.Printf("Waiting")
	err := cmd.Wait()
	log.Printf("Waited")

	channel.Close()
	if err != nil {
		log.Printf("Error when running command (%s)", err)
	}
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
		panic("could not accept channel.")
	}

	// We just handle "exec" requests
	for req := range requests {
		// scp does an exec, so that's all we care about
		switch req.Type {
		case "exec":
			go handleRequest(channel, req)
		default:
			ok := false
			fmt.Println(req.Type, string(req.Payload))
			req.Reply(ok, nil)
		}
	}
}

// Handle new connections
func handleConn(nConn net.Conn, config *ssh.ServerConfig) {
	// Before use, a handshake must be performed on the incoming
	// net.Conn.
	_, chans, _, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		panic("failed to handshake")
	}

	// Service the incoming Channel channel.
	for newChannel := range chans {
		go handleNewChannel(newChannel)
	}
}

func passwordAuth(conn ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
	// TODO: Everything
	// Should use constant-time compare (or better, salt+hash) in
	// a production setting.
	if conn.User() == "testuser" && string(pass) == "tiger" {
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
	// TODO: Regenerate private keys on the fly if they don't exist

	privateBytes, err := ioutil.ReadFile("id_rsa")
	if err != nil {
		panic("Failed to load private key")
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		panic("Failed to parse private key")
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
