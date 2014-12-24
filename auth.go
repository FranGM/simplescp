package main

import (
	"fmt"
	"golang.org/x/crypto/ssh"
	"log"
	"os"
)

func passwordAuth(conn ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
	user := os.Getenv("SIMPLESCP_USER")
	if len(user) == 0 {
		user = "scpuser"
	}
	scpPasswd := os.Getenv("SIMPLESCP_PASS")
	if len(scpPasswd) == 0 {
		// TODO: Generate random password
		// TODO: This doesn't belong in this function
	}
	// TODO: Everything!!
	// Should use constant-time compare (or better, salt+hash) in
	// a production setting.
	if conn.User() == user && string(pass) == scpPasswd {
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
