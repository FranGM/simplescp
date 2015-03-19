package main

import (
	"bytes"
	"fmt"

	"github.com/FranGM/simplelog"
	"golang.org/x/crypto/ssh"
)

func (c scpConfig) passwordAuth(conn ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
	username := conn.User()
	simplelog.Debug.Printf("Doing password authentication for user %v", username)
	// Consider using hashes for the comparison instead of a straight equality check
	if username == c.User && string(pass) == c.passwords[username] {
		simplelog.Info.Printf("Accepted password for %v", username)
		return nil, nil
	}

	simplelog.Info.Printf("Rejected password for %v", username)
	return nil, fmt.Errorf("password rejected for %v", username)
}

func (c scpConfig) keyAuth(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	username := conn.User()

	simplelog.Debug.Printf("authenticating with key of type %q", key.Type())

	listKeys, ok := c.AuthKeys[username]
	if !ok {
		return nil, fmt.Errorf("No keys for %q", username)
	}

	for _, authorizedKey := range listKeys {
		if bytes.Compare(key.Marshal(), authorizedKey.Marshal()) == 0 {
			simplelog.Info.Printf("Access granted for user %v", username)
			return nil, nil
		}
	}

	simplelog.Info.Printf("Rejected key authentication for user %v", username)
	return nil, fmt.Errorf("key rejected for %v", username)
}
