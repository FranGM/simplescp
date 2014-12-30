package main

import (
	"bytes"
	"fmt"
	"golang.org/x/crypto/ssh"
	"log"
)

func passwordAuth(conn ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
	username := conn.User()
	log.Printf("Doing password authentication for user %v", username)
	// Consider using hashes for the comparison instead of a straight equality check
	if username == globalConfig.username && string(pass) == globalConfig.passwords[username] {
		log.Printf("Accepted password for %v", username)
		return nil, nil
	}

	log.Printf("Rejected password for %v", username)
	return nil, fmt.Errorf("password rejected for %v", username)
}

func keyAuth(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	username := conn.User()

	log.Println("authenticating with key of type", key.Type())

	listKeys, ok := globalConfig.authorized_keys[username]
	if !ok {
		return nil, fmt.Errorf("No keys for %q", username)
	}

	for _, authorized_key := range listKeys {
		if bytes.Compare(key.Marshal(), authorized_key.Marshal()) == 0 {
			log.Printf("Access granted for user %v", username)
			return nil, nil
		}
	}

	log.Printf("Rejected key authentication for user %v", username)
	return nil, fmt.Errorf("key rejected for %v", username)
}
