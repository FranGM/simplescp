package main

import (
	"bytes"
	"fmt"
	"golang.org/x/crypto/ssh"
	"log"
)

func passwordAuth(conn ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
	// TODO: Everything!!
	// Should use constant-time compare (or better, salt+hash) in
	// a production setting.
	if conn.User() == globalConfig.username && string(pass) == globalConfig.passwords[conn.User()] {
		return nil, nil
	}
	return nil, fmt.Errorf("password rejected for %q", conn.User())
}

func keyAuth(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {

	log.Println(conn.RemoteAddr(), "authenticating with key of type", key.Type())

	listKeys, ok := globalConfig.authorized_keys[conn.User()]
	if !ok {
		return nil, fmt.Errorf("No keys for %q", conn.User())
	}

	for _, authorized_key := range listKeys {
		if bytes.Compare(key.Marshal(), authorized_key.Marshal()) == 0 {
			log.Println("Access granted for user", conn.User())
			return nil, nil
		}
	}

	return nil, fmt.Errorf("key rejected for %q", conn.User())
}
