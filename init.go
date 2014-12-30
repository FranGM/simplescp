package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"unicode"
)

// Generates a random string of length n (http://play.golang.org/p/1GwSRsKIsd)
func randString(n int) string {
	g := big.NewInt(0)
	max := big.NewInt(130)
	bs := make([]byte, n)

	for i, _ := range bs {
		g, _ = rand.Int(rand.Reader, max)
		r := rune(g.Int64())
		for !unicode.IsNumber(r) && !unicode.IsLetter(r) {
			g, _ = rand.Int(rand.Reader, max)
			r = rune(g.Int64())
		}
		bs[i] = byte(g.Int64())
	}
	return string(bs)
}

func init_homedir() error {
	if sharedDirenv := os.Getenv("SIMPLESCP_DIR"); len(sharedDirenv) > 0 {
		globalConfig.basedir = sharedDirenv
	} else {
		globalConfig.basedir = os.Getenv("PWD")
	}

	log.Printf("Sharing files out of %q", globalConfig.basedir)

	// TODO: Check if we can open the directory before continuing
	return nil
}

func init_username() error {
	username := os.Getenv("SIMPLESCP_USER")
	if len(username) == 0 {
		username = "scpuser"
	}

	globalConfig.username = username

	log.Printf("Allowing logins from user %q", globalConfig.username)
	return nil
}

func init_password() error {
	globalConfig.passwords = make(map[string]string)

	scpPasswd := os.Getenv("SIMPLESCP_PASS")
	// TODO: This doesn't allow for setting the password to ""
	if len(scpPasswd) == 0 {
		scpPasswd = randString(15)
		log.Printf("Generating random password for user %v: %q", globalConfig.username, scpPasswd)
	}

	globalConfig.passwords[globalConfig.username] = scpPasswd
	return nil
}

func init_authkeys() error {
	globalConfig.authorized_keys = make(map[string][]ssh.PublicKey)
	globalConfig.authorized_keys[globalConfig.username] = make([]ssh.PublicKey, 0)

	authKeysFile := os.Getenv("SIMPLESCP_AUTHKEYS")
	if len(authKeysFile) == 0 {
		// Nothing to do here
		return nil
	}

	f, err := os.Open(authKeysFile)
	if err != nil {
		return fmt.Errorf("Error opening authorized keys file, ignoring file:", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		pk, err := parsePubKey(scanner.Text())
		if err != nil {
			log.Println("Error when parsing public key, ignoring:", err)
		} else {
			globalConfig.authorized_keys[globalConfig.username] = append(globalConfig.authorized_keys[globalConfig.username], pk)
		}
	}

	f.Close()
	log.Printf("loaded %d authorized keys", len(globalConfig.authorized_keys[globalConfig.username]))
	return nil
}

func init_privatekey() error {
	privateKeyLocation := os.Getenv("SIMPLESCP_PRIVATEKEY")
	privateBytes, err := ioutil.ReadFile(privateKeyLocation)
	if err != nil {
		if len(privateKeyLocation) > 0 {
			return fmt.Errorf("Can't load private key: ", err)
		}
		log.Print("Generating random private key...")
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		globalConfig.privateKey, _ = ssh.NewSignerFromKey(key)
		log.Print("Done")
	} else {
		globalConfig.privateKey, err = ssh.ParsePrivateKey(privateBytes)
		if err != nil {
			return fmt.Errorf("Failed to parse private key: ", err)
		}
	}
	return nil
}

func init_port() error {
	// TODO: Do sanity checking and ensure port is valid (at least that it's numeric and inside acceptable range)
	port := os.Getenv("SIMPLESCP_PORT")
	if len(port) == 0 {
		port = "2222"
	}
	globalConfig.port = port

	return nil
}

// Initialize global config based in environment variables (or their defaults)
// Environment variables:
//   SIMPLESCP_DIR: Directory to share. Nothing outside of it will be accessible. Default: Working directory
//   SIMPLESCP_PORT: Port we'll be listening in. Default: 2222
//   SIMPLESCP_USER: Username for connecting to this server. Default: scpuser
//   SIMPLESCP_PASS: Password used for connecting to this server. Default: One will be generated randomly
//   SIMPLESCP_PRIVATEKEY: Location for the private key that will identify this server. Default: One will be generated randomly
//   SIMPLESCP_AUTHKEYS: Location of the authorized keys file for this server. Default: No pubkey authentication
func init() {
	init_port()
	init_homedir()
	init_username()
	init_password()
	err := init_privatekey()
	if err != nil {
		log.Fatal(err)
	}

	err = init_authkeys()
	if err != nil {
		log.Println(err)
	}
}
