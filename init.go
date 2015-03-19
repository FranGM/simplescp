package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"unicode"

	"github.com/FranGM/simplelog"
	"github.com/kelseyhightower/envconfig"
	"golang.org/x/crypto/ssh"
)

// Generates a random string of length n (http://play.golang.org/p/1GwSRsKIsd)
func randString(n int) string {
	g := big.NewInt(0)
	max := big.NewInt(130)
	bs := make([]byte, n)

	for i := range bs {
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

func (c *scpConfig) initPassword() error {
	c.passwords = make(map[string]string)

	scpPasswd := os.Getenv("SIMPLESCP_PASS")
	// TODO: This doesn't allow for setting the password to ""
	if len(scpPasswd) == 0 {
		scpPasswd = randString(15)
		simplelog.Info.Printf("Generating random password for user %v: %q", c.User, scpPasswd)
	}

	c.passwords[c.User] = scpPasswd
	return nil
}

func (c *scpConfig) initAuthKeys() error {
	c.AuthKeys = make(map[string][]ssh.PublicKey)
	c.AuthKeys[c.User] = make([]ssh.PublicKey, 0)

	if len(c.AuthKeysFile) == 0 {
		// Nothing to do here
		return nil
	}

	f, err := os.Open(c.AuthKeysFile)
	if err != nil {
		return fmt.Errorf("Error opening authorized keys file, ignoring file: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		pk, err := parsePubKey(scanner.Text())
		if err != nil {
			simplelog.Warning.Printf("Error when parsing public key, ignoring: %q", err)
			continue
		}
		c.AuthKeys[c.User] = append(c.AuthKeys[c.User], pk)
	}

	simplelog.Info.Printf("loaded %d authorized keys", len(c.AuthKeys[c.User]))
	return nil
}

func (c *scpConfig) initPrivateKey() error {
	privateBytes, err := ioutil.ReadFile(c.PrivateKeyFile)
	if err != nil {
		if len(c.PrivateKeyFile) > 0 {
			return fmt.Errorf("Can't load private key: %v", err)
		}
		simplelog.Debug.Printf("Generating random private key...")
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		c.privateKey, _ = ssh.NewSignerFromKey(key)
		simplelog.Debug.Printf("Done")
	} else {
		c.privateKey, err = ssh.ParsePrivateKey(privateBytes)
		if err != nil {
			return fmt.Errorf("Failed to parse private key: %v", err)
		}
		// TODO: At this point we've generated a new private key so store it in ~/.simplescp/keys for the next time
	}
	return nil
}

// Initialize global config based in environment variables (or their defaults)
// Environment variables:
//   SIMPLESCP_DIR: Directory to share. Nothing outside of it will be accessible. Default: Working directory
//   SIMPLESCP_PORT: Port we'll be listening in. Default: 2222
//   SIMPLESCP_USER: Username for connecting to this server. Default: scpuser
//   SIMPLESCP_PASS: Password used for connecting to this server. Default: One will be generated randomly
//   SIMPLESCP_PRIVATEKEYFILE: Location for the private key that will identify this server. Default: One will be generated randomly
//   SIMPLESCP_AUTHKEYSFILE: Location of the authorized keys file for this server. Default: No pubkey authentication
func initSettings() *scpConfig {

	// TODO: workingDir should be configurable
	simplelog.SetThreshold(simplelog.LevelInfo)

	config := newScpConfig()
	err := envconfig.Process("simplescp", config)
	if err != nil {
		log.Fatal(err)
	}

	simplelog.Info.Printf("Allowing logins from user %q", config.User)
	simplelog.Info.Printf("Sharing files out of %q", config.Dir)

	config.initPassword()

	err = config.initPrivateKey()
	if err != nil {
		log.Fatal(err)
	}

	err = config.initAuthKeys()
	if err != nil {
		simplelog.Error.Printf("%v", err)
	}
	return config

}
