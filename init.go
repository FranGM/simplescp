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

func initPassword() error {
	globalConfig.passwords = make(map[string]string)

	scpPasswd := os.Getenv("SIMPLESCP_PASS")
	// TODO: This doesn't allow for setting the password to ""
	if len(scpPasswd) == 0 {
		scpPasswd = randString(15)
		simplelog.Info.Printf("Generating random password for user %v: %q", globalConfig.User, scpPasswd)
	}

	globalConfig.passwords[globalConfig.User] = scpPasswd
	return nil
}

func initAuthKeys() error {
	globalConfig.AuthKeys = make(map[string][]ssh.PublicKey)
	globalConfig.AuthKeys[globalConfig.User] = make([]ssh.PublicKey, 0)

	if len(globalConfig.AuthKeysFile) == 0 {
		// Nothing to do here
		return nil
	}

	f, err := os.Open(globalConfig.AuthKeysFile)
	if err != nil {
		return fmt.Errorf("Error opening authorized keys file, ignoring file: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		pk, err := parsePubKey(scanner.Text())
		if err != nil {
			simplelog.Warning.Printf("Error when parsing public key, ignoring: %q", err)
		} else {
			globalConfig.AuthKeys[globalConfig.User] = append(globalConfig.AuthKeys[globalConfig.User], pk)
		}
	}

	f.Close()
	simplelog.Info.Printf("loaded %d authorized keys", len(globalConfig.AuthKeys[globalConfig.User]))
	return nil
}

func initPrivateKey() error {
	privateBytes, err := ioutil.ReadFile(globalConfig.PrivateKeyFile)
	if err != nil {
		if len(globalConfig.PrivateKeyFile) > 0 {
			return fmt.Errorf("Can't load private key: %v", err)
		}
		simplelog.Debug.Printf("Generating random private key...")
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		globalConfig.privateKey, _ = ssh.NewSignerFromKey(key)
		simplelog.Debug.Printf("Done")
	} else {
		globalConfig.privateKey, err = ssh.ParsePrivateKey(privateBytes)
		if err != nil {
			return fmt.Errorf("Failed to parse private key: %v", err)
		}
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
func init() {

	simplelog.SetThreshold(simplelog.LevelInfo)

	globalConfig = newSimpleScpConfig()
	err := envconfig.Process("simplescp", globalConfig)
	if err != nil {
		log.Fatal(err)
	}

	simplelog.Info.Printf("Allowing logins from user %q", globalConfig.User)
	simplelog.Info.Printf("Sharing files out of %q", globalConfig.Dir)

	initPassword()

	err = initPrivateKey()
	if err != nil {
		log.Fatal(err)
	}

	err = initAuthKeys()
	if err != nil {
		simplelog.Error.Printf("%v", err)
	}

}
