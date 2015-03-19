package main

import (
	"crypto/md5"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"testing"
)
import "os/exec"
import "time"

// Testing idea:
// Create sample files/directory structure in support/testing/blah
// Start server on rando port
// Have client connect to it
// Get it to copy the files
// Compare the whole directory structure
// some kind of teardown to delete the files copied?

// To give scp a password, do this:
//   export SIMPLESCP_TESTPASS="hunter2"
//   export SSH_ASKPASS=./bla.sh  # blah.sh just prints the password to stdin
//   setsid -w scp ...

type testConf struct {
	src      string
	dst      string
	password string
	t        *testing.T
}

func (conf testConf) runCopyTest() error {
	err := cleanupDir(conf.dst)
	if err != nil {
		conf.t.Fatalf("Error preparing for test: %q", err)
	}
	os.Setenv("SIMPLESCP_PASS", conf.password)
	os.Setenv("SIMPLESCP_DIR", conf.src)
	c := initSettings()
	serverConfig := c.initSSHConfig()
	c.Dir = conf.src
	// TODO: Remove the OneShot option and add a StopServer method
	c.OneShot = true
	go startServer(c, serverConfig)
	time.Sleep(500 * time.Millisecond)

	// Look into SSH_ASKPASS to specify a binary to ask for ssh password
	cmd := exec.Command("setsid", "-w", "scp", "-P", "2222", "scpuser@localhost:*", conf.dst)
	//	cmd := exec.Command("tty")
	cmd.Env = append(cmd.Env, "SIMPLESCP_TESTPASS="+conf.password)
	cmd.Env = append(cmd.Env, "SSH_ASKPASS=support/ssh_pass.sh")
	cmd.Env = append(cmd.Env, "DISPLAY=totallybogus")

	// TODO: maybe separate stdout and stderr here
	//err := cmd.Run()
	out, err := cmd.CombinedOutput()

	fmt.Println(string(out))
	if err != nil {
		conf.t.Fatal(err)
	}

	err = compareDirs(conf.src, conf.dst)
	if err != nil {
		fmt.Printf("Src and Dst don't match: %s", err)
		conf.t.Fail()
	}

	return nil
}

func TestSource(t *testing.T) {
	c := testConf{
		dst:      "support/test/files/test1/dst",
		src:      "support/test/files/test1/src",
		password: "12345",
	}

	c.runCopyTest()
}

// Aux functions/types

type fileStats struct {
	filename string
	size     int64
	md5      string
}

//func compareDirs(dir1 []FileStats, dir2 []FileStats) error {
func compareDirs(src string, dst string) error {
	dirsInfo := make(map[string][]fileStats)
	dirs := []string{src, dst}

	for _, dir := range dirs {
		dirsInfo[dir] = make([]fileStats, 0, 0)

		err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if info.IsDir() {
				return nil
			}

			relName, _ := filepath.Rel(dir, path)
			fBytes, err := ioutil.ReadFile(path)
			if err != nil {
				return err
			}
			md5 := fmt.Sprintf("%x", md5.Sum(fBytes))
			dirsInfo[dir] = append(dirsInfo[dir], fileStats{filename: relName, size: info.Size(), md5: md5})

			return nil
		})
		if err != nil {
			log.Fatal(err)
		}
	}

	dirSrc := dirsInfo[src]
	dirDst := dirsInfo[dst]

	if len(dirSrc) != len(dirDst) {
		return fmt.Errorf("%s has %d elements while %s has %d", src, len(dirSrc), dst, len(dirDst))
	}

	for i, file := range dirSrc {
		dstFile := dirDst[i]
		if file.filename != dstFile.filename || file.md5 != dstFile.md5 {
			return fmt.Errorf("Expected %q with md5 %s, found %q with md5 %s", file.filename, file.md5, dstFile.filename, dstFile.md5)
		}
	}

	return nil
}

func cleanupDir(dirName string) error {
	matches, _ := filepath.Glob(filepath.Join(dirName, "*"))
	for _, f := range matches {
		err := os.RemoveAll(f)
		if err != nil {
			return err
		}
	}
	return nil
}
