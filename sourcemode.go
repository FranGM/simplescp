package main

import (
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func startSCPSource(channel ssh.Channel, fileNames []string, opts scpOptions) error {
	// We need to wait for client to initialize data transfer with a binary zero
	checkSCPClientCode(channel)

	for _, target := range fileNames {
		var absTarget string

		if !filepath.IsAbs(target) {
			absTarget = filepath.Clean(filepath.Join(basedir, target))
		} else {
			absTarget = target
		}

		absTarget = filepath.Clean(absTarget)
		if !strings.HasPrefix(absTarget, basedir) {
			// We've requested a file outside of our working directory, so deny it even exists!
			msg := fmt.Sprintf("scp: %s: No such file or directory", target)
			sendErrorToClient(msg, channel)
			continue
		}

		log.Println("Target is now ", absTarget, target)

		fileList, err := filepath.Glob(absTarget)
		if err != nil {
			log.Println("Error when evaluating glob:", err)
			// TODO: I should probably report something to the client here?
			//       (Maybe a file not found?)
			continue
		}

		// If there are no matches it needs to be reported as an error (scp: <target>: No such file or directory)
		if len(fileList) == 0 {
			// TODO: Sanitize the error returned to the client
			msg := fmt.Sprintf("scp: %s: No such file or directory", target)
			sendErrorToClient(msg, channel)
		}

		for _, file := range fileList {
			// FIXME: We probably don't want to stop here, just log/report an error
			err := sendFileBySCP(file, channel, opts)
			if err != nil {
				// TODO: Need to do something with the error here
			}
		}
	}

	// TODO: If there have been recoverable errors along the way, we still need to send 1 as status code
	sendExitStatusCode(channel, 0)
	channel.Close()
	log.Printf("session closed")
	// TODO: We're not actually returning any errors here, maybe just change the func so it doesn't return anything
	return nil
}

// Sends file modification and access times
func sendFileTimes(fi os.FileInfo, channel ssh.Channel) error {
	// TODO: This is not portable, need to figure out how this behaves in non-unix systems
	f, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		// TODO: Handle the error
		// Agghh!! We're not in unix!!
		log.Println("We're not in unix")
		return errors.New("Not in a unix system, not sure what to do")
	}

	msg := fmt.Sprintf("T%d 0 %d 0\n", f.Mtim.Sec, f.Atim.Sec)
	err := sendSCPControlMsg(msg, channel)
	return err
}

// Compose and send an scp control message
func composeSCPControlMsg(fi os.FileInfo, channel ssh.Channel, opts scpOptions) error {
	if opts.PreserveMode {
		err := sendFileTimes(fi, channel)
		if err != nil {
			return err
		}
	}

	var msg string
	if fi.IsDir() {
		// TODO: Is the "&os.ModePerm" still needed? (it seems to be)
		// TODO: We format mode as octal making sure it has a leading zero. What happens if sticky bit is already set?
		msg = fmt.Sprintf("D%#o 0 %v\n", fi.Mode()&os.ModePerm, fi.Name())
	} else {
		msg = fmt.Sprintf("C%#o %d %v\n", fi.Mode()&os.ModePerm, fi.Size(), fi.Name())
	}
	return sendSCPControlMsg(msg, channel)
}

// Sends a scp control message and waits for the reply
func sendSCPControlMsg(msg string, channel ssh.Channel) error {
	log.Println("Sending control message: ", msg)
	fmt.Println(len([]byte(msg)))
	// TODO: Do error checking on write as well
	n, err := channel.Write([]byte(msg))
	log.Printf("Sent %d bytes", n)
	if err != nil {
		return err
	}
	return checkSCPClientCode(channel)
}

// Checks the status messages that the client is sending
// They can be as follows:
//   0: Everything's good
//   1: Warning (can be recovered from)
//   2: Fatal error (This will end the connection)
// 1 and 2 are followed by a text message (delimited by newline character)
func checkSCPClientCode(channel ssh.Channel) error {
	statusbuf := make([]byte, 1)
	// TODO: Determine how big the buffer could/should be
	statusmsgbuf := make([]byte, 256)
	nread, err := channel.Read(statusbuf)
	if err != nil {
		return err
	}

	log.Printf("Received %d bytes from client", nread)

	if statusbuf[0] == 0 {
		return nil
	}

	nread, err = channel.Read(statusmsgbuf)
	msgSize := strings.Index(string(statusmsgbuf), "\n")
	msg := string(statusmsgbuf)[:msgSize]
	log.Printf("Got error %d from client: %v", statusbuf[0], msg)

	//TODO: Return a fatal error (special type) if we've received a 2 so we can close the connection
	return errors.New(msg)
}

// Notify the client of an error. Doesn't break the connection
func sendErrorToClient(msg string, channel ssh.Channel) error {
	_, err := channel.Write([]byte("\001" + msg + "\n"))
	return err
}

func sendFileBySCP(file string, channel ssh.Channel, opts scpOptions) error {

	// Filename as the client sees it (used for error reporting purposes)
	filename := strings.TrimPrefix(file, basedir)

	f, err := os.Open(file)
	if err != nil {
		// FIXME: Need to do more than just logging the error
		log.Println("Open failed", err)
		msg := fmt.Sprintf("scp: %s: %s", filename, err.(*os.PathError).Err)
		sendErrorToClient(msg, channel)
		return err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		// FIXME: Need to do more than just logging the error
		log.Println("Stat failed", err)
		msg := fmt.Sprintf("scp: %s: %s", filename, err.(*os.PathError).Err)
		sendErrorToClient(msg, channel)
		return err
	}

	if fi.IsDir() {
		if !opts.Recursive {
			log.Println("Found a dir but we're not being recursive (not a regular file): ", file)

			// TODO: We just want to print the path of file relative to our base path, not the full path
			msg := fmt.Sprintf("scp: %s: not a regular file", filename)
			sendErrorToClient(msg, channel)
			return errors.New("not a regular file")
		} else {
			err := composeSCPControlMsg(fi, channel, opts)

			if err != nil {
				// TODO: React accordingly (we probably don't want to keep sending this directory now)
				log.Println("ERROR", err)
			}
			names, err := f.Readdirnames(0)
			log.Println("Found the following files", names, err)
			for _, name := range names {
				// TODO: Too many recursive calls might be a problem here. Investigate
				err := sendFileBySCP(file+"/"+name, channel, opts)
				if err != nil {
					// TODO: Handle this properly
					log.Println("Got error after trying to send file")
					return err
				}
			}
			// Signal that we've finished with this directory
			return sendSCPControlMsg("E\n", channel)
		}

	} else {
		err := composeSCPControlMsg(fi, channel, opts)
		if err != nil {
			// TODO: React accordingly
			log.Println("ERROR", err)
			return err
		}
		err = sendFileContentsBySCP(f, channel)
		return err
	}
	return nil
}

// Does the actual data transfer of the file's contents
func sendFileContentsBySCP(f *os.File, channel ssh.Channel) error {
	n, err := io.Copy(channel, f)
	log.Printf("Sending content, sent %d bytes", n)
	if err != nil {
		return err
	}

	// Need to send binary zero after actual data transfer to signify everything's ok
	_, err = channel.Write([]byte("\000"))
	if err != nil {
		return err
	}

	return checkSCPClientCode(channel)
}
