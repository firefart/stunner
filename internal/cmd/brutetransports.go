package cmd

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/firefart/stunner/internal"
	"github.com/sirupsen/logrus"
)

type BruteTransportOpts struct {
	TurnServer string
	Protocol   string
	Username   string
	Password   string
	UseTLS     bool
	Timeout    time.Duration
	Log        *logrus.Logger
}

func (opts BruteTransportOpts) Validate() error {
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
	if opts.Password == "" {
		return fmt.Errorf("please supply a password")
	}
	if opts.Log == nil {
		return fmt.Errorf("please supply a valid logger")
	}

	return nil
}

func BruteTransports(ctx context.Context, opts BruteTransportOpts) error {
	if err := opts.Validate(); err != nil {
		return err
	}

	for i := 0; i <= 255; i++ {
		conn, err := internal.Connect(ctx, opts.Protocol, opts.TurnServer, opts.UseTLS, opts.Timeout)
		if err != nil {
			return err
		}

		x := internal.RequestedTransport(uint32(i))
		allocateRequest := internal.AllocateRequest(x, internal.AllocateProtocolIgnore)
		allocateResponse, err := allocateRequest.SendAndReceive(ctx, opts.Log, conn, opts.Timeout)
		if err != nil {
			return fmt.Errorf("error on sending allocate request: %w", err)
		}

		realm := string(allocateResponse.GetAttribute(internal.AttrRealm).Value)
		nonce := string(allocateResponse.GetAttribute(internal.AttrNonce).Value)

		allocateRequest = internal.AllocateRequestAuth(opts.Username, opts.Password, nonce, realm, x, internal.AllocateProtocolIgnore)
		allocateResponse, err = allocateRequest.SendAndReceive(ctx, opts.Log, conn, opts.Timeout)
		if err != nil {
			return fmt.Errorf("error on sending allocate request auth: %w", err)
		}
		if allocateResponse.Header.MessageType.Class != internal.MsgTypeClassSuccess {
			errorCode := allocateResponse.GetAttribute(internal.AttrErrorCode).Value[4:]
			opts.Log.Errorf("%d %s", i, string(errorCode))
			if allocateResponse.Header.MessageType.Class != internal.MsgTypeClassError {
				opts.Log.Infof("%d %02x", i, allocateResponse.Header.MessageType)
			}
		} else {
			// valid transport found
			switch x {
			case internal.RequestedTransportTCP:
				opts.Log.Infof("Found supported protocol %d which is TCP and a default protocol", i)
			case internal.RequestedTransportUDP:
				opts.Log.Infof("Found supported protocol %d which is UDP and a default protocol", i)
			default:
				opts.Log.Infof("Found non standard protocol %d", i)
			}
		}
		if err := conn.Close(); err != nil {
			return fmt.Errorf("error on closing connection: %w", err)
		}
	}
	return nil
}
