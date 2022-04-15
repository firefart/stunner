package cmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/firefart/stunner/internal"
	"github.com/sirupsen/logrus"
)

type InfoOpts struct {
	TurnServer string
	Protocol   string
	UseTLS     bool
	Timeout    time.Duration
	Log        *logrus.Logger
}

func (opts InfoOpts) Validate() error {
	if opts.TurnServer == "" {
		return fmt.Errorf("need a valid turnserver")
	}
	if !strings.Contains(opts.TurnServer, ":") {
		return fmt.Errorf("turnserver needs a port")
	}
	if opts.Protocol != "tcp" && opts.Protocol != "udp" {
		return fmt.Errorf("protocol needs to be either tcp or udp")
	}
	if opts.Log == nil {
		return fmt.Errorf("please supply a valid logger")
	}

	return nil
}

func Info(opts InfoOpts) error {
	if err := opts.Validate(); err != nil {
		return err
	}

	conn, err := internal.Connect(opts.Protocol, opts.TurnServer, opts.UseTLS, opts.Timeout)
	if err != nil {
		return err
	}
	defer conn.Close()

	allocateRequest := internal.AllocateRequest(internal.RequestedTransportTCP, internal.AllocateProtocolIgnore)
	allocateResponse, err := allocateRequest.SendAndReceive(opts.Log, conn, opts.Timeout)
	if err != nil {
		return fmt.Errorf("error on sending allocate request: %w", err)
	}
	if allocateResponse.Header.MessageType.Class != internal.MsgTypeClassError {
		return fmt.Errorf("MessageClass is not Error (should be not authenticated)")
	}

	for _, a := range allocateResponse.Attributes {
		// do not print common protocol related attributes
		if a.Type == internal.AttrNonce || a.Type == internal.AttrErrorCode || a.Type == internal.AttrFingerprint {
			continue
		}

		humanName := internal.AttributeTypeString(a.Type)
		value := string(a.Value)
		if humanName == "" {
			opts.Log.Warnf("Non Standard Attribute %d returned with value %s", uint16(a.Type), value)
		}

		opts.Log.Infof("%s: %s", humanName, value)
	}

	return nil
}
