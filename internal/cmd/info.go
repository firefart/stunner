package cmd

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/firefart/stunner/internal"
	"github.com/firefart/stunner/internal/helper"
	"github.com/sirupsen/logrus"
)

type InfoOpts struct {
	TurnServer string
	UseTLS     bool
	Protocol   string
	Timeout    time.Duration
	Log        *logrus.Logger
}

func (opts InfoOpts) Validate() error {
	if opts.TurnServer == "" {
		return errors.New("need a valid turnserver")
	}
	if !strings.Contains(opts.TurnServer, ":") {
		return errors.New("turnserver needs a port")
	}
	if opts.Protocol != "tcp" && opts.Protocol != "udp" {
		return errors.New("protocol needs to be either tcp or udp")
	}
	if opts.Log == nil {
		return errors.New("please supply a valid logger")
	}

	return nil
}

func Info(ctx context.Context, opts InfoOpts) error {
	if err := opts.Validate(); err != nil {
		return err
	}

	if attr, err := testStun(ctx, opts); err != nil {
		opts.Log.Debugf("STUN error: %v", err)
		opts.Log.Error("this server does not support the STUN protocol")
	} else {
		opts.Log.Info("this server supports the STUN protocol")
		printAttributes(opts, attr)
	}

	if attr, err := testTurn(ctx, opts, internal.RequestedTransportUDP); err != nil {
		opts.Log.Debugf("TURN UDP error: %v", err)
		opts.Log.Error("this server does not support the TURN UDP protocol")
	} else {
		opts.Log.Info("this server supports the TURN protocol with UDP transports")
		printAttributes(opts, attr)
	}

	if attr, err := testTurn(ctx, opts, internal.RequestedTransportTCP); err != nil {
		opts.Log.Debugf("TURN TCP error: %v", err)
		opts.Log.Error("this server does not support the TURN TCP protocol")
	} else {
		opts.Log.Info("this server supports the TURN protocol with TCP transports")
		printAttributes(opts, attr)
	}

	return nil
}

func testStun(ctx context.Context, opts InfoOpts) ([]internal.Attribute, error) {
	conn, err := internal.Connect(ctx, opts.Protocol, opts.TurnServer, opts.UseTLS, opts.Timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	bindingRequest := internal.BindingRequest()
	bindingResponse, err := bindingRequest.SendAndReceive(ctx, opts.Log, conn, opts.Timeout)
	if err != nil {
		return nil, fmt.Errorf("error on sending binding request: %w", err)
	}
	if bindingResponse.Header.MessageType.Class == internal.MsgTypeClassError {
		return nil, fmt.Errorf("MessageClass is Error: %v", bindingResponse.GetErrorString())
	}

	return bindingResponse.Attributes, nil
}

func testTurn(ctx context.Context, opts InfoOpts, proto internal.RequestedTransport) ([]internal.Attribute, error) {
	conn, err := internal.Connect(ctx, opts.Protocol, opts.TurnServer, opts.UseTLS, opts.Timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	allocateRequest := internal.AllocateRequest(proto, internal.AllocateProtocolIgnore)
	allocateResponse, err := allocateRequest.SendAndReceive(ctx, opts.Log, conn, opts.Timeout)
	if err != nil {
		return nil, fmt.Errorf("error on sending allocate request: %w", err)
	}
	if allocateResponse.Header.MessageType.Class != internal.MsgTypeClassError {
		return nil, errors.New("MessageClass is not Error (should be not authenticated)")
	}

	return allocateResponse.Attributes, nil
}

func printAttributes(opts InfoOpts, attr []internal.Attribute) {
	if len(attr) == 0 {
		return
	}

	headerPrinted := false

	for _, a := range attr {
		// do not print common protocol related attributes
		if a.Type == internal.AttrNonce || a.Type == internal.AttrErrorCode || a.Type == internal.AttrFingerprint || a.Type == internal.AttrXorMappedAddress || a.Type == internal.AttrMappedAddress {
			continue
		}

		// inside here so we don't print an unnecessary "Attributes:" line
		if !headerPrinted {
			opts.Log.Info("Attributes:")
			headerPrinted = true
		}

		value := string(a.Value)
		// checks for old RFC5780 but still implemented (for example in coturn)
		if a.Type == internal.AttrResponseOrigin || a.Type == internal.AttrOtherAddress {
			tmpIP, tmpPort, err := internal.ParseMappedAdress(a.Value)
			if err != nil {
				opts.Log.Errorf("could not parse mapped address: %02x %v", a.Value, err)
				continue
			}
			value = fmt.Sprintf("%s:%d", tmpIP.String(), tmpPort)
		}

		humanName := internal.AttributeTypeString(a.Type)
		if humanName == "" {
			if helper.IsPrintable(value) {
				opts.Log.Warnf("\tNon Standard Attribute %d returned with value %s", uint16(a.Type), value)
			} else {
				opts.Log.Warnf("\tNon Standard Attribute %d returned with value %02x", uint16(a.Type), a.Value)
			}
		} else {
			opts.Log.Infof("\t%s: %s", humanName, value)
		}
	}
}
