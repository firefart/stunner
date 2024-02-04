package cmd

import (
	"context"
	"fmt"
	"strings"
	"time"

	socks "github.com/firefart/gosocks"
	"github.com/firefart/stunner/internal/socksimplementations"
	"github.com/sirupsen/logrus"
)

type SocksOpts struct {
	TurnServer string
	Protocol   string
	Username   string
	Password   string
	UseTLS     bool
	Timeout    time.Duration
	Log        *logrus.Logger
	Listen     string
	DropPublic bool
}

func (opts SocksOpts) Validate() error {
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
	if opts.Listen == "" {
		return fmt.Errorf("please supply a valid listen address")
	}
	if !strings.Contains(opts.Listen, ":") {
		return fmt.Errorf("listen must be in the format host:port")
	}

	return nil
}

func Socks(ctx context.Context, opts SocksOpts) error {
	if err := opts.Validate(); err != nil {
		return err
	}

	handler := &socksimplementations.SocksTurnTCPHandler{
		Server:                 opts.TurnServer,
		TURNUsername:           opts.Username,
		TURNPassword:           opts.Password,
		Timeout:                opts.Timeout,
		UseTLS:                 opts.UseTLS,
		DropNonPrivateRequests: opts.DropPublic,
		Log:                    opts.Log,
	}
	p := socks.Proxy{
		ServerAddr:   opts.Listen,
		Proxyhandler: handler,
		Timeout:      opts.Timeout,
		Log:          opts.Log,
	}
	opts.Log.Infof("starting SOCKS server on %s", opts.Listen)
	if err := p.Start(ctx); err != nil {
		return err
	}
	<-p.Done
	return nil
}
