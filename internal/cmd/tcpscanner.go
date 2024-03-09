package cmd

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/firefart/stunner/internal"
	"github.com/firefart/stunner/internal/helper"
	"github.com/sirupsen/logrus"
)

const httpRequest = "GET / HTTP/1.0\r\n\r\n"

type TCPScannerOpts struct {
	TurnServer string
	Protocol   string
	Username   string
	Password   string
	UseTLS     bool
	Timeout    time.Duration
	Log        *logrus.Logger
	Ports      []string
	IPs        []string
}

func (opts TCPScannerOpts) Validate() error {
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
	if len(opts.Ports) == 0 {
		return fmt.Errorf("please supply valid ports")
	}
	// no need to check IPs, it can be nil

	return nil
}

func TCPScanner(ctx context.Context, opts TCPScannerOpts) error {
	if err := opts.Validate(); err != nil {
		return err
	}

	ipInput := opts.IPs
	if len(ipInput) == 0 {
		ipInput = helper.PrivateRanges
	}

	ipChan := helper.IPIterator(ipInput)

	for ip := range ipChan {
		if ip.Error != nil {
			opts.Log.Error(ip.Error)
			continue
		}
		for _, port := range opts.Ports {
			port := strings.TrimSpace(port)
			portI, err := strconv.ParseInt(port, 10, 16)
			if err != nil {
				return fmt.Errorf("Invalid port %s: %w", port, err)
			}
			opts.Log.Debugf("Scanning %s:%d", ip.IP.String(), portI)
			if err := httpScan(ctx, opts, ip.IP, uint16(portI)); err != nil {
				opts.Log.Errorf("error on running HTTP Scan for %s:%d: %v", ip.IP.String(), portI, err)
			}
		}
	}

	return nil
}

func httpScan(ctx context.Context, opts TCPScannerOpts, ip netip.Addr, port uint16) error {
	_, _, controlConnection, dataConnection, err := internal.SetupTurnTCPConnection(ctx, opts.Log, opts.TurnServer, opts.UseTLS, opts.Timeout, ip, port, opts.Username, opts.Password)
	if err != nil {
		return err
	}
	defer controlConnection.Close()
	defer dataConnection.Close()

	useTLS := false
	if port == 443 || port == 8443 || port == 7443 || port == 8843 {
		useTLS = true
	}

	if useTLS {
		tlsConn := tls.Client(dataConnection, &tls.Config{InsecureSkipVerify: true})
		if err := helper.ConnectionWrite(ctx, tlsConn, []byte(httpRequest), opts.Timeout); err != nil {
			return fmt.Errorf("error on sending TLS data: %w", err)
		}
		data, err := helper.ConnectionReadAll(ctx, tlsConn, opts.Timeout)
		if err != nil {
			return fmt.Errorf("error on reading after sending TLS data: %w", err)
		}
		opts.Log.Info(string(data))
		opts.Log.Info(hex.EncodeToString(data))
		return nil
	}

	// plain text connection
	if err := helper.ConnectionWrite(ctx, dataConnection, []byte(httpRequest), opts.Timeout); err != nil {
		return fmt.Errorf("error on sending data: %w", err)
	}
	data, err := helper.ConnectionReadAll(ctx, dataConnection, opts.Timeout)
	if err != nil {
		return fmt.Errorf("error on reading after sending data: %w", err)
	}
	opts.Log.Info(string(data))
	opts.Log.Info(hex.EncodeToString(data))
	return nil
}
