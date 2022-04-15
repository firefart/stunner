package cmd

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/firefart/stunner/internal"
	"github.com/firefart/stunner/internal/helper"
	"github.com/sirupsen/logrus"
)

type RangeScanOpts struct {
	TurnServer string
	Protocol   string
	Username   string
	Password   string
	UseTLS     bool
	Timeout    time.Duration
	Log        *logrus.Logger
}

func (opts RangeScanOpts) Validate() error {
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

func RangeScan(opts RangeScanOpts) error {
	if err := opts.Validate(); err != nil {
		return err
	}

	ranges := []string{
		// all
		"0.0.0.0",
		"::",
		// localhosts
		"127.0.0.1",
		"127.0.0.8",
		"127.255.255.254",
		"::1",
		// private ranges
		"10.0.0.1",
		"10.255.255.254",
		"172.16.0.1",
		"172.31.255.254",
		"192.168.0.1",
		"192.168.255.254",
		// Link Local
		"169.254.0.1",
		"169.254.254.255",
		// Multicast
		"224.0.0.1",
		"239.255.255.254",
		// Shared Address Space
		"100.64.0.0",
		"100.127.255.254",
		// ietf
		"192.0.0.1",
		"192.0.0.254",
		// TEST-NET-1
		"192.0.2.1",
		"192.0.2.254",
		// Benchmark
		"198.18.0.1",
		"198.19.255.254",
		// TEST-NET-2
		"198.51.100.1",
		"198.51.100.254",
		// TEST-NET-3
		"203.0.113.1",
		"203.0.113.254",
		// Reserved
		"240.0.0.1",
		// Broadcast
		"255.255.255.255",
		// Cloud Metadata Services
		"169.254.169.254",
	}

	// UDP scanning
	for _, ipString := range ranges {
		ip, err := netip.ParseAddr(ipString)
		if err != nil {
			return fmt.Errorf("target is no valid ip address: %w", err)
		}

		suc, err := scanUDP(opts, ip, 80)
		if err != nil {
			opts.Log.Errorf("UDP %s: %v", ip, err)
		}
		if suc {
			opts.Log.Warnf("UDP %s was successful!", ip)
		}
	}

	// TCP scanning
	for _, ipString := range ranges {
		ip, err := netip.ParseAddr(ipString)
		if err != nil {
			return fmt.Errorf("target is no valid ip address: %w", err)
		}

		suc, err := scanTCP(opts, ip, 80)
		if err != nil {
			opts.Log.Errorf("TCP %s: %v", ip, err)
		}
		if suc {
			opts.Log.Warnf("TCP %s was successful!", ip)
		}
	}
	return nil
}

func scanTCP(opts RangeScanOpts, targetHost netip.Addr, targetPort uint16) (bool, error) {
	conn, err := internal.Connect(opts.Protocol, opts.TurnServer, opts.UseTLS, opts.Timeout)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	addressFamily := internal.AllocateProtocolIgnore
	if targetHost.Is6() {
		addressFamily = internal.AllocateProtocolIPv6
	}

	allocateRequest := internal.AllocateRequest(internal.RequestedTransportTCP, addressFamily)
	allocateResponse, err := allocateRequest.SendAndReceive(opts.Log, conn, opts.Timeout)
	if err != nil {
		return false, fmt.Errorf("error on sending allocate request 1: %w", err)
	}
	if allocateResponse.Header.MessageType.Class != internal.MsgTypeClassError {
		return false, fmt.Errorf("MessageClass is not Error (should be not authenticated)")
	}

	realm := string(allocateResponse.GetAttribute(internal.AttrRealm).Value)
	nonce := string(allocateResponse.GetAttribute(internal.AttrNonce).Value)

	allocateRequest = internal.AllocateRequestAuth(opts.Username, opts.Password, nonce, realm, internal.RequestedTransportTCP, addressFamily)
	allocateResponse, err = allocateRequest.SendAndReceive(opts.Log, conn, opts.Timeout)
	if err != nil {
		return false, fmt.Errorf("error on sending allocate request 2: %w", err)
	}
	if allocateResponse.Header.MessageType.Class == internal.MsgTypeClassError {
		return false, fmt.Errorf("error on allocate response: %s", allocateResponse.GetErrorString())
	}

	connectRequest, err := internal.ConnectRequestAuth(opts.Username, opts.Password, nonce, realm, targetHost, targetPort)
	if err != nil {
		return false, fmt.Errorf("error on generating Connect request: %w", err)
	}
	connectResponse, err := connectRequest.SendAndReceive(opts.Log, conn, opts.Timeout)
	if err != nil {
		// ignore timeouts, a timeout means open port
		if errors.Is(err, helper.ErrTimeout) {
			return true, nil
		}
		return false, fmt.Errorf("error on sending Connect request: %w", err)
	}
	if connectResponse.Header.MessageType.Class == internal.MsgTypeClassError {
		return false, fmt.Errorf("error on Connect response: %s", connectResponse.GetErrorString())
	}

	return true, nil
}

func scanUDP(opts RangeScanOpts, targetHost netip.Addr, targetPort uint16) (bool, error) {
	remote, _, _, err := internal.SetupTurnConnection(opts.Log, opts.Protocol, opts.TurnServer, opts.UseTLS, opts.Timeout, targetHost, targetPort, opts.Username, opts.Password)
	if err != nil {
		return false, err
	}
	defer remote.Close()

	return true, nil
}
