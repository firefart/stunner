package internal

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/firefart/stunner/internal/helper"
	"github.com/pion/dtls/v2"
)

func Connect(protocol string, turnServer string, useTLS bool, timeout time.Duration) (net.Conn, error) {
	if !useTLS {
		// non TLS connection
		conn, err := net.DialTimeout(protocol, turnServer, timeout)
		if err != nil {
			return nil, fmt.Errorf("error on establishing a connection to the server: %w", err)
		}
		return conn, nil
	}

	// if we reach here we have a TLS connection
	switch protocol {
	case "tcp":
		d := net.Dialer{
			Timeout: timeout,
		}
		conn, err := tls.DialWithDialer(&d, protocol, turnServer, &tls.Config{
			InsecureSkipVerify: true,
		})
		if err != nil {
			return nil, fmt.Errorf("error on establishing a TLS connection to the server: %w", err)
		}
		return conn, nil
	case "udp":
		conn, err := net.DialTimeout(protocol, turnServer, timeout)
		if err != nil {
			return nil, fmt.Errorf("error on establishing a connection to the server: %w", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		dtlsConn, err := dtls.ClientWithContext(ctx, conn, &dtls.Config{
			InsecureSkipVerify: true,
		})
		if err != nil {
			return nil, fmt.Errorf("error on establishing a DTLS connection to the server: %w", err)
		}
		return dtlsConn, nil
	default:
		return nil, fmt.Errorf("invalid protocol %s", protocol)
	}
}

// send serializes a STUN object and sends it on the provided connection
func (s *Stun) send(conn net.Conn, timeout time.Duration) error {
	data, err := s.Serialize()
	if err != nil {
		return fmt.Errorf("Serialize: %w", err)
	}
	if err := helper.ConnectionWrite(conn, data, timeout); err != nil {
		return fmt.Errorf("ConnectionWrite: %w", err)
	}

	return nil
}

// SendAndReceive sends a TURN request on a connection and gets a response
func (s *Stun) SendAndReceive(logger DebugLogger, conn net.Conn, timeout time.Duration) (*Stun, error) {
	logger.Debugf("Sending\n%s", s.String())
	err := s.send(conn, timeout)
	if err != nil {
		return nil, fmt.Errorf("Send: %w", err)
	}
	buffer, err := helper.ConnectionRead(conn, timeout)
	if err != nil {
		return nil, fmt.Errorf("ConnectionRead: %w", err)
	}
	resp, err := fromBytes(buffer)
	if err != nil {
		return nil, fmt.Errorf("fromBytes: %w", err)
	}
	logger.Debugf("Received\n%s", resp.String())
	return resp, nil
}
