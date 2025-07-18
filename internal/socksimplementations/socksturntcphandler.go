package socksimplementations

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"

	socks "github.com/firefart/gosocks"
	"github.com/firefart/stunner/internal"
	"github.com/firefart/stunner/internal/helper"

	"github.com/sirupsen/logrus"
)

// SocksTurnTCPHandler is the implementation of a TCP TURN server
type SocksTurnTCPHandler struct {
	ControlConnection      net.Conn
	TURNUsername           string
	TURNPassword           string
	Server                 string
	Timeout                time.Duration
	UseTLS                 bool
	DropNonPrivateRequests bool
	Log                    *logrus.Logger
	realm                  string
	nonce                  string
}

// Init connects to the STUN server, sets the connection up and returns the data connections
func (s *SocksTurnTCPHandler) Init(ctx context.Context, request socks.Request) (context.Context, io.ReadWriteCloser, *socks.Error) {
	var target netip.Addr
	var err error
	switch request.AddressType {
	case socks.RequestAddressTypeIPv4, socks.RequestAddressTypeIPv6:
		tmp, ok := netip.AddrFromSlice(request.DestinationAddress)
		if !ok {
			return ctx, nil, socks.NewError(socks.RequestReplyAddressTypeNotSupported, fmt.Errorf("%02x is no ip address", request.DestinationAddress))
		}
		target = tmp
	case socks.RequestAddressTypeDomainname:
		// check if the input is an ip adress
		if ip, err := netip.ParseAddr(string(request.DestinationAddress)); err == nil {
			target = ip
		} else {
			// input is a hostname
			names, err := helper.ResolveName(ctx, string(request.DestinationAddress))
			if err != nil {
				return ctx, nil, socks.NewError(socks.RequestReplyHostUnreachable, err)
			}
			if len(names) == 0 {
				return ctx, nil, socks.NewError(socks.RequestReplyHostUnreachable, fmt.Errorf("%s could not be resolved", string(request.DestinationAddress)))
			}
			target = names[0]
		}
	default:
		return ctx, nil, socks.NewError(socks.RequestReplyAddressTypeNotSupported, fmt.Errorf("AddressType %#x not implemented", request.AddressType))
	}

	if s.DropNonPrivateRequests && !helper.IsPrivateIP(target) {
		s.Log.Debugf("dropping non private connection to %s:%d", target.String(), request.DestinationPort)
		return ctx, nil, socks.NewError(socks.RequestReplyHostUnreachable, fmt.Errorf("dropping non private connection to %s:%d", target.String(), request.DestinationPort))
	}

	realm, nonce, controlConnection, dataConnection, err := internal.SetupTurnTCPConnection(ctx, s.Log, s.Server, s.UseTLS, s.Timeout, target, request.DestinationPort, s.TURNUsername, s.TURNPassword)
	if err != nil {
		return ctx, nil, socks.NewError(socks.RequestReplyHostUnreachable, err)
	}
	s.realm = realm
	s.nonce = nonce

	// we need to keep this connection open
	s.ControlConnection = controlConnection
	return ctx, dataConnection, nil
}

// Refresh is used to refresh an active connection every 2 minutes
func (s *SocksTurnTCPHandler) Refresh(ctx context.Context) {
	nonce := s.nonce
	realm := s.realm
	tick := time.NewTicker(5 * time.Minute) // default timeout on coturn is 600 seconds (10 minutes)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			s.Log.Debug("[socks] refreshing connection")
			refresh := internal.RefreshRequest(s.TURNUsername, s.TURNPassword, nonce, realm)
			response, err := refresh.SendAndReceive(ctx, s.Log, s.ControlConnection, s.Timeout)
			if err != nil {
				s.Log.Error(err)
				return
			}
			// should happen on a stale nonce
			if response.Header.MessageType.Class == internal.MsgTypeClassError {
				realm := string(response.GetAttribute(internal.AttrRealm).Value)
				nonce := string(response.GetAttribute(internal.AttrNonce).Value)
				s.nonce = nonce
				s.realm = realm
				refresh = internal.RefreshRequest(s.TURNUsername, s.TURNPassword, nonce, realm)
				response, err = refresh.SendAndReceive(ctx, s.Log, s.ControlConnection, s.Timeout)
				if err != nil {
					s.Log.Error(err)
					return
				}
				if response.Header.MessageType.Class == internal.MsgTypeClassError {
					s.Log.Error(response.GetErrorString())
					return
				}
			}
		}
	}
}

const bufferLength = 1024 * 100

type readDeadline interface {
	SetReadDeadline(time.Time) error
}
type writeDeadline interface {
	SetWriteDeadline(time.Time) error
}

// ReadFromClient is used to copy data
func (s *SocksTurnTCPHandler) ReadFromClient(ctx context.Context, client io.ReadCloser, remote io.WriteCloser) error {
	for {
		// anonymous func for defer
		// this might not be the fastest, but it does the trick
		// in this case the timeout is per buffer read/write to support
		// long-running downloads.
		err := func() error {
			timeOut := time.Now().Add(s.Timeout)

			ctx, cancel := context.WithDeadline(ctx, timeOut)
			defer cancel()

			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				if c, ok := remote.(writeDeadline); ok {
					if err := c.SetWriteDeadline(timeOut); err != nil {
						return fmt.Errorf("could not set write deadline on remote: %w", err)
					}
				}

				if c, ok := client.(readDeadline); ok {
					if err := c.SetReadDeadline(timeOut); err != nil {
						return fmt.Errorf("could not set read deadline on client: %w", err)
					}
				}

				i, err := io.CopyN(remote, client, bufferLength)
				if errors.Is(err, io.EOF) {
					return nil
				} else if err != nil {
					return fmt.Errorf("ReadFromClient: %w", err)
				}
				s.Log.Debugf("[socks] wrote %d bytes to client", i)
			}
			return nil
		}()
		if err != nil {
			return err
		}
	}
}

// ReadFromRemote is used to copy data
func (s *SocksTurnTCPHandler) ReadFromRemote(ctx context.Context, remote io.ReadCloser, client io.WriteCloser) error {
	for {
		// anonymous func for defer
		// this might not be the fastest, but it does the trick
		// in this case the timeout is per buffer read/write to support
		// long-running downloads.
		err := func() error {
			timeOut := time.Now().Add(s.Timeout)

			ctx, cancel := context.WithDeadline(ctx, timeOut)
			defer cancel()

			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				if c, ok := client.(writeDeadline); ok {
					if err := c.SetWriteDeadline(timeOut); err != nil {
						return fmt.Errorf("could not set write deadline on client: %w", err)
					}
				}

				if c, ok := remote.(readDeadline); ok {
					if err := c.SetReadDeadline(timeOut); err != nil {
						return fmt.Errorf("could not set read deadline on remote: %w", err)
					}
				}

				i, err := io.CopyN(client, remote, bufferLength)
				if errors.Is(err, io.EOF) {
					return nil
				} else if err != nil {
					return fmt.Errorf("ReadFromRemote: %w", err)
				}
				s.Log.Debugf("[socks] wrote %d bytes to remote", i)
			}
			return nil
		}()
		if err != nil {
			return err
		}
	}
}

// Close closes the stored control connection
func (s *SocksTurnTCPHandler) Close(_ context.Context) error {
	if s.ControlConnection != nil {
		return s.ControlConnection.Close()
	}
	return nil
}
