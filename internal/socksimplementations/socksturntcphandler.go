package socksimplementations

import (
	"context"
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
	Ctx                    context.Context
	ControlConnection      net.Conn
	TURNUsername           string
	TURNPassword           string
	Server                 string
	Timeout                time.Duration
	UseTLS                 bool
	DropNonPrivateRequests bool
	Log                    *logrus.Logger
}

// PreHandler connects to the STUN server, sets the connection up and returns the data connections
func (s *SocksTurnTCPHandler) Init(request socks.Request) (io.ReadWriteCloser, *socks.Error) {
	var target netip.Addr
	var err error
	switch request.AddressType {
	case socks.RequestAddressTypeIPv4, socks.RequestAddressTypeIPv6:
		tmp, ok := netip.AddrFromSlice(request.DestinationAddress)
		if !ok {
			return nil, socks.NewError(socks.RequestReplyAddressTypeNotSupported, fmt.Errorf("%02x is no ip address", request.DestinationAddress))
		}
		target = tmp
	case socks.RequestAddressTypeDomainname:
		// check if the input is an ip adress
		if ip, err := netip.ParseAddr(string(request.DestinationAddress)); err == nil {
			target = ip
		} else {
			// input is a hostname
			names, err := helper.ResolveName(s.Ctx, string(request.DestinationAddress))
			if err != nil {
				return nil, socks.NewError(socks.RequestReplyHostUnreachable, err)
			}
			if len(names) == 0 {
				return nil, socks.NewError(socks.RequestReplyHostUnreachable, fmt.Errorf("%s could not be resolved", string(request.DestinationAddress)))
			}
			target = names[0]
		}
	default:
		return nil, socks.NewError(socks.RequestReplyAddressTypeNotSupported, fmt.Errorf("AddressType %#x not implemented", request.AddressType))
	}

	if s.DropNonPrivateRequests && !helper.IsPrivateIP(target) {
		s.Log.Debugf("dropping non private connection to %s:%d", target.String(), request.DestinationPort)
		return nil, socks.NewError(socks.RequestReplyHostUnreachable, fmt.Errorf("dropping non private connection to %s:%d", target.String(), request.DestinationPort))
	}

	controlConnection, dataConnection, err := internal.SetupTurnTCPConnection(s.Log, s.Server, s.UseTLS, s.Timeout, target, request.DestinationPort, s.TURNUsername, s.TURNPassword)
	if err != nil {
		return nil, socks.NewError(socks.RequestReplyHostUnreachable, err)
	}

	// we need to keep this connection open
	s.ControlConnection = controlConnection
	return dataConnection, nil
}

// Refresh is used to refresh an active connection every 2 minutes
func (s *SocksTurnTCPHandler) Refresh(ctx context.Context) {
	nonce := ""
	realm := ""
	tick := time.NewTicker(2 * time.Minute)
	select {
	case <-ctx.Done():
		return
	case <-tick.C:
		s.Log.Debug("[socks] refreshing connection")
		refresh := internal.RefreshRequest(s.TURNUsername, s.TURNPassword, nonce, realm)
		response, err := refresh.SendAndReceive(s.Log, s.ControlConnection, s.Timeout)
		if err != nil {
			s.Log.Error(err)
			return
		}
		// should happen on a stale nonce
		if response.Header.MessageType.Class == internal.MsgTypeClassError {
			realm := string(response.GetAttribute(internal.AttrRealm).Value)
			nonce := string(response.GetAttribute(internal.AttrNonce).Value)
			refresh = internal.RefreshRequest(s.TURNUsername, s.TURNPassword, nonce, realm)
			response, err = refresh.SendAndReceive(s.Log, s.ControlConnection, s.Timeout)
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

// ReadFromClient is used to copy data
func (s *SocksTurnTCPHandler) ReadFromClient(ctx context.Context, client io.ReadCloser, remote io.WriteCloser) error {
	i, err := io.Copy(remote, client)
	if err != nil {
		return fmt.Errorf("CopyFromRemoteToClient: %w", err)
	}
	s.Log.Debugf("[socks] wrote %d bytes to client", i)
	return nil
}

// ReadFromRemote is used to copy data
func (s *SocksTurnTCPHandler) ReadFromRemote(ctx context.Context, remote io.ReadCloser, client io.WriteCloser) error {
	i, err := io.Copy(client, remote)
	if err != nil {
		return fmt.Errorf("CopyFromClientToRemote: %w", err)
	}
	s.Log.Debugf("[socks] wrote %d bytes to remote", i)
	return nil
}

// Cleanup closes the stored control connection
func (s *SocksTurnTCPHandler) Close() error {
	if s.ControlConnection != nil {
		return s.ControlConnection.Close()
	}
	return nil
}
