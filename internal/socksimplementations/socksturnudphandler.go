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

// SocksTurnUDPHandler is the implementation of a UDP TURN server
type SocksTurnUDPHandler struct {
	TURNUsername           string
	TURNPassword           string
	Server                 string
	ConnectProtocol        string
	channelNumber          []byte
	Timeout                time.Duration
	UseTLS                 bool
	DropNonPrivateRequests bool
	Log                    *logrus.Logger
}

// PreHandler creates a connection to the target server and returns a connection to send data
func (s *SocksTurnUDPHandler) Init(ctx context.Context, request socks.Request) (io.ReadWriteCloser, *socks.Error) {
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
		names, err := helper.ResolveName(ctx, string(request.DestinationAddress))
		if err != nil {
			return nil, socks.NewError(socks.RequestReplyHostUnreachable, err)
		}
		if len(names) == 0 {
			return nil, socks.NewError(socks.RequestReplyHostUnreachable, fmt.Errorf("%s could not be resolved", string(request.DestinationAddress)))
		}
		target = names[0]
	default:
		return nil, socks.NewError(socks.RequestReplyAddressTypeNotSupported, fmt.Errorf("AddressType %#x not implemented", request.AddressType))
	}

	if s.DropNonPrivateRequests && !helper.IsPrivateIP(target) {
		s.Log.Debugf("dropping non private connection to %s:%d", target.String(), request.DestinationPort)
		return nil, socks.NewError(socks.RequestReplyHostUnreachable, fmt.Errorf("dropping non private connection to %s:%d", target.String(), request.DestinationPort))
	}

	remote, realm, nonce, err := internal.SetupTurnConnection(ctx, s.Log, s.ConnectProtocol, s.Server, s.UseTLS, s.Timeout, target, request.DestinationPort, s.TURNUsername, s.TURNPassword)
	if err != nil {
		return nil, socks.NewError(socks.RequestReplyHostUnreachable, err)
	}
	defer remote.Close()

	s.channelNumber, err = helper.RandomChannelNumber()
	if err != nil {
		return nil, socks.NewError(socks.RequestReplyGeneralFailure, fmt.Errorf("error on getting random channel number: %w", err))
	}
	channelBindRequest, err := internal.ChannelBindRequest(s.TURNUsername, s.TURNPassword, nonce, realm, target, request.DestinationPort, s.channelNumber)
	if err != nil {
		return nil, socks.NewError(socks.RequestReplyHostUnreachable, fmt.Errorf("error on generating ChannelBindRequest: %w", err))
	}
	s.Log.Debugf("ChannelBind Request:\n%s", channelBindRequest.String())
	channelBindResponse, err := channelBindRequest.SendAndReceive(ctx, s.Log, remote, s.Timeout)
	if err != nil {
		return nil, socks.NewError(socks.RequestReplyHostUnreachable, fmt.Errorf("error on sending ChannelBindRequest: %w", err))
	}
	s.Log.Debugf("ChannelBind Response:\n%s", channelBindResponse.String())
	if channelBindResponse.Header.MessageType.Class == internal.MsgTypeClassError {
		return nil, socks.NewError(socks.RequestReplyGeneralFailure, fmt.Errorf("error on ChannelBind: %s", channelBindResponse.GetErrorString()))
	}
	return remote, nil
}

// CopyFromRemoteToClient is used to send data and remove the extra channel data header
func (s *SocksTurnUDPHandler) ReadFromRemote(ctx context.Context, remote io.ReadCloser, client io.WriteCloser) error {
	clientConn, ok := client.(net.Conn)
	if !ok {
		return fmt.Errorf("could not cast client to net.Conn")
	}
	remoteConn, ok := remote.(net.Conn)
	if !ok {
		return fmt.Errorf("could not cast remote to net.Conn")
	}

	recv, err := helper.ConnectionRead(ctx, remoteConn, s.Timeout)
	if err != nil {
		return err
	}

	channel, data, err := internal.ExtractChannelData(recv)
	if err != nil {
		return err
	}
	s.Log.Debugf("received %d bytes on channel %02x", len(data), channel)

	err = helper.ConnectionWrite(ctx, clientConn, data, s.Timeout)
	if err != nil {
		return err
	}
	return nil
}

// CopyFromClientToRemote is used to send data and add the extra channel data header
func (s *SocksTurnUDPHandler) ReadFromClient(ctx context.Context, client io.ReadCloser, remote io.WriteCloser) error {
	clientConn, ok := client.(net.Conn)
	if !ok {
		return fmt.Errorf("could not cast client to net.Conn")
	}
	remoteConn, ok := remote.(net.Conn)
	if !ok {
		return fmt.Errorf("could not cast remote to net.Conn")
	}

	toSend, err := helper.ConnectionRead(ctx, clientConn, s.Timeout)
	if err != nil {
		return err
	}
	toSend = internal.Padding(toSend)
	toSendLen := len(toSend)

	var buf []byte
	buf = append(buf, s.channelNumber...)
	buf = append(buf, helper.PutUint16(uint16(toSendLen))...)
	buf = append(buf, toSend...)

	err = helper.ConnectionWrite(ctx, remoteConn, buf, s.Timeout)
	if err != nil {
		return err
	}
	return nil
}

// Refresh is not used in this implementation
func (s *SocksTurnUDPHandler) Refresh(_ context.Context) {
}

// Cleanup is not used in this implementation
func (s *SocksTurnUDPHandler) Close(ctx context.Context) error {
	return nil
}
