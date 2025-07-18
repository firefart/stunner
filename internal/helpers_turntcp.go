package internal

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"
)

type keepAlive interface {
	SetKeepAlive(bool)
}

// SetupTurnTCPConnection executes the following:
//
//	Allocate Unauth (to get realm and nonce)
//	Allocate Auth
//	Connect
//	Opens Data Connection
//	ConnectionBind
//
// it returns the controlConnection, the dataConnection and an error
func SetupTurnTCPConnection(ctx context.Context, logger DebugLogger, turnServer string, useTLS bool, timeout time.Duration, targetHost netip.Addr, targetPort uint16, username, password string) (string, string, net.Conn, net.Conn, error) {
	// protocol needs to be tcp
	controlConnection, err := Connect(ctx, "tcp", turnServer, useTLS, timeout)
	if err != nil {
		return "", "", nil, nil, fmt.Errorf("error on establishing control connection: %w", err)
	}

	if x, ok := controlConnection.(keepAlive); ok {
		logger.Debug("controlconnection: set keepalive to true")
		x.SetKeepAlive(true)
	}

	logger.Debugf("opened turn tcp control connection from %s to %s", controlConnection.LocalAddr().String(), controlConnection.RemoteAddr().String())

	addressFamily := AllocateProtocolIgnore
	if targetHost.Is6() {
		addressFamily = AllocateProtocolIPv6
	}

	allocateRequest := AllocateRequest(RequestedTransportTCP, addressFamily)
	allocateResponse, err := allocateRequest.SendAndReceive(ctx, logger, controlConnection, timeout)
	if err != nil {
		return "", "", nil, nil, fmt.Errorf("error on sending allocate request 1: %w", err)
	}
	if allocateResponse.Header.MessageType.Class != MsgTypeClassError {
		return "", "", nil, nil, errors.New("MessageClass is not Error (should be not authenticated)")
	}

	realm := string(allocateResponse.GetAttribute(AttrRealm).Value)
	nonce := string(allocateResponse.GetAttribute(AttrNonce).Value)

	allocateRequest = AllocateRequestAuth(username, password, nonce, realm, RequestedTransportTCP, addressFamily)
	allocateResponse, err = allocateRequest.SendAndReceive(ctx, logger, controlConnection, timeout)
	if err != nil {
		return "", "", nil, nil, fmt.Errorf("error on sending allocate request 2: %w", err)
	}
	if allocateResponse.Header.MessageType.Class == MsgTypeClassError {
		return "", "", nil, nil, fmt.Errorf("error on allocate response: %s", allocateResponse.GetErrorString())
	}

	connectRequest, err := ConnectRequestAuth(username, password, nonce, realm, targetHost, targetPort)
	if err != nil {
		return "", "", nil, nil, fmt.Errorf("error on generating Connect request: %w", err)
	}
	connectResponse, err := connectRequest.SendAndReceive(ctx, logger, controlConnection, timeout)
	if err != nil {
		return "", "", nil, nil, fmt.Errorf("error on sending Connect request: %w", err)
	}
	if connectResponse.Header.MessageType.Class == MsgTypeClassError {
		return "", "", nil, nil, fmt.Errorf("error on Connect response: %s", connectResponse.GetErrorString())
	}

	connectionID := connectResponse.GetAttribute(AttrConnectionID).Value

	dataConnection, err := Connect(ctx, "tcp", turnServer, useTLS, timeout)
	if err != nil {
		return "", "", nil, nil, fmt.Errorf("error on establishing data connection: %w", err)
	}

	if x, ok := dataConnection.(keepAlive); ok {
		logger.Debug("dataconnection: set keepalive to true")
		x.SetKeepAlive(true)
	}

	logger.Debugf("opened turn tcp data connection from %s to %s", dataConnection.LocalAddr().String(), dataConnection.RemoteAddr().String())

	connectionBindRequest := ConnectionBindRequest(connectionID, username, password, nonce, realm)
	connectionBindResponse, err := connectionBindRequest.SendAndReceive(ctx, logger, dataConnection, timeout)
	if err != nil {
		return "", "", nil, nil, fmt.Errorf("error on sending ConnectionBind request: %w", err)
	}
	if connectionBindResponse.Header.MessageType.Class == MsgTypeClassError {
		return "", "", nil, nil, fmt.Errorf("error on ConnectionBind reposnse: %s", connectionBindResponse.GetErrorString())
	}

	return realm, nonce, controlConnection, dataConnection, nil
}
