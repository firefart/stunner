package internal

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// SetupTurnTCPConnection executes the following:
//
//	Allocate Unauth (to get realm and nonce)
//	Allocate Auth
//	Connect
//	Opens Data Connection
//	ConnectionBind
//
// it returns the controlConnection, the dataConnection and an error
func SetupTurnTCPConnection(logger DebugLogger, turnServer string, useTLS bool, timeout time.Duration, targetHost netip.Addr, targetPort uint16, username, password string) (net.Conn, net.Conn, error) {
	// protocol needs to be tcp
	controlConnectionRaw, err := Connect("tcp", turnServer, useTLS, timeout)
	if err != nil {
		return nil, nil, fmt.Errorf("error on establishing control connection: %w", err)
	}

	var controlConnection net.Conn
	switch t := controlConnectionRaw.(type) {
	case *net.TCPConn:
		if err := t.SetKeepAlive(true); err != nil {
			return nil, nil, fmt.Errorf("could not set KeepAlive on control connection: %w", err)
		}
		controlConnection = t
	case *tls.Conn:
		controlConnection = t
	default:
		return nil, nil, fmt.Errorf("could not determine control connection type (%T)", t)
	}

	logger.Debugf("opened turn tcp control connection from %s to %s", controlConnection.LocalAddr().String(), controlConnection.RemoteAddr().String())

	addressFamily := AllocateProtocolIgnore
	if targetHost.Is6() {
		addressFamily = AllocateProtocolIPv6
	}

	allocateRequest := AllocateRequest(RequestedTransportTCP, addressFamily)
	allocateResponse, err := allocateRequest.SendAndReceive(logger, controlConnection, timeout)
	if err != nil {
		return nil, nil, fmt.Errorf("error on sending allocate request 1: %w", err)
	}
	if allocateResponse.Header.MessageType.Class != MsgTypeClassError {
		return nil, nil, fmt.Errorf("MessageClass is not Error (should be not authenticated)")
	}

	realm := string(allocateResponse.GetAttribute(AttrRealm).Value)
	nonce := string(allocateResponse.GetAttribute(AttrNonce).Value)

	allocateRequest = AllocateRequestAuth(username, password, nonce, realm, RequestedTransportTCP, addressFamily)
	allocateResponse, err = allocateRequest.SendAndReceive(logger, controlConnection, timeout)
	if err != nil {
		return nil, nil, fmt.Errorf("error on sending allocate request 2: %w", err)
	}
	if allocateResponse.Header.MessageType.Class == MsgTypeClassError {
		return nil, nil, fmt.Errorf("error on allocate response: %s", allocateResponse.GetErrorString())
	}

	connectRequest, err := ConnectRequestAuth(username, password, nonce, realm, targetHost, targetPort)
	if err != nil {
		return nil, nil, fmt.Errorf("error on generating Connect request: %w", err)
	}
	connectResponse, err := connectRequest.SendAndReceive(logger, controlConnection, timeout)
	if err != nil {
		return nil, nil, fmt.Errorf("error on sending Connect request: %w", err)
	}
	if connectResponse.Header.MessageType.Class == MsgTypeClassError {
		return nil, nil, fmt.Errorf("error on Connect response: %s", connectResponse.GetErrorString())
	}

	connectionID := connectResponse.GetAttribute(AttrConnectionID).Value

	dataConnectionRaw, err := Connect("tcp", turnServer, useTLS, timeout)
	if err != nil {
		return nil, nil, fmt.Errorf("error on establishing data connection: %w", err)
	}

	var dataConnection net.Conn
	switch t := dataConnectionRaw.(type) {
	case *net.TCPConn:
		if err := t.SetKeepAlive(true); err != nil {
			return nil, nil, fmt.Errorf("could not set KeepAlive on data connection: %w", err)
		}
		dataConnection = t
	case *tls.Conn:
		dataConnection = t
	default:
		return nil, nil, fmt.Errorf("could not determine data connection type (%T)", t)
	}

	logger.Debugf("opened turn tcp data connection from %s to %s", dataConnection.LocalAddr().String(), dataConnection.RemoteAddr().String())

	connectionBindRequest := ConnectionBindRequest(connectionID, username, password, nonce, realm)
	connectionBindResponse, err := connectionBindRequest.SendAndReceive(logger, dataConnection, timeout)
	if err != nil {
		return nil, nil, fmt.Errorf("error on sending ConnectionBind request: %w", err)
	}
	if connectionBindResponse.Header.MessageType.Class == MsgTypeClassError {
		return nil, nil, fmt.Errorf("error on ConnectionBind reposnse: %s", connectionBindResponse.GetErrorString())
	}

	return controlConnection, dataConnection, nil
}
