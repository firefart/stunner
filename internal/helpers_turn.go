package internal

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/firefart/stunner/internal/helper"
)

func xor(content, key []byte) []byte {
	var buf []byte
	index := 0
	for i := 0; i < len(content); i++ {
		if index >= len(key) {
			index = 0
		}
		buf = append(buf, content[i]^key[index])
		index++
	}
	return buf
}

// xorAddr implements the XOR required for the STUN and TURN protocol
//
//		0                   1                   2                   3
//		0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//		|x x x x x x x x|    Family     |         X-Port                |
//		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//		|                X-Address (Variable)
//		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//	        Figure 6: Format of XOR-MAPPED-ADDRESS Attribute
func xorAddr(ip netip.Addr, port uint16, transactionID []byte) ([]byte, error) {
	var family uint16
	var key []byte

	if ip.Is6() {
		family = uint16(0x02)
		key = append(MagicCookie, transactionID...)
	} else if ip.Is4() {
		family = uint16(0x01)
		key = MagicCookie
	} else {
		return nil, fmt.Errorf("invalid IP address %02x", ip)
	}

	var buf []byte

	/*
			If the IP
		  address family is IPv4, X-Address is computed by taking the mapped IP
		  address in host byte order, XOR'ing it with the magic cookie, and
		  converting the result to network byte order.  If the IP address
		  family is IPv6, X-Address is computed by taking the mapped IP address
		  in host byte order, XOR'ing it with the concatenation of the magic
		  cookie and the 96-bit transaction ID, and converting the result to
			network byte order.
	*/
	magicInt := binary.BigEndian.Uint16(MagicCookie)

	buf = append(buf, helper.PutUint16(family)...)
	buf = append(buf, helper.PutUint16(port^magicInt)...)

	ipByte := ip.AsSlice()
	buf = append(buf, xor(ipByte, key)...)

	return buf, nil
}

func ConvertXORAddr(input []byte, transactionID string) (string, uint16, error) {
	if len(input) < 5 {
		return "", 0, fmt.Errorf("invalid buffer length %d, need to be > 4", len(input))
	}
	family := input[0:2] // 0x0001 = ipv4, 0x0002 = ipv6
	if !bytes.Equal(family, []byte{00, 01}) && !bytes.Equal(family, []byte{00, 02}) {
		return "", 0, fmt.Errorf("invalid family %02x", family)
	}
	portRaw := input[2:4]
	payload := input[4:]
	magicInt := binary.BigEndian.Uint16(MagicCookie)
	portInt := binary.BigEndian.Uint16(portRaw)
	port := portInt ^ magicInt

	key := MagicCookie
	switch family[1] {
	case 0x01:
		key = MagicCookie
	case 0x02:
		key = append(MagicCookie, transactionID...)
	}

	host := xor(payload, key)
	ip, ok := netip.AddrFromSlice(host)
	if !ok {
		return "", 0, fmt.Errorf("invalid IP %02x", host)
	}
	return ip.String(), port, nil
}

// SetupTurnConnection executes the following:
//
//	Allocate Unauth (to get realm and nonce)
//	Allocate Auth
//	CreatePermission
//
// it returns the connection, the realm, the nonce and an error
func SetupTurnConnection(logger DebugLogger, connectProtocol string, turnServer string, useTLS bool, timeout time.Duration, targetHost netip.Addr, targetPort uint16, username, password string) (net.Conn, string, string, error) {
	remote, err := Connect(connectProtocol, turnServer, useTLS, timeout)
	if err != nil {
		return nil, "", "", err
	}

	addressFamily := AllocateProtocolIgnore
	if targetHost.Is6() {
		addressFamily = AllocateProtocolIPv6
	}

	allocateRequest := AllocateRequest(RequestedTransportUDP, addressFamily)
	allocateResponse, err := allocateRequest.SendAndReceive(logger, remote, timeout)
	if err != nil {
		return nil, "", "", fmt.Errorf("error on sending AllocateRequest: %w", err)
	}
	if allocateResponse.Header.MessageType.Class != MsgTypeClassError {
		return nil, "", "", fmt.Errorf("MessageClass is not Error (should be not authenticated)")
	}

	realm := string(allocateResponse.GetAttribute(AttrRealm).Value)
	nonce := string(allocateResponse.GetAttribute(AttrNonce).Value)

	allocateRequest = AllocateRequestAuth(username, password, nonce, realm, RequestedTransportUDP, addressFamily)
	allocateResponse, err = allocateRequest.SendAndReceive(logger, remote, timeout)
	if err != nil {
		return nil, "", "", fmt.Errorf("error on sending AllocateRequest Auth: %w", err)
	}
	if allocateResponse.Header.MessageType.Class == MsgTypeClassError {
		return nil, "", "", fmt.Errorf("error on AllocateRequest Auth: %s", allocateResponse.GetErrorString())
	}
	permissionRequest, err := CreatePermissionRequest(username, password, nonce, realm, targetHost, targetPort)
	if err != nil {
		return nil, "", "", fmt.Errorf("error on generating CreatePermissionRequest: %w", err)
	}
	permissionResponse, err := permissionRequest.SendAndReceive(logger, remote, timeout)
	if err != nil {
		return nil, "", "", fmt.Errorf("error on sending CreatePermissionRequest: %w", err)
	}
	if permissionResponse.Header.MessageType.Class == MsgTypeClassError {
		return nil, "", "", fmt.Errorf("error on CreatePermission: %s", permissionResponse.GetErrorString())
	}

	return remote, realm, nonce, nil
}
