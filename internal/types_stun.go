package internal

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/firefart/stunner/internal/helper"
)

const headerSize = 20
const messageIntegritySize = 20

// nolint:deadcode,varcheck,unused
const fingerPrintSize = 4

var (
	// MagicCookie is the fixed value according to the rfc
	MagicCookie = []byte{'\x21', '\x12', '\xa4', '\x42'}
)

// Stun is the main object
type Stun struct {
	Header     Header
	Attributes []Attribute
	Username   string
	Password   string
	Log        DebugLogger
}

// RequestedTransport represents the requested transport
type RequestedTransport uint32

var (
	// RequestedTransportTCP represents TCP
	RequestedTransportTCP RequestedTransport = 0x00000006
	// RequestedTransportUDP represents UDP
	RequestedTransportUDP RequestedTransport = 0x00000011
)

var requestedTransportNames = map[RequestedTransport]string{
	RequestedTransportTCP: "TCP",
	RequestedTransportUDP: "UDP",
}

/*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0 0|     STUN Message Type     |         Message Length        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         Magic Cookie                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |                     Transaction ID (96 bits)                  |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

// Header represents the header of a STUN message
type Header struct {
	MessageType   MessageType
	MessageLength uint16
	TransactionID string
}

/*
MessageType represents the message type

For example, a Binding request has class=0b00 (request) and
method=0b000000000001 (Binding) and is encoded into the first 16 bits
as 0x0001.  A Binding response has class=0b10 (success response) and
method=0b000000000001, and is encoded into the first 16 bits as
0x0101.
*/
type MessageType struct {
	Class  MessageTypeClass
	Method MessageTypeMethod
}

// Serialize converts the MessageType into a byte array
func (m MessageType) Serialize() []byte {
	tmp := m.toUint16()
	return helper.PutUint16(tmp)
}

func (m MessageType) toUint16() uint16 {
	class := ((uint16(m.Class) & 0x02) << 7) | ((uint16(m.Class) & 0x01) << 4)
	method := uint16(m.Method) & 0x3EEF
	return class | method
}

// MessageTypeClass represents the Class
type MessageTypeClass uint8

const (
	// MsgTypeClassRequest https://tools.ietf.org/html/rfc5389#section-6
	MsgTypeClassRequest MessageTypeClass = 0x00
	// MsgTypeClassIndication https://tools.ietf.org/html/rfc5389#section-6
	MsgTypeClassIndication MessageTypeClass = 0x01
	// MsgTypeClassSuccess https://tools.ietf.org/html/rfc5389#section-6
	MsgTypeClassSuccess MessageTypeClass = 0x02
	// MsgTypeClassError https://tools.ietf.org/html/rfc5389#section-6
	MsgTypeClassError MessageTypeClass = 0x03
)

var msgTypeClassNames = map[MessageTypeClass]string{
	MsgTypeClassRequest:    "Request",
	MsgTypeClassIndication: "Indication",
	MsgTypeClassSuccess:    "Success Response",
	MsgTypeClassError:      "Error Response",
}

// MessageTypeMethod holds the STUN method
type MessageTypeMethod uint16

const (
	// MsgTypeMethodBinding https://tools.ietf.org/html/rfc5389#section-18.1
	MsgTypeMethodBinding MessageTypeMethod = 0x01
)

var msgTypeMethodNames = map[MessageTypeMethod]string{
	MsgTypeMethodBinding: "Binding",
}

/*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Type                  |            Length             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         Value (variable)                ....
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

// Attribute represents a single STUN attribute
type Attribute struct {
	Type   AttributeType
	Length uint16
	Value  []byte

	padding uint16
}

func (a *Attribute) String(transactionID string) string {
	value := ""
	attrType := AttributeTypeString(a.Type)
	switch a.Type {
	// STUN
	case AttrMappedAddress:
		value = string(a.Value)
	case AttrUsername:
		value = string(a.Value)
	case AttrMessageIntegrity:
		value = fmt.Sprintf("%02x", a.Value)
	case AttrErrorCode:
		attrError := ParseError(a.Value)
		value = fmt.Sprintf("Error %d: %s", attrError.ErrorCode, attrError.ErrorText)
	case AttrUnknownAttributes:
		value = string(a.Value)
	case AttrRealm:
		value = string(a.Value)
	case AttrNonce:
		value = string(a.Value)
	case AttrRequestedAddressFamily:
		value = RequestedAddressFamilyString(AllocateProtocol(a.Value[0]))
	case AttrXorMappedAddress:
		host, port, _ := ConvertXORAddr(a.Value, transactionID)
		value = fmt.Sprintf("%02x (%s:%d)", a.Value, host, port)
	case AttrSoftware:
		value = string(a.Value)
	case AttrAlternateServer:
		value = string(a.Value)
	case AttrFingerprint:
		value = fmt.Sprintf("%02x", a.Value)
	// TURN
	case AttrChannelNumber:
		value = string(a.Value)
	case AttrLifetime:
		value = fmt.Sprintf("%d", binary.BigEndian.Uint32(a.Value))
	case AttrBandwidth:
		value = string(a.Value)
	case AttrXorPeerAddress:
		host, port, _ := ConvertXORAddr(a.Value, transactionID)
		value = fmt.Sprintf("%02x (%s:%d)", a.Value, host, port)
	case AttrData:
		value = fmt.Sprintf("%s (%02x)", a.Value, a.Value)
	case AttrXorRelayedAddress:
		host, port, _ := ConvertXORAddr(a.Value, transactionID)
		value = fmt.Sprintf("%02x (%s:%d)", a.Value, host, port)
	case AttrEvenPort:
		value = string(a.Value)
	case AttrRequestedTransport:
		value = RequestedTransportString(RequestedTransport(binary.LittleEndian.Uint16(a.Value)))
	case AttrDontFragment:
		value = string(a.Value)
	case AttrTimerVal:
		value = string(a.Value)
	case AttrReservationToken:
		value = string(a.Value)
	// TURNTCP
	case AttrConnectionID:
		value = fmt.Sprintf("%02x", a.Value)
	default:
		var v string
		if helper.IsPrintable(string(a.Value)) {
			v = string(a.Value)
		} else {
			v = fmt.Sprintf("%02x", a.Value)
		}
		value = fmt.Sprintf("\t%02x (%d): %s", a.Type, a.Length, v)
	}

	padding := ""
	if a.padding > 0 {
		padding = fmt.Sprintf(" Padding: %d", a.padding)
	}
	return fmt.Sprintf("%s: %s%s", attrType, value, padding)
}

// Serialize returns the byte slice representation of an attribute
func (a *Attribute) Serialize() []byte {
	if a.Length == 0 {
		a.Length = uint16(len(a.Value))
	}

	var buf []byte
	buf = append(buf, helper.PutUint16(a.Type.Value())...)
	buf = append(buf, helper.PutUint16(a.Length)...)
	buf = append(buf, a.Value...)
	buf = Padding(buf)

	return buf
}

// AttributeType defines the type of the attribute
type AttributeType uint16

// Value returns the uint16 value of an AttributeType
func (a AttributeType) Value() uint16 {
	return uint16(a)
}

const (
	// AttrMappedAddress https://tools.ietf.org/html/rfc5389#section-15.1
	AttrMappedAddress AttributeType = 0x0001
	// AttrUsername https://tools.ietf.org/html/rfc5389#section-15.3
	AttrUsername AttributeType = 0x0006
	// AttrMessageIntegrity https://tools.ietf.org/html/rfc5389#section-15.4
	AttrMessageIntegrity AttributeType = 0x0008
	// AttrErrorCode https://tools.ietf.org/html/rfc5389#section-15.6
	AttrErrorCode AttributeType = 0x0009
	// AttrUnknownAttributes https://tools.ietf.org/html/rfc5389#section-15.9
	AttrUnknownAttributes AttributeType = 0x000a
	// AttrRealm https://tools.ietf.org/html/rfc5389#section-15.7
	AttrRealm AttributeType = 0x0014
	// AttrNonce https://tools.ietf.org/html/rfc5389#section-15.8
	AttrNonce AttributeType = 0x0015
	// https://datatracker.ietf.org/doc/html/rfc6156#section-10.1
	AttrRequestedAddressFamily = 0x0017
	// AttrXorMappedAddress https://tools.ietf.org/html/rfc5389#section-15.2
	AttrXorMappedAddress AttributeType = 0x0020
	// AttrSoftware https://tools.ietf.org/html/rfc5389#section-15.10
	AttrSoftware AttributeType = 0x8022
	// AttrAlternateServer https://tools.ietf.org/html/rfc5389#section-15.11
	AttrAlternateServer AttributeType = 0x8023
	// AttrFingerprint https://tools.ietf.org/html/rfc5389#section-15.5
	AttrFingerprint AttributeType = 0x8028
)

var attrNames = map[AttributeType]string{
	AttrMappedAddress:          "MAPPED-ADDRESS",
	AttrUsername:               "USERNAME",
	AttrMessageIntegrity:       "MESSAGE-INTEGRITY",
	AttrErrorCode:              "ERROR-CODE",
	AttrUnknownAttributes:      "UNKNOWN-ATTRIBUTES",
	AttrRealm:                  "REALM",
	AttrNonce:                  "NONCE",
	AttrRequestedAddressFamily: "REQUESTED-ADDRESS-FAMILY",
	AttrXorMappedAddress:       "XOR-MAPPED-ADDRESS",
	AttrSoftware:               "SOFTWARE",
	AttrAlternateServer:        "ALTERNATE-SERVER",
	AttrFingerprint:            "FINGERPRINT",
}

/*
Error holds the Error Attribute

0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Reserved, should be 0         |Class|     Number    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Reason Phrase (variable)                                ..
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
type Error struct {
	ErrorCode ErrorCode
	ErrorText string
}

// ParseError returns an Error type from a byte slice
func ParseError(buf []byte) Error {
	errorCode := ErrorCode(int(buf[2])*100 + int(buf[3]))
	errorText := string(buf[4:])
	if len(strings.TrimSpace(errorText)) == 0 {
		if tmp, ok := errorNames[errorCode]; ok {
			errorText = tmp
		} else if tmp, ok := TurnErrorNames[errorCode]; ok {
			errorText = tmp
		} else if tmp, ok := TurnTCPErrorNames[errorCode]; ok {
			errorText = tmp
		} else {
			errorText = "Invalid Error"
		}
	}
	return Error{
		ErrorCode: errorCode,
		ErrorText: errorText,
	}
}

// ErrorCode defines the returned error code
type ErrorCode uint16

const (
	// ErrorTryAlternate error
	/*
		Try Alternate: The client should contact an alternate server for
		this request.  This error response MUST only be sent if the
		request included a USERNAME attribute and a valid MESSAGE-
		INTEGRITY attribute; otherwise, it MUST NOT be sent and error
		code 400 (Bad Request) is suggested.  This error response MUST
		be protected with the MESSAGE-INTEGRITY attribute, and receivers
		MUST validate the MESSAGE-INTEGRITY of this response before
		redirecting themselves to an alternate server.
		Note: Failure to generate and validate message integrity
		for a 300 response allows an on-path attacker to falsify a
		300 response thus causing subsequent STUN messages to be
		sent to a victim.
	*/
	ErrorTryAlternate ErrorCode = 300
	// ErrorBadRequest error
	/*
		Bad Request: The request was malformed.  The client SHOULD NOT
		retry the request without modification from the previous
		attempt.  The server may not be able to generate a valid
		MESSAGE-INTEGRITY for this error, so the client MUST NOT expect
		a valid MESSAGE-INTEGRITY attribute on this response.
	*/
	ErrorBadRequest ErrorCode = 400
	// ErrorUnauthorized error
	/*
		Unauthorized: The request did not contain the correct
		credentials to proceed.  The client should retry the request
		with proper credentials.
	*/
	ErrorUnauthorized ErrorCode = 401
	// ErrorUnknownAttribute error
	/*
		Unknown Attribute: The server received a STUN packet containing
		a comprehension-required attribute that it did not understand.
		The server MUST put this unknown attribute in the UNKNOWN-
		ATTRIBUTE attribute of its error response.
	*/
	ErrorUnknownAttribute ErrorCode = 420
	// ErrorStaleNonce error
	/*
		Stale Nonce: The NONCE used by the client was no longer valid.
		The client should retry, using the NONCE provided in the
		response.
	*/
	ErrorStaleNonce ErrorCode = 438
	// https://datatracker.ietf.org/doc/html/rfc6156#section-10.2
	ErrorAddressFamilyNotSupported ErrorCode = 440
	// https://datatracker.ietf.org/doc/html/rfc6156#section-10.2
	ErrorPeerAddressFamilyMissmatch ErrorCode = 443
	// ErrorServerError error
	/*
		Server Error: The server has suffered a temporary error.  The
		client should try again.
	*/
	ErrorServerError ErrorCode = 500
)

// nolint:deadcode,varcheck,unused
var errorNames = map[ErrorCode]string{
	ErrorTryAlternate:               "Try Alternate",
	ErrorBadRequest:                 "Bad Request",
	ErrorUnauthorized:               "Unauthorized",
	ErrorUnknownAttribute:           "Unknown Attribute",
	ErrorStaleNonce:                 "Stale Nonce",
	ErrorAddressFamilyNotSupported:  "Address Family not supported",
	ErrorPeerAddressFamilyMissmatch: "Peer Address Family Missmatch",
	ErrorServerError:                "Server Error",
}
