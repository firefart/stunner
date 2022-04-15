package internal

/*
0x003  :  Allocate          (only request/response semantics defined)
0x004  :  Refresh           (only request/response semantics defined)
0x006  :  Send              (only indication semantics defined)
0x007  :  Data              (only indication semantics defined)
0x008  :  CreatePermission  (only request/response semantics defined
0x009  :  ChannelBind       (only request/response semantics defined)

This STUN extension defines the following new attributes:

0x000C: CHANNEL-NUMBER
0x000D: LIFETIME
0x0010: Reserved (was BANDWIDTH)
0x0012: XOR-PEER-ADDRESS
0x0013: DATA
0x0016: XOR-RELAYED-ADDRESS
0x0018: EVEN-PORT
0x0019: REQUESTED-TRANSPORT
0x001A: DONT-FRAGMENT
0x0021: Reserved (was TIMER-VAL)
0x0022: RESERVATION-TOKEN


This document defines the following new error response codes:

403  (Forbidden): The request was valid but cannot be performed due
	to administrative or similar restrictions.

437  (Allocation Mismatch): A request was received by the server that
	requires an allocation to be in place, but no allocation exists,
	or a request was received that requires no allocation, but an
	allocation exists.

441  (Wrong Credentials): The credentials in the (non-Allocate)
	request do not match those used to create the allocation.

442  (Unsupported Transport Protocol): The Allocate request asked the
	server to use a transport protocol between the server and the peer
	that the server does not support.  NOTE: This does NOT refer to
	the transport protocol used in the 5-tuple.

486  (Allocation Quota Reached): No more allocations using this
	username can be created at the present time.

508  (Insufficient Capacity): The server is unable to carry out the
	request due to some capacity limit being reached.  In an Allocate
	response, this could be due to the server having no more relayed
	transport addresses available at that time, having none with the
	requested properties, or the one that corresponds to the specified
	reservation token is not available.
*/

const (
	MsgTypeMethodAllocate         MessageTypeMethod = 0x03
	MsgTypeMethodRefresh          MessageTypeMethod = 0x04
	MsgTypeMethodSend             MessageTypeMethod = 0x06
	MsgTypeMethodDataInd          MessageTypeMethod = 0x07
	MsgTypeMethodCreatePermission MessageTypeMethod = 0x08
	MsgTypeMethodChannelbind      MessageTypeMethod = 0x09
)

var turnMsgTypeMethodNames = map[MessageTypeMethod]string{
	MsgTypeMethodAllocate:         "Allocate",
	MsgTypeMethodRefresh:          "Refresh",
	MsgTypeMethodChannelbind:      "Channel-Bind",
	MsgTypeMethodCreatePermission: "CreatePermission",
	MsgTypeMethodSend:             "Send",
	MsgTypeMethodDataInd:          "Data",
}

const (
	AttrChannelNumber      AttributeType = 0x000c
	AttrLifetime           AttributeType = 0x000d
	AttrBandwidth          AttributeType = 0x0010
	AttrXorPeerAddress     AttributeType = 0x0012
	AttrData               AttributeType = 0x0013
	AttrXorRelayedAddress  AttributeType = 0x0016
	AttrEvenPort           AttributeType = 0x0018
	AttrRequestedTransport AttributeType = 0x0019
	AttrDontFragment       AttributeType = 0x001a
	AttrTimerVal           AttributeType = 0x0021
	AttrReservationToken   AttributeType = 0x0022
)

var turnAttrNames = map[AttributeType]string{
	AttrChannelNumber:      "CHANNEL-NUMBER",
	AttrLifetime:           "LIFETIME",
	AttrBandwidth:          "BANDWIDTH",
	AttrXorPeerAddress:     "XOR-PEER-ADDRESS",
	AttrData:               "DATA",
	AttrXorRelayedAddress:  "XOR-RELAYED-ADDRESS",
	AttrEvenPort:           "EVEN-PORT",
	AttrRequestedTransport: "REQUESTED-TRANSPORT",
	AttrDontFragment:       "DONT-FRAGMENT",
	AttrTimerVal:           "TIMER-VAL",
	AttrReservationToken:   "RESERVATION-TOKEN",
}

const (
	ErrorForbidden                    ErrorCode = 403
	ErrorAllocationMismatch           ErrorCode = 437
	ErrorWrongCredentials             ErrorCode = 441
	ErrorUnsupportedTransportProtocol ErrorCode = 442
	ErrorAllocationQuotaReached       ErrorCode = 486
	ErrorInsufficientCapacity         ErrorCode = 508
)

var TurnErrorNames = map[ErrorCode]string{
	ErrorForbidden:                    "Forbidden",
	ErrorAllocationMismatch:           "Allocation Mismatch",
	ErrorWrongCredentials:             "Wrong Credentials",
	ErrorUnsupportedTransportProtocol: "Unsupported Transport Protocol",
	ErrorAllocationQuotaReached:       "Allocation Quota Reached",
	ErrorInsufficientCapacity:         "Insufficient Capacity",
}

type AllocateProtocol byte

const (
	AllocateProtocolIgnore AllocateProtocol = 0x00 // only used internally, not part of the spec
	AllocateProtocolIPv4   AllocateProtocol = 0x01
	AllocateProtocolIPv6   AllocateProtocol = 0x02
)

var allocateProtocolNames = map[AllocateProtocol]string{
	AllocateProtocolIgnore: "None", // only used internally, not part of the spec
	AllocateProtocolIPv4:   "IPv4",
	AllocateProtocolIPv6:   "IPv6",
}
