package internal

import "testing"

func TestMessageTypeMethodString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		method MessageTypeMethod
		want   string
	}{
		{MsgTypeMethodBinding, "Binding"},
		{MsgTypeMethodAllocate, "Allocate"},
		{MsgTypeMethodRefresh, "Refresh"},
		{MsgTypeMethodSend, "Send"},
		{MsgTypeMethodCreatePermission, "CreatePermission"},
		{MsgTypeMethodChannelbind, "Channel-Bind"},
		{MsgTypeMethodConnect, "Connect"},
		{MsgTypeMethodConnectionBind, "ConnectionBind"},
		{MsgTypeMethodConnectionAttempt, "ConnectionAttempt"},
		{0xFF, ""}, // unknown returns empty string
	}
	for _, tt := range tests {
		got := MessageTypeMethodString(tt.method)
		if got != tt.want {
			t.Errorf("MessageTypeMethodString(0x%02x): expected %q, got %q", tt.method, tt.want, got)
		}
	}
}

func TestMessageTypeClassString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		class MessageTypeClass
		want  string
	}{
		{MsgTypeClassRequest, "Request"},
		{MsgTypeClassIndication, "Indication"},
		{MsgTypeClassSuccess, "Success Response"},
		{MsgTypeClassError, "Error Response"},
		{0xFF, ""}, // unknown
	}
	for _, tt := range tests {
		got := MessageTypeClassString(tt.class)
		if got != tt.want {
			t.Errorf("MessageTypeClassString(0x%02x): expected %q, got %q", tt.class, tt.want, got)
		}
	}
}

func TestAttributeTypeString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		attr AttributeType
		want string
	}{
		{AttrUsername, "USERNAME"},
		{AttrRealm, "REALM"},
		{AttrNonce, "NONCE"},
		{AttrMessageIntegrity, "MESSAGE-INTEGRITY"},
		{AttrErrorCode, "ERROR-CODE"},
		{AttrLifetime, "LIFETIME"},
		{AttrRequestedTransport, "REQUESTED-TRANSPORT"},
		{AttrXorPeerAddress, "XOR-PEER-ADDRESS"},
		{AttrXorRelayedAddress, "XOR-RELAYED-ADDRESS"},
		{AttrConnectionID, "CONNECTION-ID"},
		{0xFFFF, ""}, // unknown
	}
	for _, tt := range tests {
		got := AttributeTypeString(tt.attr)
		if got != tt.want {
			t.Errorf("AttributeTypeString(0x%04x): expected %q, got %q", tt.attr, tt.want, got)
		}
	}
}

func TestRequestedTransportString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		transport RequestedTransport
		want      string
	}{
		{RequestedTransportUDP, "UDP"},
		{RequestedTransportTCP, "TCP"},
		{RequestedTransport(0xFF), ""}, // unknown
	}
	for _, tt := range tests {
		got := RequestedTransportString(tt.transport)
		if got != tt.want {
			t.Errorf("RequestedTransportString(%v): expected %q, got %q", tt.transport, tt.want, got)
		}
	}
}

func TestRequestedAddressFamilyString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		proto AllocateProtocol
		want  string
	}{
		{AllocateProtocolIPv4, "IPv4"},
		{AllocateProtocolIPv6, "IPv6"},
		{AllocateProtocolIgnore, "None"},
		{0xFF, ""}, // unknown
	}
	for _, tt := range tests {
		got := RequestedAddressFamilyString(tt.proto)
		if got != tt.want {
			t.Errorf("RequestedAddressFamilyString(%v): expected %q, got %q", tt.proto, tt.want, got)
		}
	}
}
