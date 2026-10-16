package internal

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

// TestRFC5766_SendIsIndication verifies that SendRequest produces a message
// with class Indication — RFC 5766 §3 defines Send with indication-only semantics.
func TestRFC5766_SendIsIndication(t *testing.T) {
	t.Parallel()

	s, err := SendRequest(netip.MustParseAddr("10.0.0.1"), 80)
	if err != nil {
		t.Fatalf("SendRequest: %v", err)
	}
	if s.Header.MessageType.Class != MsgTypeClassIndication {
		t.Errorf("class: expected Indication (0x%02x), got 0x%02x",
			MsgTypeClassIndication, s.Header.MessageType.Class)
	}
	if s.Header.MessageType.Method != MsgTypeMethodSend {
		t.Errorf("method: expected Send (0x%02x), got 0x%02x",
			MsgTypeMethodSend, s.Header.MessageType.Method)
	}
}

// TestRFC5766_SendIndicationWireType verifies that the serialized Send indication
// has message type 0x0016 on the wire — RFC 5766 §3 + RFC 5389 §18.1.
func TestRFC5766_SendIndicationWireType(t *testing.T) {
	t.Parallel()

	s, err := SendRequest(netip.MustParseAddr("10.0.0.1"), 80)
	if err != nil {
		t.Fatalf("SendRequest: %v", err)
	}
	buf, err := s.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	wireType := binary.BigEndian.Uint16(buf[0:2])
	if wireType != 0x0016 {
		t.Errorf("wire type: expected 0x0016 (Send Indication), got 0x%04x", wireType)
	}
}

// TestRFC5766_RequestedTransportUDPEncoding verifies the REQUESTED-TRANSPORT
// attribute byte layout for UDP — RFC 5766 §14.7.
func TestRFC5766_RequestedTransportUDPEncoding(t *testing.T) {
	t.Parallel()

	s := AllocateRequest(RequestedTransportUDP, AllocateProtocolIgnore)
	attr := s.GetAttribute(AttrRequestedTransport)
	if len(attr.Value) != 4 {
		t.Fatalf("REQUESTED-TRANSPORT: expected 4 bytes, got %d", len(attr.Value))
	}
	// byte 0: protocol = 0x11 (UDP per IANA)
	if attr.Value[0] != 0x11 {
		t.Errorf("protocol byte: expected 0x11 (UDP), got 0x%02x", attr.Value[0])
	}
	// bytes 1-3: RFFU, must be zero
	for i := 1; i <= 3; i++ {
		if attr.Value[i] != 0x00 {
			t.Errorf("reserved byte %d: expected 0x00, got 0x%02x", i, attr.Value[i])
		}
	}
}

// TestRFC5766_RequestedTransportTCPEncoding verifies the REQUESTED-TRANSPORT
// attribute byte layout for TCP — RFC 5766 §14.7.
func TestRFC5766_RequestedTransportTCPEncoding(t *testing.T) {
	t.Parallel()

	s := AllocateRequest(RequestedTransportTCP, AllocateProtocolIgnore)
	attr := s.GetAttribute(AttrRequestedTransport)
	if len(attr.Value) != 4 {
		t.Fatalf("REQUESTED-TRANSPORT: expected 4 bytes, got %d", len(attr.Value))
	}
	// byte 0: protocol = 0x06 (TCP per IANA)
	if attr.Value[0] != 0x06 {
		t.Errorf("protocol byte: expected 0x06 (TCP), got 0x%02x", attr.Value[0])
	}
	for i := 1; i <= 3; i++ {
		if attr.Value[i] != 0x00 {
			t.Errorf("reserved byte %d: expected 0x00, got 0x%02x", i, attr.Value[i])
		}
	}
}

// TestRFC5766_ChannelNumberFormat verifies that the CHANNEL-NUMBER attribute
// is 4 bytes: 2-byte channel number followed by two reserved zero bytes — RFC 5766 §14.1.
func TestRFC5766_ChannelNumberFormat(t *testing.T) {
	t.Parallel()

	channelNum := []byte{0x40, 0x05}
	s, err := ChannelBindRequest("u", "p", "n", "r", netip.MustParseAddr("10.0.0.1"), 80, channelNum)
	if err != nil {
		t.Fatalf("ChannelBindRequest: %v", err)
	}

	attr := s.GetAttribute(AttrChannelNumber)
	if len(attr.Value) != 4 {
		t.Fatalf("CHANNEL-NUMBER: expected 4 bytes, got %d", len(attr.Value))
	}
	if attr.Value[0] != 0x40 || attr.Value[1] != 0x05 {
		t.Errorf("channel bytes: expected [40 05], got [%02x %02x]", attr.Value[0], attr.Value[1])
	}
	// bytes 2-3: RFFU, must be zero (RFC 5766 §14.1)
	if attr.Value[2] != 0x00 || attr.Value[3] != 0x00 {
		t.Errorf("reserved bytes: expected [00 00], got [%02x %02x]", attr.Value[2], attr.Value[3])
	}
}

// TestRFC5766_AllocateRequiresRequestedTransport verifies that an Allocate
// request always carries REQUESTED-TRANSPORT — RFC 5766 §6.1.
func TestRFC5766_AllocateRequiresRequestedTransport(t *testing.T) {
	t.Parallel()

	s := AllocateRequest(RequestedTransportUDP, AllocateProtocolIgnore)
	attr := s.GetAttribute(AttrRequestedTransport)
	if len(attr.Value) == 0 {
		t.Error("Allocate request must contain REQUESTED-TRANSPORT attribute")
	}
}

// TestRFC5766_AllocateAuthRequiresCredentials verifies that an authenticated
// Allocate carries USERNAME, REALM, and NONCE — RFC 5766 §6.1 + RFC 5389 §10.
func TestRFC5766_AllocateAuthRequiresCredentials(t *testing.T) {
	t.Parallel()

	s := AllocateRequestAuth("user", "pass", "nonce1", "realm1", RequestedTransportUDP, AllocateProtocolIgnore)

	for _, check := range []struct {
		attr AttributeType
		want string
		name string
	}{
		{AttrUsername, "user", "USERNAME"},
		{AttrRealm, "realm1", "REALM"},
		{AttrNonce, "nonce1", "NONCE"},
	} {
		a := s.GetAttribute(check.attr)
		if string(a.Value) != check.want {
			t.Errorf("%s: expected %q, got %q", check.name, check.want, string(a.Value))
		}
	}
}

// TestRFC5766_CreatePermissionRequiresPeerAddress verifies that CreatePermission
// carries XOR-PEER-ADDRESS and uses Request class — RFC 5766 §9.1.
func TestRFC5766_CreatePermissionRequiresPeerAddress(t *testing.T) {
	t.Parallel()

	s, err := CreatePermissionRequest("u", "p", "n", "r", netip.MustParseAddr("192.168.1.1"), 443)
	if err != nil {
		t.Fatalf("CreatePermissionRequest: %v", err)
	}
	if len(s.GetAttribute(AttrXorPeerAddress).Value) == 0 {
		t.Error("CreatePermission must contain XOR-PEER-ADDRESS attribute")
	}
	if s.Header.MessageType.Class != MsgTypeClassRequest {
		t.Errorf("class: expected Request, got 0x%02x", s.Header.MessageType.Class)
	}
}

// TestRFC5766_ChannelBindRequiredAttributes verifies that ChannelBind carries
// CHANNEL-NUMBER and XOR-PEER-ADDRESS — RFC 5766 §11.1.
func TestRFC5766_ChannelBindRequiredAttributes(t *testing.T) {
	t.Parallel()

	s, err := ChannelBindRequest("u", "p", "n", "r", netip.MustParseAddr("10.0.0.1"), 80, []byte{0x40, 0x01})
	if err != nil {
		t.Fatalf("ChannelBindRequest: %v", err)
	}
	if len(s.GetAttribute(AttrChannelNumber).Value) == 0 {
		t.Error("ChannelBind must contain CHANNEL-NUMBER attribute")
	}
	if len(s.GetAttribute(AttrXorPeerAddress).Value) == 0 {
		t.Error("ChannelBind must contain XOR-PEER-ADDRESS attribute")
	}
	if s.Header.MessageType.Class != MsgTypeClassRequest {
		t.Errorf("class: expected Request, got 0x%02x", s.Header.MessageType.Class)
	}
}

// TestRFC5766_RefreshHasNoXorPeerAddress verifies that a Refresh request does
// not include XOR-PEER-ADDRESS — RFC 5766 §7.1.
func TestRFC5766_RefreshHasNoXorPeerAddress(t *testing.T) {
	t.Parallel()

	s := RefreshRequest("u", "p", "n", "r")
	if len(s.GetAttribute(AttrXorPeerAddress).Value) != 0 {
		t.Error("Refresh request must not contain XOR-PEER-ADDRESS attribute")
	}
	if s.Header.MessageType.Method != MsgTypeMethodRefresh {
		t.Errorf("method: expected Refresh, got 0x%02x", s.Header.MessageType.Method)
	}
}

// TestRFC5766_ChannelDataPaddingAccepted verifies that ExtractChannelData accepts
// ChannelData with RFC-mandated trailing padding — RFC 5766 §11.5.
// The LENGTH field reports actual data bytes; padding brings total to 4-byte boundary.
func TestRFC5766_ChannelDataPaddingAccepted(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   []byte
		wantLen int
	}{
		{
			// length=1, 1 byte data + 3 bytes padding
			name:    "1-byte data padded to 4",
			input:   []byte{0x40, 0x01, 0x00, 0x01, 0xAB, 0x00, 0x00, 0x00},
			wantLen: 1,
		},
		{
			// length=2, 2 bytes data + 2 bytes padding
			name:    "2-byte data padded to 4",
			input:   []byte{0x40, 0x01, 0x00, 0x02, 0xAB, 0xCD, 0x00, 0x00},
			wantLen: 2,
		},
		{
			// length=3, 3 bytes data + 1 byte padding
			name:    "3-byte data padded to 4",
			input:   []byte{0x40, 0x01, 0x00, 0x03, 0xAB, 0xCD, 0xEF, 0x00},
			wantLen: 3,
		},
		{
			// length=4, already aligned — no padding
			name:    "4-byte data no padding",
			input:   []byte{0x40, 0x01, 0x00, 0x04, 0xAB, 0xCD, 0xEF, 0x01},
			wantLen: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, data, err := ExtractChannelData(tt.input)
			if err != nil {
				t.Fatalf("ExtractChannelData: %v", err)
			}
			if len(data) != tt.wantLen {
				t.Errorf("data length: expected %d, got %d", tt.wantLen, len(data))
			}
		})
	}
}
