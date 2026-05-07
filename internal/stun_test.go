package internal

import (
	"bytes"
	"strings"
	"testing"
)

func TestGetAttribute(t *testing.T) {
	t.Parallel()

	s := &Stun{
		Attributes: []Attribute{
			{Type: AttrRealm, Value: []byte("example.com")},
			{Type: AttrNonce, Value: []byte("abc123")},
		},
	}

	attr := s.GetAttribute(AttrRealm)
	if string(attr.Value) != "example.com" {
		t.Errorf("expected 'example.com', got %q", attr.Value)
	}

	// Missing attribute returns zero value with empty Value
	attr = s.GetAttribute(AttrSoftware)
	if attr.Type != 0 || len(attr.Value) != 0 {
		t.Error("expected zero Attribute for missing type")
	}
}

func TestGetErrorStringAbsent(t *testing.T) {
	t.Parallel()

	s := &Stun{}
	if s.GetErrorString() != "" {
		t.Error("expected empty string when no error attribute is present")
	}
}

func TestGetErrorStringWithText(t *testing.T) {
	t.Parallel()

	// ErrorCode 401 with "Unauthorized" reason phrase
	s := &Stun{
		Attributes: []Attribute{{
			Type:  AttrErrorCode,
			Value: []byte{0x00, 0x00, 0x04, 0x01, 'U', 'n', 'a', 'u', 't', 'h', 'o', 'r', 'i', 'z', 'e', 'd'},
		}},
	}
	got := s.GetErrorString()
	if !strings.Contains(got, "401") {
		t.Errorf("expected '401' in error string, got %q", got)
	}
	if !strings.Contains(got, "Unauthorized") {
		t.Errorf("expected 'Unauthorized' in error string, got %q", got)
	}
}

func TestGetErrorStringUnknownCodeFallback(t *testing.T) {
	t.Parallel()

	// ErrorCode 401 without reason phrase - should be filled in from the lookup table
	s := &Stun{
		Attributes: []Attribute{{
			Type:  AttrErrorCode,
			Value: []byte{0x00, 0x00, 0x04, 0x01},
		}},
	}
	got := s.GetErrorString()
	if !strings.Contains(got, "Unauthorized") {
		t.Errorf("expected 'Unauthorized' from lookup table for code 401, got %q", got)
	}
}

func TestStunSerializeBindingRoundTrip(t *testing.T) {
	t.Parallel()

	original := BindingRequest()
	data, err := original.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	parsed, err := fromBytes(data)
	if err != nil {
		t.Fatalf("fromBytes: %v", err)
	}

	if parsed.Header.MessageType.Class != original.Header.MessageType.Class {
		t.Errorf("class: expected %v, got %v", original.Header.MessageType.Class, parsed.Header.MessageType.Class)
	}
	if parsed.Header.MessageType.Method != original.Header.MessageType.Method {
		t.Errorf("method: expected %v, got %v", original.Header.MessageType.Method, parsed.Header.MessageType.Method)
	}
	if parsed.Header.TransactionID != original.Header.TransactionID {
		t.Errorf("transactionID: expected %q, got %q", original.Header.TransactionID, parsed.Header.TransactionID)
	}
}

func TestStunSerializeAuthenticatedRoundTrip(t *testing.T) {
	t.Parallel()

	original := AllocateRequestAuth("user", "pass", "nonce123", "example.com", RequestedTransportUDP, AllocateProtocolIgnore)
	data, err := original.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	parsed, err := fromBytes(data)
	if err != nil {
		t.Fatalf("fromBytes: %v", err)
	}

	// MESSAGE-INTEGRITY must be present after serializing an authenticated request
	mi := parsed.GetAttribute(AttrMessageIntegrity)
	if len(mi.Value) != messageIntegritySize {
		t.Errorf("expected MESSAGE-INTEGRITY of %d bytes, got %d", messageIntegritySize, len(mi.Value))
	}

	username := parsed.GetAttribute(AttrUsername)
	if string(username.Value) != "user" {
		t.Errorf("expected username 'user', got %q", username.Value)
	}
}

func TestStunSerializeMissingTransactionID(t *testing.T) {
	t.Parallel()

	s := &Stun{}
	_, err := s.Serialize()
	if err == nil {
		t.Error("expected error when TransactionID is empty")
	}
}

func TestMessageTypeSerialize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		mt   MessageType
		want []byte
	}{
		// Values verified against captured packets in parsers_stun_test.go
		{"binding request", MessageType{Class: MsgTypeClassRequest, Method: MsgTypeMethodBinding}, []byte{0x00, 0x01}},
		{"binding success", MessageType{Class: MsgTypeClassSuccess, Method: MsgTypeMethodBinding}, []byte{0x01, 0x01}},
		{"allocate request", MessageType{Class: MsgTypeClassRequest, Method: MsgTypeMethodAllocate}, []byte{0x00, 0x03}},
		{"allocate success", MessageType{Class: MsgTypeClassSuccess, Method: MsgTypeMethodAllocate}, []byte{0x01, 0x03}},
		{"allocate error", MessageType{Class: MsgTypeClassError, Method: MsgTypeMethodAllocate}, []byte{0x01, 0x13}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.mt.Serialize()
			if !bytes.Equal(got, tt.want) {
				t.Errorf("expected %02x, got %02x", tt.want, got)
			}
		})
	}
}

func TestAttributeTypeValue(t *testing.T) {
	t.Parallel()

	if AttrRealm.Value() != 0x0014 {
		t.Errorf("AttrRealm: expected 0x0014, got 0x%04x", AttrRealm.Value())
	}
	if AttrUsername.Value() != 0x0006 {
		t.Errorf("AttrUsername: expected 0x0006, got 0x%04x", AttrUsername.Value())
	}
	if AttrConnectionID.Value() != 0x002a {
		t.Errorf("AttrConnectionID: expected 0x002a, got 0x%04x", AttrConnectionID.Value())
	}
}

func TestAttributeSerialize(t *testing.T) {
	t.Parallel()

	// 4-byte value: no padding needed
	a := Attribute{
		Type:  AttrRealm, // 0x0014
		Value: []byte("test"),
	}
	b := a.Serialize()
	if len(b) != 8 {
		t.Fatalf("expected 8 bytes, got %d", len(b))
	}
	if b[0] != 0x00 || b[1] != 0x14 {
		t.Errorf("type: expected [00 14], got [%02x %02x]", b[0], b[1])
	}
	if b[2] != 0x00 || b[3] != 0x04 {
		t.Errorf("length: expected [00 04], got [%02x %02x]", b[2], b[3])
	}
	if string(b[4:8]) != "test" {
		t.Errorf("value: expected 'test', got %q", b[4:8])
	}
}

func TestAttributeSerializePadding(t *testing.T) {
	t.Parallel()

	// 3-byte value: padded to 4 bytes
	a := Attribute{
		Type:  AttrRealm,
		Value: []byte("abc"),
	}
	b := a.Serialize()
	if len(b) != 8 { // 4 header + 3 data + 1 padding
		t.Errorf("expected 8 bytes with padding, got %d", len(b))
	}
	// Length field should reflect actual value length (3), not padded length
	if b[3] != 0x03 {
		t.Errorf("length field: expected 3, got %d", b[3])
	}
}
