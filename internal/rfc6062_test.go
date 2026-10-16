package internal

import (
	"net/netip"
	"testing"
)

// TestRFC6062_MethodNumbers verifies the STUN method numbers defined in RFC 6062 §6.1.
func TestRFC6062_MethodNumbers(t *testing.T) {
	t.Parallel()

	if MsgTypeMethodConnect != 0x000a {
		t.Errorf("Connect: expected 0x000a, got 0x%04x", MsgTypeMethodConnect)
	}
	if MsgTypeMethodConnectionBind != 0x000b {
		t.Errorf("ConnectionBind: expected 0x000b, got 0x%04x", MsgTypeMethodConnectionBind)
	}
	if MsgTypeMethodConnectionAttempt != 0x000c {
		t.Errorf("ConnectionAttempt: expected 0x000c, got 0x%04x", MsgTypeMethodConnectionAttempt)
	}
}

// TestRFC6062_AttrConnectionIDType verifies the CONNECTION-ID attribute type
// number defined in RFC 6062 §6.2.1.
func TestRFC6062_AttrConnectionIDType(t *testing.T) {
	t.Parallel()

	if AttrConnectionID != 0x002a {
		t.Errorf("CONNECTION-ID: expected type 0x002a, got 0x%04x", AttrConnectionID)
	}
}

// TestRFC6062_ErrorCodes verifies the error codes defined in RFC 6062 §6.3.
func TestRFC6062_ErrorCodes(t *testing.T) {
	t.Parallel()

	if ErrorConnectionAlreadyExists != 446 {
		t.Errorf("Connection Already Exists: expected 446, got %d", ErrorConnectionAlreadyExists)
	}
	if ErrorConnectionTimeoutOrFailure != 447 {
		t.Errorf("Connection Timeout or Failure: expected 447, got %d", ErrorConnectionTimeoutOrFailure)
	}
}

// TestRFC6062_ConnectRequestClass verifies that ConnectRequest produces a
// Request-class message — RFC 6062 §4.3.
func TestRFC6062_ConnectRequestClass(t *testing.T) {
	t.Parallel()

	s, err := ConnectRequest(netip.MustParseAddr("10.0.0.1"), 443)
	if err != nil {
		t.Fatalf("ConnectRequest: %v", err)
	}
	if s.Header.MessageType.Class != MsgTypeClassRequest {
		t.Errorf("class: expected Request, got 0x%02x", s.Header.MessageType.Class)
	}
	if s.Header.MessageType.Method != MsgTypeMethodConnect {
		t.Errorf("method: expected Connect (0x%04x), got 0x%04x", MsgTypeMethodConnect, s.Header.MessageType.Method)
	}
}

// TestRFC6062_ConnectRequiresPeerAddress verifies that ConnectRequest includes
// XOR-PEER-ADDRESS — RFC 6062 §5.2.
func TestRFC6062_ConnectRequiresPeerAddress(t *testing.T) {
	t.Parallel()

	s, err := ConnectRequest(netip.MustParseAddr("192.168.0.1"), 8080)
	if err != nil {
		t.Fatalf("ConnectRequest: %v", err)
	}
	attr := s.GetAttribute(AttrXorPeerAddress)
	if len(attr.Value) == 0 {
		t.Error("Connect request must contain XOR-PEER-ADDRESS attribute")
	}
}

// TestRFC6062_ConnectAuthRequiresCredentials verifies that ConnectRequestAuth
// includes USERNAME, REALM, and NONCE for long-term authentication.
func TestRFC6062_ConnectAuthRequiresCredentials(t *testing.T) {
	t.Parallel()

	s, err := ConnectRequestAuth("user", "pass", "nonce1", "realm1", netip.MustParseAddr("10.0.0.1"), 443)
	if err != nil {
		t.Fatalf("ConnectRequestAuth: %v", err)
	}
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
	if s.Username != "user" || s.Password != "pass" {
		t.Error("expected Username and Password set on struct for MESSAGE-INTEGRITY")
	}
}

// TestRFC6062_ConnectionBindClassAndMethod verifies ConnectionBind uses
// Request class — RFC 6062 §5.4.
func TestRFC6062_ConnectionBindClassAndMethod(t *testing.T) {
	t.Parallel()

	s := ConnectionBindRequest([]byte{0x01, 0x02, 0x03, 0x04}, "u", "p", "n", "r")
	if s.Header.MessageType.Class != MsgTypeClassRequest {
		t.Errorf("class: expected Request, got 0x%02x", s.Header.MessageType.Class)
	}
	if s.Header.MessageType.Method != MsgTypeMethodConnectionBind {
		t.Errorf("method: expected ConnectionBind (0x%04x), got 0x%04x",
			MsgTypeMethodConnectionBind, s.Header.MessageType.Method)
	}
}

// TestRFC6062_ConnectionBindRequiresConnectionID verifies that ConnectionBind
// includes a CONNECTION-ID attribute — RFC 6062 §5.4.
func TestRFC6062_ConnectionBindRequiresConnectionID(t *testing.T) {
	t.Parallel()

	connID := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	s := ConnectionBindRequest(connID, "u", "p", "n", "r")

	attr := s.GetAttribute(AttrConnectionID)
	if len(attr.Value) == 0 {
		t.Fatal("ConnectionBind must contain CONNECTION-ID attribute")
	}
	// RFC 6062 §6.2.1: CONNECTION-ID is a 32-bit unsigned integer (4 bytes)
	if len(attr.Value) != 4 {
		t.Errorf("CONNECTION-ID: expected 4 bytes, got %d", len(attr.Value))
	}
	for i, b := range connID {
		if attr.Value[i] != b {
			t.Errorf("CONNECTION-ID byte %d: expected 0x%02x, got 0x%02x", i, b, attr.Value[i])
		}
	}
}

// TestRFC6062_ConnectionBindAuthentication verifies that ConnectionBind carries
// the long-term credential attributes — RFC 6062 §5.4 requires the same
// authentication as the control connection.
func TestRFC6062_ConnectionBindAuthentication(t *testing.T) {
	t.Parallel()

	s := ConnectionBindRequest([]byte{0x01, 0x02, 0x03, 0x04}, "user", "pass", "nonce1", "realm1")

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
	if s.Username != "user" || s.Password != "pass" {
		t.Error("expected Username and Password set on struct for MESSAGE-INTEGRITY")
	}
}

// TestRFC6062_ConnectionIDFourByteEncoding verifies that a 4-byte CONNECTION-ID
// is echoed back verbatim in ConnectionBind — RFC 6062 §6.2.1.
func TestRFC6062_ConnectionIDFourByteEncoding(t *testing.T) {
	t.Parallel()

	// Simulate a CONNECTION-ID received from a Connect success response
	serverConnID := []byte{0x00, 0x00, 0x04, 0xD2} // big-endian 1234
	s := ConnectionBindRequest(serverConnID, "u", "p", "n", "r")

	buf, err := s.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	// Parse back to verify the CONNECTION-ID round-trips correctly
	msg, err := fromBytes(buf)
	if err != nil {
		t.Fatalf("fromBytes: %v", err)
	}
	connID := msg.GetAttribute(AttrConnectionID)
	if len(connID.Value) != 4 {
		t.Fatalf("round-trip CONNECTION-ID: expected 4 bytes, got %d", len(connID.Value))
	}
	for i, b := range serverConnID {
		if connID.Value[i] != b {
			t.Errorf("round-trip byte %d: expected 0x%02x, got 0x%02x", i, b, connID.Value[i])
		}
	}
}

// TestRFC6062_ConnectionAttemptMethodDefined verifies that ConnectionAttempt
// (server→client indication) has the correct method number — RFC 6062 §6.1.
// This method is received, not sent, so we only verify the constant is correct
// and that the string representation is defined.
func TestRFC6062_ConnectionAttemptMethodDefined(t *testing.T) {
	t.Parallel()

	if MsgTypeMethodConnectionAttempt != 0x000c {
		t.Errorf("ConnectionAttempt: expected 0x000c, got 0x%04x", MsgTypeMethodConnectionAttempt)
	}
	name := MessageTypeMethodString(MsgTypeMethodConnectionAttempt)
	if name == "" {
		t.Error("ConnectionAttempt method has no string name defined")
	}
}

// TestRFC6062_ConnectionIDAbsentIsDetected verifies that an absent CONNECTION-ID
// in a response can be detected by checking the returned attribute length.
// This guards the validation added to SetupTurnTCPConnection.
func TestRFC6062_ConnectionIDAbsentIsDetected(t *testing.T) {
	t.Parallel()

	// Simulate a Connect response with no CONNECTION-ID attribute
	s := newStun()
	s.Header.MessageType = MessageType{Class: MsgTypeClassSuccess, Method: MsgTypeMethodConnect}
	connIDAttr := s.GetAttribute(AttrConnectionID)
	// GetAttribute returns empty Value when attribute is absent
	if len(connIDAttr.Value) == 4 {
		t.Error("absent CONNECTION-ID should not return 4 bytes")
	}
	// A caller should check len(connIDAttr.Value) != 4 and return an error
}
