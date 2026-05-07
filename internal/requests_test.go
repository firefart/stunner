package internal

import (
	"net/netip"
	"testing"
)

// --- STUN ---

func TestBindingRequest(t *testing.T) {
	t.Parallel()

	s := BindingRequest()
	if s.Header.MessageType.Class != MsgTypeClassRequest {
		t.Errorf("class: expected Request, got %v", s.Header.MessageType.Class)
	}
	if s.Header.MessageType.Method != MsgTypeMethodBinding {
		t.Errorf("method: expected Binding, got %v", s.Header.MessageType.Method)
	}
	if s.Header.TransactionID == "" {
		t.Error("expected non-empty transaction ID")
	}
}

// --- TURN ---

func TestAllocateRequestUDP(t *testing.T) {
	t.Parallel()

	s := AllocateRequest(RequestedTransportUDP, AllocateProtocolIgnore)
	if s.Header.MessageType.Class != MsgTypeClassRequest {
		t.Errorf("class: expected Request, got %v", s.Header.MessageType.Class)
	}
	if s.Header.MessageType.Method != MsgTypeMethodAllocate {
		t.Errorf("method: expected Allocate, got %v", s.Header.MessageType.Method)
	}

	transport := s.GetAttribute(AttrRequestedTransport)
	if len(transport.Value) != 4 {
		t.Fatalf("expected 4-byte transport value, got %d", len(transport.Value))
	}
	// UDP = 0x11 in first byte (little-endian encoding)
	if transport.Value[0] != 0x11 {
		t.Errorf("transport[0]: expected 0x11 (UDP), got 0x%02x", transport.Value[0])
	}

	// No address-family attribute when AllocateProtocolIgnore
	af := s.GetAttribute(AttrRequestedAddressFamily)
	if len(af.Value) != 0 {
		t.Error("expected no address-family attribute for AllocateProtocolIgnore")
	}
}

func TestAllocateRequestTCP(t *testing.T) {
	t.Parallel()

	s := AllocateRequest(RequestedTransportTCP, AllocateProtocolIgnore)
	transport := s.GetAttribute(AttrRequestedTransport)
	if len(transport.Value) != 4 {
		t.Fatalf("expected 4-byte transport value, got %d", len(transport.Value))
	}
	if transport.Value[0] != 0x06 {
		t.Errorf("transport[0]: expected 0x06 (TCP), got 0x%02x", transport.Value[0])
	}
}

func TestAllocateRequestIPv6AddressFamily(t *testing.T) {
	t.Parallel()

	s := AllocateRequest(RequestedTransportUDP, AllocateProtocolIPv6)
	af := s.GetAttribute(AttrRequestedAddressFamily)
	if len(af.Value) < 1 {
		t.Fatal("expected address-family attribute for AllocateProtocolIPv6")
	}
	if af.Value[0] != byte(AllocateProtocolIPv6) {
		t.Errorf("address family: expected %d (IPv6), got %d", AllocateProtocolIPv6, af.Value[0])
	}
}

func TestAllocateRequestAuthAttributes(t *testing.T) {
	t.Parallel()

	s := AllocateRequestAuth("user1", "pass1", "nonce1", "realm1", RequestedTransportUDP, AllocateProtocolIgnore)

	if s.Username != "user1" || s.Password != "pass1" {
		t.Error("expected Username and Password to be set on the Stun struct")
	}

	username := s.GetAttribute(AttrUsername)
	if string(username.Value) != "user1" {
		t.Errorf("username attribute: expected 'user1', got %q", username.Value)
	}

	realm := s.GetAttribute(AttrRealm)
	if string(realm.Value) != "realm1" {
		t.Errorf("realm attribute: expected 'realm1', got %q", realm.Value)
	}

	nonce := s.GetAttribute(AttrNonce)
	if string(nonce.Value) != "nonce1" {
		t.Errorf("nonce attribute: expected 'nonce1', got %q", nonce.Value)
	}

	transport := s.GetAttribute(AttrRequestedTransport)
	if len(transport.Value) != 4 {
		t.Error("expected RequestedTransport attribute")
	}
}

func TestSendRequest(t *testing.T) {
	t.Parallel()

	ip := netip.MustParseAddr("10.0.0.1")
	s, err := SendRequest(ip, 80)
	if err != nil {
		t.Fatalf("SendRequest: %v", err)
	}

	if s.Header.MessageType.Method != MsgTypeMethodSend {
		t.Errorf("method: expected Send, got %v", s.Header.MessageType.Method)
	}
	if s.Header.MessageType.Class != MsgTypeClassRequest {
		t.Errorf("class: expected Request, got %v", s.Header.MessageType.Class)
	}

	peerAddr := s.GetAttribute(AttrXorPeerAddress)
	if len(peerAddr.Value) == 0 {
		t.Error("expected XOR-PEER-ADDRESS attribute")
	}

	data := s.GetAttribute(AttrData)
	if len(data.Value) == 0 {
		t.Error("expected DATA attribute")
	}
}

func TestSendRequestInvalidIP(t *testing.T) {
	t.Parallel()

	_, err := SendRequest(netip.Addr{}, 80)
	if err == nil {
		t.Error("expected error for invalid IP address")
	}
}

func TestCreatePermissionRequest(t *testing.T) {
	t.Parallel()

	ip := netip.MustParseAddr("192.168.1.1")
	s, err := CreatePermissionRequest("user", "pass", "nonce", "realm", ip, 443)
	if err != nil {
		t.Fatalf("CreatePermissionRequest: %v", err)
	}

	if s.Header.MessageType.Method != MsgTypeMethodCreatePermission {
		t.Errorf("method: expected CreatePermission, got %v", s.Header.MessageType.Method)
	}

	peerAddr := s.GetAttribute(AttrXorPeerAddress)
	if len(peerAddr.Value) == 0 {
		t.Error("expected XOR-PEER-ADDRESS attribute")
	}

	if s.Username != "user" || s.Password != "pass" {
		t.Error("expected Username and Password set")
	}
}

func TestChannelBindRequest(t *testing.T) {
	t.Parallel()

	ip := netip.MustParseAddr("10.0.0.1")
	channelNum := []byte{0x40, 0x01}
	s, err := ChannelBindRequest("user", "pass", "nonce", "realm", ip, 80, channelNum)
	if err != nil {
		t.Fatalf("ChannelBindRequest: %v", err)
	}

	if s.Header.MessageType.Method != MsgTypeMethodChannelbind {
		t.Errorf("method: expected ChannelBind, got %v", s.Header.MessageType.Method)
	}

	ch := s.GetAttribute(AttrChannelNumber)
	if len(ch.Value) == 0 {
		t.Error("expected CHANNEL-NUMBER attribute")
	}
	// Channel number bytes followed by 2 reserved bytes
	if ch.Value[0] != 0x40 || ch.Value[1] != 0x01 {
		t.Errorf("channel number: expected [40 01], got [%02x %02x]", ch.Value[0], ch.Value[1])
	}
}

func TestChannelBindRequestBadChannelLen(t *testing.T) {
	t.Parallel()

	ip := netip.MustParseAddr("10.0.0.1")
	_, err := ChannelBindRequest("user", "pass", "nonce", "realm", ip, 80, []byte{0x40}) // only 1 byte
	if err == nil {
		t.Error("expected error for channel number that is not 2 bytes")
	}
}

func TestRefreshRequest(t *testing.T) {
	t.Parallel()

	s := RefreshRequest("user", "pass", "nonce", "realm")

	if s.Header.MessageType.Method != MsgTypeMethodRefresh {
		t.Errorf("method: expected Refresh, got %v", s.Header.MessageType.Method)
	}
	if s.Header.MessageType.Class != MsgTypeClassRequest {
		t.Errorf("class: expected Request, got %v", s.Header.MessageType.Class)
	}

	if s.Username != "user" || s.Password != "pass" {
		t.Error("expected Username and Password set")
	}
}

// --- TURN TCP ---

func TestConnectRequest(t *testing.T) {
	t.Parallel()

	ip := netip.MustParseAddr("10.0.0.1")
	s, err := ConnectRequest(ip, 443)
	if err != nil {
		t.Fatalf("ConnectRequest: %v", err)
	}

	if s.Header.MessageType.Method != MsgTypeMethodConnect {
		t.Errorf("method: expected Connect, got %v", s.Header.MessageType.Method)
	}
	if s.Header.MessageType.Class != MsgTypeClassRequest {
		t.Errorf("class: expected Request, got %v", s.Header.MessageType.Class)
	}

	peerAddr := s.GetAttribute(AttrXorPeerAddress)
	if len(peerAddr.Value) == 0 {
		t.Error("expected XOR-PEER-ADDRESS attribute")
	}
}

func TestConnectRequestAuth(t *testing.T) {
	t.Parallel()

	ip := netip.MustParseAddr("10.0.0.1")
	s, err := ConnectRequestAuth("user", "pass", "nonce", "realm", ip, 443)
	if err != nil {
		t.Fatalf("ConnectRequestAuth: %v", err)
	}

	if s.Username != "user" || s.Password != "pass" {
		t.Error("expected Username and Password set")
	}

	realm := s.GetAttribute(AttrRealm)
	if string(realm.Value) != "realm" {
		t.Errorf("realm: expected 'realm', got %q", realm.Value)
	}
}

func TestConnectionBindRequest(t *testing.T) {
	t.Parallel()

	connID := []byte{0x35, 0xd8, 0xcb, 0x0d}
	s := ConnectionBindRequest(connID, "user", "pass", "nonce", "realm")

	if s.Header.MessageType.Method != MsgTypeMethodConnectionBind {
		t.Errorf("method: expected ConnectionBind, got %v", s.Header.MessageType.Method)
	}

	cid := s.GetAttribute(AttrConnectionID)
	if string(cid.Value) != string(connID) {
		t.Errorf("connection ID: expected %02x, got %02x", connID, cid.Value)
	}

	if s.Username != "user" || s.Password != "pass" {
		t.Error("expected Username and Password set")
	}
}
