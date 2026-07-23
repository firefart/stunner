package internal

import (
	"encoding/hex"
	"testing"
)

// TestRFC5769_XORAddressIPv4 verifies XOR-MAPPED-ADDRESS decoding against
// RFC 5769 §2.2 test vector (192.0.2.1:32853).
func TestRFC5769_XORAddressIPv4(t *testing.T) {
	t.Parallel()

	// XOR-MAPPED-ADDRESS attribute value (8 bytes) from RFC 5769 §2.2
	xorBytes := []byte{0x00, 0x01, 0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43}
	transactionIDBytes, _ := hex.DecodeString("b7e7a701bc34d686fa87dfae")
	transactionID := string(transactionIDBytes)

	host, port, err := ConvertXORAddr(xorBytes, transactionID)
	if err != nil {
		t.Fatalf("ConvertXORAddr: %v", err)
	}
	if host != "192.0.2.1" {
		t.Errorf("host: expected 192.0.2.1, got %s", host)
	}
	if port != 32853 {
		t.Errorf("port: expected 32853, got %d", port)
	}
}

// TestRFC5769_XORAddressIPv6 verifies XOR-MAPPED-ADDRESS decoding against
// RFC 5769 §2.3 test vector (2001:db8:1234:5678:11:2233:4455:6677:32853).
func TestRFC5769_XORAddressIPv6(t *testing.T) {
	t.Parallel()

	// XOR-MAPPED-ADDRESS attribute value (20 bytes) from RFC 5769 §2.3
	xorBytes := []byte{
		0x00, 0x02, 0xa1, 0x47,
		0x01, 0x13, 0xa9, 0xfa, 0xa5, 0xd3, 0xf1, 0x79,
		0xbc, 0x25, 0xf4, 0xb5, 0xbe, 0xd2, 0xb9, 0xd9,
	}
	transactionIDBytes, _ := hex.DecodeString("b7e7a701bc34d686fa87dfae")
	transactionID := string(transactionIDBytes)

	host, port, err := ConvertXORAddr(xorBytes, transactionID)
	if err != nil {
		t.Fatalf("ConvertXORAddr: %v", err)
	}
	if host != "2001:db8:1234:5678:11:2233:4455:6677" {
		t.Errorf("host: expected 2001:db8:1234:5678:11:2233:4455:6677, got %s", host)
	}
	if port != 32853 {
		t.Errorf("port: expected 32853, got %d", port)
	}
}

// TestRFC5769_LongTermAuthHMAC verifies MESSAGE-INTEGRITY calculation against
// RFC 5769 §2.4 test vector (long-term authentication).
func TestRFC5769_LongTermAuthHMAC(t *testing.T) {
	t.Parallel()

	// RFC 5769 §2.4: input buffer = STUN header (with length adjusted to include MI)
	// + USERNAME + NONCE + REALM attributes (72 bytes total, no MI).
	// Header length field = 0x0060 = 96 (72 attrs + 24 for MI TLV).
	//
	// Note: the RFC 5769 hex dump has a known typo — byte 0x9a instead of 0x9e for
	// マ (U+30DE). The HMAC in the RFC was computed with the correct UTF-8 (0x9e),
	// confirmed by RFC errata and by independent computation.
	buf := []byte{
		// Header (20 bytes)
		0x00, 0x01, 0x00, 0x60, // BINDING REQUEST, length=96
		0x21, 0x12, 0xa4, 0x42, // magic cookie
		0x78, 0xad, 0x34, 0x33, 0xc6, 0xad, 0x72, 0xc0, 0x29, 0xda, 0x41, 0x2e, // transaction ID

		// USERNAME (24 bytes): type=0x0006, length=18, value + 2 padding
		// "マトリックス" in UTF-8 (U+30DE U+30C8 U+30EA U+30C3 U+30AF U+30B9)
		0x00, 0x06, 0x00, 0x12,
		0xe3, 0x83, 0x9e, 0xe3, 0x83, 0x88, 0xe3, 0x83, 0xaa, 0xe3, 0x83, 0x83, 0xe3, 0x82, 0xaf, 0xe3, 0x82, 0xb9,
		0x00, 0x00,

		// NONCE (32 bytes): type=0x0015, length=28, value (no padding)
		0x00, 0x15, 0x00, 0x1c,
		0x66, 0x2f, 0x2f, 0x34, 0x39, 0x39, 0x6b, 0x39, 0x35, 0x34, 0x64, 0x36,
		0x4f, 0x4c, 0x33, 0x34, 0x6f, 0x4c, 0x39, 0x46, 0x53, 0x54, 0x76, 0x79, 0x36, 0x34, 0x73, 0x41,

		// REALM (16 bytes): type=0x0014, length=11, value + 1 padding
		0x00, 0x14, 0x00, 0x0b,
		0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x6f, 0x72, 0x67,
		0x00,
	}

	// correct UTF-8 encoding of "マトリックス" (matches what the RFC HMAC was computed with)
	usernameBytes := []byte{0xe3, 0x83, 0x9e, 0xe3, 0x83, 0x88, 0xe3, 0x83, 0xaa, 0xe3, 0x83, 0x83, 0xe3, 0x82, 0xaf, 0xe3, 0x82, 0xb9}
	username := string(usernameBytes)
	realm := "example.org"
	password := "TheMatrIX"

	got, err := calculateMessageIntegrity(buf, username, realm, password)
	if err != nil {
		t.Fatalf("calculateMessageIntegrity: %v", err)
	}

	expected := []byte{0xf6, 0x70, 0x24, 0x65, 0x6d, 0xd6, 0x4a, 0x3e, 0x02, 0xb8, 0xe0, 0x71, 0x2e, 0x85, 0xc9, 0xa2, 0x8c, 0xa8, 0x96, 0x66}
	if hex.EncodeToString(got) != hex.EncodeToString(expected) {
		t.Errorf("HMAC mismatch:\n  got:      %x\n  expected: %x", got, expected)
	}
}

// TestRFC5769_ParseRequest verifies that fromBytes correctly parses the complete
// RFC 5769 §2.1 sample request and that magic cookie / top-bits validation passes.
func TestRFC5769_ParseRequest(t *testing.T) {
	t.Parallel()

	// RFC 5769 §2.1 complete BINDING REQUEST (108 bytes)
	raw := []byte{
		0x00, 0x01, 0x00, 0x58, // BINDING REQUEST, length=88
		0x21, 0x12, 0xa4, 0x42, // magic cookie
		0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae, // transaction ID
		// SOFTWARE (type=0x8022, length=16, no padding)
		0x80, 0x22, 0x00, 0x10,
		0x53, 0x54, 0x55, 0x4e, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74,
		// PRIORITY (type=0x0024, length=4)
		0x00, 0x24, 0x00, 0x04, 0x6e, 0x00, 0x01, 0xff,
		// ICE-CONTROLLED (type=0x8029, length=8)
		0x80, 0x29, 0x00, 0x08, 0x93, 0x2f, 0xf9, 0xb1, 0x51, 0x26, 0x3b, 0x36,
		// USERNAME (type=0x0006, length=9, padded to 12)
		0x00, 0x06, 0x00, 0x09,
		0x65, 0x76, 0x74, 0x6a, 0x3a, 0x68, 0x36, 0x76, 0x59, 0x20, 0x20, 0x20,
		// MESSAGE-INTEGRITY (type=0x0008, length=20)
		0x00, 0x08, 0x00, 0x14,
		0x9a, 0xea, 0xa7, 0x0c, 0xbf, 0xd8, 0xcb, 0x56, 0x78, 0x1e, 0xf2, 0xb5, 0xb2, 0xd3, 0xf2, 0x49, 0xc1, 0xb5, 0x71, 0xa2,
		// FINGERPRINT (type=0x8028, length=4)
		0x80, 0x28, 0x00, 0x04, 0xe5, 0x7a, 0x3b, 0xcf,
	}

	msg, err := fromBytes(raw)
	if err != nil {
		t.Fatalf("fromBytes: %v", err)
	}

	usernameAttr := msg.GetAttribute(AttrUsername)
	if string(usernameAttr.Value) != "evtj:h6vY" {
		t.Errorf("USERNAME: expected %q, got %q", "evtj:h6vY", string(usernameAttr.Value))
	}
}

// TestRFC5769_MagicCookieValidation verifies that fromBytes rejects packets
// without the RFC 5389 magic cookie.
func TestRFC5769_MagicCookieValidation(t *testing.T) {
	t.Parallel()

	raw := make([]byte, 20)
	raw[0] = 0x00 // BINDING REQUEST
	raw[1] = 0x01
	raw[2] = 0x00 // length = 0
	raw[3] = 0x00
	// bytes 4-7: wrong magic cookie (0xDEADBEEF)
	raw[4] = 0xDE
	raw[5] = 0xAD
	raw[6] = 0xBE
	raw[7] = 0xEF

	_, err := fromBytes(raw)
	if err == nil {
		t.Error("expected error for wrong magic cookie, got nil")
	}
}

// TestRFC5769_TopBitsValidation verifies that fromBytes rejects packets where
// the top two bits of the first byte are not zero (RFC 5389 §6).
func TestRFC5769_TopBitsValidation(t *testing.T) {
	t.Parallel()

	raw := make([]byte, 20)
	raw[0] = 0x80 // top bit set — invalid per RFC 5389
	raw[1] = 0x01
	raw[2] = 0x00
	raw[3] = 0x00
	raw[4] = 0x21 // correct magic cookie
	raw[5] = 0x12
	raw[6] = 0xa4
	raw[7] = 0x42

	_, err := fromBytes(raw)
	if err == nil {
		t.Error("expected error for top bits set, got nil")
	}
}
