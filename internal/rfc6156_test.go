package internal

import (
	"net/netip"
	"testing"
)

// TestRFC6156_AttrRequestedAddressFamilyType verifies the REQUESTED-ADDRESS-FAMILY
// attribute type number defined in RFC 6156 §10.1.
func TestRFC6156_AttrRequestedAddressFamilyType(t *testing.T) {
	t.Parallel()

	if AttrRequestedAddressFamily != 0x0017 {
		t.Errorf("REQUESTED-ADDRESS-FAMILY: expected type 0x0017, got 0x%04x", AttrRequestedAddressFamily)
	}
}

// TestRFC6156_FamilyValues verifies the address-family byte values for IPv4 and
// IPv6 defined in RFC 6156 §4.1.1.
func TestRFC6156_FamilyValues(t *testing.T) {
	t.Parallel()

	if AllocateProtocolIPv4 != 0x01 {
		t.Errorf("IPv4 family: expected 0x01, got 0x%02x", AllocateProtocolIPv4)
	}
	if AllocateProtocolIPv6 != 0x02 {
		t.Errorf("IPv6 family: expected 0x02, got 0x%02x", AllocateProtocolIPv6)
	}
}

// TestRFC6156_ErrorCodes verifies the error codes defined in RFC 6156 §10.2.
func TestRFC6156_ErrorCodes(t *testing.T) {
	t.Parallel()

	if ErrorAddressFamilyNotSupported != 440 {
		t.Errorf("Address Family not Supported: expected 440, got %d", ErrorAddressFamilyNotSupported)
	}
	if ErrorPeerAddressFamilyMismatch != 443 {
		t.Errorf("Peer Address Family Mismatch: expected 443, got %d", ErrorPeerAddressFamilyMismatch)
	}
}

// TestRFC6156_ErrorStrings verifies the error string names match the RFC 6156 §10.2 text.
func TestRFC6156_ErrorStrings(t *testing.T) {
	t.Parallel()

	for _, check := range []struct {
		code ErrorCode
		want string
	}{
		{ErrorAddressFamilyNotSupported, "Address Family not Supported"},
		{ErrorPeerAddressFamilyMismatch, "Peer Address Family Mismatch"},
	} {
		got := StunErrorNames[check.code]
		if got != check.want {
			t.Errorf("error %d: expected %q, got %q", check.code, check.want, got)
		}
	}
}

// TestRFC6156_RequestedAddressFamilyEncoding verifies the wire encoding of
// REQUESTED-ADDRESS-FAMILY: 1-byte family followed by 3 reserved zero bytes —
// RFC 6156 §4.1.1.
func TestRFC6156_RequestedAddressFamilyEncoding(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		proto  AllocateProtocol
		family byte
	}{
		{"IPv4", AllocateProtocolIPv4, 0x01},
		{"IPv6", AllocateProtocolIPv6, 0x02},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s := AllocateRequest(RequestedTransportUDP, tc.proto)
			attr := s.GetAttribute(AttrRequestedAddressFamily)
			if len(attr.Value) != 4 {
				t.Fatalf("REQUESTED-ADDRESS-FAMILY: expected 4 bytes, got %d", len(attr.Value))
			}
			if attr.Value[0] != tc.family {
				t.Errorf("family byte: expected 0x%02x, got 0x%02x", tc.family, attr.Value[0])
			}
			for i := 1; i <= 3; i++ {
				if attr.Value[i] != 0x00 {
					t.Errorf("reserved byte %d: expected 0x00, got 0x%02x", i, attr.Value[i])
				}
			}
		})
	}
}

// TestRFC6156_AbsentFamilyMeansDefaultIPv4 verifies that when
// AllocateProtocolIgnore is passed no REQUESTED-ADDRESS-FAMILY attribute is
// added, which per RFC 6156 §4.2 means the server defaults to IPv4.
func TestRFC6156_AbsentFamilyMeansDefaultIPv4(t *testing.T) {
	t.Parallel()

	s := AllocateRequest(RequestedTransportUDP, AllocateProtocolIgnore)
	attr := s.GetAttribute(AttrRequestedAddressFamily)
	if len(attr.Value) != 0 {
		t.Error("absent address family: attribute must not be present when AllocateProtocolIgnore is used")
	}
}

// TestRFC6156_RefreshMustNotHaveAddressFamily verifies that a Refresh request
// does not carry REQUESTED-ADDRESS-FAMILY — RFC 6156 §5.
func TestRFC6156_RefreshMustNotHaveAddressFamily(t *testing.T) {
	t.Parallel()

	s := RefreshRequest("u", "p", "n", "r")
	attr := s.GetAttribute(AttrRequestedAddressFamily)
	if len(attr.Value) != 0 {
		t.Error("Refresh request must not contain REQUESTED-ADDRESS-FAMILY attribute")
	}
}

// TestRFC6156_IPv6AllocateCarriesAddressFamily verifies that an Allocate
// targeting an IPv6 host includes REQUESTED-ADDRESS-FAMILY with value 0x02 —
// RFC 6156 §4.2 and §4.1.1.
func TestRFC6156_IPv6AllocateCarriesAddressFamily(t *testing.T) {
	t.Parallel()

	target := netip.MustParseAddr("2001:db8::1")
	proto := AllocateProtocolIgnore
	if target.Is6() {
		proto = AllocateProtocolIPv6
	}

	s := AllocateRequest(RequestedTransportTCP, proto)
	attr := s.GetAttribute(AttrRequestedAddressFamily)
	if len(attr.Value) != 4 {
		t.Fatalf("IPv6 Allocate: expected REQUESTED-ADDRESS-FAMILY with 4 bytes, got %d", len(attr.Value))
	}
	if attr.Value[0] != 0x02 {
		t.Errorf("family byte: expected 0x02 (IPv6), got 0x%02x", attr.Value[0])
	}
}

// TestRFC6156_DisplayGuardRequiresFourBytes verifies that the display path for
// REQUESTED-ADDRESS-FAMILY does not panic on short values (< 4 bytes).
func TestRFC6156_DisplayGuardRequiresFourBytes(t *testing.T) {
	t.Parallel()

	s := newStun()
	s.Attributes = []Attribute{
		{Type: AttrRequestedAddressFamily, Value: []byte{0x01}}, // only 1 byte — invalid
	}
	// String() must not panic; the result is irrelevant
	_ = s.String()
}
