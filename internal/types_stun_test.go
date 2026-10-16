package internal

import (
	"strings"
	"testing"
)

func TestParseErrorShortBuffer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		buf  []byte
	}{
		{"empty", []byte{}},
		{"1 byte", []byte{0x00}},
		{"2 bytes", []byte{0x00, 0x00}},
		{"3 bytes", []byte{0x00, 0x00, 0x04}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// must not panic
			e := ParseError(tt.buf)
			if e.ErrorCode != 0 {
				t.Errorf("expected zero error code for short buffer, got %d", e.ErrorCode)
			}
		})
	}
}

func TestParseErrorValid(t *testing.T) {
	t.Parallel()

	// Error code 401: class byte=4, number byte=1 → 4*100+1=401
	buf := []byte{0x00, 0x00, 0x04, 0x01, 'U', 'n', 'a', 'u', 't', 'h', 'o', 'r', 'i', 'z', 'e', 'd'}
	e := ParseError(buf)
	if e.ErrorCode != ErrorUnauthorized {
		t.Errorf("expected code %d, got %d", ErrorUnauthorized, e.ErrorCode)
	}
	if e.ErrorText != "Unauthorized" {
		t.Errorf("expected text 'Unauthorized', got %q", e.ErrorText)
	}
}

func TestParseErrorNoText(t *testing.T) {
	t.Parallel()

	// 4-byte minimal error (no reason phrase)
	buf := []byte{0x00, 0x00, 0x04, 0x01}
	e := ParseError(buf)
	if e.ErrorCode != ErrorUnauthorized {
		t.Errorf("expected code %d, got %d", ErrorUnauthorized, e.ErrorCode)
	}
}

func TestAttributeStringLifetime(t *testing.T) {
	t.Parallel()

	// Lifetime = 800 seconds (0x00000320), 4-byte big-endian
	a := Attribute{
		Type:  AttrLifetime,
		Value: []byte{0x00, 0x00, 0x03, 0x20},
	}
	result := a.String("")
	if !strings.Contains(result, "800") {
		t.Errorf("expected '800' in lifetime string, got %q", result)
	}
}

func TestAttributeStringLifetimeShort(t *testing.T) {
	t.Parallel()

	// Lifetime attribute with fewer than 4 bytes must not panic
	a := Attribute{
		Type:  AttrLifetime,
		Value: []byte{0x00, 0x03},
	}
	result := a.String("")
	if !strings.Contains(result, "invalid") {
		t.Errorf("expected 'invalid' for short lifetime, got %q", result)
	}
}

func TestAttributeStringRequestedAddressFamilyShort(t *testing.T) {
	t.Parallel()

	// Empty value must not panic
	a := Attribute{
		Type:  AttrRequestedAddressFamily,
		Value: []byte{},
	}
	result := a.String("")
	if !strings.Contains(result, "invalid") {
		t.Errorf("expected 'invalid' for empty address family, got %q", result)
	}
}

func TestAttributeStringRequestedTransportShort(t *testing.T) {
	t.Parallel()

	// Single-byte value must not panic (REQUESTED-TRANSPORT requires 4 bytes: 1 protocol byte + 3 reserved)
	a := Attribute{
		Type:  AttrRequestedTransport,
		Value: []byte{0x11},
	}
	result := a.String("")
	if !strings.Contains(result, "invalid") {
		t.Errorf("expected 'invalid' for short transport, got %q", result)
	}
}
