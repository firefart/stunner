package helper

import (
	"net/netip"
	"testing"
)

func TestRandomChannelNumber(t *testing.T) {
	for range 1000 {
		channel, err := RandomChannelNumber()
		if err != nil {
			t.Fatal(err)
		}
		if channel[0] < 0x40 || channel[0] > 0x7F {
			t.Fail()
		}
	}
}

func TestPutUint16(t *testing.T) {
	t.Parallel()
	out := PutUint16(16)
	if len(out) != 2 {
		t.Error("UINT16 length is not 2")
	}
}

func TestPutUint32(t *testing.T) {
	t.Parallel()
	out := PutUint32(16)
	if len(out) != 4 {
		t.Error("UINT32 length is not 4")
	}
}

func TestIsPrintable(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  bool
	}{
		{"hello", true},
		{"Hello World", true},
		{"test123", true},
		{"", true}, // empty string has no non-printable chars
		{"\x00", false},
		{"\x01\x02\x03", false},
		{"valid\x00mixed", false},
	}
	for _, tt := range tests {
		got := IsPrintable(tt.input)
		if got != tt.want {
			t.Errorf("IsPrintable(%q): expected %v, got %v", tt.input, tt.want, got)
		}
	}
}

func TestRandomStringLength(t *testing.T) {
	t.Parallel()

	for _, length := range []int{0, 1, 5, 12, 32} {
		s := RandomString(length)
		if len(s) != length {
			t.Errorf("RandomString(%d): expected length %d, got %d", length, length, len(s))
		}
	}
}

func TestRandomStringUniqueness(t *testing.T) {
	t.Parallel()

	seen := make(map[string]bool, 100)
	for range 100 {
		s := RandomString(12)
		seen[s] = true
	}
	// With 52^12 possible values, collisions in 100 draws are astronomically unlikely
	if len(seen) < 95 {
		t.Errorf("expected high uniqueness from RandomString, got %d distinct values in 100 draws", len(seen))
	}
}

func TestIsPrivateIP(t *testing.T) {
	t.Parallel()

	// The function checks IsGlobalUnicast, IsLoopback, IsPrivate, and several
	// multicast/link-local categories — anything matching any of those returns true.
	alwaysTrue := []string{
		"127.0.0.1",   // loopback
		"10.0.0.1",    // RFC 1918 private
		"172.16.0.1",  // RFC 1918 private
		"192.168.0.1", // RFC 1918 private
		"::1",         // loopback
		"fe80::1",     // link-local unicast
		"8.8.8.8",     // global unicast (IsGlobalUnicast → true)
		"2001:db8::1", // global unicast
	}
	for _, ipStr := range alwaysTrue {
		ip := netip.MustParseAddr(ipStr)
		if !IsPrivateIP(ip) {
			t.Errorf("IsPrivateIP(%q): expected true, got false", ipStr)
		}
	}
}
