package internal

import (
	"encoding/hex"
	"net/netip"
	"testing"
)

func TestParseMappedAddress(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    []byte
		wantIP   string
		wantPort uint16
		wantErr  bool
	}{
		{
			name:     "IPv4 0.0.0.0:80",
			input:    []byte{0x00, 0x01, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00},
			wantIP:   "0.0.0.0",
			wantPort: 80,
		},
		{
			name:     "IPv4 127.0.0.1:443",
			input:    []byte{0x00, 0x01, 0x01, 0xBB, 127, 0, 0, 1},
			wantIP:   "127.0.0.1",
			wantPort: 443,
		},
		{
			name:    "too short (4 bytes)",
			input:   []byte{0x00, 0x01, 0x00, 0x50},
			wantErr: true,
		},
		{
			name:    "empty",
			input:   []byte{},
			wantErr: true,
		},
		{
			name:    "invalid family",
			input:   []byte{0x00, 0x03, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ip, port, err := ParseMappedAdress(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ip.String() != tt.wantIP {
				t.Errorf("IP: expected %q, got %q", tt.wantIP, ip.String())
			}
			if port != tt.wantPort {
				t.Errorf("port: expected %d, got %d", tt.wantPort, port)
			}
		})
	}
}

func TestXorAddrIPv6Length(t *testing.T) {
	t.Parallel()

	result, err := xorAddr(netip.MustParseAddr("::1"), 80, []byte("ASDFASDFASDF"))
	if err != nil {
		t.Fatalf("xorAddr IPv6: %v", err)
	}
	// family(2) + port(2) + IPv6 addr(16) = 20 bytes
	if len(result) != 20 {
		t.Errorf("expected 20 bytes for IPv6 XOR addr, got %d", len(result))
	}
	if result[0] != 0x00 || result[1] != 0x02 {
		t.Errorf("expected family [00 02] for IPv6, got [%02x %02x]", result[0], result[1])
	}
}

func TestXorAddrInvalidIP(t *testing.T) {
	t.Parallel()

	_, err := xorAddr(netip.Addr{}, 80, []byte("ASDF"))
	if err == nil {
		t.Error("expected error for invalid IP")
	}
}

func TestXorAddr(t *testing.T) {
	t.Parallel()
	// IPv4 127.0.0.1:22
	expected := "000121045e12a443"
	x, err := xorAddr(netip.MustParseAddr("127.0.0.1"), 22, []byte("ASDF"))
	if err != nil {
		t.Error(err)
	}
	h := hex.EncodeToString(x)
	if h != expected {
		t.Errorf("expected %q, got %q", expected, h)
	}
}

func TestConvertXORAddr(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input         string
		transactionID string
		expectedHost  string
		expectedPort  uint16
	}{
		{"000121422112a442", "ASDF", "0.0.0.0", 80},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			t.Parallel()
			in, err := hex.DecodeString(tt.input)
			if err != nil {
				t.Fatalf("invalid input %s: %v", tt.input, err)
			}
			host, port, err := ConvertXORAddr(in, tt.transactionID)
			if err != nil {
				t.Fatalf("could not convert xor %s: %v", tt.input, err)
			}
			if host != tt.expectedHost {
				t.Errorf("Host: expected %q but got %q", tt.expectedHost, host)
			}
			if port != tt.expectedPort {
				t.Errorf("Port: expected %d but got %d", tt.expectedPort, port)
			}
		})
	}
}
