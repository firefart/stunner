package internal

import (
	"encoding/hex"
	"net/netip"
	"testing"
)

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
