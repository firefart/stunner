package internal

import (
	"bytes"
	"testing"
)

func TestExtractChannelData(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		input         []byte
		wantChannel   []byte
		wantData      []byte
		wantErrSubstr string
	}{
		{
			name:        "valid packet",
			input:       []byte{0x40, 0x01, 0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF},
			wantChannel: []byte{0x40, 0x01},
			wantData:    []byte{0xDE, 0xAD, 0xBE, 0xEF},
		},
		{
			name:          "too short (3 bytes)",
			input:         []byte{0x40, 0x01, 0x00},
			wantErrSubstr: "invalid buf len",
		},
		{
			name:          "empty input",
			input:         []byte{},
			wantErrSubstr: "invalid buf len",
		},
		{
			name: "length mismatch",
			// Channel=0x4001, declared length=10 but only 4 bytes of data
			input:         []byte{0x40, 0x01, 0x00, 0x0A, 0xDE, 0xAD, 0xBE, 0xEF},
			wantErrSubstr: "reported len",
		},
		{
			name:        "zero-length data",
			input:       []byte{0x40, 0x01, 0x00, 0x00},
			wantChannel: []byte{0x40, 0x01},
			wantData:    []byte{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ch, data, err := ExtractChannelData(tt.input)
			if tt.wantErrSubstr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErrSubstr)
				}
				if !bytes.Contains([]byte(err.Error()), []byte(tt.wantErrSubstr)) {
					t.Errorf("expected error %q to contain %q", err.Error(), tt.wantErrSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !bytes.Equal(ch, tt.wantChannel) {
				t.Errorf("channel: expected %02x, got %02x", tt.wantChannel, ch)
			}
			if !bytes.Equal(data, tt.wantData) {
				t.Errorf("data: expected %02x, got %02x", tt.wantData, data)
			}
		})
	}
}
