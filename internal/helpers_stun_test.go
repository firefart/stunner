package internal

import (
	"bytes"
	"testing"
)

func TestPadding(t *testing.T) {
	t.Parallel()

	tests := []struct {
		testName    string
		inputLen    int
		expectedLen int
	}{
		{"Does not pad an empty array", 0, 0},
		{"Pads a 3 byte string", 3, 4},
		{"Pads a 5 byte string", 5, 8},
		{"Does not pad a 4 byte string", 4, 4},
		{"Does not pad a 32 byte string", 32, 32},
	}
	for _, tt := range tests {
		tt := tt // NOTE: https://github.com/golang/go/wiki/CommonMistakes#using-goroutines-on-loop-iterator-variables
		t.Run(tt.testName, func(t *testing.T) {
			t.Parallel()
			input := bytes.Repeat([]byte{1}, tt.inputLen)
			output := Padding(input)
			if len(output) != tt.expectedLen {
				t.Errorf("Expected %d got %d", tt.expectedLen, len(output))
			}
		})
	}
}
