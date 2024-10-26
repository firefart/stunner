package internal

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func TestFromBytes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		testName string
		input    string
	}{
		{"Allocate Request", "000300102112a442dca12e20d9251238502b86ac0019000411000000000d000400000320"},
		{"Allocate Error Response", "011300402112a442dca12e20d9251238502b86ac0009001000000401556e617574686f72697a6564001500103164393836623466373632633436306400140009736c61636b2e636f6df84f66802200044e6f6e65"},
		{"Allocate Success", "010300402112a442dca12e20d9251238502b86ac001600080001fb862b33a419002000080001e51c0f190adb000d000400000320802200044e6f6e6500080014537f619e9bd4f5b2f4a1d81001fe0dd1fa5c1d0d"},
		{"Send Indication", "001600382112a442dca12e20d9251238502b86ac00120008000121275e12a443001300258c550100000100000000000008636c69656e74733506676f6f676c6503636f6d0000010001000000"},
		{"Allocate Request TCP", "000300102112a442cf513b99ab329be6bb1a7d3e0019000406000000000d000400000320"},
		{"Connect Response", "010a00202112a442cf513b99ab329be6bb1a7d3e002a000435d8cb0d000800143519a43cda074bbbb61ac44342a0618ee9583817"},
	}
	for _, tt := range tests {
		tt := tt // NOTE: https://github.com/golang/go/wiki/CommonMistakes#using-goroutines-on-loop-iterator-variables
		t.Run(tt.testName, func(t *testing.T) {
			t.Parallel()
			in, err := hex.DecodeString(tt.input)
			if err != nil {
				t.Fatalf("invalid input on %s: %v", tt.testName, err)
			}
			s, err := fromBytes(in)
			if err != nil {
				t.Fatalf("could not parse paket: %v", err)
			}
			fmt.Printf("%+v\n", s)
			if s.Header.TransactionID == "" {
				t.Fatal("transaction id is empty")
			}
		})
	}
}

func TestFromBytesFail(t *testing.T) {
	t.Parallel()

	tests := []struct {
		testName string
		input    string
	}{
		{"Fails on an invalid message", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		{"Fails on short message", "aa"},
		{"Fails on empty message", ""},
		{"Fails on an invalid message (invalid attribute size)", "01130aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
	}
	for _, tt := range tests {
		tt := tt // NOTE: https://github.com/golang/go/wiki/CommonMistakes#using-goroutines-on-loop-iterator-variables
		t.Run(tt.testName, func(t *testing.T) {
			t.Parallel()
			in, err := hex.DecodeString(tt.input)
			if err != nil {
				t.Fatalf("invalid input on %s: %v", tt.testName, err)
			}
			_, err = fromBytes(in)
			if err == nil {
				t.Fatal("should have gotten an error")
			}
		})
	}
}
