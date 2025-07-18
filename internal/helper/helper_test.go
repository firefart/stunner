package helper

import "testing"

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
