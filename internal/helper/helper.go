package helper

import (
	cryptorand "crypto/rand"
	"encoding/binary"
	"math/rand/v2"
	"net/netip"
	"unicode"
)

var printRanges = []*unicode.RangeTable{
	unicode.L, unicode.M, unicode.N, unicode.P, unicode.Z,
}

// IsPrintable returns true if the string only contains printable characters
func IsPrintable(s string) bool {
	for _, r := range s {
		if !unicode.IsOneOf(printRanges, r) {
			return false
		}
	}
	return true
}

// RandomString generates a random string of specified length
func RandomString(length int) string {
	letterRunes := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	b := make([]rune, length)
	for i := range b {
		b[i] = letterRunes[rand.IntN(len(letterRunes))] // nolint: gosec
	}
	return string(b)
}

func IsPrivateIP(ip netip.Addr) bool {
	if ip.IsGlobalUnicast() || ip.IsInterfaceLocalMulticast() ||
		ip.IsLinkLocalMulticast() || ip.IsLinkLocalUnicast() ||
		ip.IsLoopback() || ip.IsMulticast() || ip.IsPrivate() ||
		ip.IsUnspecified() {
		return true
	}

	return false
}

// RandomChannelNumber generates a random valid channel number
// 0x4000 through 0x7FFF: These values are the allowed channel
// numbers (16,383 possible values).
func RandomChannelNumber() ([]byte, error) {
	token := make([]byte, 2)
	for {
		if _, err := cryptorand.Read(token); err != nil {
			return nil, err
		}
		if token[0] >= 0x40 &&
			token[0] <= 0x7f {
			break
		}
	}
	return token, nil
}

// PutUint16 is a helper function to convert an uint16 to a buffer
func PutUint16(v uint16) []byte {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, v)
	return buf
}

// PutUint32 is a helper function to convert an uint32 to a buffer
func PutUint32(v uint32) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, v)
	return buf
}
