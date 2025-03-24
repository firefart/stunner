package internal

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"hash/crc32"
)

const (
	fingerprint = 0x5354554e // nolint:unused
)

// Align the uint16 number to the smallest multiple of 4, which is larger than
// or equal to the uint16 number.
func align(n uint16) uint16 {
	return (n + 3) & 0xfffc
}

// Padding handles the padding required for STUN packets
func Padding(bytes []byte) []byte {
	length := uint16(len(bytes))
	return append(bytes, make([]byte, align(length)-length)...)
}

/*
The FINGERPRINT attribute MAY be present in all STUN messages.  The
value of the attribute is computed as the CRC-32 of the STUN message
up to (but excluding) the FINGERPRINT attribute itself, XOR'ed with
the 32-bit value 0x5354554e
*/
// nolint:unused
func generateFingerprint(buf []byte) []byte {
	crc := crc32.ChecksumIEEE(buf) ^ fingerprint
	ret := make([]byte, 4)
	binary.BigEndian.PutUint32(ret, crc)
	return ret
}

func calculateMessageIntegrity(buf []byte, username, realm, password string) ([]byte, error) {
	// key = MD5(username ":" realm ":" SASLprep(password))
	key := fmt.Sprintf("%s:%s:%s", username, realm, password)
	// key := password
	md := md5.New()
	if _, err := md.Write([]byte(key)); err != nil {
		return nil, err
	}
	hmacKey := md.Sum(nil)

	x := hmac.New(sha1.New, hmacKey)
	if _, err := x.Write(buf); err != nil {
		return nil, err
	}
	return x.Sum(nil), nil
}
