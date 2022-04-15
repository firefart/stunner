package internal

import (
	"encoding/binary"
	"fmt"
)

// ExtractChannelData extracts the channel and length from a UDP data packet
func ExtractChannelData(buf []byte) ([]byte, []byte, error) {
	if len(buf) < 4 {
		return nil, nil, fmt.Errorf("invalid buf len %d", len(buf))
	}
	channelNumber := buf[:2]
	dataLength := binary.BigEndian.Uint16(buf[2:4])
	data := buf[4:]
	if int(dataLength) != len(data) {
		return nil, nil, fmt.Errorf("reported len %d different from sent length %d", dataLength, len(data))
	}
	return channelNumber, data, nil
}
