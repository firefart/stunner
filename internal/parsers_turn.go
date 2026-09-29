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
	// RFC 5766 §11.5: ChannelData is padded to a 4-byte boundary on both UDP and
	// TCP. The LENGTH field reflects only the application data, not the padding,
	// so len(data) may exceed dataLength by 0-3 bytes.
	if int(dataLength) > len(data) {
		return nil, nil, fmt.Errorf("reported len %d greater than available data %d", dataLength, len(data))
	}

	paddingLen := len(data) - int(dataLength)
	if paddingLen > 3 {
		return nil, nil, fmt.Errorf("invalid ChannelData padding length %d", paddingLen)
	}
	if len(buf)%4 != 0 {
		return nil, nil, fmt.Errorf("invalid ChannelData size %d: not 4-byte aligned", len(buf))
	}

	return channelNumber, data[:dataLength], nil
}
