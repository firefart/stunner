package internal

import (
	"encoding/binary"
	"fmt"
)

// fromBytes creates a STUN object from a byte slice
func fromBytes(data []byte) (*Stun, error) {
	t := new(Stun)
	if len(data) < headerSize {
		return nil, fmt.Errorf("invalid turn packet. Packet Data: %s", string(data))
	}
	headerRaw := data[0:headerSize]
	t.Header = parseHeader(headerRaw)
	expectedPacketSize := int(t.Header.MessageLength) + headerSize
	if expectedPacketSize != len(data) {
		extraData := ""
		if expectedPacketSize < len(data) {
			extraData = string(data[expectedPacketSize:])
		}
		return nil, fmt.Errorf("attribute message size (%d) missmatch to received data (%d). extra data: %s", expectedPacketSize, len(data), extraData)
	}
	attributesRaw := data[headerSize:expectedPacketSize]
	t.Attributes = parseAttributes(attributesRaw)
	return t, nil
}

func parseHeader(header []byte) Header {
	parsedHeader := Header{
		MessageType:   parseSTUNMessageType(header[:2]),
		MessageLength: binary.BigEndian.Uint16(header[2:4]),
		TransactionID: string(header[8:20]),
	}
	return parsedHeader
}

func parseSTUNMessageType(msgType []byte) MessageType {
	buf := binary.BigEndian.Uint16(msgType)
	// Example: 0x0113 = Allocate Error Response (Class 3 and Method 3)
	// 0x0113 --> 0000 0001 0001 0011
	// 0x0010 --> 0000 0000 0001 0000 --> Get Error Bit
	// 0x0100 --> 0000 0001 0000 0000 --> Get Error Bit
	//        --> 0000 0000 0000 0011 --> 3
	class := ((buf & 0x0010) >> 4) | ((buf & 0x0100) >> 7)
	// Example: 0x0113 = Allocate Error Response (Class 3 and Method 3)
	// 0x0113 --> 0000 0001 0001 0011
	// 0x000F --> 0000 0000 0000 1111 --> Get last 4 bit
	// 0x00E0 --> 0000 0000 1110 0000 --> Get next 3 bits
	// 0x3E00 --> 0011 1110 0000 0000 --> Get next bits
	//        --> 0000 0000 0000 0011 --> 3
	method := (buf & 0x000F) | ((buf & 0x00E0) >> 1) | ((buf & 0x3E00) >> 2)
	return MessageType{
		Class:  MessageTypeClass(class), // nolint:gosec
		Method: MessageTypeMethod(method),
	}
}

func parseAttributes(attributes []byte) []Attribute {
	var attrs []Attribute
	if len(attributes) == 0 {
		return attrs
	}
	attrsRemaining := true
	inLength := len(attributes)
	var bufPos uint16
	for attrsRemaining {
		attr := Attribute{}
		attr.Type = AttributeType(binary.BigEndian.Uint16(attributes[bufPos : 2+bufPos]))
		bufPos += 2
		attr.Length = binary.BigEndian.Uint16(attributes[bufPos : 2+bufPos])
		bufPos += 2
		attr.Value = attributes[bufPos : attr.Length+bufPos]
		bufPos += attr.Length
		// Padding
		if rem := bufPos % 4; rem != 0 {
			attr.padding = 4 - rem
			bufPos += attr.padding
		}
		if int(bufPos) >= inLength {
			attrsRemaining = false
		}
		attrs = append(attrs, attr)
	}
	return attrs
}
