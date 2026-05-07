package internal

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// fromBytes creates a STUN object from a byte slice
func fromBytes(data []byte) (*Stun, error) {
	t := new(Stun)
	if len(data) < headerSize {
		return nil, fmt.Errorf("invalid turn packet. Packet Data: %s", string(data))
	}
	// RFC 5389 §6: top two bits of the first byte must be zero
	if data[0]&0xC0 != 0 {
		return nil, fmt.Errorf("invalid STUN packet: top two bits must be zero, got %02x", data[0])
	}
	// RFC 5389 §6: magic cookie must be 0x2112A442
	if !bytes.Equal(data[4:8], MagicCookie) {
		return nil, fmt.Errorf("invalid STUN packet: missing magic cookie, got %02x", data[4:8])
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
	inLength := len(attributes)
	bufPos := 0
	for bufPos < inLength {
		// Need at least 4 bytes for the type and length fields
		if bufPos+4 > inLength {
			break
		}
		attr := Attribute{}
		attr.Type = AttributeType(binary.BigEndian.Uint16(attributes[bufPos : bufPos+2]))
		bufPos += 2
		attr.Length = binary.BigEndian.Uint16(attributes[bufPos : bufPos+2])
		bufPos += 2
		end := bufPos + int(attr.Length)
		if end > inLength {
			break
		}
		attr.Value = attributes[bufPos:end]
		bufPos = end
		// Padding to 4-byte boundary
		if rem := bufPos % 4; rem != 0 {
			padding := 4 - rem
			attr.padding = uint16(padding) // nolint:gosec
			bufPos += padding
		}
		attrs = append(attrs, attr)
	}
	return attrs
}
