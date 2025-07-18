package internal

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/firefart/stunner/internal/helper"
)

// newStun creates a new STUN object
func newStun() *Stun {
	return &Stun{
		Header: Header{
			TransactionID: helper.RandomString(12),
		},
	}
}

// GetErrorString returns the error string from the Error Attribute if present
func (s *Stun) GetErrorString() string {
	for _, a := range s.Attributes {
		if a.Type == AttrErrorCode {
			attrError := ParseError(a.Value)
			// update error text if server did not provide one
			if len(strings.TrimSpace(attrError.ErrorText)) == 0 {
				if tmp, ok := StunErrorNames[attrError.ErrorCode]; ok {
					attrError.ErrorText = tmp
				} else if tmp, ok := TurnErrorNames[attrError.ErrorCode]; ok {
					attrError.ErrorText = tmp
				} else if tmp, ok := TurnTCPErrorNames[attrError.ErrorCode]; ok {
					attrError.ErrorText = tmp
				} else {
					attrError.ErrorText = "Invalid Error"
				}
			}
			return fmt.Sprintf("Error %d: %s", attrError.ErrorCode, attrError.ErrorText)
		}
	}
	return ""
}

// String returns a printable representation of the object
func (s *Stun) String() string {
	str := ""
	str += "Header:\n"
	str += fmt.Sprintf("\tMessage Type: %s(%02x) %s(%02x)\n", MessageTypeMethodString(s.Header.MessageType.Method), s.Header.MessageType.Method, MessageTypeClassString(s.Header.MessageType.Class), s.Header.MessageType.Class)
	str += fmt.Sprintf("\tMessage Length: %d\n", s.Header.MessageLength)
	str += fmt.Sprintf("\tMessage Transaction ID: %02x\n", s.Header.TransactionID)
	str += "Attributes\n"
	for _, a := range s.Attributes {
		str += fmt.Sprintf("\t%s\n", a.String(s.Header.TransactionID))
	}
	return strings.TrimSpace(str)
}

// Serialize converts the object into a byte stream
func (s *Stun) Serialize() ([]byte, error) {
	// first start with the attributes so we can calculate the message length afterward
	var attributes []byte
	authenticated := false
	for _, a := range s.Attributes {
		attributeByte := a.Serialize()
		attributes = append(attributes, attributeByte...)
		if a.Type == AttrUsername {
			authenticated = true
		}
	}

	integrityPos := len(attributes)
	if authenticated {
		attributes = append(attributes, helper.PutUint16(AttrMessageIntegrity.Value())...)
		attributes = append(attributes, helper.PutUint16(messageIntegritySize)...)
		// dummy data, will be replaced later after calculating the main header
		attributes = append(attributes, []byte("_DUMMYDATADUMMYDATA_")...)
	}

	// fingerprintPos := len(attributes)
	// attributes = append(attributes, PutUint16(AttrFingerprint.Value())...)
	// attributes = append(attributes, PutUint16(fingerPrintSize)...)
	// attributes = append(attributes, []byte("!!!!")...)

	var buf []byte
	buf = append(buf, s.Header.MessageType.Serialize()...)
	// Length
	buf = append(buf, helper.PutUint16(uint16(len(attributes)))...) // nolint:gosec
	// MagicCookie
	buf = append(buf, MagicCookie...)
	if s.Header.TransactionID == "" {
		return nil, errors.New("missing transaction ID")
	}
	buf = append(buf, s.Header.TransactionID...)

	buf = append(buf, attributes...)

	if authenticated {
		realm := string(s.GetAttribute(AttrRealm).Value)
		// update message integrity
		// buffer needs to be without message integrity and fingerprint, but the length needs to be correct
		messageInt, err := calculateMessageIntegrity(buf[:integrityPos+headerSize], s.Username, realm, s.Password)
		if err != nil {
			return nil, err
		}
		buf = bytes.ReplaceAll(buf, []byte("_DUMMYDATADUMMYDATA_"), messageInt)
	}

	// Fingerprint
	// fingerPrint := generateFingerprint(buf[:fingerprintPos+headerSize])
	// buf = bytes.ReplaceAll(buf, []byte("!!!!"), fingerPrint)

	// trim buffer
	return buf, nil
}

// GetAttribute gets a single Attribute. Returns an empty Attribute if not found
func (s *Stun) GetAttribute(attr AttributeType) Attribute {
	for _, a := range s.Attributes {
		if a.Type == attr {
			return a
		}
	}
	return Attribute{}
}
