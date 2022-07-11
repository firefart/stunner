package internal

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// AllocateRequest returns an ALLOCATE request
func AllocateRequest(targetProtocol RequestedTransport, allocateProtcol AllocateProtocol) *Stun {
	transport := make([]byte, 4)
	binary.LittleEndian.PutUint32(transport, uint32(targetProtocol))

	s := newStun()

	s.Header.MessageType = MessageType{
		Class:  MsgTypeClassRequest,
		Method: MsgTypeMethodAllocate,
	}

	s.Attributes = []Attribute{{
		Type:  AttrRequestedTransport,
		Value: transport,
	}}

	if allocateProtcol != AllocateProtocolIgnore {
		s.Attributes = append(s.Attributes, Attribute{
			Type:  AttrRequestedAddressFamily,
			Value: []byte{byte(allocateProtcol), 0x00, 0x00, 0x00, 0x00},
		})
	}

	return s
}

// AllocateRequestAuth returns an authenticated ALLOCATE request
func AllocateRequestAuth(username, password, nonce, realm string, targetProtocol RequestedTransport, allocateProtcol AllocateProtocol) *Stun {
	transport := make([]byte, 4)
	binary.LittleEndian.PutUint32(transport, uint32(targetProtocol))

	s := newStun()
	s.Username = username
	s.Password = password
	s.Header.MessageType = MessageType{
		Class:  MsgTypeClassRequest,
		Method: MsgTypeMethodAllocate,
	}

	s.Attributes = []Attribute{{
		Type:  AttrRequestedTransport,
		Value: transport,
	}, {
		Type:  AttrUsername,
		Value: []byte(username),
	}, {
		Type:  AttrRealm,
		Value: []byte(realm),
	}, {
		Type:  AttrNonce,
		Value: []byte(nonce),
	},
	}

	if allocateProtcol != AllocateProtocolIgnore {
		s.Attributes = append(s.Attributes, Attribute{
			Type:  AttrRequestedAddressFamily,
			Value: []byte{byte(allocateProtcol), 0x00, 0x00, 0x00, 0x00},
		})
	}

	return s
}

// SendRequest returns a SEND request
func SendRequest(target netip.Addr, port uint16) (*Stun, error) {
	s := newStun()
	targetXOR, err := xorAddr(target, port, []byte(s.Header.TransactionID))
	if err != nil {
		return nil, err
	}

	s.Header.MessageType = MessageType{
		Class:  MsgTypeClassRequest,
		Method: MsgTypeMethodSend,
	}

	s.Attributes = []Attribute{{
		Type:  AttrXorPeerAddress,
		Value: targetXOR,
	}, {
		Type:  AttrData,
		Value: []byte("pwned by firefart\n"),
	},
	}

	return s, nil
}

// CreatePermissionRequest returns a CREATE PERMISSION request
func CreatePermissionRequest(username, password, nonce, realm string, target netip.Addr, port uint16) (*Stun, error) {
	s := newStun()
	targetXOR, err := xorAddr(target, port, []byte(s.Header.TransactionID))
	if err != nil {
		return nil, err
	}

	s.Username = username
	s.Password = password
	s.Header.MessageType = MessageType{
		Class:  MsgTypeClassRequest,
		Method: MsgTypeMethodCreatePermission,
	}

	s.Attributes = []Attribute{{
		Type:  AttrXorPeerAddress,
		Value: targetXOR,
	}, {
		Type:  AttrUsername,
		Value: []byte(username),
	}, {
		Type:  AttrRealm,
		Value: []byte(realm),
	}, {
		Type:  AttrNonce,
		Value: []byte(nonce),
	},
	}

	return s, nil
}

// ChannelBindRequest returns a CHANNEL BIND request
func ChannelBindRequest(username, password, nonce, realm string, target netip.Addr, port uint16, channelNumber []byte) (*Stun, error) {
	s := newStun()
	targetXOR, err := xorAddr(target, port, []byte(s.Header.TransactionID))
	if err != nil {
		return nil, err
	}

	if len(channelNumber) != 2 {
		return nil, fmt.Errorf("need a 2 byte channel number, got %02x", channelNumber)
	}

	s.Username = username
	s.Password = password
	s.Header.MessageType = MessageType{
		Class:  MsgTypeClassRequest,
		Method: MsgTypeMethodChannelbind,
	}

	s.Attributes = []Attribute{{
		Type:  AttrChannelNumber,
		Value: append(channelNumber, []byte{0x00, 0x00}...),
	}, {
		Type:  AttrXorPeerAddress,
		Value: targetXOR,
	}, {
		Type:  AttrUsername,
		Value: []byte(username),
	}, {
		Type:  AttrRealm,
		Value: []byte(realm),
	}, {
		Type:  AttrNonce,
		Value: []byte(nonce),
	},
	}

	return s, nil
}

// RefreshRequest returns a REFRESH request
func RefreshRequest(username, password, nonce, realm string) *Stun {
	s := newStun()
	s.Username = username
	s.Password = password
	s.Header.MessageType = MessageType{
		Class:  MsgTypeClassRequest,
		Method: MsgTypeMethodRefresh,
	}

	s.Attributes = []Attribute{{
		Type:  AttrUsername,
		Value: []byte(username),
	}, {
		Type:  AttrRealm,
		Value: []byte(realm),
	}, {
		Type:  AttrNonce,
		Value: []byte(nonce),
	},
	}

	return s
}
