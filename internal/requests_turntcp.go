package internal

import (
	"net/netip"
)

// ConnectRequest returns a CONNECT request
func ConnectRequest(target netip.Addr, port uint16) (*Stun, error) {
	s := newStun()
	targetXOR, err := xorAddr(target, port, []byte(s.Header.TransactionID))
	if err != nil {
		return nil, err
	}

	s.Header.MessageType = MessageType{
		Class:  MsgTypeClassRequest,
		Method: MsgTypeMethodConnect,
	}

	s.Attributes = []Attribute{
		{
			Type:  AttrXorPeerAddress,
			Value: targetXOR,
		},
	}

	return s, nil
}

// ConnectRequestAuth returns an authorized CONNECT request
func ConnectRequestAuth(username, password, nonce, realm string, target netip.Addr, port uint16) (*Stun, error) {
	s := newStun()
	targetXOR, err := xorAddr(target, port, []byte(s.Header.TransactionID))
	if err != nil {
		return nil, err
	}
	s.Username = username
	s.Password = password
	s.Header.MessageType = MessageType{
		Class:  MsgTypeClassRequest,
		Method: MsgTypeMethodConnect,
	}

	s.Attributes = []Attribute{
		{
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

// ConnectionBindRequest creates a CONNECTION BIND request
func ConnectionBindRequest(connectionID []byte, username, password, nonce, realm string) *Stun {
	s := newStun()
	s.Username = username
	s.Password = password
	s.Header.MessageType = MessageType{
		Class:  MsgTypeClassRequest,
		Method: MsgTypeMethodConnectionBind,
	}

	s.Attributes = []Attribute{
		{
			Type:  AttrConnectionID,
			Value: connectionID,
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

	return s
}
