package internal

// BindingRequest returns a request for the BINDING method
func BindingRequest() *Stun {
	s := newStun()
	s.Header.MessageType = MessageType{
		Class:  MsgTypeClassRequest,
		Method: MsgTypeMethodBinding,
	}

	return s
}
