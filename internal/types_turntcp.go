package internal

const (
	// MsgTypeMethodConnect https://tools.ietf.org/html/rfc6062#section-6.1
	MsgTypeMethodConnect MessageTypeMethod = 0x0a
	// MsgTypeMethodConnectionBind https://tools.ietf.org/html/rfc6062#section-6.1
	MsgTypeMethodConnectionBind MessageTypeMethod = 0x0b
	// MsgTypeMethodConnectionAttempt https://tools.ietf.org/html/rfc6062#section-6.1
	MsgTypeMethodConnectionAttempt MessageTypeMethod = 0x0c
)

var turnTCPMsgTypeMethodNames = map[MessageTypeMethod]string{ // nolint:exhaustive
	MsgTypeMethodConnect:           "Connect",
	MsgTypeMethodConnectionBind:    "ConnectionBind",
	MsgTypeMethodConnectionAttempt: "ConnectionAttempt",
}

const (
	// AttrConnectionID https://tools.ietf.org/html/rfc6062#section-6.2.1
	AttrConnectionID AttributeType = 0x002a
)

var turnTCPAttrNames = map[AttributeType]string{ // nolint:exhaustive
	AttrConnectionID: "CONNECTION-ID",
}

const (
	// ErrorConnectionAlreadyExists https://tools.ietf.org/html/rfc6062#section-6.3
	ErrorConnectionAlreadyExists ErrorCode = 446
	// ErrorConnectionTimeoutOrFailure https://tools.ietf.org/html/rfc6062#section-6.3
	ErrorConnectionTimeoutOrFailure ErrorCode = 447
)

var TurnTCPErrorNames = map[ErrorCode]string{ // nolint:exhaustive
	ErrorConnectionAlreadyExists:    "Connection Already Exists",
	ErrorConnectionTimeoutOrFailure: "Connection Timeout or Failure",
}
