package internal

func MessageTypeMethodString(s MessageTypeMethod) string {
	str, ok := msgTypeMethodNames[s]
	if ok {
		return str
	}
	str, ok = turnMsgTypeMethodNames[s]
	if ok {
		return str
	}
	str, ok = turnTCPMsgTypeMethodNames[s]
	if ok {
		return str
	}
	return ""
}

func MessageTypeClassString(s MessageTypeClass) string {
	str, ok := msgTypeClassNames[s]
	if ok {
		return str
	}
	return ""
}

func AttributeTypeString(a AttributeType) string {
	str, ok := attrNames[a]
	if ok {
		return str
	}
	str, ok = turnAttrNames[a]
	if ok {
		return str
	}
	str, ok = turnTCPAttrNames[a]
	if ok {
		return str
	}
	return ""
}

func RequestedTransportString(r RequestedTransport) string {
	str, ok := requestedTransportNames[r]
	if ok {
		return str
	}
	return ""
}

func RequestedAddressFamilyString(r AllocateProtocol) string {
	str, ok := allocateProtocolNames[r]
	if ok {
		return str
	}
	return ""
}
