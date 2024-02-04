package internal

type DebugLogger interface {
	Debug(...interface{})
	Debugf(format string, args ...interface{})
}
