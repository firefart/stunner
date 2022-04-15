package internal

type DebugLogger interface {
	Debugf(format string, args ...interface{})
}
