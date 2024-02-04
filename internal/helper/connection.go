package helper

import (
	"context"
	"errors"
	"io"
	"net"
	"time"
)

var ErrTimeout = errors.New("timeout occurred. you can try to increase the timeout if the server responds too slowly")

// ConnectionRead reads all data from a connection
func ConnectionRead(ctx context.Context, conn net.Conn, timeout time.Duration) ([]byte, error) {
	var ret []byte

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	bufLen := 1024
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
			buf := make([]byte, bufLen)
			i, err := conn.Read(buf)
			if err != nil {
				if err != io.EOF {
					// also return read data on timeout so caller can use it
					if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
						return ret, ErrTimeout
					}
					return nil, err
				}
				return ret, nil
			}
			ret = append(ret, buf[:i]...)
			// we've read all data, bail out
			if i < bufLen {
				return ret, nil
			}
		}
	}
}

// ConnectionWrite makes sure to write all data to a connection
func ConnectionWrite(ctx context.Context, conn net.Conn, data []byte, timeout time.Duration) error {
	toWriteLeft := len(data)
	written := 0
	var err error

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			written, err = conn.Write(data[written:toWriteLeft])
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					return ErrTimeout
				} else {
					return err
				}
			}
			if written == toWriteLeft {
				return nil
			}
			toWriteLeft -= written
		}
	}
}
