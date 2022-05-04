package helper

import (
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

var ErrTimeout = errors.New("timeout occurred. you can try to increase the timeout if the server responds too slowly")

// ConnectionRead reads all data from a connection
func ConnectionRead(conn net.Conn, timeout time.Duration) ([]byte, error) {
	var ret []byte

	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, fmt.Errorf("could not set read deadline: %w", err)
	}

	bufLen := 1024
	for {
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

// ConnectionWrite makes sure to write all data to a connection
func ConnectionWrite(conn net.Conn, data []byte, timeout time.Duration) error {
	toWriteLeft := len(data)
	written := 0
	err := conn.SetWriteDeadline(time.Now().Add(timeout))
	if err != nil {
		return fmt.Errorf("could not set write deadline: %w", err)
	}

	for {
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
