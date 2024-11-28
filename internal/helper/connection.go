package helper

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

var ErrTimeout = errors.New("timeout occurred. you can try to increase the timeout if the server responds too slowly")

// ConnectionReadAll reads all data from a connection
func ConnectionReadAll(ctx context.Context, conn net.Conn, timeout time.Duration) ([]byte, error) {
	// need this otherwise the read call is blocking forever
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, fmt.Errorf("could not set read deadline: %v", err)
	}
	return connectionRead(ctx, bufio.NewReader(conn), nil, timeout)
}

// ConnectionRead reads the data from the connection up to maxSizeToRead
func ConnectionRead(ctx context.Context, r *bufio.Reader, maxSizeToRead int, timeout time.Duration) ([]byte, error) {
	return connectionRead(ctx, r, &maxSizeToRead, timeout)
}

func connectionRead(ctx context.Context, r *bufio.Reader, maxSizeToRead *int, timeout time.Duration) ([]byte, error) {
	var ret []byte

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	bufLen := 1024
	if maxSizeToRead != nil && *maxSizeToRead < bufLen {
		bufLen = *maxSizeToRead
	}

	buf := make([]byte, bufLen)
	alreadyRead := 0
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
			i, err := r.Read(buf)
			if err != nil {
				if err != io.EOF {
					// also return read data on timeout so caller can use it
					var netErr net.Error
					if errors.As(err, &netErr) && netErr.Timeout() {
						return ret, ErrTimeout
					}
					return nil, err
				}
				return ret, nil
			}
			alreadyRead += i
			ret = append(ret, buf[:i]...)
			// we've read all data, bail out
			if i < bufLen || (maxSizeToRead != nil && (alreadyRead >= *maxSizeToRead)) {
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

	// need this otherwise the read call is blocking forever
	if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return fmt.Errorf("could not set write deadline: %v", err)
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			written, err = conn.Write(data[written:toWriteLeft])
			if err != nil {
				var netErr net.Error
				if errors.As(err, &netErr) && netErr.Timeout() {
					return ErrTimeout
				}
			}
			if written == toWriteLeft {
				return nil
			}
			toWriteLeft -= written
		}
	}
}
