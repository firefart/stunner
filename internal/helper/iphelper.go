package helper

import (
	"fmt"
	"net/netip"
	"strings"
)

var PrivateRanges = []string{
	"127.0.0.1/32",
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
}

type IP struct {
	IP    netip.Addr
	Error error
}

func IPIterator(ranges []string) <-chan IP {
	c := make(chan IP)
	go func() {
		defer close(c)
		for _, ipRange := range ranges {
			if strings.Contains(ipRange, "/") {
				// CIDR
				prefix, err := netip.ParsePrefix(ipRange)
				if err != nil {
					c <- IP{Error: err}
					continue
				}
				GenerateSinglePrivateIPs(prefix, c)
			} else {
				tmp, err := netip.ParseAddr(ipRange)
				if err != nil {
					c <- IP{Error: fmt.Errorf("Invalid IP %s: %w", ipRange, err)}
					continue
				}
				c <- IP{IP: tmp}
			}
		}
	}()
	return c
}

func GenerateSinglePrivateIPs(prefix netip.Prefix, c chan<- IP) {
	ip := prefix.Addr()
	for {
		// loop until ip is out of range
		if !prefix.Contains(ip) {
			return
		}
		c <- IP{IP: ip}
		ip = ip.Next()
	}
}
