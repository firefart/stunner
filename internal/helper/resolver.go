package helper

import (
	"context"
	"net"
	"net/netip"
)

// ResolveName resolves a domain name to an IP address
func ResolveName(ctx context.Context, name string) ([]netip.Addr, error) {
	addr, err := net.DefaultResolver.LookupNetIP(ctx, "ip", name)
	if err != nil {
		return []netip.Addr{}, err
	}
	return addr, err
}
