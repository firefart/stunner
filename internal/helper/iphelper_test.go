package helper

import (
	"net/netip"
	"testing"
)

func TestIPIteratorSingleIP(t *testing.T) {
	t.Parallel()

	ch := IPIterator([]string{"10.0.0.1"})
	var got []netip.Addr
	for ip := range ch {
		if ip.Error != nil {
			t.Fatalf("unexpected error: %v", ip.Error)
		}
		got = append(got, ip.IP)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 IP, got %d", len(got))
	}
	if got[0].String() != "10.0.0.1" {
		t.Errorf("expected 10.0.0.1, got %s", got[0].String())
	}
}

func TestIPIteratorCIDR(t *testing.T) {
	t.Parallel()

	// /30 has 4 addresses: .0, .1, .2, .3
	ch := IPIterator([]string{"192.168.0.0/30"})
	var count int
	for ip := range ch {
		if ip.Error != nil {
			t.Fatalf("unexpected error: %v", ip.Error)
		}
		count++
	}
	if count != 4 {
		t.Errorf("expected 4 IPs for /30, got %d", count)
	}
}

func TestIPIteratorInvalidInput(t *testing.T) {
	t.Parallel()

	ch := IPIterator([]string{"not-an-ip"})
	var errCount int
	for ip := range ch {
		if ip.Error != nil {
			errCount++
		}
	}
	if errCount == 0 {
		t.Error("expected at least one error for invalid IP input")
	}
}

func TestIPIteratorInvalidCIDR(t *testing.T) {
	t.Parallel()

	ch := IPIterator([]string{"999.999.999.999/24"})
	var errCount int
	for ip := range ch {
		if ip.Error != nil {
			errCount++
		}
	}
	if errCount == 0 {
		t.Error("expected error for invalid CIDR input")
	}
}

func TestIPIteratorEmpty(t *testing.T) {
	t.Parallel()

	ch := IPIterator([]string{})
	var count int
	for range ch {
		count++
	}
	if count != 0 {
		t.Errorf("expected 0 IPs for empty input, got %d", count)
	}
}

func TestIPIteratorMixed(t *testing.T) {
	t.Parallel()

	// Single IP + /30 CIDR → 1 + 4 = 5 addresses
	ch := IPIterator([]string{"10.0.0.5", "10.0.1.0/30"})
	var count int
	for ip := range ch {
		if ip.Error != nil {
			t.Fatalf("unexpected error: %v", ip.Error)
		}
		count++
	}
	if count != 5 {
		t.Errorf("expected 5 IPs, got %d", count)
	}
}

func TestGenerateSinglePrivateIPs(t *testing.T) {
	t.Parallel()

	prefix := netip.MustParsePrefix("10.0.0.0/30") // 4 addresses
	c := make(chan IP, 10)
	go func() {
		GenerateSinglePrivateIPs(prefix, c)
		close(c)
	}()

	var ips []netip.Addr
	for ip := range c {
		ips = append(ips, ip.IP)
	}
	if len(ips) != 4 {
		t.Errorf("expected 4 IPs for /30, got %d", len(ips))
	}
	if ips[0].String() != "10.0.0.0" {
		t.Errorf("first IP: expected 10.0.0.0, got %s", ips[0].String())
	}
	if ips[3].String() != "10.0.0.3" {
		t.Errorf("last IP: expected 10.0.0.3, got %s", ips[3].String())
	}
}
