package cmd

import (
	"net/netip"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

func newTestLogger() *logrus.Logger {
	l := logrus.New()
	l.SetLevel(logrus.PanicLevel) // suppress output in tests
	return l
}

// --- InfoOpts ---

func TestInfoOptsValidate(t *testing.T) {
	t.Parallel()

	log := newTestLogger()
	valid := InfoOpts{TurnServer: "127.0.0.1:3478", Protocol: "udp", Timeout: time.Second, Log: log}

	if err := valid.Validate(); err != nil {
		t.Errorf("expected valid opts to pass, got: %v", err)
	}

	cases := []struct {
		name string
		opts InfoOpts
	}{
		{"empty turnserver", InfoOpts{Protocol: "udp", Log: log}},
		{"no port", InfoOpts{TurnServer: "127.0.0.1", Protocol: "udp", Log: log}},
		{"invalid protocol", InfoOpts{TurnServer: "127.0.0.1:3478", Protocol: "quic", Log: log}},
		{"nil logger", InfoOpts{TurnServer: "127.0.0.1:3478", Protocol: "udp"}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := tt.opts.Validate(); err == nil {
				t.Error("expected validation error, got nil")
			}
		})
	}
}

// --- BruteforceOpts ---

func TestBruteforceOptsValidate(t *testing.T) {
	t.Parallel()

	log := newTestLogger()
	valid := BruteforceOpts{TurnServer: "127.0.0.1:3478", Protocol: "udp", Username: "user", Passfile: "words.txt", Log: log}

	if err := valid.Validate(); err != nil {
		t.Errorf("expected valid opts to pass, got: %v", err)
	}

	cases := []struct {
		name string
		opts BruteforceOpts
	}{
		{"empty turnserver", BruteforceOpts{Protocol: "udp", Username: "u", Passfile: "f", Log: log}},
		{"no port", BruteforceOpts{TurnServer: "127.0.0.1", Protocol: "udp", Username: "u", Passfile: "f", Log: log}},
		{"invalid protocol", BruteforceOpts{TurnServer: "127.0.0.1:3478", Protocol: "quic", Username: "u", Passfile: "f", Log: log}},
		{"empty username", BruteforceOpts{TurnServer: "127.0.0.1:3478", Protocol: "udp", Passfile: "f", Log: log}},
		{"empty passfile", BruteforceOpts{TurnServer: "127.0.0.1:3478", Protocol: "udp", Username: "u", Log: log}},
		{"nil logger", BruteforceOpts{TurnServer: "127.0.0.1:3478", Protocol: "udp", Username: "u", Passfile: "f"}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := tt.opts.Validate(); err == nil {
				t.Error("expected validation error, got nil")
			}
		})
	}
}

// --- BruteTransportOpts ---

func TestBruteTransportOptsValidate(t *testing.T) {
	t.Parallel()

	log := newTestLogger()
	valid := BruteTransportOpts{TurnServer: "127.0.0.1:3478", Protocol: "tcp", Username: "u", Password: "p", Log: log}

	if err := valid.Validate(); err != nil {
		t.Errorf("expected valid opts to pass, got: %v", err)
	}

	cases := []struct {
		name string
		opts BruteTransportOpts
	}{
		{"empty turnserver", BruteTransportOpts{Protocol: "udp", Username: "u", Password: "p", Log: log}},
		{"no port", BruteTransportOpts{TurnServer: "127.0.0.1", Protocol: "udp", Username: "u", Password: "p", Log: log}},
		{"invalid protocol", BruteTransportOpts{TurnServer: "127.0.0.1:3478", Protocol: "sctp", Username: "u", Password: "p", Log: log}},
		{"empty username", BruteTransportOpts{TurnServer: "127.0.0.1:3478", Protocol: "udp", Password: "p", Log: log}},
		{"empty password", BruteTransportOpts{TurnServer: "127.0.0.1:3478", Protocol: "udp", Username: "u", Log: log}},
		{"nil logger", BruteTransportOpts{TurnServer: "127.0.0.1:3478", Protocol: "udp", Username: "u", Password: "p"}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := tt.opts.Validate(); err == nil {
				t.Error("expected validation error, got nil")
			}
		})
	}
}

// --- RangeScanOpts ---

func TestRangeScanOptsValidate(t *testing.T) {
	t.Parallel()

	log := newTestLogger()
	valid := RangeScanOpts{TurnServer: "127.0.0.1:3478", Protocol: "udp", Username: "u", Password: "p", Log: log}

	if err := valid.Validate(); err != nil {
		t.Errorf("expected valid opts to pass, got: %v", err)
	}

	cases := []struct {
		name string
		opts RangeScanOpts
	}{
		{"empty turnserver", RangeScanOpts{Protocol: "udp", Username: "u", Password: "p", Log: log}},
		{"no port", RangeScanOpts{TurnServer: "127.0.0.1", Protocol: "udp", Username: "u", Password: "p", Log: log}},
		{"invalid protocol", RangeScanOpts{TurnServer: "127.0.0.1:3478", Protocol: "grpc", Username: "u", Password: "p", Log: log}},
		{"empty username", RangeScanOpts{TurnServer: "127.0.0.1:3478", Protocol: "udp", Password: "p", Log: log}},
		{"empty password", RangeScanOpts{TurnServer: "127.0.0.1:3478", Protocol: "udp", Username: "u", Log: log}},
		{"nil logger", RangeScanOpts{TurnServer: "127.0.0.1:3478", Protocol: "udp", Username: "u", Password: "p"}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := tt.opts.Validate(); err == nil {
				t.Error("expected validation error, got nil")
			}
		})
	}
}

// --- SocksOpts ---

func TestSocksOptsValidate(t *testing.T) {
	t.Parallel()

	log := newTestLogger()
	valid := SocksOpts{TurnServer: "127.0.0.1:3478", Protocol: "udp", Username: "u", Password: "p", Listen: "127.0.0.1:1080", Log: log}

	if err := valid.Validate(); err != nil {
		t.Errorf("expected valid opts to pass, got: %v", err)
	}

	cases := []struct {
		name string
		opts SocksOpts
	}{
		{"empty turnserver", SocksOpts{Protocol: "udp", Username: "u", Password: "p", Listen: "127.0.0.1:1080", Log: log}},
		{"no port", SocksOpts{TurnServer: "127.0.0.1", Protocol: "udp", Username: "u", Password: "p", Listen: "127.0.0.1:1080", Log: log}},
		{"invalid protocol", SocksOpts{TurnServer: "127.0.0.1:3478", Protocol: "ws", Username: "u", Password: "p", Listen: "127.0.0.1:1080", Log: log}},
		{"empty username", SocksOpts{TurnServer: "127.0.0.1:3478", Protocol: "udp", Password: "p", Listen: "127.0.0.1:1080", Log: log}},
		{"empty password", SocksOpts{TurnServer: "127.0.0.1:3478", Protocol: "udp", Username: "u", Listen: "127.0.0.1:1080", Log: log}},
		{"nil logger", SocksOpts{TurnServer: "127.0.0.1:3478", Protocol: "udp", Username: "u", Password: "p", Listen: "127.0.0.1:1080"}},
		{"empty listen", SocksOpts{TurnServer: "127.0.0.1:3478", Protocol: "udp", Username: "u", Password: "p", Log: log}},
		{"listen no port", SocksOpts{TurnServer: "127.0.0.1:3478", Protocol: "udp", Username: "u", Password: "p", Listen: "127.0.0.1", Log: log}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := tt.opts.Validate(); err == nil {
				t.Error("expected validation error, got nil")
			}
		})
	}
}

// --- TCPScannerOpts ---

func TestTCPScannerOptsValidate(t *testing.T) {
	t.Parallel()

	log := newTestLogger()
	valid := TCPScannerOpts{TurnServer: "127.0.0.1:3478", Protocol: "udp", Username: "u", Password: "p", Ports: []string{"80"}, Log: log}

	if err := valid.Validate(); err != nil {
		t.Errorf("expected valid opts to pass, got: %v", err)
	}

	cases := []struct {
		name string
		opts TCPScannerOpts
	}{
		{"empty turnserver", TCPScannerOpts{Protocol: "udp", Username: "u", Password: "p", Ports: []string{"80"}, Log: log}},
		{"no port", TCPScannerOpts{TurnServer: "127.0.0.1", Protocol: "udp", Username: "u", Password: "p", Ports: []string{"80"}, Log: log}},
		{"invalid protocol", TCPScannerOpts{TurnServer: "127.0.0.1:3478", Protocol: "xyz", Username: "u", Password: "p", Ports: []string{"80"}, Log: log}},
		{"empty username", TCPScannerOpts{TurnServer: "127.0.0.1:3478", Protocol: "udp", Password: "p", Ports: []string{"80"}, Log: log}},
		{"empty password", TCPScannerOpts{TurnServer: "127.0.0.1:3478", Protocol: "udp", Username: "u", Ports: []string{"80"}, Log: log}},
		{"nil logger", TCPScannerOpts{TurnServer: "127.0.0.1:3478", Protocol: "udp", Username: "u", Password: "p", Ports: []string{"80"}}},
		{"empty ports", TCPScannerOpts{TurnServer: "127.0.0.1:3478", Protocol: "udp", Username: "u", Password: "p", Log: log}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := tt.opts.Validate(); err == nil {
				t.Error("expected validation error, got nil")
			}
		})
	}
}

// --- UDPScannerOpts ---

func TestUDPScannerOptsValidate(t *testing.T) {
	t.Parallel()

	log := newTestLogger()
	valid := UDPScannerOpts{TurnServer: "127.0.0.1:3478", Protocol: "udp", Username: "u", Password: "p", CommunityString: "public", DomainName: "example.com", Log: log}

	if err := valid.Validate(); err != nil {
		t.Errorf("expected valid opts to pass, got: %v", err)
	}

	cases := []struct {
		name string
		opts UDPScannerOpts
	}{
		{"empty turnserver", UDPScannerOpts{Protocol: "udp", Username: "u", Password: "p", CommunityString: "public", DomainName: "x.com", Log: log}},
		{"no port", UDPScannerOpts{TurnServer: "127.0.0.1", Protocol: "udp", Username: "u", Password: "p", CommunityString: "public", DomainName: "x.com", Log: log}},
		{"invalid protocol", UDPScannerOpts{TurnServer: "127.0.0.1:3478", Protocol: "dtls", Username: "u", Password: "p", CommunityString: "public", DomainName: "x.com", Log: log}},
		{"empty username", UDPScannerOpts{TurnServer: "127.0.0.1:3478", Protocol: "udp", Password: "p", CommunityString: "public", DomainName: "x.com", Log: log}},
		{"empty password", UDPScannerOpts{TurnServer: "127.0.0.1:3478", Protocol: "udp", Username: "u", CommunityString: "public", DomainName: "x.com", Log: log}},
		{"nil logger", UDPScannerOpts{TurnServer: "127.0.0.1:3478", Protocol: "udp", Username: "u", Password: "p", CommunityString: "public", DomainName: "x.com"}},
		{"empty community", UDPScannerOpts{TurnServer: "127.0.0.1:3478", Protocol: "udp", Username: "u", Password: "p", DomainName: "x.com", Log: log}},
		{"empty domain", UDPScannerOpts{TurnServer: "127.0.0.1:3478", Protocol: "udp", Username: "u", Password: "p", CommunityString: "public", Log: log}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := tt.opts.Validate(); err == nil {
				t.Error("expected validation error, got nil")
			}
		})
	}
}

// --- MemoryleakOpts ---

func TestMemoryleakOptsValidate(t *testing.T) {
	t.Parallel()

	log := newTestLogger()
	valid := MemoryleakOpts{
		TurnServer: "127.0.0.1:3478",
		Protocol:   "udp",
		Username:   "u",
		Password:   "p",
		TargetHost: netip.MustParseAddr("1.2.3.4"),
		TargetPort: 8080,
		Size:       1024,
		Log:        log,
	}

	if err := valid.Validate(); err != nil {
		t.Errorf("expected valid opts to pass, got: %v", err)
	}

	cases := []struct {
		name string
		opts MemoryleakOpts
	}{
		{"empty turnserver", MemoryleakOpts{Protocol: "udp", Username: "u", Password: "p", TargetHost: netip.MustParseAddr("1.2.3.4"), TargetPort: 80, Size: 100, Log: log}},
		{"no port", MemoryleakOpts{TurnServer: "127.0.0.1", Protocol: "udp", Username: "u", Password: "p", TargetHost: netip.MustParseAddr("1.2.3.4"), TargetPort: 80, Size: 100, Log: log}},
		{"invalid protocol", MemoryleakOpts{TurnServer: "127.0.0.1:3478", Protocol: "http", Username: "u", Password: "p", TargetHost: netip.MustParseAddr("1.2.3.4"), TargetPort: 80, Size: 100, Log: log}},
		{"empty username", MemoryleakOpts{TurnServer: "127.0.0.1:3478", Protocol: "udp", Password: "p", TargetHost: netip.MustParseAddr("1.2.3.4"), TargetPort: 80, Size: 100, Log: log}},
		{"empty password", MemoryleakOpts{TurnServer: "127.0.0.1:3478", Protocol: "udp", Username: "u", TargetHost: netip.MustParseAddr("1.2.3.4"), TargetPort: 80, Size: 100, Log: log}},
		{"nil logger", MemoryleakOpts{TurnServer: "127.0.0.1:3478", Protocol: "udp", Username: "u", Password: "p", TargetHost: netip.MustParseAddr("1.2.3.4"), TargetPort: 80, Size: 100}},
		{"invalid target host", MemoryleakOpts{TurnServer: "127.0.0.1:3478", Protocol: "udp", Username: "u", Password: "p", TargetPort: 80, Size: 100, Log: log}},
		{"zero target port", MemoryleakOpts{TurnServer: "127.0.0.1:3478", Protocol: "udp", Username: "u", Password: "p", TargetHost: netip.MustParseAddr("1.2.3.4"), Size: 100, Log: log}},
		{"zero size", MemoryleakOpts{TurnServer: "127.0.0.1:3478", Protocol: "udp", Username: "u", Password: "p", TargetHost: netip.MustParseAddr("1.2.3.4"), TargetPort: 80, Log: log}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := tt.opts.Validate(); err == nil {
				t.Error("expected validation error, got nil")
			}
		})
	}
}
