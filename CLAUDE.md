# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Stunner is a security testing tool for STUN, TURN, and TURN-over-TCP servers (WebRTC infrastructure). It tests for misconfigurations that allow traffic to be relayed to internal networks.

Implemented RFCs: STUN (RFC 5389), TURN (RFC 5766), TURN for TCP (RFC 6062), TURN Extension for IPv6 (RFC 6156).

## Commands

Uses [go-task](https://taskfile.dev/) (`task` or `go-task`):

```sh
task          # build (default: fmt + vet + compile for linux/amd64)
task test     # run tests with race detector (CGO_ENABLED=1 required)
task lint     # run golangci-lint + go mod tidy
task windows  # cross-compile for windows/amd64
task update   # go get -u && go mod tidy
```

Run a single test:
```sh
go test -run TestName ./internal/...
```

## Architecture

### Entry point

`main.go` — defines all CLI commands and flags using `urfave/cli/v2`, then delegates to functions in `internal/cmd/`.

### Package layout

**`internal/`** — core STUN/TURN protocol implementation (package `internal`):
- `types_stun.go`, `types_turn.go`, `types_turntcp.go` — wire types, attribute constants, error codes for each protocol layer
- `stun.go` — `Stun` struct (used for both STUN and TURN messages); `Serialize()` builds the wire format and automatically computes `MESSAGE-INTEGRITY` HMAC when `Username`/`Password` are set; `SendAndReceive()` sends a request and reads the framed response
- `connection.go` — `Connect()` establishes TCP or UDP connections with optional TLS (TCP) or DTLS (UDP) via `pion/dtls`
- `parsers_stun.go`, `parsers_turn.go`, `parsers_turntcp.go` — parse raw bytes into `Stun` structs
- `requests_stun.go`, `requests_turn.go`, `requests_turntcp.go` — factory functions that construct specific STUN/TURN request messages
- `helpers_stun.go`, `helpers_turn.go`, `helpers_turntcp.go` — encode/decode XOR addresses, attributes, etc.

**`internal/cmd/`** — one file per CLI subcommand (`info.go`, `socks.go`, `rangescan.go`, `bruteforce.go`, `brutetransports.go`, `memoryleak.go`, `tcpscanner.go`, `udpscanner.go`). Each exports a single function called from `main.go`.

**`internal/helper/`** — utility functions: low-level framed `ConnectionRead`/`ConnectionWrite`, IP range helpers (`iphelper.go`), DNS resolver (`resolver.go`).

**`internal/socksimplementations/`** — implements the SOCKS5 handler that proxies TCP connections over TURN-over-TCP (used by the `socks` command).

**`scripts/`** — Python helpers for extracting TURN credentials from Cisco Expressway.

### Authentication flow

TURN uses a two-round-trip challenge/response. The first request is sent unauthenticated, the server returns 401 with `REALM` and `NONCE` attributes, then the client resends with `USERNAME`, `REALM`, `NONCE`, and a `MESSAGE-INTEGRITY` HMAC-SHA1 over the message. `Stun.Serialize()` handles the HMAC insertion automatically when `Username`/`Password` are populated.

## Linting

golangci-lint is configured with a large set of linters in `.golangci.yml`. Notable constraints:
- Non-`main.go` files must not import `log` (use `log/slog` or the injected logger)
- `math/rand` is banned in non-test files (use `math/rand/v2`)
- `forbidigo` bans direct `fmt.Printf` in most contexts (use the logger)
- `nolint` directives are acceptable for intentional exceptions (e.g. `gosec` for `InsecureSkipVerify` on test targets)
