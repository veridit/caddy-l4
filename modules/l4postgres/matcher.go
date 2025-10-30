// Copyright 2020 Matthew Holt
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package l4postgres allows the L4 multiplexing of Postgres connections.
// SSL connections can be required.
// Non-SSL connections can also match on Message parameters.
//
// All conditions within a single matcher instance are combined with AND logic.
// To achieve OR logic, define multiple named matchers and use them in separate
// routes.
//
// Example matcher configs:
//
//	{
//		"postgres": {}
//	}
//
//	{
//		"postgres": {
//			"user": {
//				"*": ["public_db"],
//				"alice": ["planets_db", "stars_db"]
//			},
//			"client": ["psql", "TablePlus"],
//			"tls": "required"
//		}
//	}

package l4postgres

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap"

	"github.com/mholt/caddy-l4/layer4"
	"github.com/mholt/caddy-l4/modules/l4tls"
)

const (
	SSLRequestCode    = 80877103  // Code for SSL request
	CancelRequestCode = 80877102  // Code for cancellation request
	// ProtocolVersion3 is for v3.0: (3 * 65536) + 0 = 196608. This is the version caddy-l4 supports.
	ProtocolVersion3  = 196608
	lengthFieldSize   = 4         // Size of message length field (bytes)
	minMessageLen     = 8         // Smallest valid message: SSLRequest (8 bytes)
	maxPayloadSize    = 16 * 1024 // Maximum reasonable payload size (16 KB)
)

func init() {
	caddy.RegisterModule(&MatchPostgres{})
}

// MatchPostgres is able to match Postgres connections, optionally further
// matching on the User or Database being requested
type MatchPostgres struct {
	User   map[string][]string `json:"user,omitempty"`
	Client []string            `json:"client,omitempty"`
	TLS    string              `json:"tls,omitempty"`

	logger *zap.Logger `json:"-"`
}

// CaddyModule returns the Caddy module information.
func (*MatchPostgres) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.postgres",
		New: func() caddy.Module { return new(MatchPostgres) },
	}
}

// Match returns true if the connection looks like the Postgres protocol.
func (m *MatchPostgres) Match(cx *layer4.Connection) (bool, error) {
	if tlsConn, ok := cx.Conn.(*tls.Conn); ok {
		return m.matchDecryptedTLS(cx, tlsConn)
	}
	return m.matchRaw(cx)
}

func (m *MatchPostgres) matchDecryptedTLS(cx *layer4.Connection, tlsConn *tls.Conn) (bool, error) {
	m.logger.Debug("matching connection that is already a TLS-terminated stream")

	if m.TLS == "disabled" {
		m.logger.Debug("not matching, tls is disabled but connection is TLS")
		return false, nil
	}

	// ConnectionState() should not block here, as the listener wrapper
	// is handed a connection after the handshake is complete.
	m.logger.Debug("getting TLS connection state")
	state := tlsConn.ConnectionState()
	m.logger.Debug("got TLS connection state")
	m.logger.Debug("checking existing TLS connection state",
		zap.String("server_name", state.ServerName))

	// If we are here, TLS requirements are met.
	// If there are no other filters, we have a match.
	if len(m.User) == 0 && len(m.Client) == 0 {
		m.logger.Debug("matched based on TLS connection (SNI not checked here)")
		return true, nil
	}

	// If there are other filters, we must inspect the startup message
	// which is now available decrypted on the connection.
	m.logger.Debug("performing startup message match on decrypted stream")
	return m.matchStartup(cx, nil)
}

func (m *MatchPostgres) matchRaw(cx *layer4.Connection) (bool, error) {
	m.logger.Debug("matching raw connection")
	// Read first byte to check for TLS handshake
	initialByte := make([]byte, 1)
	m.logger.Debug("reading initial byte")
	// Use ReadFull to ensure we get 1 byte unless EOF.
	if _, err := io.ReadFull(cx, initialByte); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return false, nil
		}
		return false, fmt.Errorf("peeking for TLS handshake: %w", err)
	}

	const recordTypeHandshake = 0x16
	if initialByte[0] == recordTypeHandshake {
		return m.matchTLS(cx, initialByte)
	}

	return m.matchStartup(cx, initialByte)
}

func (m *MatchPostgres) matchTLS(cx *layer4.Connection, initialByte []byte) (bool, error) {
	m.logger.Debug("postgres connection appears to be TLS")
	if m.TLS == "disabled" {
		m.logger.Debug("tls is disabled, not matching")
		return false, nil
	}

	// The following logic is borrowed from l4tls.MatchTLS
	const recordHeaderLen = 5
	hdr := make([]byte, recordHeaderLen)
	copy(hdr, initialByte)
	_, err := io.ReadFull(cx, hdr[1:])
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return false, nil // Not enough data for a TLS handshake
		}
		return false, fmt.Errorf("reading TLS record header: %w", err)
	}

	const recordTypeHandshake = 0x16
	if hdr[0] != recordTypeHandshake {
		return false, nil // Should be caught by peek, but good to double-check
	}

	length := int(uint16(hdr[3])<<8 | uint16(hdr[4]))
	if length > maxPayloadSize {
		return false, nil
	}
	rawHello := make([]byte, length)
	_, err = io.ReadFull(cx, rawHello)
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return false, nil
		}
		return false, fmt.Errorf("reading ClientHello: %w", err)
	}

	chi := l4tls.ParseRawClientHello(rawHello)

	m.logger.Debug("parsed client hello", zap.Strings("alpn_protos", chi.SupportedProtos), zap.String("server_name", chi.ServerName))

	hasPostgresALPN := slices.Contains(chi.SupportedProtos, "postgresql")

	if m.TLS == "required" {
		m.logger.Debug("tls is required, matching based on ALPN", zap.Bool("matched", hasPostgresALPN))
		return hasPostgresALPN, nil
	}

	if len(m.User) > 0 || len(m.Client) > 0 {
		m.logger.Debug("not matching because user/client filters are set for TLS-negotiated session")
		return false, nil
	}

	m.logger.Debug("tls is allowed, matching based on ALPN", zap.Bool("matched", hasPostgresALPN))
	return hasPostgresALPN, nil
}

func (m *MatchPostgres) matchStartup(cx *layer4.Connection, initialByte []byte) (bool, error) {
	m.logger.Debug("postgres connection appears to be a startup message")
	if m.TLS == "required" {
		m.logger.Debug("not matching, tls is required but a startup message was received")
		return false, nil
	}
	// Read message length (first 4 bytes)
	lenBytes := make([]byte, lengthFieldSize)
	var readStart int
	if initialByte != nil {
		copy(lenBytes, initialByte)
		readStart = 1
	}

	if _, err := io.ReadFull(cx, lenBytes[readStart:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return false, nil // Not enough data for PostgreSQL
		}
		return false, fmt.Errorf("reading message length: %w", err)
	}

	// Parse and validate message length
	msgLen := binary.BigEndian.Uint32(lenBytes)
	if msgLen < minMessageLen {
		m.logger.Debug("not matching, message too short", zap.Uint32("len", msgLen))
		return false, nil // Too small to be a valid PostgreSQL message
	}

	// Calculate and validate payload length
	payloadLen := msgLen - lengthFieldSize
	if payloadLen > maxPayloadSize || payloadLen < 4 {
		m.logger.Debug("not matching, invalid payload length", zap.Uint32("len", payloadLen))
		return false, nil // Payload too large, reject to prevent DoS
	}

	// Read the payload
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(cx, payload); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return false, nil // Incomplete message
		}
		return false, fmt.Errorf("reading payload: %w", err)
	}

	// Check the first 4 bytes (code or protocol version)
	code := binary.BigEndian.Uint32(payload[:4])

	if code == SSLRequestCode {
		// TLS allowed or disabled: match only if no other filters, since SSLRequest has no user/client info
		matched := len(m.User) == 0 && len(m.Client) == 0 && len(payload) == 4
		m.logger.Debug("matching sslrequest", zap.String("tls_mode", m.TLS), zap.Bool("matched", matched))
		return matched, nil
	}

	if code == CancelRequestCode {
		// CancelRequest has no user/client info. Match only if no filters are configured.
		matched := len(m.User) == 0 && len(m.Client) == 0 && len(payload) == 12
		m.logger.Debug("matching cancelrequest", zap.Bool("matched", matched))
		return matched, nil
	}

	// From here, we assume it's a startup message. Check protocol version.
	majorVersion := code >> 16
	if majorVersion != 3 {
		m.logger.Debug("not matching, unsupported major version", zap.Uint32("version", majorVersion))
		return false, nil // Only support protocol version 3
	}

	params, ok := parseStartupParameters(payload[4:])
	if !ok {
		m.logger.Debug("not matching, malformed startup parameters")
		return false, nil // Malformed startup message
	}

	// If no user/db/client matching is configured, a valid startup message is a match.
	if len(m.User) == 0 && len(m.Client) == 0 {
		return true, nil
	}

	// If client filter is configured, it must match.
	if len(m.Client) > 0 {
		name, ok := params["application_name"]
		if !ok || !slices.Contains(m.Client, name) {
			return false, nil
		}
	}

	// If user filter is configured, it must match.
	if len(m.User) > 0 {
		user, userOK := params["user"]
		if !userOK {
			// No user parameter, check for public DBs ("*")
			databases, publicDBsConfigured := m.User["*"]
			if !publicDBsConfigured {
				return false, nil
			}
			if len(databases) > 0 {
				if db, dbOK := params["database"]; dbOK {
					if !slices.Contains(databases, db) {
						return false, nil
					}
				} else {
					return false, nil // Specific public DBs required, but none provided
				}
			}
		} else {
			// User parameter exists, check for config for this user
			databases, userConfigured := m.User[user]
			if !userConfigured {
				return false, nil
			}
			if len(databases) > 0 {
				if db, dbOK := params["database"]; dbOK {
					if !slices.Contains(databases, db) {
						return false, nil
					}
				} else {
					return false, nil // Specific DBs required, but none provided
				}
			}
		}
	}

	// If we haven't returned false yet, it's a match.
	m.logger.Debug("matched startup message")
	return true, nil
}

func (m *MatchPostgres) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)
	switch m.TLS {
	case "", "required", "allowed", "disabled":
	default:
		return fmt.Errorf("invalid tls value '%s'; must be one of 'required', 'allowed', 'disabled'", m.TLS)
	}
	return nil
}

// UnmarshalCaddyfile sets up the matcher from Caddyfile tokens.
func (m *MatchPostgres) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume wrapper name

	if d.CountRemainingArgs() > 0 {
		return d.ArgErr()
	}

	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "user":
			if d.NextArg() {
				return d.Err("`user` subdirective does not take arguments")
			}
			if m.User == nil {
				m.User = make(map[string][]string)
			}
			for d.NextBlock(nesting + 1) { // open `user { ... }` block
				for d.Next() { // iterate through lines
					user := d.Val()
					databases := d.RemainingArgs()
					if _, ok := m.User[user]; ok {
						return d.Errf("user '%s' is already defined", user)
					}
					m.User[user] = databases
				}
			}
		case "client":
			m.Client = append(m.Client, d.RemainingArgs()...)
			if d.NextBlock(nesting + 1) {
				return d.Err("`client` subdirective does not take a block")
			}
		case "tls":
			if !d.NextArg() {
				return d.Err("`tls` subdirective requires an argument")
			}
			m.TLS = d.Val()
			if d.NextArg() {
				return d.Err("`tls` subdirective takes only one argument")
			}
			if d.NextBlock(nesting + 1) {
				return d.Err("`tls` subdirective does not take a block")
			}
		default:
			return d.Errf("unrecognized subdirective '%s'", d.Val())
		}
	}

	return nil
}

// parseStartupParameters parses startup message parameters from data.
func parseStartupParameters(data []byte) (map[string]string, bool) {
	params := make(map[string]string)
	for {
		// Find key
		idx := bytes.IndexByte(data, 0)
		if idx == -1 {
			return nil, false
		}
		key := data[:idx]
		data = data[idx+1:]

		if len(key) == 0 {
			return params, len(data) == 0
		}

		// Find value
		idx = bytes.IndexByte(data, 0)
		if idx == -1 {
			return nil, false
		}
		value := data[:idx]
		data = data[idx+1:]

		params[string(key)] = string(value)
	}
}

// Interface guards
var (
	_ layer4.ConnMatcher    = (*MatchPostgres)(nil)
	_ caddyfile.Unmarshaler = (*MatchPostgres)(nil)
)
