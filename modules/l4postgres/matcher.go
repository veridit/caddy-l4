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
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"

	"github.com/mholt/caddy-l4/layer4"
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
	// Read message length (first 4 bytes)
	lenBytes := make([]byte, lengthFieldSize)
	if _, err := io.ReadFull(cx, lenBytes); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return false, nil // Not enough data for PostgreSQL
		}
		return false, fmt.Errorf("reading message length: %w", err)
	}

	// Parse and validate message length
	msgLen := binary.BigEndian.Uint32(lenBytes)
	if msgLen < minMessageLen {
		return false, nil // Too small to be a valid PostgreSQL message
	}

	// Calculate and validate payload length
	payloadLen := msgLen - lengthFieldSize
	if payloadLen > maxPayloadSize || payloadLen < 4 {
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
		if m.TLS == "disabled" {
			return false, nil // TLS disabled, but got SSLRequest
		}
		if m.TLS == "required" {
			return len(payload) == 4, nil // TLS required, and got valid SSLRequest
		}
		// TLS allowed: match only if no other filters, since SSLRequest has no user/client info
		return len(m.User) == 0 && len(m.Client) == 0 && len(payload) == 4, nil
	}

	// Not an SSLRequest...
	if m.TLS == "required" {
		return false, nil // TLS required, but got something else
	}

	if code == CancelRequestCode {
		// CancelRequest has no user/client info. Match only if no filters are configured.
		return len(m.User) == 0 && len(m.Client) == 0 && len(payload) == 12, nil
	}

	// From here, we assume it's a startup message. Check protocol version.
	majorVersion := code >> 16
	if majorVersion != 3 {
		return false, nil // Only support protocol version 3
	}

	params, ok := parseStartupParameters(payload[4:])
	if !ok {
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
	return true, nil
}

func (m *MatchPostgres) Provision(ctx caddy.Context) error {
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

	if d.NextArg() {
		return d.ArgErr()
	}

	for d.NextBlock(0) {
		switch d.Val() {
		case "user":
			if d.NextArg() {
				return d.Err("`user` subdirective does not take arguments")
			}
			if m.User == nil {
				m.User = make(map[string][]string)
			}
			for d.NextBlock(1) { // open `user { ... }` block
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
			if d.NextBlock(1) {
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
			if d.NextBlock(1) {
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
