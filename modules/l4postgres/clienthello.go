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

package l4postgres

import (
	"crypto/tls"
)

// KeyShare is a TLS 1.3 Key Share. See RFC 8446, Section 4.2.8.
type KeyShare struct {
	Group tls.CurveID
	Data  []byte
}

// PSKIdentity is a TLS 1.3 PSK Identity.
// Can be a Session Ticket, or a reference to a saved
// session. See RFC 8446, Section 4.2.11.
type PSKIdentity struct {
	label               []byte
	obfuscatedTicketAge uint32
}

// ClientHelloInfo holds information about a TLS ClientHello.
// Our own parser collects a little more information than
// the standard library's struct holds.
type ClientHelloInfo struct {
	tls.ClientHelloInfo

	Version                      uint16
	Random                       []byte
	SessionID                    []byte
	SecureRenegotiationSupported bool
	SecureRenegotiation          []byte
	CompressionMethods           []byte

	Extensions []uint16

	OCSPStapling         bool
	TicketSupported      bool
	SessionTicket        []uint8
	SupportedSchemesCert []tls.SignatureScheme
	SCTs                 bool
	Cookie               []byte
	KeyShares            []KeyShare
	EarlyData            bool
	PSKModes             []uint8
	PSKIdentities        []PSKIdentity
	PSKBinders           [][]byte
}
