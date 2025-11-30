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

package l4tls

import (
	"crypto/tls"
	"fmt"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"go.uber.org/zap"

	"github.com/mholt/caddy-l4/layer4"
)

func init() {
	caddy.RegisterModule(&Handler{})
}

// Handler is a connection handler that terminates TLS.
type Handler struct {
	ConnectionPolicies caddytls.ConnectionPolicies `json:"connection_policies,omitempty"`

	// unexported fields for Caddyfile parsing
	automationSubjects []string

	ctx    caddy.Context
	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (*Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.handlers.tls",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision sets up the module.
func (t *Handler) Provision(ctx caddy.Context) error {
	t.ctx = ctx
	t.logger = ctx.Logger(t)

	// ensure there is at least one policy, which will act as default
	if len(t.ConnectionPolicies) == 0 {
		t.ConnectionPolicies = append(t.ConnectionPolicies, new(caddytls.ConnectionPolicy))
	}

	err := t.ConnectionPolicies.Provision(ctx)
	if err != nil {
		return fmt.Errorf("setting up Handler connection policies: %v", err)
	}

	return nil
}

// Handle handles the connections.
func (t *Handler) Handle(cx *layer4.Connection, next layer4.Handler) error {
	// get the TLS config to use for this connection
	tlsCfg := t.ConnectionPolicies.TLSConfig(t.ctx)

	// capture the ClientHello info when the handshake is performed
	var clientHello ClientHelloInfo
	underlyingGetConfigForClient := tlsCfg.GetConfigForClient
	tlsCfg.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		clientHello.ClientHelloInfo = *hello
		return underlyingGetConfigForClient(hello)
	}

	// terminate TLS by performing the handshake (note that we pass
	// in cx, not cx.Conn; this is because we must read from the
	// connection to perform the handshake, and cx might have some
	// bytes already buffered need to be read first)
	tlsConn := tls.Server(cx, tlsCfg)
	err := tlsConn.Handshake()
	if err != nil {
		return err
	}
	t.logger.Debug("terminated TLS",
		zap.String("remote", cx.RemoteAddr().String()),
		zap.String("server_name", clientHello.ServerName),
	)

	// preserve this ClientHello info for later, if needed
	appendClientHello(cx, clientHello)

	// preserve the tls.ConnectionState for use in the http matcher
	connectionState := tlsConn.ConnectionState()
	appendConnectionState(cx, &connectionState)

	// all future reads/writes will now be decrypted/encrypted
	// (tlsConn, which wraps cx, is wrapped into a new cx so
	// that future I/O succeeds... if we use the same cx, it'd
	// be wrapping itself, and we'd have nested read calls out
	// to the kernel, which creates a deadlock/hang; see #18)
	return next.Handle(cx.Wrap(tlsConn))
}

// UnmarshalCaddyfile sets up the Handler from Caddyfile tokens. Syntax:
//
//	tls <domains...>|internal {
//	    ...
//	}
//
//	tls {
//		connection_policy {
//			...
//		}
//	}
func (t *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume wrapper name: tls

	// same-line options are shorthands for automation (e.g., "tls internal" or "tls example.com")
	t.automationSubjects = d.RemainingArgs()
	hasBlock := d.NextBlock(d.Nesting())

	// if there are shorthands and a block, that's an error for server-level config
	if len(t.automationSubjects) > 0 && hasBlock {
		return d.Err("cannot combine automation shorthands (like 'internal' or domain names) with a configuration block; use the block without shorthands for advanced configuration")
	}

	// if there are only shorthands, we're done (common case for server-level: "tls internal")
	if len(t.automationSubjects) > 0 && !hasBlock {
		return nil
	}

	// if there are no shorthands and no block, we're done (also valid: just "tls" with default settings)
	if !hasBlock {
		return nil
	}

	// empty block is OK (just "tls { }")
	if d.Val() == "" {
		return nil
	}

	// The block must contain one or more `connection_policy` blocks for advanced configuration.
	// This is used when the tls handler is in a route (not at server-level).
	if d.Val() != "connection_policy" {
		return d.Errf("tls block must contain 'connection_policy' subdirectives; for simple configuration at the server level, use shorthands like 'tls internal' or 'tls example.com' instead")
	}

	// Multi-policy mode: parse one or more connection_policy blocks
	t.ConnectionPolicies = nil // clear the default policy

	for {
		// the dispenser is on a `connection_policy` directive
		if d.Val() != "connection_policy" {
			return d.Err("all directives in this block must be connection_policy if the first one is")
		}

		cp := new(caddytls.ConnectionPolicy)

		// UnmarshalCaddyfile for ConnectionPolicy might be greedy, so to be safe,
		// we give it a dispenser that is scoped to just this segment.
		// d.NewFromNextSegment() gets the whole segment (directive + block)
		// and advances the main dispenser past it.
		d2 := d.NewFromNextSegment()
		if err := cp.UnmarshalCaddyfile(d2); err != nil {
			return err
		}
		t.ConnectionPolicies = append(t.ConnectionPolicies, cp)

		// see if there is another directive
		if !d.Next() {
			break
		}

		// if we are at the closing brace of the outer `tls` block, we are done
		if d.Val() == "}" {
			d.Prev()
			break
		}
	}

	return nil
}

// AutomationSubjects returns the subjects for which automation was requested
// via a Caddyfile shorthand. This is used by the Caddyfile parser to
// configure the main TLS app.
func (t *Handler) AutomationSubjects() []string {
	return t.automationSubjects
}

func appendClientHello(cx *layer4.Connection, chi ClientHelloInfo) {
	var clientHellos []ClientHelloInfo
	if val := cx.GetVar("tls_client_hellos"); val != nil {
		clientHellos = val.([]ClientHelloInfo)
	}
	clientHellos = append(clientHellos, chi)
	cx.SetVar("tls_client_hellos", clientHellos)
}

// GetClientHelloInfos gets ClientHello information for all the terminated TLS connections.
func GetClientHelloInfos(cx *layer4.Connection) []ClientHelloInfo {
	var clientHellos []ClientHelloInfo
	if val := cx.GetVar("tls_client_hellos"); val != nil {
		clientHellos = val.([]ClientHelloInfo)
	}
	return clientHellos
}

func appendConnectionState(cx *layer4.Connection, cs *tls.ConnectionState) {
	var connectionStates []*tls.ConnectionState
	if val := cx.GetVar("tls_connection_states"); val != nil {
		connectionStates = val.([]*tls.ConnectionState)
	}
	connectionStates = append(connectionStates, cs)
	cx.SetVar("tls_connection_states", connectionStates)
}

// GetConnectionStates gets the tls.ConnectionState for all the terminated TLS connections.
func GetConnectionStates(cx *layer4.Connection) []*tls.ConnectionState {
	var connectionStates []*tls.ConnectionState
	if val := cx.GetVar("tls_connection_states"); val != nil {
		connectionStates = val.([]*tls.ConnectionState)
	}
	return connectionStates
}

// Interface guards
var (
	_ caddy.Provisioner                 = (*Handler)(nil)
	_ caddyfile.Unmarshaler             = (*Handler)(nil)
	_ layer4.NextHandler                = (*Handler)(nil)
	_ layer4.AutomationSubjectsProvider = (*Handler)(nil)
)
