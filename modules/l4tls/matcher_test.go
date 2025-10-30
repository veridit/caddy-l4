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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/mholt/caddy-l4/layer4"
	"go.uber.org/zap"
)

func assertNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Unexpected error: %s\n", err)
	}
}

func generateTestCert(t *testing.T) tls.Certificate {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}
	notBefore := time.Now()
	notAfter := notBefore.Add(time.Hour)
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("Failed to generate serial number: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Caddy Test"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost", "dev.test.com", "*.wild.com"},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}
}

func buildClientHello(t *testing.T, serverName string, alpn ...string) []byte {
	client, server := net.Pipe()
	var clientHello []byte
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		defer client.Close()
		tlsClient := tls.Client(client, &tls.Config{
			NextProtos:         alpn,
			InsecureSkipVerify: true,
			ServerName:         serverName,
		})
		_ = tlsClient.Handshake()
	}()

	buf := make([]byte, 4096)
	_ = server.SetReadDeadline(time.Now().Add(1 * time.Second))
	n, err := server.Read(buf)
	if err != nil && err != io.EOF && !errors.Is(err, net.ErrClosed) {
		t.Logf("server read failed: %v", err)
	}
	clientHello = buf[:n]
	_ = server.Close()
	wg.Wait()
	return clientHello
}

func TestMatchTLS(t *testing.T) {
	// Raw ClientHello tests
	rawTests := []struct {
		name       string
		sni        []string
		alpn       []string
		serverName string
		clientAlpn []string
		wantMatch  bool
	}{
		{
			name:       "raw sni match",
			sni:        []string{"dev.test.com"},
			serverName: "dev.test.com",
			wantMatch:  true,
		},
		{
			name:       "raw sni mismatch",
			sni:        []string{"dev.test.com"},
			serverName: "other.com",
			wantMatch:  false,
		},
		{
			name:       "raw wildcard sni match",
			sni:        []string{"*.test.com"},
			serverName: "dev.test.com",
			wantMatch:  true,
		},
		{
			name:       "raw alpn match",
			alpn:       []string{"h2"},
			serverName: "dev.test.com",
			clientAlpn: []string{"h2", "http/1.1"},
			wantMatch:  true,
		},
		{
			name:       "raw alpn mismatch",
			alpn:       []string{"h3"},
			serverName: "dev.test.com",
			clientAlpn: []string{"h2", "http/1.1"},
			wantMatch:  false,
		},
		{
			name:       "raw sni and alpn match",
			sni:        []string{"dev.test.com"},
			alpn:       []string{"h2"},
			serverName: "dev.test.com",
			clientAlpn: []string{"h2", "http/1.1"},
			wantMatch:  true,
		},
		{
			name:       "raw sni match and alpn mismatch",
			sni:        []string{"dev.test.com"},
			alpn:       []string{"h3"},
			serverName: "dev.test.com",
			clientAlpn: []string{"h2", "http/1.1"},
			wantMatch:  false,
		},
		{
			name:       "raw alpn placeholder match",
			alpn:       []string{"{l4.tls.server_name}"},
			serverName: "h2",
			clientAlpn: []string{"h2", "http/1.1"},
			wantMatch:  true,
		},
	}

	for _, tc := range rawTests {
		t.Run(tc.name, func(t *testing.T) {
			matchers := caddy.ModuleMap{}
			if len(tc.sni) > 0 {
				sniJSON, err := json.Marshal(tc.sni)
				if err != nil {
					t.Fatalf("Failed to marshal SNI: %v", err)
				}
				matchers["sni"] = sniJSON
			}
			if len(tc.alpn) > 0 {
				alpnJSON, err := json.Marshal(tc.alpn)
				if err != nil {
					t.Fatalf("Failed to marshal ALPN: %v", err)
				}
				matchers["alpn"] = alpnJSON
			}

			m := &MatchTLS{
				MatchersRaw: matchers,
			}
			ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
			defer cancel()

			err := m.Provision(ctx)
			if err != nil {
				t.Fatalf("provisioning matcher: %v", err)
			}

			clientHello := buildClientHello(t, tc.serverName, tc.clientAlpn...)

			in, out := net.Pipe()
			go func() {
				defer out.Close()
				_, _ = out.Write(clientHello)
			}()

			cx := layer4.WrapConnection(in, []byte{}, zap.NewNop())
			matched, err := m.Match(cx)
			assertNoError(t, err)

			if matched != tc.wantMatch {
				t.Errorf("want match %v, got %v", tc.wantMatch, matched)
			}
		})
	}

	// Pre-terminated TLS connection tests
	preTlsTests := []struct {
		name       string
		sni        []string
		alpn       []string
		clientSNI  string
		clientALPN []string
		wantMatch  bool
	}{
		{
			name:      "pre-tls sni match",
			sni:       []string{"dev.test.com"},
			clientSNI: "dev.test.com",
			wantMatch: true,
		},
		{
			name:      "pre-tls sni mismatch",
			sni:       []string{"other.com"},
			clientSNI: "dev.test.com",
			wantMatch: false,
		},
		{
			name:      "pre-tls wildcard sni match",
			sni:       []string{"*.wild.com"},
			clientSNI: "sub.wild.com",
			wantMatch: true,
		},
		{
			name:       "pre-tls alpn placeholder match",
			alpn:       []string{"{l4.tls.server_name}"},
			clientSNI:  "h2",
			clientALPN: []string{"h2"},
			wantMatch:  true,
		},
	}

	for _, tc := range preTlsTests {
		t.Run(tc.name, func(t *testing.T) {
			matchers := caddy.ModuleMap{}
			if len(tc.sni) > 0 {
				sniJSON, err := json.Marshal(tc.sni)
				if err != nil {
					t.Fatalf("failed to marshal sni: %v", err)
				}
				matchers["sni"] = sniJSON
			}
			if len(tc.alpn) > 0 {
				alpnJSON, err := json.Marshal(tc.alpn)
				if err != nil {
					t.Fatalf("failed to marshal alpn: %v", err)
				}
				matchers["alpn"] = alpnJSON
			}

			m := &MatchTLS{
				MatchersRaw: matchers,
			}
			ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
			defer cancel()

			err := m.Provision(ctx)
			if err != nil {
				t.Fatalf("provisioning matcher: %v", err)
			}

			// Test setup with real TCP listener to avoid deadlocks
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("Failed to listen: %v", err)
			}
			defer ln.Close()

			var serverConn net.Conn
			var serverErr error
			serverDone := make(chan struct{})

			go func() {
				defer close(serverDone)
				conn, err := ln.Accept()
				if err != nil {
					serverErr = err
					return
				}
				serverConn = tls.Server(conn, &tls.Config{
					Certificates: []tls.Certificate{generateTestCert(t)},
					NextProtos:   tc.clientALPN,
				})
				err = serverConn.(*tls.Conn).Handshake()
				if err != nil && !errors.Is(err, io.EOF) {
					serverErr = err
				}
			}()

			clientConn, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatalf("Failed to dial: %v", err)
			}
			tlsClient := tls.Client(clientConn, &tls.Config{
				ServerName:         tc.clientSNI,
				InsecureSkipVerify: true,
				NextProtos:         tc.clientALPN,
			})
			err = tlsClient.Handshake()
			if err != nil {
				t.Fatalf("Client handshake failed: %v", err)
			}
			tlsClient.Close()

			<-serverDone
			assertNoError(t, serverErr)
			if serverConn == nil {
				t.Fatalf("server connection is nil")
			}

			cx := layer4.WrapConnection(serverConn, []byte{}, zap.NewNop())
			matched, err := m.Match(cx)
			assertNoError(t, err)

			if matched != tc.wantMatch {
				t.Errorf("want match %v, got %v", tc.wantMatch, matched)
			}
		})
	}
}
