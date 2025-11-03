package l4postgres

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/mholt/caddy-l4/layer4"
	"go.uber.org/zap"
)

const (
	// ProtocolVersion2 is for v2.0: (2 * 65536) + 0 = 131072. Used to test rejection of old versions.
	ProtocolVersion2 = 131072
	// ProtocolVersion4 is for v4.0: (4 * 65536) + 0 = 262144. Used to test rejection of future versions.
	ProtocolVersion4 = 262144
)

func assertNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("Unexpected error: %s\n", err)
	}
}

func closePipe(wg *sync.WaitGroup, c1 net.Conn, c2 net.Conn) {
	wg.Wait()
	_ = c1.Close()
	_ = c2.Close()
}

func matchTester(t *testing.T, matcher *MatchPostgres, input []byte) (bool, error) {
	wg := &sync.WaitGroup{}
	in, out := net.Pipe()
	defer closePipe(wg, in, out)

	// cx is the connection that the matcher will read from.
	cx := layer4.WrapConnection(out, []byte{}, zap.NewNop())

	wg.Add(1)
	go func() {
		defer wg.Done()
		if len(input) > 0 {
			_, err := in.Write(input)
			assertNoError(t, err)
		}
		// Closing the writer end of the pipe will send an EOF to the reader.
		_ = in.Close()
	}()

	matched, err := matcher.Match(cx)

	// After the matcher has done its reading, we must drain the rest of the
	// connection so that the writer goroutine doesn't block forever.
	_, _ = io.Copy(io.Discard, cx)

	return matched, err
}

func buildStartupMessage(version uint32, params map[string]string) []byte {
	var payload bytes.Buffer
	binary.Write(&payload, binary.BigEndian, version)
	for k, v := range params {
		payload.WriteString(k)
		payload.WriteByte(0)
		payload.WriteString(v)
		payload.WriteByte(0)
	}
	payload.WriteByte(0)

	var message bytes.Buffer
	binary.Write(&message, binary.BigEndian, uint32(payload.Len()+lengthFieldSize))
	message.Write(payload.Bytes())
	return message.Bytes()
}

func buildSSLRequest() []byte {
	var message bytes.Buffer
	binary.Write(&message, binary.BigEndian, uint32(8))
	binary.Write(&message, binary.BigEndian, uint32(SSLRequestCode))
	return message.Bytes()
}

func buildCancelRequest(pid, secretKey uint32) []byte {
	var message bytes.Buffer
	binary.Write(&message, binary.BigEndian, uint32(16))
	binary.Write(&message, binary.BigEndian, uint32(CancelRequestCode))
	binary.Write(&message, binary.BigEndian, pid)
	binary.Write(&message, binary.BigEndian, secretKey)
	return message.Bytes()
}

func buildClientHello(t *testing.T, alpn ...string) []byte {
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
			ServerName:         "test",
		})
		// Handshake will write client hello, then wait for server hello
		// we don't send one, so it will time out or fail on pipe close
		_ = tlsClient.Handshake()
	}()

	// The server side reads the client hello
	buf := make([]byte, 4096)
	// Set a deadline to avoid test hanging
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

func TestMatchPostgres(t *testing.T) {
	tests := []struct {
		name      string
		matcher   *MatchPostgres
		input     []byte
		wantMatch bool
	}{
		// Basic protocol validation
		{
			name:      "Valid SSLRequest",
			matcher:   &MatchPostgres{},
			input:     buildSSLRequest(),
			wantMatch: true,
		},
		{
			name:      "Valid CancelRequest",
			matcher:   &MatchPostgres{},
			input:     buildCancelRequest(12345, 67890),
			wantMatch: true,
		},
		{
			name:      "Valid StartupMessage V3",
			matcher:   &MatchPostgres{},
			input:     buildStartupMessage(ProtocolVersion3, map[string]string{"user": "test"}),
			wantMatch: true,
		},
		{
			name:      "Too Short",
			matcher:   &MatchPostgres{},
			input:     []byte{0x00, 0x00},
			wantMatch: false,
		},
		{
			name:      "Invalid Message Length (Too Small)",
			matcher:   &MatchPostgres{},
			input:     []byte{0x00, 0x00, 0x00, 0x07},
			wantMatch: false,
		},
		{
			name:      "Unsupported Protocol Version (V2)",
			matcher:   &MatchPostgres{},
			input:     buildStartupMessage(ProtocolVersion2, map[string]string{"user": "test"}),
			wantMatch: false,
		},
		{
			name:      "Unsupported Protocol Version (V4)",
			matcher:   &MatchPostgres{},
			input:     buildStartupMessage(ProtocolVersion4, map[string]string{"user": "test"}),
			wantMatch: false,
		},
		{
			name:      "Malformed Startup (Missing Final Null)",
			matcher:   &MatchPostgres{},
			input:     buildStartupMessage(ProtocolVersion3, map[string]string{"user": "test"})[0:18],
			wantMatch: false,
		},

		// TLS Tests
		{
			name:      "TLS required with SSLRequest",
			matcher:   &MatchPostgres{TLS: "required"},
			input:     buildSSLRequest(),
			wantMatch: false,
		},
		{
			name:      "TLS required with StartupMessage",
			matcher:   &MatchPostgres{TLS: "required"},
			input:     buildStartupMessage(ProtocolVersion3, nil),
			wantMatch: false,
		},
		{
			name:      "TLS disabled with SSLRequest",
			matcher:   &MatchPostgres{TLS: "disabled"},
			input:     buildSSLRequest(),
			wantMatch: false,
		},
		{
			name:      "TLS allowed with SSLRequest and user filter",
			matcher:   &MatchPostgres{TLS: "", User: map[string][]string{"alice": {}}},
			input:     buildSSLRequest(),
			wantMatch: false,
		},

		// User/DB Tests
		{
			name:      "User match (any DB)",
			matcher:   &MatchPostgres{User: map[string][]string{"alice": {}}},
			input:     buildStartupMessage(ProtocolVersion3, map[string]string{"user": "alice"}),
			wantMatch: true,
		},
		{
			name:      "User mismatch",
			matcher:   &MatchPostgres{User: map[string][]string{"alice": {}}},
			input:     buildStartupMessage(ProtocolVersion3, map[string]string{"user": "bob"}),
			wantMatch: false,
		},
		{
			name:      "User and DB match",
			matcher:   &MatchPostgres{User: map[string][]string{"alice": {"stars_db"}}},
			input:     buildStartupMessage(ProtocolVersion3, map[string]string{"user": "alice", "database": "stars_db"}),
			wantMatch: true,
		},
		{
			name:      "Public DB match",
			matcher:   &MatchPostgres{User: map[string][]string{"*": {"public_db"}}},
			input:     buildStartupMessage(ProtocolVersion3, map[string]string{"database": "public_db"}),
			wantMatch: true,
		},

		// Client Tests
		{
			name:      "Client match",
			matcher:   &MatchPostgres{Client: []string{"pgadmin"}},
			input:     buildStartupMessage(ProtocolVersion3, map[string]string{"application_name": "pgadmin"}),
			wantMatch: true,
		},
		{
			name:      "Client mismatch",
			matcher:   &MatchPostgres{Client: []string{"pgadmin"}},
			input:     buildStartupMessage(ProtocolVersion3, map[string]string{"application_name": "psql"}),
			wantMatch: false,
		},
		{
			name:      "Client match with 'postgresql' protocol",
			matcher:   &MatchPostgres{Client: []string{"postgresql"}},
			input:     buildStartupMessage(ProtocolVersion3, map[string]string{"application_name": "postgresql"}),
			wantMatch: true,
		},

		// Combined Tests
		{
			name:      "User and Client match",
			matcher:   &MatchPostgres{User: map[string][]string{"alice": {}}, Client: []string{"pgadmin"}},
			input:     buildStartupMessage(ProtocolVersion3, map[string]string{"user": "alice", "application_name": "pgadmin"}),
			wantMatch: true,
		},
		{
			name:      "User mismatch, Client match",
			matcher:   &MatchPostgres{User: map[string][]string{"alice": {}}, Client: []string{"pgadmin"}},
			input:     buildStartupMessage(ProtocolVersion3, map[string]string{"user": "bob", "application_name": "pgadmin"}),
			wantMatch: false,
		},

		// OR Logic Simulation
		{
			name:      "OR logic: user alice on planets_db (matches)",
			matcher:   &MatchPostgres{User: map[string][]string{"alice": {"planets_db"}}},
			input:     buildStartupMessage(ProtocolVersion3, map[string]string{"user": "alice", "database": "planets_db"}),
			wantMatch: true,
		},
		{
			name:      "OR logic: tls required (matches)",
			matcher:   &MatchPostgres{TLS: "required"},
			input:     buildSSLRequest(),
			wantMatch: false,
		},
		{
			name:      "OR logic: user alice on planets_db (fails tls required check)",
			matcher:   &MatchPostgres{TLS: "required"},
			input:     buildStartupMessage(ProtocolVersion3, map[string]string{"user": "alice", "database": "planets_db"}),
			wantMatch: false,
		},
		{
			name:      "OR logic: tls required (fails user check)",
			matcher:   &MatchPostgres{User: map[string][]string{"alice": {"planets_db"}}},
			input:     buildSSLRequest(),
			wantMatch: false,
		},

		// TLS direct negotiation tests
		{
			name:      "TLS with postgresql alpn",
			matcher:   &MatchPostgres{},
			input:     buildClientHello(t, "postgresql"),
			wantMatch: true,
		},
		{
			name:      "TLS with postgresql alpn and tls required",
			matcher:   &MatchPostgres{TLS: "required"},
			input:     buildClientHello(t, "postgresql"),
			wantMatch: true,
		},
		{
			name:      "TLS with wrong alpn and tls required",
			matcher:   &MatchPostgres{TLS: "required"},
			input:     buildClientHello(t, "http/1.1"),
			wantMatch: false,
		},
		{
			name:      "TLS with postgresql alpn and tls disabled",
			matcher:   &MatchPostgres{TLS: "disabled"},
			input:     buildClientHello(t, "postgresql"),
			wantMatch: false,
		},
		{
			name:      "TLS with postgresql alpn and user filter",
			matcher:   &MatchPostgres{User: map[string][]string{"alice": {}}},
			input:     buildClientHello(t, "postgresql"),
			wantMatch: false,
		},
	}

	_, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			matched, err := matchTester(t, tc.matcher, tc.input)
			assertNoError(t, err)

			if matched != tc.wantMatch {
				if tc.wantMatch {
					t.Fatalf("matcher did not match | %s\n", tc.name)
				} else {
					t.Fatalf("matcher should not have matched | %s\n", tc.name)
				}
			}
		})
	}
}
