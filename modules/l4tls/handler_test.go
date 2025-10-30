package l4tls

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

func TestUnmarshalCaddyfile(t *testing.T) {
	tests := []struct {
		name         string
		caddyfile    string
		wantPolicies caddytls.ConnectionPolicies
		wantErr      bool
	}{
		{
			name:      "alpn-inline",
			caddyfile: `tls postgresql http/1.1`,
			wantPolicies: caddytls.ConnectionPolicies{
				{ALPN: []string{"postgresql", "http/1.1"}},
			},
		},
		{
			name: "connection-policy-block",
			caddyfile: `tls {
				connection_policy {
					alpn h2
				}
			}`,
			wantPolicies: caddytls.ConnectionPolicies{
				{ALPN: []string{"h2"}},
			},
		},
		{
			name: "alpn-inline-and-block",
			caddyfile: `tls postgresql {
				connection_policy {
					alpn h2
				}
			}`,
			wantPolicies: caddytls.ConnectionPolicies{
				{ALPN: []string{"h2"}},
				{ALPN: []string{"postgresql"}},
			},
		},
		{
			name:      "empty",
			caddyfile: `tls`,
			wantPolicies: caddytls.ConnectionPolicies{
				{},
			},
		},
		{
			name:      "empty-block",
			caddyfile: `tls {}`,
			wantPolicies: caddytls.ConnectionPolicies{
				{},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := new(Handler)
			dispenser := caddyfile.NewTestDispenser(tc.caddyfile)
			err := h.UnmarshalCaddyfile(dispenser)
			if (err != nil) != tc.wantErr {
				t.Errorf("UnmarshalCaddyfile() error = %v, wantErr %v", err, tc.wantErr)
				return
			}
			if !policiesEqual(h.ConnectionPolicies, tc.wantPolicies) {
				got, _ := json.Marshal(h.ConnectionPolicies)
				want, _ := json.Marshal(tc.wantPolicies)
				t.Errorf("UnmarshalCaddyfile() got policies = %s, want %s", got, want)
			}
		})
	}
}

// policiesEqual compares two ConnectionPolicies for equality, ignoring fields we don't care about in this test.
func policiesEqual(a, b caddytls.ConnectionPolicies) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] == nil && b[i] == nil {
			continue
		}
		if a[i] == nil || b[i] == nil {
			return false
		}
		if !reflect.DeepEqual(a[i], b[i]) {
			return false
		}
	}
	return true
}
