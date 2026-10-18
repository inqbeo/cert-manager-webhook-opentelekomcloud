package dns

import (
	"strings"
	"testing"

	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
)

func TestTTLConfiguration(t *testing.T) {
	for _, tc := range []struct {
		config  string
		ttl     int
		wantErr bool
	}{
		{config: `{"region":"eu-de"}`, ttl: 0},
		{config: `{"region":"eu-de","ttl":60}`, ttl: 60},
		{config: `{"region":"eu-de","ttl":1}`, ttl: 1},
		{config: `{"region":"eu-de","ttl":2147483647}`, ttl: 2147483647},
		{config: `{"region":"eu-de","ttl":-1}`, wantErr: true},
		{config: `{"region":"eu-de","ttl":2147483648}`, wantErr: true},
	} {
		cfg, err := loadConfig(&extapi.JSON{Raw: []byte(tc.config)})
		switch {
		case tc.wantErr && (err == nil || !strings.Contains(err.Error(), "ttl")):
			t.Errorf("%s: expected a ttl error, got %v", tc.config, err)
		case !tc.wantErr && err != nil:
			t.Errorf("%s: unexpected error %v", tc.config, err)
		case !tc.wantErr && cfg.TTL != tc.ttl:
			t.Errorf("%s: got ttl %d, want %d", tc.config, cfg.TTL, tc.ttl)
		}
	}
}
