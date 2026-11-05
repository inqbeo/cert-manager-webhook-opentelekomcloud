package dns

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	golangsdk "github.com/opentelekomcloud/gophertelekomcloud"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
)

type fakeZone struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	ZoneType string `json:"zone_type"`
}

// fakeZones mimics GET /v2/zones of Open Telekom Cloud DNS: without a type
// parameter (or with type=public) only public zones are listed, with
// type=private only private ones, and the name filter matches fuzzily.
type fakeZones struct {
	mu      sync.Mutex
	zones   []fakeZone
	queries []url.Values
}

func newFakeZones(t *testing.T, zones ...fakeZone) (*fakeZones, *golangsdk.ServiceClient) {
	f := &fakeZones{zones: zones}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)

	// The SDK sets these defaults lazily on the first request.
	maxBackoffRetries, backoffRetryTimeout := 0, time.Duration(0)
	client := &golangsdk.ServiceClient{
		ProviderClient: &golangsdk.ProviderClient{
			HTTPClient:          *srv.Client(),
			MaxBackoffRetries:   &maxBackoffRetries,
			BackoffRetryTimeout: &backoffRetryTimeout,
		},
		Endpoint:     srv.URL + "/",
		ResourceBase: srv.URL + "/v2/",
	}
	return f, client
}

func (f *fakeZones) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || strings.TrimSuffix(r.URL.Path, "/") != "/v2/zones" {
		http.Error(w, "unexpected request", http.StatusNotImplemented)
		return
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	q := r.URL.Query()
	f.queries = append(f.queries, q)

	zoneType := q.Get("type")
	if zoneType == "" {
		zoneType = "public"
	}

	listed := []fakeZone{}
	// The SDK asks for a next page with a marker until a page is empty.
	if q.Get("marker") == "" {
		for _, z := range f.zones {
			if z.ZoneType == zoneType && strings.Contains(strings.ToLower(z.Name), strings.ToLower(strings.TrimSuffix(q.Get("name"), "."))) {
				listed = append(listed, z)
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"zones":    listed,
		"links":    map[string]string{},
		"metadata": map[string]int{"total_count": len(listed)},
	})
}

// listedTypes returns the type parameter of every list request without a
// marker, "-" standing for a request without one. The SDK sends the first
// request of a listing twice (AllPages fetches a test page first), so
// repeats of the same request are counted once.
func (f *fakeZones) listedTypes() []string {
	f.mu.Lock()
	defer f.mu.Unlock()

	types := []string{}
	previous := ""
	for _, q := range f.queries {
		if q.Get("marker") != "" || q.Encode() == previous {
			continue
		}
		previous = q.Encode()
		if _, ok := q["type"]; !ok {
			types = append(types, "-")
			continue
		}
		types = append(types, q.Get("type"))
	}
	return types
}

func zoneChallenge(t *testing.T, resolvedZone, zoneType string) *v1alpha1.ChallengeRequest {
	cfg := map[string]string{"region": "eu-de"}
	if zoneType != "" {
		cfg["zoneType"] = zoneType
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return &v1alpha1.ChallengeRequest{
		Action:       v1alpha1.ChallengeActionPresent,
		ResolvedZone: resolvedZone,
		ResolvedFQDN: "_acme-challenge." + resolvedZone,
		Config:       &extapi.JSON{Raw: raw},
	}
}

func resolveZone(t *testing.T, client *golangsdk.ServiceClient, resolvedZone, zoneType string) (string, error) {
	t.Helper()
	s := NewOpenTelekomCloudDnsProviderSolver(context.Background())
	s.dnsClient = client
	zone, err := s.getResolvedZone(zoneChallenge(t, resolvedZone, zoneType))
	if err != nil {
		return "", err
	}
	return zone.ID, nil
}

var (
	publicExample  = fakeZone{ID: "pub-example", Name: "example.com.", ZoneType: "public"}
	privateExample = fakeZone{ID: "priv-example", Name: "example.com.", ZoneType: "private"}
)

func TestLoadConfigZoneType(t *testing.T) {
	for _, zoneType := range []string{"", "public", "private", "auto"} {
		raw := `{"region":"eu-de","zoneType":"` + zoneType + `"}`
		cfg, err := loadConfig(&extapi.JSON{Raw: []byte(raw)})
		if err != nil {
			t.Errorf("zoneType %q: unexpected error: %v", zoneType, err)
			continue
		}
		if cfg.ZoneType != zoneType {
			t.Errorf("zoneType %q: decoded as %q", zoneType, cfg.ZoneType)
		}
	}
}

func TestInvalidZoneTypeFailsWithoutListingZones(t *testing.T) {
	for _, zoneType := range []string{"Private", "all", "internal"} {
		f, client := newFakeZones(t, publicExample, privateExample)

		id, err := resolveZone(t, client, "example.com.", zoneType)
		if err == nil {
			t.Errorf("zoneType %q: expected an error, got zone %s", zoneType, id)
		} else if !strings.Contains(err.Error(), zoneType) {
			t.Errorf("zoneType %q: expected the error to name it, got: %v", zoneType, err)
		}
		if got := f.listedTypes(); len(got) != 0 {
			t.Errorf("zoneType %q: expected no list request, got %v", zoneType, got)
		}
	}
}

func TestZoneTypeIsOmittedWhenUnset(t *testing.T) {
	encoded, err := json.Marshal(OpenTelekomCloudDnsProviderConfig{Region: "eu-de"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "zoneType") {
		t.Fatalf("zoneType must not be introduced in the config when not set, got %s", encoded)
	}
}

// Without zoneType the request is exactly the one sent before private zones
// were supported, and a private zone of the same name is never used.
func TestUnsetZoneTypeUsesPublicZoneOnly(t *testing.T) {
	f, client := newFakeZones(t, privateExample, publicExample)

	id, err := resolveZone(t, client, "example.com.", "")
	if err != nil {
		t.Fatal(err)
	}
	if id != publicExample.ID {
		t.Fatalf("expected zone %s, got %s", publicExample.ID, id)
	}
	if got := strings.Join(f.listedTypes(), ","); got != "-" {
		t.Fatalf("expected one list request without a type, got %s", got)
	}
}

func TestUnsetZoneTypeDoesNotFallBackToPrivate(t *testing.T) {
	_, client := newFakeZones(t, privateExample)

	if id, err := resolveZone(t, client, "example.com.", ""); err == nil {
		t.Fatalf("expected an error, got zone %s", id)
	}
}

func TestPublicZoneTypeUsesPublicZoneOnly(t *testing.T) {
	f, client := newFakeZones(t, privateExample, publicExample)

	id, err := resolveZone(t, client, "example.com.", "public")
	if err != nil {
		t.Fatal(err)
	}
	if id != publicExample.ID {
		t.Fatalf("expected zone %s, got %s", publicExample.ID, id)
	}
	if got := strings.Join(f.listedTypes(), ","); got != "-" {
		t.Fatalf("expected one list request without a type, got %s", got)
	}
}

func TestPrivateZoneTypeUsesPrivateZone(t *testing.T) {
	f, client := newFakeZones(t, publicExample, privateExample)

	id, err := resolveZone(t, client, "example.com.", "private")
	if err != nil {
		t.Fatal(err)
	}
	if id != privateExample.ID {
		t.Fatalf("expected zone %s, got %s", privateExample.ID, id)
	}
	if got := strings.Join(f.listedTypes(), ","); got != "private" {
		t.Fatalf("expected one list request for private zones, got %s", got)
	}
}

// The name filter of the API matches fuzzily, so other private zones whose
// names contain the resolved zone are listed too and must be ignored.
func TestPrivateZoneTypeMatchesNameExactly(t *testing.T) {
	_, client := newFakeZones(t,
		fakeZone{ID: "priv-sub", Name: "sub.example.com.", ZoneType: "private"},
		fakeZone{ID: "priv-myexample", Name: "myexample.com.", ZoneType: "private"},
		privateExample,
	)

	id, err := resolveZone(t, client, "example.com.", "private")
	if err != nil {
		t.Fatal(err)
	}
	if id != privateExample.ID {
		t.Fatalf("expected zone %s, got %s", privateExample.ID, id)
	}
}

func TestPrivateZoneTypeMatchesNameCaseAndDotInsensitively(t *testing.T) {
	_, client := newFakeZones(t, fakeZone{ID: "priv-example", Name: "Example.COM.", ZoneType: "private"})

	id, err := resolveZone(t, client, "example.com", "private")
	if err != nil {
		t.Fatal(err)
	}
	if id != "priv-example" {
		t.Fatalf("expected zone priv-example, got %s", id)
	}
}

func TestPrivateZoneTypeWithoutPrivateZoneFails(t *testing.T) {
	_, client := newFakeZones(t, publicExample,
		fakeZone{ID: "priv-sub", Name: "sub.example.com.", ZoneType: "private"})

	if id, err := resolveZone(t, client, "example.com.", "private"); err == nil {
		t.Fatalf("expected an error, got zone %s", id)
	}
}

// Private zones of the same name can exist for different VPCs; the webhook
// cannot know which one the CA resolves, so it does not guess.
func TestPrivateZoneTypeWithSeveralPrivateZonesOfTheNameFails(t *testing.T) {
	_, client := newFakeZones(t,
		fakeZone{ID: "priv-vpc-a", Name: "example.com.", ZoneType: "private"},
		fakeZone{ID: "priv-vpc-b", Name: "example.com.", ZoneType: "private"},
	)

	id, err := resolveZone(t, client, "example.com.", "private")
	if err == nil {
		t.Fatalf("expected an error, got zone %s", id)
	}
	for _, want := range []string{"priv-vpc-a", "priv-vpc-b"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("expected the error to name zone %s, got: %v", want, err)
		}
	}
}

func TestAutoZoneTypePrefersPublicZone(t *testing.T) {
	f, client := newFakeZones(t, privateExample, publicExample)

	id, err := resolveZone(t, client, "example.com.", "auto")
	if err != nil {
		t.Fatal(err)
	}
	if id != publicExample.ID {
		t.Fatalf("expected zone %s, got %s", publicExample.ID, id)
	}
	if got := strings.Join(f.listedTypes(), ","); got != "-" {
		t.Fatalf("expected only the public list request, got %s", got)
	}
}

func TestAutoZoneTypeFallsBackToPrivateZone(t *testing.T) {
	f, client := newFakeZones(t, privateExample,
		fakeZone{ID: "pub-other", Name: "other.com.", ZoneType: "public"})

	id, err := resolveZone(t, client, "example.com.", "auto")
	if err != nil {
		t.Fatal(err)
	}
	if id != privateExample.ID {
		t.Fatalf("expected zone %s, got %s", privateExample.ID, id)
	}
	if got := strings.Join(f.listedTypes(), ","); got != "-,private" {
		t.Fatalf("expected a public then a private list request, got %s", got)
	}
}

func TestAutoZoneTypeWithoutAnyZoneFails(t *testing.T) {
	_, client := newFakeZones(t)

	if id, err := resolveZone(t, client, "example.com.", "auto"); err == nil {
		t.Fatalf("expected an error, got zone %s", id)
	}
}

// A public zone whose name only contains the resolved zone is not a public
// zone of that name.
func TestAutoZoneTypeIgnoresFuzzyPublicMatches(t *testing.T) {
	_, client := newFakeZones(t, privateExample,
		fakeZone{ID: "pub-sub", Name: "sub.example.com.", ZoneType: "public"})

	id, err := resolveZone(t, client, "example.com.", "auto")
	if err != nil {
		t.Fatal(err)
	}
	if id != privateExample.ID {
		t.Fatalf("expected zone %s, got %s", privateExample.ID, id)
	}
}
