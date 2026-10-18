package dns

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	golangsdk "github.com/opentelekomcloud/gophertelekomcloud"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
)

const (
	testZoneID = "zone-1"
	testZone   = "example.com."
	testFQDN   = "_acme-challenge.example.com."
)

type fakeRecordSet struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	Records []string `json:"records"`
	Status  string   `json:"status"`
}

// fakeDNS mimics the parts of the Open Telekom Cloud DNS API the solver uses:
// a fuzzy name filter, no data filter, PUT replacing the whole list of
// records and DNS.0312 for a second record set with the same name and type.
type fakeDNS struct {
	mu         sync.Mutex
	nextID     int
	recordSets map[string]*fakeRecordSet
	writes     int

	// beforeWrite and afterWrite let a test act as a concurrent writer.
	beforeWrite func(f *fakeDNS)
	afterWrite  func(f *fakeDNS)

	// failWrites makes that many writes answer 500 although they were applied.
	failWrites int
}

func newFakeDNS(t *testing.T) (*fakeDNS, *golangsdk.ServiceClient) {
	f := &fakeDNS{recordSets: map[string]*fakeRecordSet{}}
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

// put creates or replaces a record set directly, as another writer would.
func (f *fakeDNS) put(name string, records ...string) {
	if rs := f.find(name); rs != nil {
		rs.Records = records
		return
	}
	f.nextID++
	id := fmt.Sprintf("rs-%d", f.nextID)
	f.recordSets[id] = &fakeRecordSet{ID: id, Name: name, Type: "TXT", Records: records, Status: "ACTIVE"}
}

func (f *fakeDNS) find(name string) *fakeRecordSet {
	for _, rs := range f.recordSets {
		if rs.Name == name {
			return rs
		}
	}
	return nil
}

func (f *fakeDNS) records(name string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if rs := f.find(name); rs != nil {
		out := append([]string{}, rs.Records...)
		sort.Strings(out)
		return out
	}
	return nil
}

func (f *fakeDNS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	path := strings.TrimPrefix(r.URL.Path, "/v2/")
	parts := strings.Split(path, "/")
	q := r.URL.Query()

	reply := func(code int, body any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(body)
	}
	notFound := func() {
		reply(404, map[string]string{"code": "DNS.0313", "message": "This record set does not exist."})
	}
	// write runs apply, which answers itself when it refuses the change; an
	// applied change is answered with ok, or with 500 if failWrites says so.
	write := func(ok func(), apply func() bool) {
		f.writes++
		if f.beforeWrite != nil {
			f.beforeWrite(f)
		}
		applied := apply()
		if f.afterWrite != nil {
			f.afterWrite(f)
		}
		switch {
		case applied && f.failWrites > 0:
			f.failWrites--
			reply(500, map[string]string{"message": "Internal Server Error"})
		case applied:
			ok()
		}
	}

	switch {
	case r.Method == http.MethodGet && path == "zones":
		zones := []map[string]string{}
		if q.Get("marker") == "" {
			zones = append(zones, map[string]string{"id": testZoneID, "name": testZone})
		}
		reply(200, map[string]any{"zones": zones, "links": map[string]string{}})

	case r.Method == http.MethodGet && len(parts) == 3 && parts[2] == "recordsets":
		found := []*fakeRecordSet{}
		if q.Get("marker") == "" {
			for _, rs := range f.recordSets {
				if strings.Contains(rs.Name, strings.TrimSuffix(q.Get("name"), ".")) &&
					(q.Get("type") == "" || rs.Type == q.Get("type")) {
					found = append(found, rs)
				}
			}
		}
		reply(200, map[string]any{"recordsets": found, "links": map[string]string{}})

	case r.Method == http.MethodPost && len(parts) == 3:
		var body fakeRecordSet
		_ = json.NewDecoder(r.Body).Decode(&body)
		write(func() { reply(202, body) }, func() bool {
			for _, rs := range f.recordSets {
				if strings.EqualFold(rs.Name, body.Name) && rs.Type == body.Type {
					reply(400, map[string]string{"code": "DNS.0312", "message": "Attribute 'name' conflicts with Record Set."})
					return false
				}
			}
			f.put(body.Name, body.Records...)
			return true
		})

	case r.Method == http.MethodPut && len(parts) == 4:
		var body fakeRecordSet
		_ = json.NewDecoder(r.Body).Decode(&body)
		write(func() { reply(202, f.recordSets[parts[3]]) }, func() bool {
			rs, ok := f.recordSets[parts[3]]
			if !ok {
				notFound()
				return false
			}
			rs.Records = body.Records
			return true
		})

	case r.Method == http.MethodDelete && len(parts) == 4:
		write(func() { reply(202, map[string]string{}) }, func() bool {
			if _, ok := f.recordSets[parts[3]]; !ok {
				notFound()
				return false
			}
			delete(f.recordSets, parts[3])
			return true
		})

	default:
		reply(404, map[string]string{"message": "unexpected request " + r.Method + " " + r.URL.String()})
	}
}

func newTestSolver(client *golangsdk.ServiceClient) *OpenTelekomCloudDnsProviderSolver {
	s := NewOpenTelekomCloudDnsProviderSolver(context.Background())
	s.dnsClient = client
	return s
}

func challenge(key string) *v1alpha1.ChallengeRequest {
	return &v1alpha1.ChallengeRequest{
		ResolvedFQDN: testFQDN,
		ResolvedZone: testZone,
		Key:          key,
		Config:       &extapi.JSON{Raw: []byte(`{"region":"eu-de"}`)},
	}
}

func quoted(values ...string) []string {
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = `"` + v + `"`
	}
	sort.Strings(out)
	return out
}

func noPause(t *testing.T) {
	saved := retryPause
	retryPause = func(int) {}
	t.Cleanup(func() { retryPause = saved })
}

func assertRecords(t *testing.T, f *fakeDNS, name string, want []string) {
	t.Helper()
	got := f.records(name)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("records of %s: got %v, want %v", name, got, want)
	}
}

func TestPresentCreatesRecordSet(t *testing.T) {
	noPause(t)
	f, client := newFakeDNS(t)
	s := newTestSolver(client)

	if err := s.Present(challenge("a")); err != nil {
		t.Fatal(err)
	}
	assertRecords(t, f, testFQDN, quoted("a"))
}

func TestPresentAddsToExistingValues(t *testing.T) {
	noPause(t)
	f, client := newFakeDNS(t)
	f.put(testFQDN, `"wildcard"`)
	s := newTestSolver(client)

	if err := s.Present(challenge("apex")); err != nil {
		t.Fatal(err)
	}
	assertRecords(t, f, testFQDN, quoted("apex", "wildcard"))
}

func TestPresentIsIdempotent(t *testing.T) {
	noPause(t)
	f, client := newFakeDNS(t)
	s := newTestSolver(client)

	if err := s.Present(challenge("a")); err != nil {
		t.Fatal(err)
	}
	writes := f.writes
	if err := s.Present(challenge("a")); err != nil {
		t.Fatal(err)
	}
	if f.writes != writes {
		t.Fatalf("second Present wrote %d times, want 0", f.writes-writes)
	}
	assertRecords(t, f, testFQDN, quoted("a"))
}

func TestCleanUpRemovesOnlyOwnValue(t *testing.T) {
	noPause(t)
	f, client := newFakeDNS(t)
	s := newTestSolver(client)

	for _, key := range []string{"apex", "wildcard"} {
		if err := s.Present(challenge(key)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.CleanUp(challenge("apex")); err != nil {
		t.Fatal(err)
	}
	assertRecords(t, f, testFQDN, quoted("wildcard"))

	if err := s.CleanUp(challenge("wildcard")); err != nil {
		t.Fatal(err)
	}
	if rs := f.records(testFQDN); rs != nil {
		t.Fatalf("record set not deleted after its last value was cleaned up: %v", rs)
	}
}

func TestCleanUpWithoutRecordSet(t *testing.T) {
	noPause(t)
	f, client := newFakeDNS(t)
	s := newTestSolver(client)

	if err := s.CleanUp(challenge("a")); err != nil {
		t.Fatal(err)
	}
	if f.writes != 0 {
		t.Fatalf("CleanUp of a missing record set wrote %d times", f.writes)
	}
}

func TestOnlyExactNameIsTouched(t *testing.T) {
	noPause(t)
	f, client := newFakeDNS(t)
	other := "sub._acme-challenge.example.com."
	f.put(other, `"other"`)
	s := newTestSolver(client)

	if err := s.Present(challenge("a")); err != nil {
		t.Fatal(err)
	}
	if err := s.CleanUp(challenge("a")); err != nil {
		t.Fatal(err)
	}
	assertRecords(t, f, other, quoted("other"))
}

// Another writer creates the record set between our read and our create.
func TestPresentMergesAfterConcurrentCreate(t *testing.T) {
	noPause(t)
	f, client := newFakeDNS(t)
	f.beforeWrite = func(f *fakeDNS) {
		f.beforeWrite = nil
		f.put(testFQDN, `"wildcard"`)
	}
	s := newTestSolver(client)

	if err := s.Present(challenge("apex")); err != nil {
		t.Fatal(err)
	}
	assertRecords(t, f, testFQDN, quoted("apex", "wildcard"))
}

// Another writer overwrites our write; Present must notice and write again.
func TestPresentRepairsLostUpdate(t *testing.T) {
	noPause(t)
	f, client := newFakeDNS(t)
	f.put(testFQDN, `"x"`)
	f.afterWrite = func(f *fakeDNS) {
		f.afterWrite = nil
		f.put(testFQDN, `"x"`, `"wildcard"`)
	}
	s := newTestSolver(client)

	if err := s.Present(challenge("apex")); err != nil {
		t.Fatal(err)
	}
	assertRecords(t, f, testFQDN, quoted("apex", "wildcard", "x"))
}

// A write answers 500 although it was applied: the read-back decides.
func TestWriteFailedButApplied(t *testing.T) {
	noPause(t)
	f, client := newFakeDNS(t)
	f.failWrites = 2
	s := newTestSolver(client)

	if err := s.Present(challenge("a")); err != nil {
		t.Fatal(err)
	}
	if err := s.CleanUp(challenge("a")); err != nil {
		t.Fatal(err)
	}
	if f.writes != 2 {
		t.Fatalf("wrote %d times, want 2 (one create, one delete)", f.writes)
	}
	if rs := f.records(testFQDN); rs != nil {
		t.Fatalf("record set left: %v", rs)
	}
}

func TestPresentGivesUp(t *testing.T) {
	noPause(t)
	f, client := newFakeDNS(t)
	f.afterWrite = func(f *fakeDNS) { f.put(testFQDN, `"someone-else"`) }
	s := newTestSolver(client)

	err := s.Present(challenge("a"))
	if err == nil || !strings.Contains(err.Error(), "after 6 attempts") {
		t.Fatalf("expected Present to give up, got %v", err)
	}
}
