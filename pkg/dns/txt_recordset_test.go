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

var testLock = lockName(testFQDN)

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

	// challengeWrites counts writes to record sets other than locks;
	// unlocked counts those made while the record set's lock did not exist.
	challengeWrites int
	unlocked        int

	// beforeWrite and afterWrite let a test act as a concurrent writer that
	// does not take the lock; they are called around writes to record sets
	// other than locks.
	beforeWrite func(f *fakeDNS)
	afterWrite  func(f *fakeDNS)

	// failLockCreates makes that many lock creates answer 500 although they
	// were applied.
	failLockCreates int
}

func newFakeDNS(t *testing.T) (*fakeDNS, *golangsdk.ServiceClient) {
	f := &fakeDNS{recordSets: map[string]*fakeRecordSet{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)

	// The SDK sets these defaults lazily on the first request, which races
	// when the first requests run concurrently.
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
	for _, rs := range f.recordSets {
		if rs.Name == name {
			rs.Records = records
			return
		}
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

func (f *fakeDNS) locks() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []string{}
	for _, rs := range f.recordSets {
		if strings.HasPrefix(rs.Name, lockPrefix) {
			out = append(out, rs.Name)
		}
	}
	return out
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
		f.write(body.Name, func() {
			for _, rs := range f.recordSets {
				if strings.EqualFold(rs.Name, body.Name) && rs.Type == body.Type {
					reply(400, map[string]string{"code": "DNS.0312", "message": "Attribute 'name' conflicts with Record Set."})
					return
				}
			}
			f.put(body.Name, body.Records...)
			if strings.HasPrefix(body.Name, lockPrefix) && f.failLockCreates > 0 {
				f.failLockCreates--
				reply(500, map[string]string{"message": "Internal Server Error"})
				return
			}
			reply(202, body)
		})

	case r.Method == http.MethodPut && len(parts) == 4:
		var body fakeRecordSet
		_ = json.NewDecoder(r.Body).Decode(&body)
		rs, ok := f.recordSets[parts[3]]
		if !ok {
			notFound()
			return
		}
		f.write(rs.Name, func() {
			if rs, ok := f.recordSets[parts[3]]; ok {
				rs.Records = body.Records
				reply(202, rs)
				return
			}
			notFound()
		})

	case r.Method == http.MethodDelete && len(parts) == 4:
		rs, ok := f.recordSets[parts[3]]
		if !ok {
			notFound()
			return
		}
		f.write(rs.Name, func() {
			if _, ok := f.recordSets[parts[3]]; ok {
				delete(f.recordSets, parts[3])
				reply(202, map[string]string{})
				return
			}
			notFound()
		})

	default:
		reply(404, map[string]string{"message": "unexpected request " + r.Method + " " + r.URL.String()})
	}
}

func (f *fakeDNS) write(name string, apply func()) {
	if strings.HasPrefix(name, lockPrefix) {
		apply()
		return
	}

	f.challengeWrites++
	if f.find(lockName(name)) == nil {
		f.unlocked++
	}
	if f.beforeWrite != nil {
		f.beforeWrite(f)
	}
	apply()
	if f.afterWrite != nil {
		f.afterWrite(f)
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
	savedRetry, savedLock, savedWait, savedNow := retryPause, lockPause, lockWaitTimeout, now
	retryPause, lockPause = func(int) {}, func() {}
	t.Cleanup(func() { retryPause, lockPause, lockWaitTimeout, now = savedRetry, savedLock, savedWait, savedNow })
}

func assertRecords(t *testing.T, f *fakeDNS, name string, want []string) {
	t.Helper()
	got := f.records(name)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("records of %s: got %v, want %v", name, got, want)
	}
}

func assertUnlocked(t *testing.T, f *fakeDNS) {
	t.Helper()
	if locks := f.locks(); len(locks) != 0 {
		t.Fatalf("locks left behind: %v", locks)
	}
	if f.unlocked != 0 {
		t.Fatalf("%d writes without holding the lock", f.unlocked)
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
	assertUnlocked(t, f)
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
	assertUnlocked(t, f)
}

func TestPresentIsIdempotent(t *testing.T) {
	noPause(t)
	f, client := newFakeDNS(t)
	s := newTestSolver(client)

	if err := s.Present(challenge("a")); err != nil {
		t.Fatal(err)
	}
	writes := f.challengeWrites
	if err := s.Present(challenge("a")); err != nil {
		t.Fatal(err)
	}
	if f.challengeWrites != writes {
		t.Fatalf("second Present wrote %d times, want 0", f.challengeWrites-writes)
	}
	assertRecords(t, f, testFQDN, quoted("a"))
	assertUnlocked(t, f)
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
	assertUnlocked(t, f)
}

func TestCleanUpWithoutRecordSet(t *testing.T) {
	noPause(t)
	f, client := newFakeDNS(t)
	s := newTestSolver(client)

	if err := s.CleanUp(challenge("a")); err != nil {
		t.Fatal(err)
	}
	if f.challengeWrites != 0 {
		t.Fatalf("CleanUp of a missing record set wrote %d times", f.challengeWrites)
	}
	assertUnlocked(t, f)
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
	assertUnlocked(t, f)
}

// A writer that does not take the lock creates the record set between our
// read and our create.
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
	assertUnlocked(t, f)
}

// A writer that does not take the lock overwrites our write; Present must
// notice and write again.
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
	assertUnlocked(t, f)
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
	assertUnlocked(t, f)
}

// Another webhook instance holds the lock and releases it after a while.
func TestWaitsForLock(t *testing.T) {
	noPause(t)
	f, client := newFakeDNS(t)
	f.put(testLock, newLockToken(time.Now()))
	waits := 0
	lockPause = func() {
		waits++
		if waits == 3 {
			f.mu.Lock()
			delete(f.recordSets, f.find(testLock).ID)
			f.mu.Unlock()
		}
	}
	s := newTestSolver(client)

	if err := s.Present(challenge("a")); err != nil {
		t.Fatal(err)
	}
	if waits != 3 {
		t.Fatalf("waited %d times for the lock, want 3", waits)
	}
	assertRecords(t, f, testFQDN, quoted("a"))
	assertUnlocked(t, f)
}

func TestGivesUpOnHeldLock(t *testing.T) {
	noPause(t)
	lockWaitTimeout = 0
	f, client := newFakeDNS(t)
	token := newLockToken(time.Now())
	f.put(testLock, token)
	s := newTestSolver(client)

	err := s.Present(challenge("a"))
	if err == nil || !strings.Contains(err.Error(), "locked by another webhook instance") {
		t.Fatalf("expected Present to fail on the held lock, got %v", err)
	}
	if f.challengeWrites != 0 {
		t.Fatalf("wrote %d times without the lock", f.challengeWrites)
	}
	assertRecords(t, f, testLock, []string{token})
}

func TestRemovesStaleLock(t *testing.T) {
	noPause(t)
	f, client := newFakeDNS(t)
	f.put(testLock, newLockToken(time.Now().Add(-lockStaleAfter-time.Minute)))
	s := newTestSolver(client)

	if err := s.Present(challenge("a")); err != nil {
		t.Fatal(err)
	}
	assertRecords(t, f, testFQDN, quoted("a"))
	assertUnlocked(t, f)
}

// The create of the lock answers 500 but was applied: the lock is ours.
func TestLockCreateFailedButApplied(t *testing.T) {
	noPause(t)
	f, client := newFakeDNS(t)
	f.failLockCreates = 1
	s := newTestSolver(client)

	if err := s.Present(challenge("a")); err != nil {
		t.Fatal(err)
	}
	assertRecords(t, f, testFQDN, quoted("a"))
	assertUnlocked(t, f)
}

// A holder must not write once its lock may be taken as stale.
func TestStopsWritingWhenLockHeldTooLong(t *testing.T) {
	noPause(t)
	f, client := newFakeDNS(t)
	f.afterWrite = func(f *fakeDNS) { f.put(testFQDN, `"someone-else"`) }
	start := time.Now()
	clock := start
	now = func() time.Time { return clock }
	retryPause = func(int) { clock = clock.Add(lockStaleAfter/2 + time.Second) }
	s := newTestSolver(client)

	err := s.Present(challenge("a"))
	if err == nil || !strings.Contains(err.Error(), "held too long") {
		t.Fatalf("expected Present to stop writing, got %v", err)
	}
	if f.challengeWrites != 1 {
		t.Fatalf("wrote %d times, want 1", f.challengeWrites)
	}
	assertUnlocked(t, f)
}

// Two replicas (two solvers) present and clean up the values of several
// overlapping challenges for one name at the same time; no write may happen
// without the lock and no value may get lost.
func TestReplicasPresentAndCleanUpConcurrently(t *testing.T) {
	noPause(t)
	lockPause = func() { time.Sleep(time.Millisecond) }

	for round := 0; round < 20; round++ {
		f, client := newFakeDNS(t)
		replicas := []*OpenTelekomCloudDnsProviderSolver{newTestSolver(client), newTestSolver(client)}
		keys := []string{"apex", "wildcard", "apex-renewal", "wildcard-renewal"}

		run := func(op func(s *OpenTelekomCloudDnsProviderSolver, ch *v1alpha1.ChallengeRequest) error) {
			var wg sync.WaitGroup
			errs := make(chan error, len(keys))
			for i, key := range keys {
				wg.Add(1)
				go func(s *OpenTelekomCloudDnsProviderSolver, key string) {
					defer wg.Done()
					errs <- op(s, challenge(key))
				}(replicas[i%2], key)
			}
			wg.Wait()
			close(errs)
			for err := range errs {
				if err != nil {
					t.Fatalf("round %d: %v", round, err)
				}
			}
		}

		run((*OpenTelekomCloudDnsProviderSolver).Present)
		assertRecords(t, f, testFQDN, quoted(keys...))

		run((*OpenTelekomCloudDnsProviderSolver).CleanUp)
		if rs := f.records(testFQDN); rs != nil {
			t.Fatalf("round %d: record set left after cleaning up all values: %v", round, rs)
		}
		assertUnlocked(t, f)
	}
}
