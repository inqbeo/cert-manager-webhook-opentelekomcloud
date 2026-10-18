//go:build live

// Live tests against a real Open Telekom Cloud DNS zone.
//
//	OS_ACCESS_KEY=... OS_SECRET_KEY=... TEST_ZONE_NAME=example.org. \
//	  go test -tags live -run Live -v -timeout 60m ./pkg/dns/
package dns

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
	"github.com/miekg/dns"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/dns/v2/recordsets"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/klog/v2"
)

func init() {
	klog.InitFlags(nil)
	_ = flag.Set("v", "4")
}

// observe logs every change of fqdn's records, as seen by an independent
// client polling the API, until stop is closed.
func (l *live) observe(fqdn string) (stop func()) {
	done := make(chan struct{})
	finished := make(chan struct{})
	o := replica()
	_ = o.setOpenTelekomCloudDnsServiceClient(l.challenge(fqdn, "observer"))
	go func() {
		defer close(finished)
		last := "-"
		for {
			select {
			case <-done:
				return
			default:
			}
			rs, err := o.findTxtRecordSet(l.zoneID, fqdn)
			now := "<none>"
			switch {
			case err != nil:
				now = "ERR " + err.Error()
			case rs != nil:
				now = rs.ID[len(rs.ID)-6:] + " " + strings.Join(rs.Records, ",")
			}
			if now != last {
				klog.InfoS("OBSERVED", "fqdn", fqdn, "state", now)
				last = now
			}
			time.Sleep(300 * time.Millisecond)
		}
	}()
	return func() { close(done); <-finished }
}

// ns1.open-telekom-cloud.com, ns2.open-telekom-cloud.com
var authoritative = []string{"80.158.48.19:53", "93.188.242.252:53"}

type live struct {
	t      *testing.T
	zone   string
	zoneID string
	api    *OpenTelekomCloudDnsProviderSolver // only reads, as an observer
}

func newLive(t *testing.T) *live {
	zone := os.Getenv("TEST_ZONE_NAME")
	if zone == "" || os.Getenv("OS_ACCESS_KEY") == "" {
		t.Skip("TEST_ZONE_NAME and OS_ACCESS_KEY/OS_SECRET_KEY are required")
	}
	l := &live{t: t, zone: zone, api: replica()}
	ch := l.challenge("probe", "probe")
	if err := l.api.setOpenTelekomCloudDnsServiceClient(ch); err != nil {
		t.Fatal(err)
	}
	z, err := l.api.getResolvedZone(ch)
	if err != nil {
		t.Fatal(err)
	}
	l.zoneID = z.ID
	return l
}

// replica is a solver with its own client and locks, like one webhook pod.
func replica() *OpenTelekomCloudDnsProviderSolver {
	return NewOpenTelekomCloudDnsProviderSolver(context.Background())
}

func (l *live) name(prefix string) string {
	return fmt.Sprintf("_acme-challenge.%s-%d.%s", prefix, time.Now().UnixNano(), l.zone)
}

func (l *live) challenge(fqdn, key string) *v1alpha1.ChallengeRequest {
	return &v1alpha1.ChallengeRequest{
		ResolvedFQDN: fqdn,
		ResolvedZone: l.zone,
		Key:          key,
		Config:       &extapi.JSON{Raw: []byte(`{"region":"eu-de"}`)},
	}
}

// records returns the values of fqdn's TXT record set via the API, unquoted and sorted.
func (l *live) records(fqdn string) []string {
	l.t.Helper()
	rs, err := l.api.findTxtRecordSet(l.zoneID, fqdn)
	if err != nil {
		l.t.Fatal(err)
	}
	if rs == nil {
		return nil
	}
	out := []string{}
	for _, r := range rs.Records {
		out = append(out, strings.Trim(r, `"`))
	}
	sort.Strings(out)
	return out
}

func (l *live) expect(fqdn string, want ...string) {
	l.t.Helper()
	sort.Strings(want)
	got := l.records(fqdn)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		l.t.Fatalf("API records of %s: got %v, want %v", fqdn, got, want)
	}
}

// expectNoLock fails if the lock of fqdn was left behind.
func (l *live) expectNoLock(fqdn string) {
	l.t.Helper()
	rs, err := l.api.findTxtRecordSet(l.zoneID, lockName(fqdn))
	if err != nil {
		l.t.Fatal(err)
	}
	if rs != nil {
		l.t.Fatalf("lock of %s left behind: %v", fqdn, rs.Records)
	}
}

// expectDNS waits until both authoritative name servers answer exactly want.
func (l *live) expectDNS(fqdn string, want ...string) time.Duration {
	l.t.Helper()
	sort.Strings(want)
	start := time.Now()
	var last string
	for time.Since(start) < 3*time.Minute {
		ok := true
		for _, ns := range authoritative {
			msg, err := util.DNSQuery(context.Background(), fqdn, dns.TypeTXT, []string{ns}, false)
			if err != nil {
				ok = false
				last = err.Error()
				break
			}
			got := []string{}
			for _, rr := range msg.Answer {
				if txt, isTXT := rr.(*dns.TXT); isTXT {
					got = append(got, strings.Join(txt.Txt, ""))
				}
			}
			sort.Strings(got)
			last = fmt.Sprintf("%s: %v", ns, got)
			if strings.Join(got, ",") != strings.Join(want, ",") {
				ok = false
				break
			}
		}
		if ok {
			return time.Since(start)
		}
		time.Sleep(2 * time.Second)
	}
	l.t.Fatalf("authoritative DNS for %s never showed %v, last: %s", fqdn, want, last)
	return 0
}

func (l *live) remove(fqdn string) {
	for _, name := range []string{fqdn, lockName(fqdn)} {
		rs, err := l.api.findTxtRecordSet(l.zoneID, name)
		if err == nil && rs != nil {
			_ = recordsets.Delete(l.api.dnsClient, l.zoneID, rs.ID).ExtractErr()
		}
	}
}

type call struct {
	what string
	err  error
	took time.Duration
}

// parallel runs fns at the same time and fails on any error.
func (l *live) parallel(fns map[string]func() error) {
	l.t.Helper()
	var wg sync.WaitGroup
	results := make(chan call, len(fns))
	for what, fn := range fns {
		wg.Add(1)
		go func() {
			defer wg.Done()
			start := time.Now()
			err := fn()
			results <- call{what, err, time.Since(start)}
		}()
	}
	wg.Wait()
	close(results)
	for r := range results {
		l.t.Logf("  %-28s %6.1fs err=%v", r.what, r.took.Seconds(), r.err)
		if r.err != nil {
			l.t.Errorf("%s: %v", r.what, r.err)
		}
	}
	if l.t.Failed() {
		l.t.FailNow()
	}
}

func TestLiveSequential(t *testing.T) {
	l := newLive(t)
	s := replica()
	fqdn := l.name("seq")
	defer l.remove(fqdn)

	if err := s.CleanUp(l.challenge(fqdn, "nothing")); err != nil {
		t.Fatalf("CleanUp without record set: %v", err)
	}
	for _, step := range []struct {
		op   func(*v1alpha1.ChallengeRequest) error
		key  string
		want []string
	}{
		{s.Present, "a", []string{"a"}},
		{s.Present, "a", []string{"a"}}, // idempotent
		{s.Present, "b", []string{"a", "b"}},
		{s.CleanUp, "a", []string{"b"}},
		{s.CleanUp, "a", []string{"b"}}, // idempotent
		{s.CleanUp, "b", nil},
	} {
		start := time.Now()
		if err := step.op(l.challenge(fqdn, step.key)); err != nil {
			t.Fatal(err)
		}
		t.Logf("  %s took %.1fs", step.key, time.Since(start).Seconds())
		l.expect(fqdn, step.want...)
	}
	l.expectNoLock(fqdn)
	l.expectDNS(fqdn)
}

// Wildcard and apex challenges presented at the same time on two replicas,
// cleaned up one after the other as their validations finish.
func TestLiveWildcardAndApexOnTwoReplicas(t *testing.T) {
	l := newLive(t)
	rounds := 10
	for round := 1; round <= rounds; round++ {
		r1, r2 := replica(), replica()
		fqdn := l.name("wa")
		apex, wildcard := l.challenge(fqdn, fmt.Sprintf("apex-%d", round)), l.challenge(fqdn, fmt.Sprintf("wildcard-%d", round))
		t.Logf("round %d: %s", round, fqdn)

		l.parallel(map[string]func() error{
			"present apex (replica 1)":     func() error { return r1.Present(apex) },
			"present wildcard (replica 2)": func() error { return r2.Present(wildcard) },
		})
		l.expect(fqdn, apex.Key, wildcard.Key)
		if round == 1 || round == rounds {
			t.Logf("  authoritative DNS shows both after %.1fs", l.expectDNS(fqdn, apex.Key, wildcard.Key).Seconds())
		}

		if err := r1.CleanUp(apex); err != nil {
			t.Fatal(err)
		}
		l.expect(fqdn, wildcard.Key)
		if err := r2.CleanUp(wildcard); err != nil {
			t.Fatal(err)
		}
		l.expect(fqdn)
		l.expectNoLock(fqdn)
		l.remove(fqdn)
	}
}

// Four overlapping challenges on one name (e.g. two certificates covering
// the same domain renewing together), presented and cleaned up all at once.
func TestLiveFourChallengesOnTwoReplicas(t *testing.T) {
	l := newLive(t)
	for round := 1; round <= 10; round++ {
		replicas := []*OpenTelekomCloudDnsProviderSolver{replica(), replica()}
		fqdn := l.name("four")
		t.Logf("round %d: %s", round, fqdn)
		stop := l.observe(fqdn)
		keys := []string{"k1", "k2", "k3", "k4"}

		present, cleanUp := map[string]func() error{}, map[string]func() error{}
		for i, key := range keys {
			s, ch := replicas[i%2], l.challenge(fqdn, key)
			present[fmt.Sprintf("present %s (replica %d)", key, i%2+1)] = func() error { return s.Present(ch) }
			cleanUp[fmt.Sprintf("clean up %s (replica %d)", key, i%2+1)] = func() error { return s.CleanUp(ch) }
		}
		l.parallel(present)
		l.expect(fqdn, keys...)
		l.parallel(cleanUp)
		time.Sleep(2 * time.Second)
		stop()
		l.expect(fqdn)
		l.expectNoLock(fqdn)
		l.remove(fqdn)
	}
}

// One challenge is cleaned up on one replica while another is presented on
// the other replica.
func TestLiveCleanUpWhilePresenting(t *testing.T) {
	l := newLive(t)
	for round := 1; round <= 5; round++ {
		r1, r2 := replica(), replica()
		fqdn := l.name("mix")
		t.Logf("round %d: %s", round, fqdn)
		old, keep, fresh := l.challenge(fqdn, "old"), l.challenge(fqdn, "keep"), l.challenge(fqdn, "new")
		for _, ch := range []*v1alpha1.ChallengeRequest{old, keep} {
			if err := r1.Present(ch); err != nil {
				t.Fatal(err)
			}
		}

		l.parallel(map[string]func() error{
			"clean up old (replica 1)": func() error { return r1.CleanUp(old) },
			"present new (replica 2)":  func() error { return r2.Present(fresh) },
		})
		l.expect(fqdn, "keep", "new")

		// the last value goes while another one is added
		l.parallel(map[string]func() error{
			"clean up keep (replica 1)": func() error { return r1.CleanUp(keep) },
			"clean up new (replica 2)":  func() error { return r2.CleanUp(fresh) },
		})
		l.expect(fqdn)
		l.expectNoLock(fqdn)
		l.remove(fqdn)
	}
}

// Eight challenges on one name, spread over four replicas, all at once.
func TestLiveEightChallengesOnFourReplicas(t *testing.T) {
	l := newLive(t)
	for round := 1; round <= 3; round++ {
		replicas := []*OpenTelekomCloudDnsProviderSolver{replica(), replica(), replica(), replica()}
		fqdn := l.name("eight")
		t.Logf("round %d: %s", round, fqdn)
		stop := l.observe(fqdn)
		keys := []string{"k1", "k2", "k3", "k4", "k5", "k6", "k7", "k8"}

		present, cleanUp := map[string]func() error{}, map[string]func() error{}
		for i, key := range keys {
			s, ch := replicas[i%4], l.challenge(fqdn, key)
			present[fmt.Sprintf("present %s (replica %d)", key, i%4+1)] = func() error { return s.Present(ch) }
			cleanUp[fmt.Sprintf("clean up %s (replica %d)", key, i%4+1)] = func() error { return s.CleanUp(ch) }
		}
		l.parallel(present)
		l.expect(fqdn, keys...)
		l.expectNoLock(fqdn)
		l.parallel(cleanUp)
		time.Sleep(2 * time.Second)
		stop()
		l.expect(fqdn)
		l.expectNoLock(fqdn)
		l.remove(fqdn)
	}
}
