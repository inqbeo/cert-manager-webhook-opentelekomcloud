package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/akyriako/cert-manager-webhook-opentelekomcloud/pkg/dns"
	"os"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
	acmetest "github.com/cert-manager/cert-manager/test/acme"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/util/wait"
)

var (
	zone = os.Getenv("TEST_ZONE_NAME")
)

// HACK: Sets the controller-runtime logger otherwise test suite is raising a warning
func init() {
	opts := zap.Options{}
	logger := zap.New(zap.UseFlagOptions(&opts))
	logf.SetLogger(logger)
}

func TestRunsSuite(t *testing.T) {
	// The manifest path should contain a file named config.json that is a
	// snippet of valid configuration that should be included on the
	// ChallengeRequest passed as part of the test cases.

	//dnsIpAddress := dns.GetOpenTelekomCloudDnsServerAddress()

	fixture := acmetest.NewFixture(dns.NewOpenTelekomCloudDnsProviderSolver(context.Background()),
		acmetest.SetResolvedZone(zone),
		acmetest.SetAllowAmbientCredentials(false),
		acmetest.SetManifestPath("testdata/opentelekomcloud"),

		// Open Telekom Cloud DNS keeps all values of a name in one TXT record set.
		// Present adds its value to that record set and CleanUp removes only its
		// own, so the strict Extended/DeletingOneRecordRetainsOthers test applies.
		acmetest.SetStrict(true),
	)

	fixture.RunConformance(t)
}

func TestProjectNameConfiguration(t *testing.T) {
	cfg := dns.OpenTelekomCloudDnsProviderConfig{}
	if err := json.Unmarshal([]byte(`{"region":"eu-de"}`), &cfg); err != nil {
		t.Fatalf("decoding solver config failed: %v", err)
	}

	if cfg.ProjectName != "" {
		t.Fatalf("expected projectName to be unset, got %q", cfg.ProjectName)
	}

	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("encoding solver config failed: %v", err)
	}

	if strings.Contains(string(encoded), "projectName") {
		t.Fatalf("projectName must not be introduced in the config when not set, got %s", encoded)
	}

	cfg = dns.OpenTelekomCloudDnsProviderConfig{}
	if err := json.Unmarshal([]byte(`{"region":"eu-de","projectName":"my-project"}`), &cfg); err != nil {
		t.Fatalf("decoding solver config failed: %v", err)
	}

	if cfg.ProjectName != "my-project" {
		t.Fatalf("expected projectName to be my-project, got %q", cfg.ProjectName)
	}
}

// TestWildcardAndApexChallenges presents the challenges of a certificate for
// a domain and its wildcard at the same time, through two solvers as two
// webhook replicas would, and checks with cert-manager's own DNS check that
// both values are served together and that cleaning up one keeps the other.
func TestWildcardAndApexChallenges(t *testing.T) {
	if zone == "" {
		t.Skip("TEST_ZONE_NAME is not set")
	}

	config, err := os.ReadFile("testdata/opentelekomcloud/config.json")
	if err != nil {
		t.Fatal(err)
	}

	id := time.Now().UnixNano()
	domain := fmt.Sprintf("cm-webhook-%d.%s", id, zone)
	challenge := func(dnsName, key string) *v1alpha1.ChallengeRequest {
		return &v1alpha1.ChallengeRequest{
			DNSName:      dnsName,
			ResolvedFQDN: "_acme-challenge." + domain,
			ResolvedZone: zone,
			Key:          key,
			Config:       &extapi.JSON{Raw: config},
		}
	}
	apex := challenge(strings.TrimSuffix(domain, "."), fmt.Sprintf("apex-%d", id))
	wildcard := challenge("*."+strings.TrimSuffix(domain, "."), fmt.Sprintf("wildcard-%d", id))

	replicas := []*dns.OpenTelekomCloudDnsProviderSolver{
		dns.NewOpenTelekomCloudDnsProviderSolver(context.Background()),
		dns.NewOpenTelekomCloudDnsProviderSolver(context.Background()),
	}
	defer func() {
		_ = replicas[0].CleanUp(apex)
		_ = replicas[1].CleanUp(wildcard)
	}()

	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, ch := range []*v1alpha1.ChallengeRequest{apex, wildcard} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = replicas[i].Present(ch)
		}()
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatalf("expected Present to not error, but got: %v", err)
		}
	}

	served := func(key string) wait.ConditionWithContextFunc {
		return func(ctx context.Context) (bool, error) {
			return util.PreCheckDNS(ctx, apex.ResolvedFQDN, key, []string{"8.8.8.8:53"}, true)
		}
	}
	gone := func(key string) wait.ConditionWithContextFunc {
		return func(ctx context.Context) (bool, error) {
			ok, err := served(key)(ctx)
			return !ok, err
		}
	}
	waitFor := func(what string, conditions ...wait.ConditionWithContextFunc) {
		t.Helper()
		err := wait.PollUntilContextTimeout(t.Context(), 5*time.Second, 3*time.Minute, true, func(ctx context.Context) (bool, error) {
			for _, c := range conditions {
				if ok, err := c(ctx); !ok || err != nil {
					return false, nil
				}
			}
			return true, nil
		})
		if err != nil {
			t.Fatalf("waiting for %s: %v", what, err)
		}
	}

	waitFor("both values to be served", served(apex.Key), served(wildcard.Key))

	if err := replicas[0].CleanUp(apex); err != nil {
		t.Fatalf("expected CleanUp to not error, but got: %v", err)
	}
	waitFor("the apex value to be removed and the wildcard value to stay", gone(apex.Key), served(wildcard.Key))

	if err := replicas[1].CleanUp(wildcard); err != nil {
		t.Fatalf("expected CleanUp to not error, but got: %v", err)
	}
	waitFor("the wildcard value to be removed", gone(wildcard.Key))
}
