package dns

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	mathrand "math/rand"
	"strconv"
	"strings"
	"time"

	golangsdk "github.com/opentelekomcloud/gophertelekomcloud"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/dns/v2/recordsets"
	"k8s.io/klog/v2"
)

// The lock of a TXT record set is a second TXT record set in the same zone,
// named lockPrefix + the record set's name. Creating a record set is atomic
// (of several concurrent creates of one name exactly one succeeds, the others
// get DNS.0312), so whoever created the lock holds it. This works across
// webhook replicas, and across clusters sharing the zone, without any
// permissions beyond the DNS ones the webhook already has.
//
// The lock record holds a token "<random> <unix time>" of its holder. A lock
// older than lockStaleAfter is left over from a holder that died and is
// removed. A holder never writes after lockStaleAfter/2 and every API call is
// bounded by apiCallTimeout, so no write of a holder can land after its lock
// was taken as stale.

const (
	lockPrefix       = "_cert-manager-lock."
	lockDescription  = "cert-manager-webhook-opentelekomcloud: lock held while changing the TXT record set of the same name without this prefix"
	apiCallTimeout   = 2 * time.Minute
	releaseAttempts  = 3
	lockTokenRandLen = 8
)

var (
	// lockStaleAfter must exceed lockStaleAfter/2 + apiCallTimeout plus clock skew.
	lockStaleAfter = 5 * time.Minute
	// lockWaitTimeout is how long to wait for a lock held by someone else.
	// Changes to one record set take a few seconds each, so this covers a
	// queue of many; cert-manager retries a failed Present or CleanUp later.
	lockWaitTimeout = 90 * time.Second
	// lockPause waits before trying a taken lock again.
	lockPause = func() {
		time.Sleep(time.Second + time.Duration(mathrand.Intn(1000))*time.Millisecond)
	}
	now = time.Now
)

func lockName(fqdn string) string {
	return lockPrefix + fqdn
}

// recordSetLock is a held lock.
type recordSetLock struct {
	id string
	// writeUntil is the last moment the holder may start a write.
	writeUntil time.Time
}

func (l *recordSetLock) mayWrite() error {
	if now().After(l.writeUntil) {
		return fmt.Errorf("txt record set lock held too long, not writing any more")
	}
	return nil
}

func newLockToken(at time.Time) string {
	b := make([]byte, lockTokenRandLen)
	_, _ = rand.Read(b)
	return strconv.Quote(fmt.Sprintf("%s %d", hex.EncodeToString(b), at.Unix()))
}

// lockAge returns how old the lock record set rs is, from its holder's token,
// or from its creation time if the token cannot be read.
func lockAge(rs *recordsets.RecordSet) time.Duration {
	for _, r := range rs.Records {
		fields := strings.Fields(strings.Trim(r, `"`))
		if len(fields) == 2 {
			if t, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
				return now().Sub(time.Unix(t, 0))
			}
		}
	}
	if !rs.CreatedAt.IsZero() {
		return now().Sub(rs.CreatedAt)
	}
	return 0
}

// acquireRecordSetLock takes the lock of the TXT record set fqdn, waiting up
// to lockWaitTimeout while someone else holds it.
func (s *OpenTelekomCloudDnsProviderSolver) acquireRecordSetLock(zoneID, fqdn string) (*recordSetLock, error) {
	name := lockName(fqdn)
	deadline := now().Add(lockWaitTimeout)

	for {
		takenAt := now()
		token := newLockToken(takenAt)
		_, createErr := recordsets.Create(s.dnsClient, zoneID, recordsets.CreateOpts{
			Name:        name,
			Type:        txtRecordSetType,
			Records:     []string{token},
			Description: lockDescription,
		}).Extract()

		// The outcome of the create is decided by reading the lock back: a
		// create that failed with e.g. a 500 may still have been applied.
		lock, readErr := s.findTxtRecordSet(zoneID, name)
		switch {
		case readErr != nil:
			klog.InfoS("reading txt record set lock failed, retrying", "fqdn", fqdn, "err", readErr)
		case lock != nil && containsTxtValue(lock.Records, token):
			klog.V(verbosity).InfoS("acquired txt record set lock", "fqdn", fqdn, "id", lock.ID)
			return &recordSetLock{id: lock.ID, writeUntil: takenAt.Add(lockStaleAfter / 2)}, nil
		case lock != nil && lockAge(lock) > lockStaleAfter:
			klog.InfoS("removing stale txt record set lock", "fqdn", fqdn, "id", lock.ID, "records", lock.Records, "age", lockAge(lock))
			// By ID: if someone else replaced the stale lock in the meantime,
			// their lock is not touched.
			if err := recordsets.Delete(s.dnsClient, zoneID, lock.ID).ExtractErr(); err != nil {
				klog.InfoS("removing stale txt record set lock failed", "fqdn", fqdn, "id", lock.ID, "err", err)
			}
			continue
		case lock != nil:
			klog.V(verbosity).InfoS("txt record set is locked, waiting", "fqdn", fqdn, "holder", lock.Records)
		default:
			klog.V(verbosity).InfoS("txt record set lock not created, retrying", "fqdn", fqdn, "err", createErr)
		}

		if now().After(deadline) {
			holder := "unknown"
			if lock != nil {
				holder = strings.Join(lock.Records, ",")
			}
			return nil, fmt.Errorf("txt record set %s is locked by another webhook instance (lock %s, holder %s); giving up after %s", fqdn, name, holder, lockWaitTimeout)
		}
		lockPause()
	}
}

func (s *OpenTelekomCloudDnsProviderSolver) releaseRecordSetLock(zoneID, fqdn, lockID string) {
	var err error
	for attempt := 1; attempt <= releaseAttempts; attempt++ {
		err = recordsets.Delete(s.dnsClient, zoneID, lockID).ExtractErr()
		if err == nil || isNotFound(err) {
			klog.V(verbosity).InfoS("released txt record set lock", "fqdn", fqdn, "id", lockID)
			return
		}
		retryPause(attempt)
	}
	klog.ErrorS(err, "releasing txt record set lock failed; it expires as stale", "fqdn", fqdn, "id", lockID, "staleAfter", lockStaleAfter)
}

func isNotFound(err error) bool {
	var notFound golangsdk.ErrDefault404
	return errors.As(err, &notFound)
}
