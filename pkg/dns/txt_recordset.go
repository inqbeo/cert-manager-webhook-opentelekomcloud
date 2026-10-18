package dns

import (
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/opentelekomcloud/gophertelekomcloud/openstack/dns/v2/recordsets"
	"k8s.io/klog/v2"
)

// Open Telekom Cloud DNS keeps all TXT values of one name in one record set
// (a second record set with the same name and type is rejected with DNS.0312).
// One name can carry several challenge values, so Present adds its value to
// that record set and CleanUp removes only its own value, as the webhook
// contract requires. Every change is read back before it counts.

const maxWriteAttempts = 6

// retryPause waits before the record set is read back after a write. It grows
// per attempt and is jittered.
var retryPause = func(attempt int) {
	time.Sleep(time.Duration(attempt)*500*time.Millisecond + time.Duration(rand.Intn(500))*time.Millisecond)
}

// presentTxtValue makes sure value is one of the records of fqdn, keeping all others.
func (s *OpenTelekomCloudDnsProviderSolver) presentTxtValue(zoneID, fqdn, value string) error {
	return s.converge(zoneID, fqdn, value,
		func(rs *recordsets.RecordSet) bool {
			return rs != nil && containsTxtValue(rs.Records, value)
		},
		func(rs *recordsets.RecordSet) error {
			if rs == nil {
				klog.V(verbosity).InfoS("creating txt record set", "fqdn", fqdn, "records", []string{value})
				_, err := recordsets.Create(s.dnsClient, zoneID, recordsets.CreateOpts{
					Name:    fqdn,
					Type:    txtRecordSetType,
					Records: []string{value},
				}).Extract()
				return err
			}

			records := append(append([]string{}, rs.Records...), value)
			klog.V(verbosity).InfoS("updating txt record set", "fqdn", fqdn, "id", rs.ID, "records", records)
			_, err := recordsets.Update(s.dnsClient, zoneID, rs.ID, recordsets.UpdateOpts{Records: records}).Extract()
			return err
		},
	)
}

// cleanUpTxtValue removes value from the records of fqdn, keeping all others.
// The record set is deleted only when value was its last record.
func (s *OpenTelekomCloudDnsProviderSolver) cleanUpTxtValue(zoneID, fqdn, value string) error {
	return s.converge(zoneID, fqdn, value,
		func(rs *recordsets.RecordSet) bool {
			return rs == nil || !containsTxtValue(rs.Records, value)
		},
		func(rs *recordsets.RecordSet) error {
			remaining := withoutTxtValue(rs.Records, value)
			klog.V(verbosity).InfoS("removing txt record", "fqdn", fqdn, "id", rs.ID, "records", remaining)
			if len(remaining) == 0 {
				return recordsets.Delete(s.dnsClient, zoneID, rs.ID).ExtractErr()
			}

			_, err := recordsets.Update(s.dnsClient, zoneID, rs.ID, recordsets.UpdateOpts{Records: remaining}).Extract()
			return err
		},
	)
}

// converge reads the TXT record set of fqdn until done reports the wanted
// state, calling write whenever it is not there. A failed write is not final
// (e.g. a 500 may still have been applied); the next read decides.
func (s *OpenTelekomCloudDnsProviderSolver) converge(
	zoneID, fqdn, value string,
	done func(*recordsets.RecordSet) bool,
	write func(*recordsets.RecordSet) error,
) error {
	var lastErr error
	for attempt := 1; ; attempt++ {
		rs, err := s.findTxtRecordSet(zoneID, fqdn)
		if err != nil {
			return err
		}
		if rs != nil {
			klog.V(verbosity).InfoS("read txt record set", "fqdn", fqdn, "value", value, "attempt", attempt, "id", rs.ID, "records", rs.Records)
		} else {
			klog.V(verbosity).InfoS("read txt record set", "fqdn", fqdn, "value", value, "attempt", attempt, "id", nil)
		}

		if done(rs) {
			return nil
		}
		if attempt > maxWriteAttempts {
			return fmt.Errorf("txt record set %s not in the expected state after %d attempts, last error: %v", fqdn, maxWriteAttempts, lastErr)
		}

		start := time.Now()
		lastErr = write(rs)
		klog.V(verbosity).InfoS("wrote txt record set", "fqdn", fqdn, "value", value, "attempt", attempt, "took", time.Since(start), "err", lastErr)
		if lastErr != nil {
			klog.InfoS("txt record set write failed, retrying", "fqdn", fqdn, "value", value, "attempt", attempt, "err", lastErr)
		}

		retryPause(attempt)
	}
}

// findTxtRecordSet returns the TXT record set named exactly fqdn, or nil.
// The name filter of the API matches fuzzily, so the name is compared here.
func (s *OpenTelekomCloudDnsProviderSolver) findTxtRecordSet(zoneID, fqdn string) (*recordsets.RecordSet, error) {
	allPages, err := recordsets.ListByZone(s.dnsClient, zoneID, recordsets.ListOpts{
		Name: fqdn,
		Type: txtRecordSetType,
	}).AllPages()
	if err != nil {
		return nil, err
	}

	allRecordSets, err := recordsets.ExtractRecordSets(allPages)
	if err != nil {
		return nil, err
	}

	for i := range allRecordSets {
		if allRecordSets[i].Type == txtRecordSetType && normalizeFQDN(allRecordSets[i].Name) == normalizeFQDN(fqdn) {
			return &allRecordSets[i], nil
		}
	}

	return nil, nil
}

func normalizeFQDN(fqdn string) string {
	return strings.ToLower(strings.TrimSuffix(fqdn, "."))
}

// TXT records are compared without their quotes: the API returns them quoted.
func sameTxtValue(a, b string) bool {
	return strings.Trim(a, `"`) == strings.Trim(b, `"`)
}

func containsTxtValue(records []string, value string) bool {
	for _, r := range records {
		if sameTxtValue(r, value) {
			return true
		}
	}
	return false
}

func withoutTxtValue(records []string, value string) []string {
	remaining := make([]string, 0, len(records))
	for _, r := range records {
		if !sameTxtValue(r, value) {
			remaining = append(remaining, r)
		}
	}
	return remaining
}
