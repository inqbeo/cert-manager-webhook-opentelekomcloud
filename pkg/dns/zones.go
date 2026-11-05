package dns

import (
	"fmt"
	"strings"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/dns/v2/zones"
	"github.com/pkg/errors"
	"k8s.io/klog/v2"
)

// Values of OpenTelekomCloudDnsProviderConfig.ZoneType, which selects the
// kind of zone the challenge records are written to: "public" (the default
// when unset), "private", or "auto" (the public zone of the name, or the
// private one when there is no public zone of that name).
const (
	zoneTypePublic  = "public"
	zoneTypePrivate = "private"
	zoneTypeAuto    = "auto"
)

func validateZoneType(zoneType string) error {
	switch zoneType {
	case "", zoneTypePublic, zoneTypePrivate, zoneTypeAuto:
		return nil
	default:
		return fmt.Errorf("zoneType %q is invalid, it must be one of %q, %q or %q", zoneType, zoneTypePublic, zoneTypePrivate, zoneTypeAuto)
	}
}

// getPrivateZone returns the private zone named exactly like the resolved
// zone. Private zones of one name can exist for several VPCs; which of them
// the CA resolves is not known here, so more than one is an error.
func (s *OpenTelekomCloudDnsProviderSolver) getPrivateZone(ch *v1alpha1.ChallengeRequest) (*zones.Zone, error) {
	allZones, err := s.listZones(ch, zoneTypePrivate)
	if err != nil {
		return nil, err
	}

	matching := zonesNamed(allZones, ch.ResolvedZone)
	switch len(matching) {
	case 0:
		return nil, fmt.Errorf("found no private zone %s", ch.ResolvedZone)
	case 1:
		return &matching[0], nil
	default:
		ids := make([]string, 0, len(matching))
		for _, zone := range matching {
			ids = append(ids, zone.ID)
		}
		return nil, fmt.Errorf("found %d private zones %s (%s) while expecting 1", len(matching), ch.ResolvedZone, strings.Join(ids, ", "))
	}
}

// getPublicOrPrivateZone returns the public zone named exactly like the
// resolved zone, or the private one when there is no such public zone.
func (s *OpenTelekomCloudDnsProviderSolver) getPublicOrPrivateZone(ch *v1alpha1.ChallengeRequest) (*zones.Zone, error) {
	allZones, err := s.listZones(ch, "")
	if err != nil {
		return nil, err
	}

	if matching := zonesNamed(allZones, ch.ResolvedZone); len(matching) > 0 {
		return &matching[0], nil
	}

	klog.V(verbosity).InfoS("found no public zone, looking for a private one", "zone", ch.ResolvedZone)
	return s.getPrivateZone(ch)
}

// listZones lists the zones whose names match the resolved zone fuzzily, as
// the name filter of the API does. An empty zoneType sends no type, which
// lists public zones only.
func (s *OpenTelekomCloudDnsProviderSolver) listZones(ch *v1alpha1.ChallengeRequest, zoneType string) ([]zones.Zone, error) {
	action := strings.ToLower(string(ch.Action))

	listOpts := zones.ListOpts{
		Name: ch.ResolvedZone,
		Type: zoneType,
	}

	allPages, err := zones.List(s.dnsClient, listOpts).AllPages()
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("%s up failed", action))
	}

	allZones, err := zones.ExtractZones(allPages)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("%s up failed", action))
	}

	return allZones, nil
}

// zonesNamed returns the zones named exactly name, ignoring case and the
// trailing dot.
func zonesNamed(allZones []zones.Zone, name string) []zones.Zone {
	want := strings.ToLower(strings.TrimSuffix(name, "."))
	matching := []zones.Zone{}
	for _, zone := range allZones {
		if strings.ToLower(strings.TrimSuffix(zone.Name, ".")) == want {
			matching = append(matching, zone)
		}
	}
	return matching
}
