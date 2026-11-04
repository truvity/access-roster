package sessiond

import (
	"context"
	"encoding/base64"

	"github.com/truvity/sluis/v2/kits/go/subject"
)

// pairwiseSubject is the sub a relying party of a tenant sees (0034 "Subjects and sectors"): Mac over the tenant's
// pairwise key with the label "pairwise" and subject.PairwiseInput (the length-prefixed sector and the person's id,
// the same function exchange uses), cut to 256 bits and written in base64url without padding. A sector that is declared "public" gets the person's own id, which is the
// same at every tenant that declares it.
func (k keys) pairwiseSubject(ctx context.Context, tenant string, sec Sector, personID string) (string, error) {
	if sec.Public {
		return personID, nil
	}
	m, err := k.mac(ctx, "pairwise", tenant, labelPairwise, subject.PairwiseInput(sec.Name, personID))
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(m[:32]), nil
}

// Sector is the sector of a tenant (0034): a name, or the declared public one.
type Sector struct {
	Name   string
	Public bool
}

// sectorOf is the sector of a tenant (0034). The first working version has no Tenant item (decision D-4), so a
// tenant's sector is its own name, never the public one: a tenant must declare "public", and nothing can.
func (s *Service) sectorOf(tenant string) Sector {
	if s.opts.Sectors != nil {
		return s.opts.Sectors(tenant)
	}
	return Sector{Name: tenant}
}
