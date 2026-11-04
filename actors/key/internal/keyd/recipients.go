package keyd

import (
	"context"
	"crypto/ecdh"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"
	"sync"

	"connectrpc.com/connect"

	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
	keystorev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/port/keystore/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/store"
)

// Who may receive a wrap (ADR 0006): the recipients are the signed list in the KeyPlan, each the RFC 7638
// thumbprint of a node's wrapping public key, and no one else. The KeyCertificate items in the store are not
// signed. They only supply the public key of a recipient the list already names, and a certificate is used only
// when the thumbprint of its key equals a listed id (REQ-KEYS-075).

// reasonRecipient is the reason of an audit fact about the recipients: a certificate that is not used, or a listed
// recipient that has no key.
const reasonRecipient = "recipient"

// recipient is a node that may open data keys: its id in the KeyPlan, its label in a wrap's address and its
// wrapping public key.
type recipient struct {
	id    string // the thumbprint, as the KeyPlan lists it
	label string // the recipient part of the wrap's id
	pub   *ecdh.PublicKey
}

// recipientSet is the recipients of the KeyPlan as key@ can use them now.
type recipientSet struct {
	wrap    []recipient // listed, with a key whose thumbprint matches, sorted by label
	missing []string    // listed ids that no key was found for, sorted
	self    bool        // this node's own wrapping key is listed
	// events are the audit facts of problems this process has not reported yet. The caller emits them, and not
	// while it holds loadMu: a slow transport must not hold up the loading of keys.
	events []Event
}

// plannedRecipients reads the list of the KeyPlan: sorted, each a thumbprint, none twice.
func plannedRecipients(plan *configv2alpha1.KeyPlan) ([]string, error) {
	out := slices.Clone(plan.GetRecipients())
	slices.Sort(out)
	for i, id := range out {
		if !validRecipientID(id) {
			return nil, fmt.Errorf("keyplan/default: recipients[%d] is not an RFC 7638 thumbprint", i)
		}
		if i > 0 && out[i-1] == id {
			return nil, errors.New("keyplan/default: a recipient is listed twice")
		}
	}
	return out, nil
}

// recipients reads the KeyPlan again and finds the public key of each listed recipient. This node's own key is
// known from the key store, and the others come from the KeyCertificate items wrapping/*, each used only when the
// thumbprint of its key is listed. A certificate that is not listed or does not fit is refused and audited, once.
// A listed recipient with no key is reported and audited, once for each set of them; the wrap set is incomplete
// until the key appears, and it is never completed with a key the list does not name.
func (s *Server) recipients(ctx context.Context) (recipientSet, error) {
	p, err := s.planCl.Get(ctx, "", "default")
	if err != nil {
		return recipientSet{}, unavailable(reasonStore)
	}
	listed, err := plannedRecipients(p.Value)
	if err != nil {
		return recipientSet{}, err
	}
	certs, err := s.listCertificates(ctx)
	if err != nil {
		return recipientSet{}, unavailable(reasonStore)
	}
	var set recipientSet
	found := map[string]bool{}
	if slices.Contains(listed, s.wrappingID) {
		set.self = true
		found[s.wrappingID] = true
		set.wrap = append(set.wrap, recipient{id: s.wrappingID, label: s.recipient, pub: s.wrappingPub})
	}
	for _, c := range certs {
		if c.id == s.wrappingID {
			continue // this node's own key is not taken from the store
		}
		switch {
		case !slices.Contains(listed, c.id):
			set.report("cert:"+c.item+":"+c.id, "certificate-not-listed", c.item, c.id, &s.reported)
		case found[c.id]:
		default:
			found[c.id] = true
			set.wrap = append(set.wrap, recipient{id: c.id, label: c.label, pub: c.pub})
		}
	}
	for _, id := range listed {
		if !found[id] {
			set.missing = append(set.missing, id)
		}
	}
	if len(set.missing) > 0 {
		set.report("missing:"+strings.Join(set.missing, ","), "recipient-has-no-key", "keyplan.recipients", strings.Join(set.missing, ","), &s.reported)
	}
	slices.SortFunc(set.wrap, func(a, b recipient) int { return strings.Compare(a.label, b.label) })
	if len(set.wrap) > store.MaxBatch {
		return recipientSet{}, errors.New("keyd: more recipients than one batch holds")
	}
	return set, nil
}

// certificate is a wrapping KeyCertificate that parses, with the thumbprint of its key.
type certificate struct {
	item  string // the item id, wrapping/<label>
	id    string // the thumbprint of the key
	label string
	pub   *ecdh.PublicKey
}

// listCertificates lists the wrapping certificates in the store. One that does not parse, or whose label does not
// fit its key, is skipped and logged.
func (s *Server) listCertificates(ctx context.Context) ([]certificate, error) {
	var out []certificate
	var token string
	for {
		items, next, err := s.certs.List(ctx, "", store.PageSize(200), store.PageToken(token))
		if err != nil {
			return nil, err
		}
		for _, it := range items {
			label, ok := strings.CutPrefix(it.ID, certPrefix)
			if !ok || it.Value.GetPurpose() != wrappingPurpose || it.Value.GetRecipient() != label {
				continue
			}
			spki := it.Value.GetSpkiDer()
			pub, err := parseP384(spki)
			if err != nil || !labelFits(label, spki) {
				slog.Warn("skipping a wrapping certificate that does not parse or does not fit its label", "certificate", it.ID)
				continue
			}
			ek, err := pub.ECDH()
			if err != nil {
				continue
			}
			id, err := thumbprint(pub)
			if err != nil {
				continue
			}
			out = append(out, certificate{item: it.ID, id: id, label: label, pub: ek})
		}
		if next == "" {
			return out, nil
		}
		token = next
	}
}

// report logs a problem with the recipients and adds its audit fact the first time this process sees it. The fact
// is a refusal of the audit table (key.refuse): failure status and reason "recipient". It carries ids and a field
// path, never a key.
func (r *recipientSet) report(key, what, path, detail string, seen *sync.Map) {
	if _, dup := seen.LoadOrStore(key, struct{}{}); dup {
		return
	}
	slog.Warn("recipient problem", "what", what, "path", path, "detail", detail)
	r.events = append(r.events, Event{
		Action: ActionRefuse, Failure: true, Reason: reasonRecipient,
		Fields: map[string]any{"op": "recipients", "what": what, "path": path, "recipient": detail},
	})
}

// checkRecipients is the part of the check command about the recipients: it reports this node's wrapping key id,
// whether the KeyPlan lists it, and the listed recipients that have no key. An incomplete wrap set fails the check;
// a node that is not listed yet does not (it is how a node joins: it starts, its id is read, and the list is
// changed by a reviewed commit). The check writes no audit record: the serving process audits the same finding.
func (s *Server) checkRecipients(ctx context.Context, plan *configv2alpha1.KeyPlan) error {
	out := s.cfg.Out
	if out == nil {
		out = os.Stdout
	}
	listed, err := plannedRecipients(plan)
	if err != nil {
		return err
	}
	id, err := s.currentWrappingID(ctx)
	if err != nil {
		return err
	}
	if id == "" {
		_, _ = fmt.Fprintln(out, "wrapping key id: none yet")
	} else {
		_, _ = fmt.Fprintf(out, "wrapping key id: %s\n", id)
		_, _ = fmt.Fprintf(out, "wrapping key listed: %t\n", slices.Contains(listed, id))
	}
	certs, err := s.listCertificates(ctx)
	if err != nil {
		return errors.New("store@: the wrapping certificates cannot be listed")
	}
	var missing []string
	for _, l := range listed {
		if l == id || slices.ContainsFunc(certs, func(c certificate) bool { return c.id == l }) {
			continue
		}
		missing = append(missing, l)
	}
	_, _ = fmt.Fprintf(out, "recipients listed: %d\n", len(listed))
	if len(missing) > 0 {
		return fmt.Errorf("the wrap set is incomplete: %d listed recipients have no key (%s)", len(missing), strings.Join(missing, " "))
	}
	return nil
}

// currentWrappingID asks the key store for the wrapping public key without making one. An empty id means the key
// store has none yet.
func (s *Server) currentWrappingID(ctx context.Context) (string, error) {
	if s.wrappingID != "" {
		return s.wrappingID, nil
	}
	res, err := s.driver.PublicKey(ctx, connect.NewRequest(&keystorev2alpha1.KeyStorePublicKeyRequest{Purpose: wrappingPurpose}))
	if err != nil {
		if connect.CodeOf(err) == connect.CodeNotFound {
			return "", nil
		}
		return "", fmt.Errorf("key-store driver public key: %w", err)
	}
	return spkiThumbprint(res.Msg.GetSpkiDer())
}
