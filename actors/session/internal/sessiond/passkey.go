package sessiond

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	sessionv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/session/v2alpha1"
	typev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/type/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/store"
)

// The passkey ceremonies of ADR 0017 ("Passkeys", "The passkey class"): the registration of a credential after a fresh
// sign-in, and the assertion that signs a person in without a username. The WebAuthn protocol is the library's
// (docs/reference/approved-libraries.md); what is session's is where state lives, that a challenge works once, the class of
// a credential, the counter rule, and that nothing here decides who may sign in: policy does, after the assertion.

// The names of the passkey kinds, the key purpose and the labels.
const (
	passkeyKind       = "StaffPasskey"
	challengeKind     = "WebAuthnChallenge"
	purposeCredential = "credential"

	labelPasskey        = "sluis-staff-passkey-v1"         // the id of a StaffPasskey and its by_credential index: a keyed hash of the credential id
	labelPasskeySubject = "sluis-staff-passkey-subject-v1" // the by_subject index: a keyed hash of the subject
	indexByCredential   = "by_credential"                  //nolint:gosec // the name of an index, not a credential
	indexBySubject      = "by_subject"
	ceremonyAddr        = "passkey-ceremony" // the address kind a ceremony is sealed to (keys.sealFlow)

	ceremonyRegister = "register"
	ceremonyAssert   = "assert"

	classHardware = "hardware"
	classSynced   = "synced"

	// attestationNotVerified is the outcome of the attestation check until the verifier of the parity milestone exists
	// (AUTHN-081): the statement was parsed and its own signature checked, and nothing took its chain to a pinned vendor root.
	attestationNotVerified = "not-verified"

	// ceremonyLife is how long a ceremony may take between its two steps.
	ceremonyLife = 5 * time.Minute
	// maxCredentialID is the longest credential id session stores (WebAuthn allows 1023; real authenticators use 16 to 64).
	maxCredentialID = 255
	// maxPasskeys is how many passkeys one person may have.
	maxPasskeys = 10
	// maxPasskeyResponse bounds the body of a ceremony's response; entry reads a form value of at most 8 KiB.
	maxPasskeyResponse = 8 * 1024
	// userHandleLen is the length of the WebAuthn user handle (REQ-SUBJ-029).
	userHandleLen = 32
)

// The ways a ceremony is refused. They are the closed words of the audit reason and the log, and never carry a value of the
// request.
var (
	// errPasskeyResponse: the response is not a well-formed answer to this ceremony (the library refused it: the challenge,
	// the origin, the relying-party ID hash, the user verification, the signature, the flags).
	errPasskeyResponse = errors.New("sessiond: the passkey response is refused")
	// errPasskeyReplay: the challenge of the ceremony was used before.
	errPasskeyReplay = errors.New("sessiond: the challenge was used before")
	// errPasskeyExpired: the ceremony is past its end or is not the one asked for.
	errPasskeyExpired = errors.New("sessiond: the passkey ceremony is not valid")
	// errPasskeyUnknown: no credential of this id, or its user handle is not the one in the response.
	errPasskeyUnknown = errors.New("sessiond: no such passkey")
	// errPasskeyClone: a counter that did not rise on a credential that is not synced.
	errPasskeyClone = errors.New("sessiond: the signature counter went back")
	// errPasskeyTaken: the credential id is registered already, or the person has the most passkeys.
	errPasskeyTaken = errors.New("sessiond: the passkey cannot be added")
	// errPasskeyHeld: the person is under an operator's hold, and may neither register nor use a passkey.
	errPasskeyHeld = errors.New("sessiond: the person is held")
	// errPasskeyBadID: a credential id longer than session stores.
	errPasskeyBadID = errors.New("sessiond: the credential id is not stored")
)

// passkeyUser is a person to the library: the user handle and the credentials registered so far.
type passkeyUser struct {
	handle []byte
	name   string
	creds  []webauthn.Credential
}

func (u *passkeyUser) WebAuthnID() []byte                         { return u.handle }
func (u *passkeyUser) WebAuthnName() string                       { return u.name }
func (u *passkeyUser) WebAuthnDisplayName() string                { return u.name }
func (u *passkeyUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

// relyingParty builds the library's relying party from the configuration: the relying-party ID and the exact origins, and
// nothing else. A cross-origin response, or one from an origin outside the list, is refused by the library
// (REQ-AUTHN-050, REQ-ISO-034).
func (p *PasskeyConfig) relyingParty() (*webauthn.WebAuthn, error) {
	return webauthn.New(&webauthn.Config{
		RPID:          p.host.GetRpId(),
		RPDisplayName: p.host.GetRpName(),
		RPOrigins:     p.host.GetOrigins(),
	})
}

// credentialOf turns a record into the library's credential, for an assertion.
func credentialOf(r *sessionv2alpha1.StaffPasskey) webauthn.Credential {
	c := webauthn.Credential{
		ID:        r.GetCredentialId(),
		PublicKey: r.GetPublicKey(),
		Flags: webauthn.CredentialFlags{
			UserPresent: true, UserVerified: true, BackupEligible: r.GetBackupEligible(), BackupState: r.GetBackupState(),
		},
		AttestationType:   r.GetAttestationType(),
		AttestationFormat: r.GetAttestationFormat(),
		Authenticator:     webauthn.Authenticator{AAGUID: r.GetAaguid(), SignCount: r.GetSignCount()},
	}
	for _, t := range r.GetTransports() {
		c.Transport = append(c.Transport, protocol.AuthenticatorTransport(t))
	}
	return c
}

// classOf is the class of a credential (ADR 0017, "The passkey class"): synced when the backup eligible flag is set, whatever
// the attestation says, and hardware otherwise. hardware-attested needs the verifier of the parity milestone and is never
// given here.
func classOf(backupEligible bool) string {
	if backupEligible {
		return classSynced
	}
	return classHardware
}

// amrOf is the amr that a passkey sign-in adds to its tokens: mfa for a passkey of any class (it is possession and user
// verification), and swk for a synced one, which has left its device (ADR 0017: amr never claims more than sluis verified).
func amrOf(class string) []string {
	if class == classSynced {
		return []string{"mfa", "swk"}
	}
	return []string{"mfa"}
}

// credentialAddr is the address a StaffPasskey is sealed to.
func credentialAddr(tenant, id string) *typev2alpha1.Address {
	return &typev2alpha1.Address{Kind: mustSegment(passkeyKind), Tenant: tenant, Id: id}
}

func mustSegment(kind string) string {
	seg, err := segment(kind)
	if err != nil {
		panic(err) // a kind of the registry that this file names
	}
	return seg
}

// passkeyID is the id of a StaffPasskey, a keyed hash of the credential id: 256 bits in lower-case base32. A credential id
// is not secret, and the hash is not for secrecy: the id of an item may not carry what an authenticator chose, and this
// is a valid address however the authenticator chose it (credential ids are base64url and can begin with - or _).
func (k keys) passkeyID(ctx context.Context, credentialID []byte) (string, error) {
	m, err := k.mac(ctx, "mac", "", labelPasskey, credentialID, nil)
	if err != nil {
		return "", err
	}
	return lowerBase32(m[:32]), nil
}

// subjectIndex is the by_subject index value of a person's passkeys: a keyed hash, so that the index holds no subject.
func (k keys) subjectIndex(ctx context.Context, subject string) ([]byte, error) {
	m, err := k.mac(ctx, "mac", "", labelPasskeySubject, []byte(subject), nil)
	if err != nil {
		return nil, err
	}
	return m[:32], nil
}

// stored is a StaffPasskey with the version it was read at.
type stored struct {
	rec     *sessionv2alpha1.StaffPasskey
	id      string
	version uint64
}

// openPasskey opens the envelope of a StaffPasskey item. errNotOurs says it does not open.
func (s *Service) openPasskey(ctx context.Context, tenant, id string, env []byte) (*sessionv2alpha1.StaffPasskey, error) {
	r := &sessionv2alpha1.StaffPasskey{}
	if err := s.keys.open(ctx, purposeCredential, credentialAddr(tenant, id), env, r); err != nil {
		return nil, err
	}
	return r, nil
}

// passkeysOf lists the passkeys of a person by the by_subject index. The listing is linearizable.
func (s *Service) passkeysOf(ctx context.Context, tenant, subject string) ([]stored, error) {
	ix, err := s.keys.subjectIndex(ctx, subject)
	if err != nil {
		return nil, unavailable("key", err)
	}
	items, err := s.sealed.listIndex(ctx, passkeyKind, tenant, indexBySubject, ix)
	if err != nil {
		return nil, unavailable("store", err)
	}
	var out []stored
	for _, it := range items {
		r, err := s.openPasskey(ctx, tenant, it.GetAddress().GetId(), it.GetValue())
		switch {
		case errors.Is(err, errNotOurs):
			return nil, internal("passkey", errors.New("a credential does not open"))
		case err != nil:
			return nil, unavailable("key", err)
		}
		if r.GetSubject() != subject {
			return nil, internal("passkey", errors.New("a credential is indexed under another person"))
		}
		out = append(out, stored{rec: r, id: it.GetAddress().GetId(), version: it.GetVersion()})
	}
	return out, nil
}

// spendChallenge marks the challenge of a ceremony as used, before the response is verified, so a response works once
// (REQ-AUTHN-019, REQ-AUTHN-051). It creates the item and does not read one: the first use is the usual case, and a Get of
// an item that is not there is a refusal that store@ audits. The second create finds the item and is the replay. The item is
// the boundary's (tenant -), and lives as long as the kind's default; the ceremony is shorter.
func (s *Service) spendChallenge(ctx context.Context, challenge, ceremony string) error {
	err := s.sealed.createAll(ctx, "", nil, newSealed{
		kind: challengeKind, id: secretID(challenge), plain: true, value: &sessionv2alpha1.WebAuthnChallenge{Ceremony: ceremony},
	})
	switch {
	case err == nil:
		return nil
	case errors.Is(err, store.ErrExists):
		return errPasskeyReplay
	}
	return unavailable("store", err)
}

// sealCeremony seals a ceremony into the value of the sign-in cookie.
func (s *Service) sealCeremony(ctx context.Context, c *sessionv2alpha1.PasskeyCeremony) ([]byte, error) {
	id, err := randomID()
	if err != nil {
		return nil, internal("random", err)
	}
	env, err := s.keys.sealFlow(ctx, ceremonyAddr, id, c)
	if err != nil {
		return nil, unavailable("key", err)
	}
	return append([]byte(id+"."), env...), nil
}

// openCeremony opens a ceremony sealed by sealCeremony. errPasskeyExpired says it is not ours, is not of the kind asked for
// or is past its end.
func (s *Service) openCeremony(ctx context.Context, sealed []byte, ceremony string, now time.Time) (*sessionv2alpha1.PasskeyCeremony, error) {
	id, env, ok := bytes.Cut(sealed, []byte("."))
	if !ok || len(id) != cookieIDLen || store.ValidateID(string(id)) != nil {
		return nil, errPasskeyExpired
	}
	c := &sessionv2alpha1.PasskeyCeremony{}
	if err := s.keys.openFlow(ctx, ceremonyAddr, string(id), env, c); err != nil {
		if errors.Is(err, errNotOurs) {
			return nil, errPasskeyExpired
		}
		return nil, unavailable("key", err)
	}
	if c.GetCeremony() != ceremony || c.GetExpiresAt() == nil || !now.Before(c.GetExpiresAt().AsTime()) {
		return nil, errPasskeyExpired
	}
	return c, nil
}

// beginRegistration starts the registration of a passkey for a person who has just signed in: the options for
// navigator.credentials.create (as JSON, for PublicKeyCredential.parseCreationOptionsFromJSON) and the ceremony to keep.
// The credential must be discoverable (the sign-in has no username), must verify the user, and the attestation is asked for
// directly and never as enterprise (REQ-AUTHN-018, REQ-AUTHN-084). The credentials the person has are excluded, so one
// authenticator is not registered twice.
func (s *Service) beginRegistration(pk *PasskeyConfig, subject, account string, handle []byte, existing []stored, now time.Time) (options []byte, ceremony *sessionv2alpha1.PasskeyCeremony, err error) {
	if len(handle) != userHandleLen {
		return nil, nil, internal("passkey", errors.New("user handle"))
	}
	if len(existing) >= maxPasskeys {
		return nil, nil, errPasskeyTaken
	}
	wa, err := pk.relyingParty()
	if err != nil {
		return nil, nil, internal("passkey", err)
	}
	u := &passkeyUser{handle: handle, name: subject}
	var exclude []protocol.CredentialDescriptor
	for _, e := range existing {
		exclude = append(exclude, protocol.CredentialDescriptor{Type: protocol.PublicKeyCredentialType, CredentialID: e.rec.GetCredentialId()})
	}
	creation, sd, err := wa.BeginRegistration(u,
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationRequired,
		}),
		webauthn.WithConveyancePreference(protocol.PreferDirectAttestation),
		webauthn.WithExclusions(exclude),
	)
	if err != nil {
		return nil, nil, internal("passkey", err)
	}
	return s.ceremonyOf(creation.Response, sd, ceremonyRegister, subject, account, handle, now)
}

// beginAssertion starts a sign-in with a passkey: the options for navigator.credentials.get, with no allowed credentials,
// so the options carry nothing of any person and are the same for every request (REQ-AUTHN-020), and user verification
// required.
func (s *Service) beginAssertion(pk *PasskeyConfig, now time.Time) (options []byte, ceremony *sessionv2alpha1.PasskeyCeremony, err error) {
	wa, err := pk.relyingParty()
	if err != nil {
		return nil, nil, internal("passkey", err)
	}
	assertion, sd, err := wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return nil, nil, internal("passkey", err)
	}
	return s.ceremonyOf(assertion.Response, sd, ceremonyAssert, "", "", nil, now)
}

func (s *Service) ceremonyOf(opts any, sd *webauthn.SessionData, kind, subject, account string, handle []byte, now time.Time) ([]byte, *sessionv2alpha1.PasskeyCeremony, error) {
	// The library's own expiry reads the wall clock; the ceremony's is ours, on the clock of the service.
	sd.Expires = time.Time{}
	raw, err := json.Marshal(sd)
	if err != nil {
		return nil, nil, internal("passkey", err)
	}
	options, err := json.Marshal(opts)
	if err != nil {
		return nil, nil, internal("passkey", err)
	}
	return options, &sessionv2alpha1.PasskeyCeremony{
		Ceremony: kind, SessionData: raw, Subject: subject, Account: account, UserHandle: handle,
		ExpiresAt: timestamppb.New(now.Add(ceremonyLife)),
	}, nil
}

// sessionData reads the library's session data back out of a ceremony.
func sessionData(c *sessionv2alpha1.PasskeyCeremony) (webauthn.SessionData, error) {
	var sd webauthn.SessionData
	if err := json.Unmarshal(c.GetSessionData(), &sd); err != nil {
		return sd, errPasskeyExpired
	}
	return sd, nil
}

// refuseResponse logs the library's refusal by its type and nothing of the response, and gives the closed error.
func refuseResponse(step string, err error) error {
	var pe *protocol.Error
	typ := "other"
	if errors.As(err, &pe) {
		typ = pe.Type
	}
	slog.Info("passkey response refused", "step", step, "type", typ)
	return errPasskeyResponse
}

// finishRegistration verifies the response to a registration ceremony and returns the record to store. The challenge is
// spent first (a response works once, also a refused one); then the library checks the challenge, the origin against the
// allow-list, the relying-party ID hash, user presence and verification, the flags and the attestation statement's own
// signature. Nothing is written: the caller stores the record under the grant of its decision (storePasskey).
func (s *Service) finishRegistration(ctx context.Context, pk *PasskeyConfig, c *sessionv2alpha1.PasskeyCeremony, body []byte, now time.Time) (*sessionv2alpha1.StaffPasskey, error) {
	if c.GetCeremony() != ceremonyRegister || c.GetSubject() == "" {
		return nil, errPasskeyExpired
	}
	sd, err := sessionData(c)
	if err != nil {
		return nil, err
	}
	if len(body) == 0 || len(body) > maxPasskeyResponse {
		return nil, errPasskeyResponse
	}
	if err := s.spendChallenge(ctx, sd.Challenge, ceremonyRegister); err != nil {
		return nil, err
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(body)
	if err != nil {
		return nil, refuseResponse("register-parse", err)
	}
	wa, err := pk.relyingParty()
	if err != nil {
		return nil, internal("passkey", err)
	}
	u := &passkeyUser{handle: c.GetUserHandle(), name: c.GetSubject()}
	cred, err := wa.CreateCredential(u, sd, parsed)
	if err != nil {
		return nil, refuseResponse("register", err)
	}
	if len(cred.ID) == 0 || len(cred.ID) > maxCredentialID {
		return nil, errPasskeyBadID
	}
	rec := &sessionv2alpha1.StaffPasskey{
		Subject: c.GetSubject(), CredentialId: cred.ID, PublicKey: cred.PublicKey, UserHandle: c.GetUserHandle(),
		SignCount: cred.Authenticator.SignCount, Class: classOf(cred.Flags.BackupEligible), Aaguid: cred.Authenticator.AAGUID,
		AttestationObject: cred.Attestation.Object, AttestationFormat: cred.AttestationFormat, AttestationType: cred.AttestationType,
		AttestationOutcome: attestationNotVerified, BackupEligible: cred.Flags.BackupEligible, BackupState: cred.Flags.BackupState,
		Account: c.GetAccount(), CreatedAt: timestamppb.New(now), UpstreamCheckedAt: timestamppb.New(now),
	}
	for _, t := range cred.Transport {
		rec.Transports = append(rec.Transports, string(t))
	}
	return rec, nil
}

// storePasskey writes a verified record under the grant of the decision that allows it. The id and the by_credential index
// are keyed hashes of the credential id, so a credential id that is registered already (for anyone) makes the create fail.
func (s *Service) storePasskey(ctx context.Context, tenant string, grant []byte, rec *sessionv2alpha1.StaffPasskey) error {
	id, err := s.keys.passkeyID(ctx, rec.GetCredentialId())
	if err != nil {
		return unavailable("key", err)
	}
	ix, err := s.keys.subjectIndex(ctx, rec.GetSubject())
	if err != nil {
		return unavailable("key", err)
	}
	err = s.sealed.createAll(ctx, tenant, grant, newSealed{
		kind: passkeyKind, id: id, value: rec, purpose: purposeCredential,
		indexes: []*typev2alpha1.IndexEntry{{Name: indexByCredential, Value: []byte(id)}, {Name: indexBySubject, Value: ix}},
	})
	switch {
	case err == nil:
		return nil
	case errors.Is(err, store.ErrExists):
		return errPasskeyTaken
	}
	return unavailable("store", err)
}

// passkeyLogin is a verified assertion: the record the credential is, the version it was read at, and what the assertion
// changes in it.
type passkeyLogin struct {
	stored
	// next is the record to write once the sign-in is decided: the counter, the backup state and the time of use.
	next *sessionv2alpha1.StaffPasskey
}

// finishAssertion verifies the response to an assertion ceremony. The challenge is spent first. The credential is found by
// the keyed hash of the id in the response (a listing by index: an unknown id is an empty answer, not a refusal of store@),
// opened under the credential key by rule alone, and held to the user handle of the response. The library then checks the
// challenge, the origin allow-list, the relying-party ID hash, user presence and verification, the flags and the signature.
// The counter of a credential that is not synced must rise (a counter that was 0 and stays 0 is "no counter"); a synced
// credential's is stored and not judged (ADR 0017, REQ-AUTHN-052). Nothing is written and nobody is signed in: policy decides
// next, and the caller writes login.next (touchPasskey).
func (s *Service) finishAssertion(ctx context.Context, pk *PasskeyConfig, tenant string, c *sessionv2alpha1.PasskeyCeremony, body []byte, now time.Time) (*passkeyLogin, error) {
	if c.GetCeremony() != ceremonyAssert {
		return nil, errPasskeyExpired
	}
	sd, err := sessionData(c)
	if err != nil {
		return nil, err
	}
	if len(body) == 0 || len(body) > maxPasskeyResponse {
		return nil, errPasskeyResponse
	}
	if err := s.spendChallenge(ctx, sd.Challenge, ceremonyAssert); err != nil {
		return nil, err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(body)
	if err != nil {
		return nil, refuseResponse("assert-parse", err)
	}
	wa, err := pk.relyingParty()
	if err != nil {
		return nil, internal("passkey", err)
	}
	var found *stored
	var dep error // the first failure of key@ or store@ in the lookup
	fail := func(err error) (webauthn.User, error) {
		dep = err
		return nil, err
	}
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		if len(rawID) == 0 || len(rawID) > maxCredentialID {
			return nil, errPasskeyUnknown
		}
		id, err := s.keys.passkeyID(ctx, rawID)
		if err != nil {
			return fail(unavailable("key", err))
		}
		items, err := s.sealed.listIndex(ctx, passkeyKind, tenant, indexByCredential, []byte(id))
		if err != nil {
			return fail(unavailable("store", err))
		}
		for _, it := range items {
			if it.GetAddress().GetId() != id {
				continue
			}
			r, err := s.openPasskey(ctx, tenant, id, it.GetValue())
			if errors.Is(err, errNotOurs) {
				return nil, errPasskeyUnknown
			}
			if err != nil {
				return fail(unavailable("key", err))
			}
			if subtle.ConstantTimeCompare(r.GetCredentialId(), rawID) != 1 || subtle.ConstantTimeCompare(r.GetUserHandle(), userHandle) != 1 {
				return nil, errPasskeyUnknown
			}
			found = &stored{rec: r, id: id, version: it.GetVersion()}
			return &passkeyUser{handle: r.GetUserHandle(), name: r.GetSubject(), creds: []webauthn.Credential{credentialOf(r)}}, nil
		}
		return nil, errPasskeyUnknown
	}
	_, cred, err := wa.ValidatePasskeyLogin(handler, sd, parsed)
	if dep != nil {
		return nil, dep // a dependency failed inside the lookup: unavailable, and not a refused response
	}
	if err != nil {
		return nil, refuseResponse("assert", err)
	}
	if found == nil {
		return nil, errPasskeyUnknown
	}
	if cred.Authenticator.CloneWarning && found.rec.GetClass() != classSynced {
		return nil, errPasskeyClone
	}
	next := proto.Clone(found.rec).(*sessionv2alpha1.StaffPasskey)
	if cred.Authenticator.SignCount > next.GetSignCount() {
		next.SignCount = cred.Authenticator.SignCount
	}
	next.BackupState = parsed.Response.AuthenticatorData.Flags.HasBackupState()
	next.LastUsedAt = timestamppb.New(now)
	return &passkeyLogin{stored: *found, next: next}, nil
}

// touchPasskey writes the changes of an assertion under the grant of the decision that allowed the sign-in: the counter, the
// backup state, the time. The write is conditional on the version read, so two assertions that read the same counter do not
// both succeed; the loser is refused as a replay would be.
func (s *Service) touchPasskey(ctx context.Context, tenant string, grant []byte, l *passkeyLogin) error {
	env, err := s.keys.sealCredential(ctx, credentialAddr(tenant, l.id), l.next, grant)
	if err != nil {
		return unavailable("key", err)
	}
	if err := s.sealed.updateSealed(ctx, passkeyKind, tenant, l.id, l.version, env, grant); err != nil {
		if errors.Is(err, store.ErrVersion) {
			return errPasskeyReplay
		}
		return unavailable("store", err)
	}
	return nil
}

// ensureUserHandle returns the WebAuthn user handle of a person, making it at the person's first passkey: 32 random bytes
// from the operating system's generator, kept on the Person and derived from nothing (REQ-SUBJ-029, REQ-SUBJ-030). The
// Person exists, so it is read with a Get that finds it; the update is conditional on the version read.
func (s *Service) ensureUserHandle(ctx context.Context, tenant, subject string, grant []byte) ([]byte, error) {
	for range 2 {
		it, err := s.sealed.getItem(ctx, "Person", tenant, subject)
		if err != nil {
			return nil, unavailable("store", err)
		}
		p := &sessionv2alpha1.Person{}
		if err := s.keys.openData(ctx, "person", tenant, subject, it.GetValue(), p, grant); err != nil {
			if errors.Is(err, errNotOurs) {
				return nil, internal("person", errors.New("does not open"))
			}
			return nil, unavailable("key", err)
		}
		if len(p.GetUserHandle()) == userHandleLen {
			return p.GetUserHandle(), nil
		}
		h, err := randomBytes(userHandleLen)
		if err != nil {
			return nil, internal("random", err)
		}
		p.UserHandle = h
		env, err := s.keys.sealData(ctx, "person", tenant, subject, p, grant)
		if err != nil {
			return nil, unavailable("key", err)
		}
		switch err := s.sealed.updateSealed(ctx, "Person", tenant, subject, it.GetVersion(), env, grant); {
		case err == nil:
			return h, nil
		case errors.Is(err, store.ErrVersion):
			continue // another registration set it first: read it
		default:
			return nil, unavailable("store", err)
		}
	}
	return nil, unavailable("store", fmt.Errorf("the user handle kept moving"))
}

// registerBegin is the first step of a registration for a person who has just signed in, under the grant of the decision
// that admitted that sign-in: it makes the user handle if the person has none, lists the passkeys the person has to exclude
// them, and returns the options and the sealed ceremony. errPasskeysOff says the installation has no passkeys.
func (s *Service) registerBegin(ctx context.Context, tenant, subject, account string, grant []byte) (options, sealed []byte, err error) {
	pk, err := s.opts.Config.Passkeys(ctx)
	if err != nil {
		return nil, nil, passkeysConfigError(err)
	}
	if err := s.passkeyNotHeld(ctx, tenant, subject); err != nil {
		return nil, nil, err
	}
	handle, err := s.ensureUserHandle(ctx, tenant, subject, grant)
	if err != nil {
		return nil, nil, err
	}
	existing, err := s.passkeysOf(ctx, tenant, subject)
	if err != nil {
		return nil, nil, err
	}
	now := s.now()
	options, c, err := s.beginRegistration(pk, subject, account, handle, existing, now)
	if err != nil {
		return nil, nil, err
	}
	if sealed, err = s.sealCeremony(ctx, c); err != nil {
		return nil, nil, err
	}
	return options, sealed, nil
}

// registerFinish is the second step: it opens the ceremony, verifies the response and stores the passkey under the grant of
// a decision that the caller made after it checked that the person is not held.
func (s *Service) registerFinish(ctx context.Context, tenant string, sealed, body, grant []byte) (*sessionv2alpha1.StaffPasskey, error) {
	pk, err := s.opts.Config.Passkeys(ctx)
	if err != nil {
		return nil, passkeysConfigError(err)
	}
	now := s.now()
	c, err := s.openCeremony(ctx, sealed, ceremonyRegister, now)
	if err != nil {
		return nil, err
	}
	rec, err := s.finishRegistration(ctx, pk, c, body, now)
	if err != nil {
		return nil, err
	}
	if err := s.passkeyNotHeld(ctx, tenant, rec.GetSubject()); err != nil {
		return nil, err
	}
	// The limit is checked at the write too: two registrations that began together do not both exceed it.
	if existing, err := s.passkeysOf(ctx, tenant, rec.GetSubject()); err != nil {
		return nil, err
	} else if len(existing) >= maxPasskeys {
		return nil, errPasskeyTaken
	}
	if err := s.storePasskey(ctx, tenant, grant, rec); err != nil {
		return nil, err
	}
	return rec, nil
}

// assertBegin is the first step of a sign-in with a passkey: the options and the sealed ceremony. Nothing is written.
func (s *Service) assertBegin(ctx context.Context) (options, sealed []byte, err error) {
	pk, err := s.opts.Config.Passkeys(ctx)
	if err != nil {
		return nil, nil, passkeysConfigError(err)
	}
	options, c, err := s.beginAssertion(pk, s.now())
	if err != nil {
		return nil, nil, err
	}
	if sealed, err = s.sealCeremony(ctx, c); err != nil {
		return nil, nil, err
	}
	return options, sealed, nil
}

// assertFinish is the second step: it opens the ceremony and verifies the response. The caller decides, checks that the
// person is not held and that the upstream was seen lately enough, and then writes the counter with touchPasskey.
func (s *Service) assertFinish(ctx context.Context, tenant string, sealed, body []byte) (*passkeyLogin, error) {
	pk, err := s.opts.Config.Passkeys(ctx)
	if err != nil {
		return nil, passkeysConfigError(err)
	}
	now := s.now()
	c, err := s.openCeremony(ctx, sealed, ceremonyAssert, now)
	if err != nil {
		return nil, err
	}
	l, err := s.finishAssertion(ctx, pk, tenant, c, body, now)
	if err != nil {
		return nil, err
	}
	if err := s.passkeyNotHeld(ctx, tenant, l.rec.GetSubject()); err != nil {
		return nil, err
	}
	return l, nil
}

// passkeyNotHeld refuses a person under an operator's hold. A held person registers no passkey and signs in with none,
// whatever the passkey proves; the lookup is the listing that every sign-in uses (sealedStore.held), not a Get of the
// usual absent hold.
func (s *Service) passkeyNotHeld(ctx context.Context, tenant, subject string) error {
	held, err := s.sealed.held(ctx, tenant, subject)
	if err != nil {
		return unavailable("store", err)
	}
	if held {
		return errPasskeyHeld
	}
	return nil
}

// passkeysConfigError keeps errPasskeysOff as it is and makes a failed read of the configuration unavailable.
func passkeysConfigError(err error) error {
	if errors.Is(err, errPasskeysOff) {
		return err
	}
	return unavailable("config", err)
}
