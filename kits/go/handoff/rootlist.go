package handoff

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"time"
)

// The reason codes of a host that reads a signed root list (ritueel's root list reference, "How a host reads it").
const (
	RootListMalformed          = "malformed"
	RootListUnknownSigner      = "unknown-signer"
	RootListSignatureInvalid   = "signature-invalid"
	RootListVersionUnsupported = "version-unsupported"
	RootListRollback           = "rollback"
	RootListSequenceConflict   = "sequence-conflict"
	RootListRemovalInvalid     = "removal-invalid"
	RootListInsufficient       = "insufficient-signers"
	RootListExpired            = "expired"
	// CodeCABundleMismatch is the code of a CA bundle that does not match its list (the root list reference, "The CA bundle").
	CodeCABundleMismatch = "ca-bundle-mismatch"
)

// WarningHeldExpired is the warning of a list that a host holds past its `expires_at`: the host keeps the list, goes on
// trusting its root keys and warns; it does not drop them (ADR 0024, "Root pins and the root list").
const WarningHeldExpired = "held-expired"

// rootListMonths is the life of a list: `expires_at` is this many calendar months after `signed_at`.
const rootListMonths = 13

// RootListExpiry is the `expires_at` of a list signed at t: 13 calendar months later, the only value a reader accepts (the root
// list reference, "The list").
func RootListExpiry(t time.Time) time.Time { return addCalendarMonths(t, rootListMonths) }

// certificateMonths is the validity of an intermediate: `notAfter` is this many calendar months after `notBefore` (the contract's
// "What is issued").
const certificateMonths = 13

// CertificateExpiry is the `notAfter` of an intermediate whose `notBefore` is notBefore: 13 calendar months later, the same day
// and time of the month or the last day of that month. A certifier issues this value and a requester accepts only this value.
func CertificateExpiry(notBefore time.Time) time.Time {
	return addCalendarMonths(notBefore, certificateMonths)
}

// SubjectKeyID is the subject key identifier of a certificate of the public key spki (DER SubjectPublicKeyInfo): the leftmost 160
// bits of the SHA-256 of the subject public key bits (RFC 7093, section 2, method 1; the contract's "What is issued").
func SubjectKeyID(spki []byte) ([]byte, error) {
	var info struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	rest, err := asn1.Unmarshal(spki, &info)
	if err != nil || len(rest) != 0 {
		return nil, fmt.Errorf("handoff: the public key is not a SubjectPublicKeyInfo")
	}
	sum := sha256.Sum256(info.PublicKey.Bytes)
	return sum[:20], nil
}

// addCalendarMonths is the same day and time of the month n months later, or the last day of that month when it has no such
// day (31 January and one month is 28 or 29 February), as the contract writes it for a certificate and a list. time.AddDate
// would carry the overflow into the next month.
func addCalendarMonths(t time.Time, n int) time.Time {
	t = t.UTC()
	y, m, d := t.Date()
	first := time.Date(y, m+time.Month(n), 1, t.Hour(), t.Minute(), t.Second(), 0, time.UTC)
	last := first.AddDate(0, 1, -1).Day()
	if d > last {
		d = last
	}
	return time.Date(first.Year(), first.Month(), d, t.Hour(), t.Minute(), t.Second(), 0, time.UTC)
}

// RootListVersion is the version of the root list this reader knows.
const RootListVersion = 1

// Root is an active root of a root list: pinned by the SHA-256 of its public key, never by a certificate.
type Root struct {
	Label string
	// X509SPKISHA256 is the pin: the SHA-256 of the DER SubjectPublicKeyInfo of the root's X.509 key, in lower-case
	// hexadecimal. It is the `issuer` member of an X.509 answer.
	X509SPKISHA256 string
	// OpenPGPFingerprint is the primary's version 4 fingerprint, 40 hexadecimal digits.
	OpenPGPFingerprint string
}

type removal struct {
	label, pin, authorisation string
}

// RootList is a signed root list that a reader accepted.
type RootList struct {
	Sequence  int64
	SignedAt  time.Time
	ExpiresAt time.Time
	Roots     []Root
	// Raw is the bytes of root-list.json as read; a list at the same sequence must be byte for byte these.
	Raw []byte

	removals []removal
}

// HasPin reports whether pin is the key of an active root.
func (l *RootList) HasPin(pin string) bool {
	for _, r := range l.Roots {
		if r.X509SPKISHA256 == pin {
			return true
		}
	}
	return false
}

// Expired reports whether the list has passed its expiry. A host keeps an expired list and warns; it never drops it
// (ADR 0024, "Root pins and the root list").
func (l *RootList) Expired(now time.Time) bool { return !now.Before(l.ExpiresAt) }

// Warnings are the warnings of a list that the host holds at the time now: held-expired when it is past `expires_at`. The
// list stays in use: a caller that holds a list keeps trusting its root keys and shows the warning.
func (l *RootList) Warnings(now time.Time) []string {
	if l.Expired(now) {
		return []string{WarningHeldExpired}
	}
	return nil
}

// RootListChecks says which checks of the reader ran. A check that cannot run is never reported as passed.
type RootListChecks struct {
	// Anchored is true when the list was read against a held list or initial pins, so that the checks that weigh the
	// signers (2, 8, 9, 10) and the sequence (6, 7) ran. Without either, only the checks that need nothing but the
	// list itself ran: the signatures it carries (1, 3), the version and the members (4, 5) and the expiry (11).
	Anchored bool
	// Warnings are raised beside a refusal or an acceptance: held-expired when the list read is the list the host holds, byte
	// for byte, and it is past its expiry (the refusal `expired` comes with the warning, and the host keeps the held list).
	Warnings []string
}

// ReadRootList reads `root-list.json` and its detached signatures `root-list.jws` with the eleven checks of ritueel's
// "How a host reads it", in their order; the first that fails gives the reason code. Held is the list the host holds,
// and pins are its initial pins (the x509_spki_sha256 of the roots it was installed to trust), used before it holds a
// list. With neither, the list is read as the file an operator committed: the checks that need something to compare
// with are reported as not run (RootListChecks.Anchored false).
//
// The bytes are verified as received and never re-serialised.
func ReadRootList(list, jws []byte, held *RootList, pins []string, now time.Time) (*RootList, RootListChecks, error) {
	return ReadRootListMin(list, jws, held, pins, 0, now)
}

// ReadRootListMin is ReadRootList with the lowest sequence that the operator gave with the initial pins (`--min-sequence`
// of ritueel's command): against initial pins, a list below it is refused with `rollback` (check 6), so that an old list that
// is still signed and not expired cannot come back. It has no effect once the host holds a list, whose own sequence is the floor.
func ReadRootListMin(list, jws []byte, held *RootList, pins []string, minSequence int64, now time.Time) (*RootList, RootListChecks, error) {
	anchored := held != nil || len(pins) > 0
	checks := RootListChecks{Anchored: anchored}
	fail := func(code, at string) (*RootList, RootListChecks, error) {
		return nil, checks, refuse(code, at)
	}

	// 1. The signature file.
	sigs, err := parseJWS(jws)
	if err != nil {
		return fail(RootListMalformed, "root-list.jws")
	}
	// The known pins: the roots of the held list, or the initial pins.
	trusted := map[string]bool{}
	switch {
	case held != nil:
		for _, r := range held.Roots {
			trusted[r.X509SPKISHA256] = true
		}
	default:
		for _, p := range pins {
			trusted[p] = true
		}
	}
	// 2. One signer is a root the host already trusts.
	if anchored {
		ok := false
		for _, s := range sigs {
			if trusted[s.kid] {
				ok = true
			}
		}
		if !ok {
			return fail(RootListUnknownSigner, "root-list.jws")
		}
	}
	// 3. Every signature verifies, with the key in its x5c, over the bytes as read.
	payload := base64.RawURLEncoding.EncodeToString(list)
	for _, s := range sigs {
		if !verifyES384(s.key, []byte(s.protected+"."+payload), s.sig) {
			return fail(RootListSignatureInvalid, "root-list.jws")
		}
	}
	// 4. The version, which is read before the members.
	o, err := parseObject(list, "")
	if err != nil {
		return fail(RootListMalformed, "root-list.json")
	}
	vraw, ok := o.take("version")
	if !ok {
		return fail(RootListMalformed, "version")
	}
	if string(vraw) != "1" {
		if isInteger(string(vraw)) {
			return fail(RootListVersionUnsupported, "version")
		}
		return fail(RootListMalformed, "version")
	}
	// 5. The members.
	l, err := parseRootListMembers(o, now)
	if err != nil {
		return fail(RootListMalformed, "root-list.json")
	}
	l.Raw = append([]byte(nil), list...)
	if held == nil && minSequence > 0 && l.Sequence < minSequence {
		// 6. Not lower than the lowest sequence given with the initial pins.
		return fail(RootListRollback, "sequence")
	}
	if held != nil {
		// 6. Not lower than the held list.
		if l.Sequence < held.Sequence {
			return fail(RootListRollback, "sequence")
		}
		// 7. The same sequence is the same list.
		if l.Sequence == held.Sequence && !bytes.Equal(l.Raw, held.Raw) {
			return fail(RootListSequenceConflict, "sequence")
		}
	}
	listed := map[string]bool{}
	for _, r := range l.Roots {
		listed[r.X509SPKISHA256] = true
	}
	// The held list again brings nothing new: a list at the same sequence that is byte for byte the held one passes without
	// checks 8 to 10 (its signers need not be on it, and its removals name keys it no longer holds).
	again := held != nil && bytes.Equal(l.Raw, held.Raw)
	if anchored && !again {
		// 8. Every signer is trusted already or is a root of this list.
		for _, s := range sigs {
			if !trusted[s.kid] && !listed[s.kid] {
				return fail(RootListUnknownSigner, "root-list.jws")
			}
		}
	}
	// 9. Every removal is a valid authorisation of a root of the held list that this list drops.
	authorised := map[string]bool{}
	if anchored && !again {
		for _, rm := range l.removals {
			if !trusted[rm.pin] || listed[rm.pin] || !validRemoval(rm) {
				return fail(RootListRemovalInvalid, "removals")
			}
			authorised[rm.pin] = true
		}
		// 10. When the root set changes, every held root signed or is removed, and every added root signed.
		if changed(l, held, pins) {
			signed := map[string]bool{}
			for _, s := range sigs {
				signed[s.kid] = true
			}
			for pin := range trusted {
				if !signed[pin] && !authorised[pin] {
					return fail(RootListInsufficient, "root-list.jws")
				}
			}
			for _, r := range l.Roots {
				if !trusted[r.X509SPKISHA256] && !signed[r.X509SPKISHA256] {
					return fail(RootListInsufficient, "root-list.jws")
				}
			}
		}
	}
	// 11. Before the expiry. The same list again after its expiry is refused, and the host keeps the list it holds and warns.
	if l.Expired(now) {
		if again {
			checks.Warnings = append(checks.Warnings, WarningHeldExpired)
		}
		return fail(RootListExpired, "expires_at")
	}
	return l, checks, nil
}

func isInteger(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// changed reports whether the roots of l differ from those of the held list, or from the initial pins when there is no
// held list ("Against initial pins, the roots are compared by their pins").
func changed(l, held *RootList, pins []string) bool {
	a := map[string]bool{}
	for _, r := range l.Roots {
		a[r.X509SPKISHA256] = true
	}
	b := map[string]bool{}
	if held != nil {
		for _, r := range held.Roots {
			b[r.X509SPKISHA256] = true
		}
		if len(a) != len(b) {
			return true
		}
		for p := range a {
			if !b[p] {
				return true
			}
		}
		// The same pins with a different label or fingerprint are a different root entry.
		return !slices.EqualFunc(sortedRoots(l.Roots), sortedRoots(held.Roots), func(x, y Root) bool { return x == y })
	}
	for _, p := range pins {
		b[p] = true
	}
	if len(a) != len(b) {
		return true
	}
	for p := range a {
		if !b[p] {
			return true
		}
	}
	return false
}

func sortedRoots(rs []Root) []Root {
	out := slices.Clone(rs)
	slices.SortFunc(out, func(a, b Root) int { return strings.Compare(a.X509SPKISHA256, b.X509SPKISHA256) })
	return out
}

// parseRootListMembers reads the members of a list (check 5). now is the host's clock: a list signed after it is refused, and
// so is a list whose expiry is not exactly 13 calendar months after its signing.
func parseRootListMembers(o *object, now time.Time) (*RootList, error) {
	l := &RootList{}
	seq, _, err := o.integer("sequence", true)
	if err != nil || seq < 1 {
		return nil, refuse(CodeMalformed, "sequence")
	}
	l.Sequence = seq
	for _, f := range []struct {
		name string
		dst  *time.Time
	}{{"signed_at", &l.SignedAt}, {"expires_at", &l.ExpiresAt}} {
		s, _, err := o.str(f.name, true)
		if err != nil {
			return nil, err
		}
		t, ok := parseTime(s)
		if !ok {
			return nil, refuse(CodeMalformed, f.name)
		}
		*f.dst = t
	}
	if l.SignedAt.After(now) {
		return nil, refuse(CodeMalformed, "signed_at")
	}
	if !l.ExpiresAt.Equal(addCalendarMonths(l.SignedAt, rootListMonths)) {
		return nil, refuse(CodeMalformed, "expires_at")
	}
	roots, _, err := o.list("roots", true)
	if err != nil || len(roots) == 0 {
		return nil, refuse(CodeMalformed, "roots")
	}
	labels := map[string]bool{}
	pinsSeen := map[string]bool{}
	for i, raw := range roots {
		ro, err := parseObject(raw, joinAt("roots", itoa(i)))
		if err != nil {
			return nil, err
		}
		var r Root
		if r.Label, _, err = ro.str("label", true); err != nil {
			return nil, err
		}
		if r.X509SPKISHA256, _, err = ro.str("x509_spki_sha256", true); err != nil {
			return nil, err
		}
		// A bundle with no OpenPGP root writes entries without the fingerprint (the root list reference, "The list").
		var hasFingerprint bool
		if r.OpenPGPFingerprint, hasFingerprint, err = ro.str("openpgp_fingerprint", false); err != nil {
			return nil, err
		}
		if err := ro.done(); err != nil {
			return nil, err
		}
		if len(r.Label) != 1 || r.Label[0] < 'A' || r.Label[0] > 'Z' || !isDigest(r.X509SPKISHA256) || (hasFingerprint && !isLowerHex(r.OpenPGPFingerprint, 40)) || labels[r.Label] || pinsSeen[r.X509SPKISHA256] {
			return nil, refusef(CodeMalformed, "roots[%d]", i)
		}
		labels[r.Label], pinsSeen[r.X509SPKISHA256] = true, true
		l.Roots = append(l.Roots, r)
	}
	if s, ok, err := o.str("last_record_sha256", false); err != nil || (ok && !isDigest(s)) {
		return nil, refuse(CodeMalformed, "last_record_sha256")
	}
	rms, has, err := o.list("removals", false)
	if err != nil || (has && len(rms) == 0) {
		return nil, refuse(CodeMalformed, "removals")
	}
	for i, raw := range rms {
		ro, err := parseObject(raw, joinAt("removals", itoa(i)))
		if err != nil {
			return nil, err
		}
		var rm removal
		if rm.label, _, err = ro.str("label", true); err != nil {
			return nil, err
		}
		if rm.pin, _, err = ro.str("x509_spki_sha256", true); err != nil {
			return nil, err
		}
		if rm.authorisation, _, err = ro.str("authorisation", true); err != nil {
			return nil, err
		}
		if err := ro.done(); err != nil {
			return nil, err
		}
		// A pin twice, and an empty authorisation, are refused with the list (check 5); the authorisation itself is check 9's.
		if !isDigest(rm.pin) || rm.authorisation == "" || slices.ContainsFunc(l.removals, func(o removal) bool { return o.pin == rm.pin }) {
			return nil, refusef(CodeMalformed, "removals[%d]", i)
		}
		l.removals = append(l.removals, rm)
	}
	if err := o.done(); err != nil {
		return nil, err
	}
	return l, nil
}

// jwsSig is one signature of root-list.jws after its header was read.
type jwsSig struct {
	protected string // the Base64url text, as signed
	kid       string
	key       *ecdsa.PublicKey
	sig       []byte
}

// parseJWS reads root-list.jws: the general JSON serialisation with a detached payload (RFC 7515, section 7.2.1 and
// appendix F), one object whose only member is `signatures`, each with exactly `protected` and `signature`.
func parseJWS(b []byte) ([]jwsSig, error) {
	o, err := parseObject(b, "")
	if err != nil {
		return nil, err
	}
	items, _, err := o.list("signatures", true)
	if err != nil || len(items) == 0 {
		return nil, refuse(CodeMalformed, "signatures")
	}
	if err := o.done(); err != nil {
		return nil, err
	}
	var out []jwsSig
	seen := map[string]bool{}
	for _, raw := range items {
		so, err := parseObject(raw, "signatures")
		if err != nil {
			return nil, err
		}
		prot, _, err := so.str("protected", true)
		if err != nil {
			return nil, err
		}
		sigText, _, err := so.str("signature", true)
		if err != nil {
			return nil, err
		}
		if err := so.done(); err != nil {
			return nil, err
		}
		hdr, err := base64.RawURLEncoding.Strict().DecodeString(prot)
		if err != nil {
			return nil, refuse(CodeMalformed, "protected")
		}
		sig, err := base64.RawURLEncoding.Strict().DecodeString(sigText)
		if err != nil || len(sig) != 96 {
			return nil, refuse(CodeMalformed, "signature")
		}
		kid, key, err := readProtected(hdr, "root-list+json")
		if err != nil {
			return nil, err
		}
		if seen[kid] {
			return nil, refuse(CodeMalformed, "kid")
		}
		seen[kid] = true
		out = append(out, jwsSig{protected: prot, kid: kid, key: key, sig: sig})
	}
	return out, nil
}

// readProtected reads a protected header with exactly alg ES384, kid, typ and x5c of one certificate whose key has the
// SHA-256 kid, and returns the kid and the key.
func readProtected(hdr []byte, typ string) (string, *ecdsa.PublicKey, error) {
	h, err := parseObject(hdr, "protected")
	if err != nil {
		return "", nil, err
	}
	alg, _, err := h.str("alg", true)
	if err != nil || alg != "ES384" {
		return "", nil, refuse(CodeMalformed, "alg")
	}
	kid, _, err := h.str("kid", true)
	if err != nil || !isDigest(kid) {
		return "", nil, refuse(CodeMalformed, "kid")
	}
	if t, _, err := h.str("typ", true); err != nil || t != typ {
		return "", nil, refuse(CodeMalformed, "typ")
	}
	x5c, _, err := h.list("x5c", true)
	if err != nil || len(x5c) != 1 {
		return "", nil, refuse(CodeMalformed, "x5c")
	}
	if err := h.done(); err != nil {
		return "", nil, err
	}
	der, ok := b64(x5c[0])
	if !ok {
		return "", nil, refuse(CodeMalformed, "x5c")
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return "", nil, refuse(CodeMalformed, "x5c")
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P384() {
		return "", nil, refuse(CodeMalformed, "x5c")
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	if hex.EncodeToString(sum[:]) != kid {
		return "", nil, refuse(CodeMalformed, "kid")
	}
	return kid, pub, nil
}

// verifyES384 checks an ES384 signature of a JWS: the 96 bytes r and s over SHA-384 of the signing input
// (RFC 7518, section 3.4).
func verifyES384(pub *ecdsa.PublicKey, input, sig []byte) bool {
	if len(sig) != 96 {
		return false
	}
	d := sha512.Sum384(input)
	r := new(big.Int).SetBytes(sig[:48])
	s := new(big.Int).SetBytes(sig[48:])
	return ecdsa.Verify(pub, d[:], r, s)
}

// validRemoval checks a removal authorisation: a compact JWS with the payload attached, whose header, key, signature
// and payload all name the pin of the root it removes (ritueel's root list reference, "The removal authorisation").
func validRemoval(rm removal) bool {
	parts := strings.Split(rm.authorisation, ".")
	if len(parts) != 3 {
		return false
	}
	hdr, err := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	if err != nil {
		return false
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil {
		return false
	}
	sig, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil {
		return false
	}
	kid, key, err := readProtected(hdr, "root-removal+json")
	if err != nil || kid != rm.pin {
		return false
	}
	po, err := parseObject(payload, "payload")
	if err != nil {
		return false
	}
	v, ok := po.take("version")
	if !ok || string(v) != "1" {
		return false
	}
	pin, _, err := po.str("x509_spki_sha256", true)
	if err != nil || pin != rm.pin || po.done() != nil {
		return false
	}
	return verifyES384(key, []byte(parts[0]+"."+parts[1]), sig)
}

// SPKIPin is the pin of a certificate's key: the SHA-256 of its DER SubjectPublicKeyInfo, in lower-case hexadecimal.
func SPKIPin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// ParseBundle reads a CA bundle (ritueel's root list reference, "The CA bundle"): the certificates of the roots, PEM
// armoured, with `# trust-sequence: N` as the first line when ritueel made it. A bundle of another source has no such
// line, and its sequence is 0. The text outside the armour is skipped, as PEM readers do (RFC 7468, section 2).
func ParseBundle(b []byte) ([]*x509.Certificate, int64, error) {
	var seq int64
	if rest, ok := bytes.CutPrefix(b, []byte("# trust-sequence: ")); ok {
		line, _, _ := bytes.Cut(rest, []byte("\n"))
		n := string(line)
		if !isInteger(n) || len(n) > 15 {
			return nil, 0, refuse(CodeMalformed, "ca-bundle sequence")
		}
		if _, err := fmt.Sscanf(n, "%d", &seq); err != nil {
			return nil, 0, refuse(CodeMalformed, "ca-bundle sequence")
		}
	}
	var certs []*x509.Certificate
	for rest := b; ; {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, 0, refuse(CodeMalformed, "ca-bundle certificate")
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, 0, refuse(CodeMalformed, "ca-bundle")
	}
	return certs, seq, nil
}

// maxBundle bounds a CA bundle (256 KiB, as a JSON file of the contract).
const maxBundle = 256 << 10

// CheckBundle checks a CA bundle against the root list it goes with, as ritueel's `--ca-bundle` does (the root list reference,
// "The CA bundle"): the first line names the list's sequence; the bundle holds one certificate for each root of the list and
// nothing else; the key of each certificate is the key of the root at its place in the list; each certificate names itself as its
// issuer (the two names equal as bytes), verifies with its own key, and is a CA certificate. The dates, the names and the serial
// number are not judged: an older genuine certificate of the same key passes. Any failure is `ca-bundle-mismatch`.
func CheckBundle(bundle []byte, list *RootList) error {
	bad := func(at string) error { return refuse(CodeCABundleMismatch, at) }
	if len(bundle) > maxBundle {
		return bad("ca-bundle.size")
	}
	rest, ok := bytes.CutPrefix(bundle, []byte("# trust-sequence: "))
	if !ok {
		return bad("ca-bundle.first-line")
	}
	line, rest, _ := bytes.Cut(rest, []byte("\n"))
	if string(line) != itoa(int(list.Sequence)) {
		return bad("ca-bundle.trust_sequence")
	}
	var certs []*x509.Certificate
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			return bad("ca-bundle.block")
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return bad("ca-bundle.certificate")
		}
		certs = append(certs, c)
	}
	if len(certs) != len(list.Roots) {
		return bad("ca-bundle.count")
	}
	for i, c := range certs {
		switch {
		case SPKIPin(c) != list.Roots[i].X509SPKISHA256:
			return bad(joinAt("ca-bundle", itoa(i)) + ".key")
		case !bytes.Equal(c.RawIssuer, c.RawSubject):
			return bad(joinAt("ca-bundle", itoa(i)) + ".issuer")
		case c.Version != 3 || !c.BasicConstraintsValid || !c.IsCA:
			return bad(joinAt("ca-bundle", itoa(i)) + ".basic-constraints")
		case c.CheckSignatureFrom(c) != nil:
			// A root certificate signs itself and is a CA certificate: CheckSignatureFrom needs both.
			return bad(joinAt("ca-bundle", itoa(i)) + ".signature")
		}
	}
	return nil
}
