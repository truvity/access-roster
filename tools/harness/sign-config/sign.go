package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/truvity/sluis/v2/kits/go/registry"
)

// Options say what to sign and where to put it.
type Options struct {
	ConfigDir         string // the unsigned sources
	BootstrapTemplate string // the bootstrap file whose publishers block is replaced
	KeyDir            string // holds publisher.key (PEM, mode 0600)
	Out               string // receives <kind>.jws
	BootstrapOut      string // the bootstrap file to write
	KID               string
	Seq               uint64
	// Recipients are the thumbprints put into the KeyPlan's list of wrap recipients (ADR 0006, "Who may receive a
	// wrap"). The source key-plan.yaml holds the empty list on the line `  recipients: []`; with recipients, that
	// line is replaced, and a source without it is an error.
	Recipients []string
	// Subjects are the values of the upstream's subject claim of the test users, by user name. A source names a test
	// user's account by the placeholder {{sub:<user>}}, because the identity provider makes the value when it imports
	// its realm (REQ-SUBJ-044: the binding is by `sub`, never by the user name). Each placeholder is replaced with the
	// user's value; a placeholder with no value, and a value that no placeholder names, are errors.
	Subjects map[string]string
}

// maxSeq is 2^53 - 1: a seq is "a positive integer, below 2^53" (signed-config.md, "The document").
const maxSeq = 1<<53 - 1

// kidPattern is the shape of a kid in the bootstrap file: lower-case kebab-case, 1 to 32 characters.
var kidPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// sources are the extensions of an unsigned config source: YAML and JSON for the data kinds, Cedar text for a policy.
var sources = []string{".yaml", ".json", ".cedar"}

// Run signs every source of the config directory and writes the bootstrap file. It returns the names of the documents.
func Run(o Options) ([]string, error) {
	if o.Seq == 0 || o.Seq > maxSeq {
		return nil, errors.New("seq must be a positive integer below 2^53")
	}
	if !kidPattern.MatchString(o.KID) {
		return nil, errors.New("kid must be lower-case kebab-case, 1 to 32 characters, starting with a letter")
	}
	key, err := loadOrMakeKey(o.KeyDir)
	if err != nil {
		return nil, err
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(o.ConfigDir)
	if err != nil {
		return nil, fmt.Errorf("config directory: %w", err)
	}
	if err := os.MkdirAll(o.Out, 0o755); err != nil { //nolint:gosec // the documents are public: they are signed, not secret
		return nil, err
	}
	var names []string
	used := map[string]bool{}
	for _, e := range entries {
		ext := filepath.Ext(e.Name())
		if e.IsDir() || !slices.Contains(sources, ext) {
			continue
		}
		payload, err := os.ReadFile(filepath.Join(o.ConfigDir, e.Name()))
		if err != nil {
			return nil, err
		}
		kind := strings.TrimSuffix(e.Name(), ext)
		// The header names the kind (signed-config.md, "The document"): the file's name is the kind's segment.
		k, ok := registry.KindBySegment(kind)
		if !ok || k.Class != "config" {
			return nil, fmt.Errorf("%s: %q is not the segment of a config kind", e.Name(), kind)
		}
		if kind == "key-plan" && len(o.Recipients) > 0 {
			if payload, err = WithRecipients(payload, o.Recipients); err != nil {
				return nil, fmt.Errorf("%s: %w", e.Name(), err)
			}
		}
		if payload, err = WithSubjects(payload, o.Subjects, used); err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		doc, err := Sign(key, o.KID, o.Seq, k.Name, payload)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		// 0644: the file driver runs as another user than the one that signs, and a signed document is not secret.
		if err := writeAtomic(filepath.Join(o.Out, kind+".jws"), doc, 0o644); err != nil {
			return nil, err
		}
		names = append(names, kind+".jws")
	}
	for _, u := range slices.Sorted(maps.Keys(o.Subjects)) {
		if !used[u] {
			return nil, fmt.Errorf("a subject is given for %q, and no source names {{sub:%s}}", u, u)
		}
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("%s holds no source (%s): nothing was signed", o.ConfigDir, strings.Join(sources, ", "))
	}
	tpl, err := os.ReadFile(o.BootstrapTemplate)
	if err != nil {
		return nil, fmt.Errorf("bootstrap template: %w", err)
	}
	boot, err := Bootstrap(string(tpl), o.KID, spki)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(o.BootstrapOut), 0o755); err != nil { //nolint:gosec // the bootstrap file is public: a pin and a public key
		return nil, err
	}
	if err := writeAtomic(o.BootstrapOut, []byte(boot), 0o644); err != nil {
		return nil, err
	}
	return names, nil
}

// recipientsLine is the line of the KeyPlan source that the recipients replace.
const recipientsLine = "  recipients: []"

// thumbprintPattern is an RFC 7638 thumbprint of SHA-256: 43 characters of unpadded base64url.
var thumbprintPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// WithRecipients returns the KeyPlan source with its empty list of wrap recipients replaced by ids. It is an error
// when an id is not a thumbprint, when one is listed twice, or when the source has no empty list to replace: the
// harness and the source must not drift apart unseen.
func WithRecipients(source []byte, ids []string) ([]byte, error) {
	seen := map[string]bool{}
	for _, id := range ids {
		if !thumbprintPattern.MatchString(id) {
			return nil, errors.New("a recipient is not an RFC 7638 thumbprint")
		}
		if seen[id] {
			return nil, errors.New("a recipient is listed twice")
		}
		seen[id] = true
	}
	lines := strings.Split(string(source), "\n")
	at := slices.Index(lines, recipientsLine)
	if at < 0 {
		return nil, fmt.Errorf("the source has no %q line", recipientsLine)
	}
	repl := []string{"  recipients:"}
	for _, id := range ids {
		repl = append(repl, "    - "+id)
	}
	return []byte(strings.Join(slices.Concat(lines[:at], repl, lines[at+1:]), "\n")), nil
}

// subjectPlaceholder is a test user's account in a source: {{sub:<user>}}, the user name as the identity provider has it.
var subjectPlaceholder = regexp.MustCompile(`\{\{sub:([a-z][a-z0-9_-]{0,63})\}\}`)

// subjectPattern is the value a placeholder may become: at most 255 characters (the bound of a subject value, ADR 0019)
// from a set that needs no escaping in a Cedar string literal or a YAML scalar. Keycloak's `sub` is a UUID.
var subjectPattern = regexp.MustCompile(`^[A-Za-z0-9._~:@-]{1,255}$`)

// WithSubjects returns source with every {{sub:<user>}} replaced by subjects[user], and marks each user it replaced in
// used. A placeholder whose user has no value, and a value outside subjectPattern, are errors: an unfilled binding must
// not be signed, and a value must not be able to change the text around it.
func WithSubjects(source []byte, subjects map[string]string, used map[string]bool) ([]byte, error) {
	var bad error
	out := subjectPlaceholder.ReplaceAllFunc(source, func(m []byte) []byte {
		user := string(subjectPlaceholder.FindSubmatch(m)[1])
		v, ok := subjects[user]
		switch {
		case bad != nil:
		case !ok:
			bad = fmt.Errorf("{{sub:%s}} has no subject; give the harness the user's sub (-subjects)", user)
		case !subjectPattern.MatchString(v):
			bad = fmt.Errorf("the subject of %q is not 1 to 255 characters of [A-Za-z0-9._~:@-]", user)
		default:
			used[user] = true
			return []byte(v)
		}
		return m
	})
	if bad != nil {
		return nil, bad
	}
	if strings.Contains(string(out), "{{sub:") {
		return nil, errors.New("a {{sub:...}} placeholder is not of the form {{sub:<user>}}")
	}
	return out, nil
}

// Sign returns the signed config document of payload: a JWS in the general JSON serialisation (RFC 7515, section
// 7.2) with one signature, ES384 (RFC 7518, section 3.4: r then s, 48 bytes each). The protected header has exactly
// alg, kid, seq and kind, the registry name of the kind (signed-config.md, "The document"), and the signature covers
// ASCII(protected) "." payload (RFC 7515, section 5.1).
func Sign(key *ecdsa.PrivateKey, kid string, seq uint64, kind string, payload []byte) ([]byte, error) {
	if key.Curve != elliptic.P384() {
		return nil, errors.New("the publisher key is not on P-384")
	}
	header, err := json.Marshal(struct {
		Alg  string `json:"alg"`
		KID  string `json:"kid"`
		Seq  uint64 `json:"seq"`
		Kind string `json:"kind"`
	}{"ES384", kid, seq, kind})
	if err != nil {
		return nil, err
	}
	protected := base64.RawURLEncoding.EncodeToString(header)
	p := base64.RawURLEncoding.EncodeToString(payload)
	digest := sha512.Sum384([]byte(protected + "." + p))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return nil, err
	}
	sig := make([]byte, 96)
	r.FillBytes(sig[:48])
	s.FillBytes(sig[48:])
	type signature struct {
		Protected string `json:"protected"`
		Signature string `json:"signature"`
	}
	return json.MarshalIndent(struct {
		Payload    string      `json:"payload"`
		Signatures []signature `json:"signatures"`
	}{p, []signature{{protected, base64.RawURLEncoding.EncodeToString(sig)}}}, "", "  ")
}

// Verify checks a document made by Sign against a public key and the kind it must name, and returns its payload and
// seq. It is the test's reading of signed-config.md, steps 1 to 4; store@ is the real verifier.
func Verify(doc []byte, pub *ecdsa.PublicKey, kind string) (payload []byte, seq uint64, err error) {
	var d struct {
		Payload    string `json:"payload"`
		Signatures []struct {
			Protected string `json:"protected"`
			Signature string `json:"signature"`
		} `json:"signatures"`
	}
	if err := json.Unmarshal(doc, &d); err != nil || len(d.Signatures) != 1 {
		return nil, 0, errors.New("not a general JWS with one signature")
	}
	s := d.Signatures[0]
	sig, err := base64.RawURLEncoding.DecodeString(s.Signature)
	if err != nil || len(sig) != 96 {
		return nil, 0, errors.New("the signature is not 96 bytes of base64url")
	}
	digest := sha512.Sum384([]byte(s.Protected + "." + d.Payload))
	if !ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(sig[:48]), new(big.Int).SetBytes(sig[48:])) {
		return nil, 0, errors.New("the signature does not verify")
	}
	hb, err := base64.RawURLEncoding.DecodeString(s.Protected)
	if err != nil {
		return nil, 0, err
	}
	var h map[string]any
	if err := json.Unmarshal(hb, &h); err != nil {
		return nil, 0, err
	}
	if len(h) != 4 || h["alg"] != "ES384" {
		return nil, 0, errors.New("the protected header is not exactly alg, kid, seq and kind")
	}
	if h["kind"] != kind {
		return nil, 0, errors.New("the document names another kind")
	}
	n, ok := h["seq"].(float64)
	if !ok || n < 1 {
		return nil, 0, errors.New("no seq")
	}
	payload, err = base64.RawURLEncoding.DecodeString(d.Payload)
	return payload, uint64(n), err
}

// Bootstrap returns the template with its `publishers` block replaced by the one key: its PEM and its pin, the
// SHA-384 of the SubjectPublicKeyInfo, in lower-case hex (bootstrap-file.md, "publishers").
func Bootstrap(template, kid string, spki []byte) (string, error) {
	lines := strings.Split(template, "\n")
	cut := -1
	for i, l := range lines {
		if strings.HasPrefix(l, "publishers:") {
			cut = i
			break
		}
	}
	if cut < 0 {
		return "", errors.New("the bootstrap template has no publishers block")
	}
	// The comment lines directly above the block belong to the block; they describe the key of the vectors.
	for cut > 0 && strings.HasPrefix(lines[cut-1], "#") {
		cut--
	}
	head := strings.TrimRight(strings.Join(lines[:cut], "\n"), "\n")
	sum := sha512.Sum384(spki)
	pemText := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki}))
	var b strings.Builder
	b.WriteString(head)
	b.WriteString("\n\n# The pin of the key that signs the local config documents. It is made by tools/harness/sign-config for this run\n")
	b.WriteString("# and held in a file of the harness; store@ verifies every document against this pin and nothing else.\n")
	b.WriteString("publishers:\n")
	fmt.Fprintf(&b, "  - kid: %s\n    public_key: |\n", kid)
	for l := range strings.SplitSeq(strings.TrimRight(pemText, "\n"), "\n") {
		fmt.Fprintf(&b, "      %s\n", l)
	}
	fmt.Fprintf(&b, "    spki_sha384: %q\n", hex.EncodeToString(sum[:]))
	return b.String(), nil
}

// loadOrMakeKey reads the publisher key of dir, or makes it (P-384, a file with mode 0600).
func loadOrMakeKey(dir string) (*ecdsa.PrivateKey, error) {
	path := filepath.Join(dir, "publisher.key")
	b, err := os.ReadFile(path) //nolint:gosec // the harness's own key directory
	switch {
	case err == nil:
		block, _ := pem.Decode(b)
		if block == nil || block.Type != "EC PRIVATE KEY" {
			return nil, fmt.Errorf("%s is not an EC private key", path)
		}
		k, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if k.Curve != elliptic.P384() {
			return nil, fmt.Errorf("%s is not on P-384", path)
		}
		return k, nil
	case !errors.Is(err, os.ErrNotExist):
		return nil, err
	}
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := writeAtomic(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return nil, err
	}
	return k, nil
}

// writeAtomic writes a file under a temporary name and renames it, so that a watcher never reads half a document.
func writeAtomic(path string, b []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
