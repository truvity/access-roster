package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// sshCredential signs a certificate for a key that did not exist a
// moment ago.
//
// The key pair is generated here, for this one certificate, and the
// private half never leaves the process unless the caller asked for it on
// disk. That is what makes the certificate's own lifetime the whole
// story: there is no long-lived key that a certificate merely decorates,
// so nothing survives its expiry to be signed again by someone else.
//
// OpenBAO is sent the public key and the principals, and nothing else —
// no TTL, no key id, no extensions. The role decides all three, and the
// `key_id` it writes is the roster subject, which is how a line in an
// sshd log and a row in the issuer's audit trail turn out to be about the
// same person.
func sshCredential(ctx context.Context, bao *openbao, request credentialRequest) error {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate a key: %w", err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		return fmt.Errorf("read back the generated key: %w", err)
	}

	body := map[string]any{"public_key": string(ssh.MarshalAuthorizedKey(signer.PublicKey()))}
	if len(request.principals) > 0 {
		body["valid_principals"] = strings.Join(request.principals, ",")
	}

	data, err := bao.write(ctx, request.path(), body)
	if err != nil {
		return err
	}
	signed, _ := data["signed_key"].(string)
	if strings.TrimSpace(signed) == "" {
		return fmt.Errorf("%s returned no certificate", request.path())
	}
	certificate, err := parseCertificate(signed)
	if err != nil {
		return err
	}

	// The comment is what `ssh-add -l` and the key's own `.pub` show, so
	// it says where the certificate came from and who it is about.
	comment := fmt.Sprintf("accessctl %s %s", request.env, certificate.KeyId)

	_, _ = fmt.Fprintf(stdout, "key_id     %s\n", certificate.KeyId)
	if len(certificate.ValidPrincipals) > 0 {
		_, _ = fmt.Fprintf(stdout, "principals %s\n", strings.Join(certificate.ValidPrincipals, ", "))
	}
	if expires, ok := expiryOf(certificate); ok {
		_, _ = fmt.Fprintf(stdout, "expires    %s\n", expires.Format(time.RFC3339))
	}

	if request.identity != "" {
		return intoSSHDirectory(request.identity, private, signer.PublicKey(), signed, comment)
	}
	return intoAgent(private, certificate, comment)
}

// parseCertificate reads back what OpenBAO signed.
//
// Everything printed and everything the agent is told comes from the
// certificate itself rather than from what was asked for: the role may
// have narrowed the principals, and it certainly chose the lifetime.
func parseCertificate(signed string) (*ssh.Certificate, error) {
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(signed))
	if err != nil {
		return nil, fmt.Errorf("read the signed certificate: %w", err)
	}
	certificate, ok := key.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("the role returned a %s, not a certificate", key.Type())
	}
	return certificate, nil
}

// expiryOf is when the certificate stops being one, if it ever does.
func expiryOf(certificate *ssh.Certificate) (time.Time, bool) {
	if certificate.ValidBefore == ssh.CertTimeInfinity || certificate.ValidBefore > math.MaxInt64 {
		return time.Time{}, false
	}
	return time.Unix(int64(certificate.ValidBefore), 0), true
}

// intoAgent hands the key and its certificate to the running ssh-agent,
// with a lifetime the CERTIFICATE decides.
//
// Taking the lifetime from the certificate rather than from a flag keeps
// the one rule this command has: nothing here chooses how long anything
// lives. The agent forgets the key as the certificate expires, so the
// next `ssh` either works because a valid certificate is loaded or asks
// for a new one — never offers an expired key to every host it meets.
func intoAgent(private ed25519.PrivateKey, certificate *ssh.Certificate, comment string) error {
	socket := strings.TrimSpace(os.Getenv("SSH_AUTH_SOCK"))
	if socket == "" {
		return fmt.Errorf(
			"no ssh-agent to add this to (SSH_AUTH_SOCK is unset): start one, or pass --identity to write the files instead")
	}
	connection, err := net.Dial("unix", socket)
	if err != nil {
		return fmt.Errorf("reach the ssh-agent at %s: %w", socket, err)
	}
	defer func() { _ = connection.Close() }()

	added := agent.AddedKey{PrivateKey: private, Certificate: certificate, Comment: comment}
	if expires, ok := expiryOf(certificate); ok {
		seconds := time.Until(expires).Seconds()
		if seconds < 1 {
			return fmt.Errorf("the certificate expired at %s before it could be added", expires.Format(time.RFC3339))
		}
		added.LifetimeSecs = uint32(math.Min(seconds, math.MaxUint32))
	}
	if err = agent.NewClient(connection).Add(added); err != nil {
		return fmt.Errorf("add the certificate to the ssh-agent: %w", err)
	}

	_, _ = fmt.Fprintln(stdout, "\nAdded to the ssh-agent, which forgets it when it expires.")
	return nil
}

// intoSSHDirectory writes the key and the certificate as OpenSSH expects
// to find them: the certificate beside the key, named after it, so that
// `ssh -i <path>` picks both up without being told about the second.
func intoSSHDirectory(
	where string, private ed25519.PrivateKey, public ssh.PublicKey, signed, comment string,
) error {
	path, err := identityPath(where)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(path), err)
	}
	if err = ownedIdentity(path); err != nil {
		return err
	}

	block, err := ssh.MarshalPrivateKey(private, comment)
	if err != nil {
		return fmt.Errorf("render the private key: %w", err)
	}
	if err = writeSecret(path, pem.EncodeToMemory(block)); err != nil {
		return err
	}
	authorized := strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(public)), "\n") + " " + comment + "\n"
	if err = writePublic(path+".pub", []byte(authorized)); err != nil {
		return err
	}
	if err = writePublic(path+"-cert.pub", []byte(strings.TrimSuffix(signed, "\n")+"\n")); err != nil {
		return err
	}

	_, _ = fmt.Fprintf(stdout, "\nWritten to %s, with the certificate at %s-cert.pub.\n", path, path)
	_, _ = fmt.Fprintf(stdout, "  ssh -i %s <host>\n", path)
	return nil
}

// identityPath is where `--identity` means. A bare name is under
// `~/.ssh`, where ssh looks anyway; anything with a separator in it is
// taken as given.
func identityPath(where string) (string, error) {
	where = strings.TrimSpace(where)
	if strings.ContainsRune(where, filepath.Separator) || strings.HasPrefix(where, "~") {
		if rest, found := strings.CutPrefix(where, "~"+string(filepath.Separator)); found {
			home, err := os.UserHomeDir()
			if err != nil {
				return "", fmt.Errorf("find the home directory: %w", err)
			}
			return filepath.Join(home, rest), nil
		}
		return filepath.Clean(where), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("find the home directory: %w", err)
	}
	return filepath.Join(home, ".ssh", where), nil
}

// ownedIdentity refuses to write over a key this tool did not write.
//
// `--identity id_ed25519` is one keystroke away from the key somebody has
// been using for years, and a tool that overwrites it has destroyed
// something no backup of ours holds. A key of ours is recognisable by the
// comment in the `.pub` beside it, which is plain text; anything else,
// including a key with no `.pub`, is somebody's own.
func ownedIdentity(path string) error {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("look at %s: %w", path, err)
	}
	public, err := os.ReadFile(path + ".pub") //nolint:gosec // the path the caller named
	if err == nil && strings.Contains(string(public), "accessctl ") {
		return nil
	}
	return fmt.Errorf("%s is a key this tool did not write: name another identity, or move it out of the way", path)
}

// writeSecret replaces a file that only this account may read.
//
// Removed first rather than truncated: writing over a file keeps the mode
// it already had, and a key written into a world-readable file that
// existed before is a key somebody else can read.
func writeSecret(path string, body []byte) error { return replace(path, body, 0o600) }

// writePublic replaces a file everyone may read, which is what OpenSSH
// expects of a `.pub` and of a certificate.
func writePublic(path string, body []byte) error { return replace(path, body, 0o644) }

func replace(path string, body []byte, mode os.FileMode) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode) //nolint:gosec // a path the caller named
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if _, err = file.Write(body); err != nil {
		_ = file.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err = file.Close(); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
