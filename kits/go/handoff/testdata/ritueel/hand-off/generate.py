#!/usr/bin/env python3
"""Generate the hand-off test vectors of version 1 into testdata/hand-off/v1/, the root list and CA
bundle vectors of version 1 into testdata/root-list/v1/, the SSH CA key list vectors into
testdata/ssh-ca-keys/v1/ and the CRL vectors into testdata/crl/v1/, from one test trust set.

Test fixtures only. Every key here is a throw-away software key made by this script;
its private half is never written to disk, so the output holds public material only:
CSRs, certificates, public subkey packets, signatures and JSON files. The attestation
hierarchy is a made-up "Example Test" hierarchy and not the maker's.

Every key, serial number and random value comes from a SHA-256 counter stream over a
seed, one stream for each part of the set, and every ECDSA signature is the
deterministic one of RFC 6979. The seed is RITUEEL_VECTOR_SEED (64 hexadecimal digits)
when it is set, and 32 fresh random bytes otherwise; it is never printed or written.
With the same seed, Python and cryptography versions, a run makes the same bytes, and a
part added later changes no file of the other parts. The seed is not in the repository:
keys derived from a published seed would be private key material in the repository,
which docs/contributing/public-content.md keeps out. A run without the seed of the
committed files makes every file again, so the committed files are the fixtures and this
script is the record of how they were made.

The test trust set has two roots, A and B, as on two root cards: each has an X.509 root
and an OpenPGP primary, and both are active on the signed root list. A third root, Z, is
on no list; it makes the "untrusted issuer" and "unknown primary" cases. The roots follow the
root profile of docs/reference/bundle.md, and the root lists and CA bundles that name them
follow docs/reference/root-list.md, the SSH CA key lists docs/reference/ssh-ca-key-list.md and the
CRLs docs/reference/crl.md. All four sets are made in one run because the lists and the CRLs are
signed by the same throw-away root keys that issue the hand-off answers.

Made with Python 3.14 and cryptography 46.0.5.

usage: generate.py HANDOFF_OUTDIR ROOTLIST_OUTDIR SSHCA_OUTDIR CRL_OUTDIR
"""
import base64, contextlib, datetime as dt, hashlib, ipaddress, json, math, os, struct, sys
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, decode_dss_signature
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier

OUT = sys.argv[1]
RL_OUT = sys.argv[2]
SSH_OUT = sys.argv[3]
CRL_OUT = sys.argv[4]
UTC = dt.timezone.utc
CLOCK = dt.datetime(2026, 11, 15, 12, 0, 0, tzinfo=UTC)   # the ceremony time used by every vector
UNTIL = dt.datetime(2027, 12, 15, 12, 0, 0, tzinfo=UTC)   # 13 calendar months later
SEQUENCE = 7
DER, PEM = serialization.Encoding.DER, serialization.Encoding.PEM
SPKI = serialization.PublicFormat.SubjectPublicKeyInfo
POINT = (serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
HOST = "example.org"


def w(path, data, out=None):
    path = os.path.join(out or OUT, path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb" if isinstance(data, bytes) else "w") as f:
        f.write(data)


def wj(path, obj, out=None):
    w(path, json.dumps(obj, indent=2) + "\n", out)


b64 = lambda b: base64.b64encode(b).decode()
sha = lambda b: hashlib.sha256(b).hexdigest()
spki = lambda pub: pub.public_bytes(DER, SPKI)
ts = lambda t: t.strftime("%Y-%m-%dT%H:%M:%SZ")


def name(cn, o="acme"):
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, o), x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def ski(pub):   # RFC 7093, method 1: the leftmost 160 bits of the SHA-256 of the key bits (EC keys here)
    return hashlib.sha256(pub.public_bytes(*POINT)).digest()[:20]


# ---------------------------------------------------------------- the deterministic random stream
SEED = bytes.fromhex(os.environ["RITUEEL_VECTOR_SEED"]) if os.environ.get("RITUEEL_VECTOR_SEED") else os.urandom(32)
_stream = ["hand-off", 0]   # the part of the set being made, and the next block of its stream


def rand_bytes(n):
    """The next n bytes of the current stream: SHA-256 over the seed, the part's name and a counter, block by block."""
    out = b""
    while len(out) < n:
        out += hashlib.sha256(SEED + b"/" + _stream[0].encode() + _stream[1].to_bytes(8, "big")).digest()
        _stream[1] += 1
    return out[:n]


@contextlib.contextmanager
def stream(name):
    """Draw from the stream of another part while inside the block, so that a part added later changes no other file."""
    saved = list(_stream)
    _stream[:] = [name, 0]
    try:
        yield
    finally:
        _stream[:] = saved


def rand_int(bits):
    return int.from_bytes(rand_bytes((bits + 7) // 8), "big") >> (-bits % 8)


def ec_key(curve, order):
    """A private key on the curve from the stream: an integer in [1, order - 1]."""
    return ec.derive_private_key(int.from_bytes(rand_bytes(64), "big") % (order - 1) + 1, curve)


P384_ORDER = 0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973
P256_ORDER = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551


def ec384():
    return ec_key(ec.SECP384R1(), P384_ORDER)


def ec256():
    return ec_key(ec.SECP256R1(), P256_ORDER)


def ed25519_key():
    return ed25519.Ed25519PrivateKey.from_private_bytes(rand_bytes(32))


SMALL_PRIMES = [p for p in range(3, 2000) if all(p % q for q in range(2, int(p ** 0.5) + 1))]


def _probable_prime(n):
    if any(n % p == 0 for p in SMALL_PRIMES):
        return n in SMALL_PRIMES
    d, r = n - 1, 0
    while d % 2 == 0:
        d, r = d // 2, r + 1
    for _ in range(40):   # Miller-Rabin with bases from the stream
        x = pow(rand_int(n.bit_length() - 1) % (n - 3) + 2, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def rsa2048():
    """An RSA 2048 key from the stream: two 1024-bit primes with the top two bits set, e = 65537."""
    def prime():
        while True:
            c = rand_int(1024) | (3 << 1022) | 1
            if math.gcd(c - 1, 65537) == 1 and _probable_prime(c):
                return c
    p, q = prime(), prime()
    d = pow(65537, -1, (p - 1) * (q - 1) // math.gcd(p - 1, q - 1))
    pub = rsa.RSAPublicNumbers(65537, p * q)
    return rsa.RSAPrivateNumbers(p, q, d, rsa.rsa_crt_dmp1(d, p), rsa.rsa_crt_dmq1(d, q), rsa.rsa_crt_iqmp(p, q), pub).private_key()


def serial160():
    """A certificate serial: 19 bytes from the stream, with bit 150 set so that it is positive and 20 bytes at most."""
    return int.from_bytes(rand_bytes(19), "big") | 1 << 150


def serial63():
    return rand_int(63) | 1 << 62


def sign_builder(builder, key, alg):
    """Sign a certificate, CSR or CRL builder; ECDSA keys sign deterministically (RFC 6979)."""
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return builder.sign(key, alg, ecdsa_deterministic=True)
    return builder.sign(key, alg)


def ecdsa(alg):
    return ec.ECDSA(alg, deterministic_signing=True)


# ---------------------------------------------------------------- X.509 pieces
def ca_cert(subject, key, issuer_name, issuer_key, nb, na, pathlen, issuer_pub=None, extra=()):
    b = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer_name).public_key(key.public_key())
         .serial_number(serial160()).not_valid_before(nb).not_valid_after(na)
         .add_extension(x509.BasicConstraints(ca=True, path_length=pathlen), critical=True)
         .add_extension(x509.SubjectKeyIdentifier(ski(key.public_key())), critical=False))
    for e, crit in extra:
        b = b.add_extension(e, critical=crit)
    if issuer_pub is not None:
        b = b.add_extension(x509.AuthorityKeyIdentifier(ski(issuer_pub), None, None), critical=False)
    return sign_builder(b, issuer_key, hashes.SHA384() if isinstance(issuer_key, ec.EllipticCurvePrivateKey) else hashes.SHA256())


KU_CA = x509.KeyUsage(False, False, False, False, False, True, True, False, False)


def root(cn):
    """A made-up maker's attestation root (not a ritueel root): ten years, with an organisation."""
    k = ec384()
    n = name(cn)
    c = ca_cert(n, k, n, k, dt.datetime(2026, 1, 1, tzinfo=UTC), dt.datetime(2036, 1, 1, tzinfo=UTC), None,
                extra=[(KU_CA, True)])
    return k, c


T_ROOTS = dt.datetime(2026, 1, 1, tzinfo=UTC)          # when the test roots were made (their `init`)
T_ROOTS_UNTIL = dt.datetime(2029, 1, 1, tzinfo=UTC)    # 36 calendar months later


def ritueel_root(label):
    """A ritueel test root in the root profile: self-signed, the subject one common name `<name> Root <label>`
    with ` (TEST ONLY)` for a test root, basic constraints critical with no path length, key usage critical
    keyCertSign and cRLSign, a subject key identifier, no authority key identifier, 36 months."""
    k = ec384()
    n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"Example Test Root {label} (TEST ONLY)")])
    return k, ca_cert(n, k, n, k, T_ROOTS, T_ROOTS_UNTIL, None, extra=[(KU_CA, True)])


# the certifier's test roots (what ritueel would hold): A and B are on the root list, Z is not (the "untrusted issuer")
ROOT_A_KEY, ROOT_A = ritueel_root("A")
ROOT_B_KEY, ROOT_B = ritueel_root("B")
ROOT_Z_KEY, ROOT_Z = ritueel_root("Z")
w("pki/test-root-a.pem", ROOT_A.public_bytes(PEM))
w("pki/test-root-b.pem", ROOT_B.public_bytes(PEM))
w("pki/test-root-z.pem", ROOT_Z.public_bytes(PEM))

# the made-up attestation hierarchy: root -> intermediate -> per-card key -> per-key certificate. The PIV applet and the
# OpenPGP applet of a card have their own intermediates under one maker root, as on a real card.
ATT_ROOT_KEY, ATT_ROOT = root("Example Test Attestation Root (TEST ONLY)")


def att_intermediate(cn, parent_key, parent):
    k = ec384()
    c = ca_cert(name(cn), k, parent.subject, parent_key, dt.datetime(2025, 1, 1, tzinfo=UTC),
                dt.datetime(9999, 12, 31, 23, 59, 59, tzinfo=UTC), 1, parent_key.public_key(), extra=[(KU_CA, True)])
    return k, c


ATT_INT_KEY, ATT_INT = att_intermediate("Example Test PIV Attestation Intermediate", ATT_ROOT_KEY, ATT_ROOT)
OPGP_INT_KEY, OPGP_INT = att_intermediate("Example Test OPGP Attestation Intermediate", ATT_ROOT_KEY, ATT_ROOT)
w("pki/test-attestation-root.pem", ATT_ROOT.public_bytes(PEM))
w("pki/test-attestation-intermediate.pem", ATT_INT.public_bytes(PEM))
w("pki/test-opgp-attestation-intermediate.pem", OPGP_INT.public_bytes(PEM))
OTHER_ROOT_KEY, OTHER_ROOT = root("Example Other Attestation Root (TEST ONLY)")   # never pinned


class Card:
    """A made-up token: a per-card attestation key (RSA 2048, like the real one) certified by a test intermediate."""

    def __init__(self, int_key, int_cert, cn="Example Test PIV Attestation"):
        self.key = rsa2048()
        self.cert = (x509.CertificateBuilder().subject_name(name(cn, "Example Test")).issuer_name(int_cert.subject)
                     .public_key(self.key.public_key()).serial_number(serial63())
                     .not_valid_before(dt.datetime(2025, 8, 1, tzinfo=UTC)).not_valid_after(dt.datetime(9999, 12, 31, 23, 59, 59, tzinfo=UTC))
                     .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True))
        self.cert = sign_builder(self.cert, int_key, hashes.SHA384())

    def slot_cert(self, pub, slot="9c", firmware=bytes([5, 8, 0]), serial=12345678, policy=bytes([2, 1]), form=bytes([2])):
        """The certificate a token makes for a key born in a PIV slot. The OIDs and encodings are the ones measured on a
        real token on 2026-10-31 (firmware 5.8.0): raw bytes for firmware, policy and form factor, a DER INTEGER for the
        serial."""
        base = "1.3.6.1.4.1.41482.3."
        sn = serial.to_bytes((serial.bit_length() + 8) // 8, "big")
        ext = [("3", firmware), ("7", b"\x02" + bytes([len(sn)]) + sn), ("8", policy), ("9", form)]
        b = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"YubiKey PIV Attestation {slot}")]))
             .issuer_name(self.cert.subject).public_key(pub).serial_number(serial63())
             .not_valid_before(dt.datetime(2025, 8, 1, tzinfo=UTC)).not_valid_after(dt.datetime(9999, 12, 31, 23, 59, 59, tzinfo=UTC)))
        for o, v in ext:
            b = b.add_extension(x509.UnrecognizedExtension(ObjectIdentifier(base + o), v), critical=False)
        return sign_builder(b, self.key, hashes.SHA256())

    def opgp_cert(self, pub, slot="SIG"):
        """The certificate a card's OpenPGP applet makes for a key it generated. The extensions under 1.3.6.1.4.1.41482.5
        are not specified by the contract yet, so this certificate carries none: a certifier records the key as attested
        and enforces no PIN or touch policy."""
        b = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"YubiKey OPGP Attestation {slot}")]))
             .issuer_name(self.cert.subject).public_key(pub).serial_number(serial63())
             .not_valid_before(dt.datetime(2025, 8, 1, tzinfo=UTC)).not_valid_after(dt.datetime(9999, 12, 31, 23, 59, 59, tzinfo=UTC)))
        return sign_builder(b, self.key, hashes.SHA256())


CARD = Card(ATT_INT_KEY, ATT_INT)
OPGP_CARD = Card(OPGP_INT_KEY, OPGP_INT, cn="Example Test OPGP Attestation")
OTHER_INT_KEY, OTHER_INT = att_intermediate("Example Other Attestation Intermediate", OTHER_ROOT_KEY, OTHER_ROOT)
OTHER_CARD = Card(OTHER_INT_KEY, OTHER_INT)
OTHER_OPGP_CARD = Card(OTHER_INT_KEY, OTHER_INT, cn="Example Other OPGP Attestation")


def attestation(pub, card=CARD, **kw):
    """The evidence member of a proof for a PIV key: the slot certificate, then the card's own certificate (leaf first)."""
    return {"attestation": [b64(card.slot_cert(pub, **kw).public_bytes(DER)), b64(card.cert.public_bytes(DER))]}


def opgp_attestation(pub, card=OPGP_CARD):
    """The evidence member of a proof for an OpenPGP-card key: the key's certificate, then the card's own (leaf first)."""
    return {"attestation": [b64(card.opgp_cert(pub).public_bytes(DER)), b64(card.cert.public_bytes(DER))]}


# The certifier's own account is 123456789012. A requester's key in another account (111122223333) is read through the
# read-only role the certifier's policy lists for that account; an account with no listed role (444455556666) is unreadable.
ARN = "arn:aws:kms:eu-west-1:123456789012:key/11111111-2222-3333-4444-555555555555"
ARN_OTHER = "arn:aws:kms:eu-west-1:111122223333:key/66666666-7777-8888-9999-000000000000"
ARN_UNLISTED = "arn:aws:kms:eu-west-1:444455556666:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
READ_ROLE = "arn:aws:iam::111122223333:role/example-certifier-read"


def kms_stub(pub, arn=ARN, two_actors=False, spec="ECC_NIST_P384", via_role=None, denied=False):
    """The answers of DescribeKey, GetPublicKey and GetKeyPolicy that a test replays instead of calling AWS. via_role is
    the role the certifier must assume first (a key in another account); denied means every read is refused."""
    acct = arn.split(":")[4]
    if denied:
        err = {"error": "AccessDeniedException"}
        return {"describe_key": err, "get_public_key": err, "get_key_policy": err}
    role = f"arn:aws:iam::{acct}:role/example-key-holder"
    stmts = [{"Sid": "Admin", "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{acct}:role/example-key-admin"},
              "Action": ["kms:Describe*", "kms:Get*", "kms:List*", "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion"], "Resource": "*"},
             {"Sid": "Use", "Effect": "Allow", "Principal": {"AWS": role}, "Action": ["kms:Sign", "kms:GetPublicKey", "kms:DescribeKey"], "Resource": "*"}]
    if via_role:
        stmts.append({"Sid": "CertifierRead", "Effect": "Allow", "Principal": {"AWS": via_role},
                      "Action": ["kms:DescribeKey", "kms:GetPublicKey", "kms:GetKeyPolicy"], "Resource": "*"})
    if two_actors:
        stmts.append({"Sid": "Use2", "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{acct}:role/example-other"},
                      "Action": "kms:Sign", "Resource": "*"})
    stub = {}
    if via_role:
        stub["assume_role"] = {"RoleArn": via_role}
    stub.update({"describe_key": {"KeyMetadata": {"Arn": arn, "KeyId": arn.rsplit("/", 1)[1], "KeySpec": spec, "KeyUsage": "SIGN_VERIFY",
                                                   "KeyState": "Enabled", "Origin": "AWS_KMS", "KeyManager": "CUSTOMER", "MultiRegion": False,
                                                   "SigningAlgorithms": ["ECDSA_SHA_384"]}},
                 "get_public_key": {"KeyId": arn, "KeySpec": spec, "PublicKey": b64(spki(pub))},
                 "get_key_policy": {"PolicyName": "default", "Policy": json.dumps({"Version": "2012-10-17", "Statement": stmts})}})
    return stub


# ---------------------------------------------------------------- CSR and certificate
# Extended key usage (contract version 1): a request for an intermediate must state it, and may state only server
# authentication and client authentication, one or both. The certificate carries it exactly as requested.
SERVER_AUTH, CLIENT_AUTH = ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH
ANY_EKU, CODE_SIGNING = ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE, ExtendedKeyUsageOID.CODE_SIGNING
EKU_DEFAULT = (SERVER_AUTH,)   # what a valid request states unless a case says otherwise

# Whether the extended key usage extension of a request, and so of the certificate issued for it, is critical. Decided
# (2026-11-14; docs/reference/hand-off-contract.md, "The request"): it is not critical, as for a subordinate CA in the CA/Browser Forum Baseline Requirements 2.3.1
# (7.1.2.5.1 and 7.1.2.6.1: extKeyUsage, critical "N"); RFC 5280, 4.2.1.12 allows either. Every request and every certificate
# takes its value from this one constant, except the cases that set the flag on purpose.
EKU_CRITICAL = False

_SAME = object()   # issue(): carry the extended key usage of the request


def der(tag, body):
    """One DER element: the tag byte, the length, the body."""
    n = len(body)
    ln = bytes([n]) if n < 128 else (bytes([0x81, n]) if n < 256 else bytes([0x82]) + n.to_bytes(2, "big"))
    return bytes([tag]) + ln + body


def der_parts(buf):
    """The elements of a DER body, as (tag, whole element, body) tuples."""
    out, i = [], 0
    while i < len(buf):
        tag, n, i0 = buf[i], buf[i + 1], i + 2
        if n & 0x80:
            k = n & 0x7F
            n, i0 = int.from_bytes(buf[i + 2:i + 2 + k], "big"), i + 2 + k
        out.append((tag, buf[i:i0 + n], buf[i0:i0 + n]))
        i = i0 + n
    return out


def make_csr(key, cn="acme example intermediate CA", nc=("%s" % HOST,), pathlen=0, hash_=hashes.SHA384(), excluded=(),
             eku=EKU_DEFAULT, eku_critical=None, subject=None, extra_permitted=(), raw_permitted=(), raw_subtrees=()):
    """eku: the key purposes the request states, or None for a request that states none; eku_critical: the flag of the
    extension, EKU_CRITICAL when None. subject: the whole subject name, when not the one of cn. extra_permitted: name
    constraint subtrees (x509 general names) beside the URI hosts of nc; raw_permitted: the same as (tag, content) pairs of
    the DER, for a name that the library refuses to write; raw_subtrees: whole subtrees as DER (a subtree with a minimum)."""
    b = (x509.CertificateSigningRequestBuilder().subject_name(subject or name(cn))
         .add_extension(x509.BasicConstraints(ca=True, path_length=pathlen), critical=True)
         .add_extension(KU_CA, critical=True))
    if nc and (raw_permitted or raw_subtrees):
        subtrees = (b"".join(der(0x30, der(0x86, h.encode())) for h in nc) + b"".join(der(0x30, der(t, c)) for t, c in raw_permitted)
                    + b"".join(raw_subtrees))
        b = b.add_extension(x509.UnrecognizedExtension(ObjectIdentifier("2.5.29.30"), der(0x30, der(0xA0, subtrees))), critical=True)
    elif nc:
        # excluded: IP ranges as strings ("0.0.0.0/0"), or DNS names as x509.DNSName
        ex = [e if isinstance(e, x509.GeneralName) else x509.IPAddress(ipaddress.ip_network(e)) for e in excluded]
        permitted = [x509.UniformResourceIdentifier(h) for h in nc] + list(extra_permitted)
        b = b.add_extension(x509.NameConstraints(permitted, ex or None), critical=True)
    if eku is not None:
        b = b.add_extension(x509.ExtendedKeyUsage(list(eku)), critical=EKU_CRITICAL if eku_critical is None else eku_critical)
    return sign_builder(b, key, hash_)


def csr_form(csr, key, version=0, extra_attributes=()):
    """The DER of a request with the same content as csr and another form, signed again by key with ecdsa-with-SHA384:
    a version number other than 0, or an attribute beside the extension request."""
    return csr_rebuild(csr, key, version=version, extra_attributes=extra_attributes)


# the object identifiers (the content octets) that the hand-made names and extensions use
OID_CN, OID_C, OID_O, OID_OU, OID_SERIAL, OID_DNQ = (bytes.fromhex(h) for h in ("550403", "550406", "55040a", "55040b", "550405", "55042e"))
OID_DC = bytes.fromhex("0992268993f22c640119")
OID_EMAIL = bytes.fromhex("2a864886f70d010901")
OID_OTHER = bytes.fromhex("2b0601040186b71f01")   # 1.3.6.1.4.1.99999.1, an attribute type that the profile does not name
OID_EXTENSION_REQUEST = bytes.fromhex("2a864886f70d01090e")
OID_EXT_BASIC, OID_EXT_KEY_USAGE, OID_EXT_NAME_CONSTRAINTS, OID_EXT_EKU = (bytes.fromhex(h) for h in ("551d13", "551d0f", "551d1e", "551d25"))
UTF8, PRINTABLE, IA5 = 0x0C, 0x13, 0x16


def attr(oid, tag, value, after=b""):
    """One name attribute: the type and a string of the given tag; after: an element behind the value."""
    return attr_raw(oid, der(tag, value), after)


def attr_raw(oid, element, after=b""):
    """One name attribute with any element as its value."""
    return der(0x30, der(0x06, oid) + element + after)


def rdn_of(*attrs, in_order=False):
    """A relative name: a set, its attributes in DER order unless in_order says to keep the order given."""
    return der(0x31, b"".join(attrs if in_order else sorted(attrs)))


def name_of(*rdns):
    return der(0x30, b"".join(rdns))


def ext_elements(csr):
    """The extensions of a request, each as its DER sequence."""
    info = der_parts(der_parts(der_parts(csr.public_bytes(DER))[0][2])[0][2])
    attribute = der_parts(der_parts(info[3][2])[0][2])           # the type, then the set of values
    return [e[1] for e in der_parts(der_parts(attribute[1][2])[0][2])]


def ext_oid(element):
    return der_parts(der_parts(element)[0][2])[0][2]


def extension(oid, value, critical=False):
    return der(0x30, der(0x06, oid) + (der(0x01, b"\xff") if critical else b"") + der(0x04, value))


def extension_request(*value_lists):
    """An extension-request attribute with one value for each list of extensions given."""
    return der(0x30, der(0x06, OID_EXTENSION_REQUEST) + der(0x31, b"".join(der(0x30, b"".join(v)) for v in value_lists)))


def csr_rebuild(csr, key, version=0, subject=None, attributes=None, extra_attributes=(), sigalg=None):
    """The DER of a request made of the parts of csr, signed again by key with ecdsa-with-SHA384. subject: the DER of another
    name; attributes: the attributes to carry (DER elements) in place of the request's own; extra_attributes: beside them;
    sigalg: the DER of the signature algorithm element, when it is not ecdsa-with-SHA384 (the signature is still made with SHA-384)."""
    info = der_parts(der_parts(der_parts(csr.public_bytes(DER))[0][2])[0][2])
    attrs = list(attributes) if attributes is not None else [a[1] for a in der_parts(info[3][2])]
    body = der(0x02, bytes([version])) + (info[1][1] if subject is None else subject) + info[2][1] + der(0xA0, b"".join(sorted(attrs + list(extra_attributes))))
    cri = der(0x30, body)
    sigalg = sigalg if sigalg is not None else der(0x30, der(0x06, bytes.fromhex("2a8648ce3d040303")))
    sig = key.sign(cri, ecdsa(hashes.SHA384()))
    return der(0x30, cri + sigalg + der(0x03, b"\x00" + sig))


# the challengePassword attribute (PKCS #9, 1.2.840.113549.1.9.7), with a made-up value
CHALLENGE_PASSWORD = der(0x30, der(0x06, bytes.fromhex("2a864886f70d010907")) + der(0x31, der(0x13, b"example")))


def issue(csr, issuer_key=ROOT_A_KEY, issuer=ROOT_A, nb=CLOCK, na=UNTIL, pubkey=None, pathlen=None, eku=_SAME, eku_critical=None):
    """What a conforming certifier issues for a CSR (the profile of the reference page): exactly what was asked, plus times.
    eku: _SAME carries the request's extended key usage with its criticality; None leaves it out; a tuple of key purposes
    puts those in instead (the faults of an answer a requester must refuse); eku_critical sets the flag of that extension
    when it is not the request's (EKU_CRITICAL, or the request's own flag with _SAME)."""
    exts = {type(e.value): e for e in csr.extensions}
    bc = exts[x509.BasicConstraints].value
    b = (x509.CertificateBuilder().subject_name(csr.subject).issuer_name(issuer.subject).public_key(pubkey or csr.public_key())
         .serial_number(serial160()).not_valid_before(nb).not_valid_after(na)
         .add_extension(x509.BasicConstraints(ca=True, path_length=bc.path_length if pathlen is None else pathlen), critical=True)
         .add_extension(exts[x509.KeyUsage].value, critical=True))
    if x509.NameConstraints in exts:
        b = b.add_extension(exts[x509.NameConstraints].value, critical=True)
    if eku is _SAME:
        if x509.ExtendedKeyUsage in exts:
            e = exts[x509.ExtendedKeyUsage]
            b = b.add_extension(e.value, critical=e.critical if eku_critical is None else eku_critical)
    elif eku is not None:
        b = b.add_extension(x509.ExtendedKeyUsage(list(eku)), critical=EKU_CRITICAL if eku_critical is None else eku_critical)
    b = (b.add_extension(x509.SubjectKeyIdentifier(ski(pubkey or csr.public_key())), critical=False)
         .add_extension(x509.AuthorityKeyIdentifier(ski(issuer.public_key()), None, None), critical=False))
    return sign_builder(b, issuer_key, hashes.SHA384())


def tamper_csr(csr):
    d = bytearray(csr.public_bytes(DER))
    d[-1] ^= 0x01
    return bytes(d)


def pem_csr(der):
    return ("-----BEGIN CERTIFICATE REQUEST-----\n" + "\n".join(b64(der)[i:i + 64] for i in range(0, len(b64(der)), 64))
            + "\n-----END CERTIFICATE REQUEST-----\n").encode()


# ---------------------------------------------------------------- OpenPGP pieces (v4 packets, RFC 9580)
T_PRIMARY = int(dt.datetime(2026, 1, 1, tzinfo=UTC).timestamp())
T_SUBKEY = int(dt.datetime(2026, 10, 20, tzinfo=UTC).timestamp())
T_CEREMONY = int(CLOCK.timestamp())
T_UNTIL = int(UNTIL.timestamp())
OID_P384 = bytes.fromhex("2b81040022")
OID_ED25519 = bytes.fromhex("2b06010401da470f01")


def pkt(tag, body):
    return bytes([0xC0 | tag, 255]) + struct.pack(">I", len(body)) + body


def mpi(b):
    b = b.lstrip(b"\0")
    return struct.pack(">H", (len(b) - 1) * 8 + b[0].bit_length()) + b


def sub(t, d, crit=False):
    n = len(d) + 1
    ln = bytes([n]) if n < 192 else bytes([((n - 192) >> 8) + 192, (n - 192) & 255])
    return ln + bytes([t | (0x80 if crit else 0)]) + d


def keyhash(body):
    return b"\x99" + struct.pack(">H", len(body)) + body


def fpr(body):
    return hashlib.sha1(keyhash(body)).digest()


class PgpKey:
    """A v4 OpenPGP key packet. alg 19 = ECDSA P-384; alg 22 = EdDSALegacy (Ed25519), used only to make a refused vector."""

    def __init__(self, created, alg=19):
        self.alg, self.created = alg, created
        if alg == 19:
            self.priv = ec384()
            self.body = b"\x04" + struct.pack(">I", created) + b"\x13" + bytes([len(OID_P384)]) + OID_P384 + mpi(self.priv.public_key().public_bytes(*POINT))
            self.pub = self.priv.public_key()
        else:
            self.priv = ed25519_key()
            raw = self.priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            self.body = b"\x04" + struct.pack(">I", created) + b"\x16" + bytes([len(OID_ED25519)]) + OID_ED25519 + mpi(b"\x40" + raw)
            self.pub = self.priv.public_key()
        self.fpr = fpr(self.body)

    def sign_digest(self, d):   # returns the two MPIs of a signature
        if self.alg == 19:
            r, s = decode_dss_signature(self.priv.sign(d, ecdsa(Prehashed(hashes.SHA384()))))
            return mpi(r.to_bytes(48, "big")) + mpi(s.to_bytes(48, "big"))
        sg = self.priv.sign(d)
        return mpi(sg[:32]) + mpi(sg[32:])


def sig_body(stype, hashed, unhashed, data, signer, alg=19):
    head = b"\x04" + bytes([stype, alg, 9]) + struct.pack(">H", len(hashed)) + hashed   # 9 = SHA-384
    d = hashlib.sha384(data + head + b"\x04\xff" + struct.pack(">I", len(head))).digest()
    return head + struct.pack(">H", len(unhashed)) + unhashed + d[:2] + signer(d)


def issuer(k):
    """Every signature carries both: the Issuer Fingerprint subpacket (33, hashed) and the Issuer Key ID subpacket
    (16, unhashed). gpg 2.2 refuses a v4 signature without the key ID."""
    return sub(33, b"\x04" + k.fpr), sub(16, k.fpr[-8:])


T_PRIMARY_UNTIL = int(T_ROOTS_UNTIL.timestamp())


def primary_cert(k, uid):
    """The public certificate of a test primary: key, the release identity, a positive certification (certify only,
    expiring 36 months after it was made, as the root profile says)."""
    ih, iu = issuer(k)
    hashed = sub(2, struct.pack(">I", T_PRIMARY + 1)) + sub(27, b"\x01") + sub(9, struct.pack(">I", T_PRIMARY_UNTIL - k.created), True) + ih
    cert = sig_body(0x13, hashed, iu, keyhash(k.body) + b"\xb4" + struct.pack(">I", len(uid)) + uid, k.sign_digest)
    return pkt(6, k.body) + pkt(13, uid) + pkt(2, cert)


def backsig(sk, primary, stype=0x19, creation=T_SUBKEY + 60, key_id=True):
    """The back-signature: made by the subkey over the primary and the subkey (RFC 9580, section 5.2.1.9)."""
    ih, iu = issuer(sk)
    return sig_body(stype, sub(2, struct.pack(">I", creation)) + ih, iu if key_id else b"",
                    keyhash(primary.body) + keyhash(sk.body), sk.sign_digest, alg=sk.alg)


KEY_FLAGS = {"sign": b"\x02", "authenticate": b"\x20"}   # RFC 9580, section 5.2.3.29


def binding(sk, primary, back, until=T_UNTIL, embed=True, when=T_CEREMONY, flags=KEY_FLAGS["sign"]):
    """The subkey binding the certifier makes: the key flags of the capability asked (signing or authentication), expiry
    set so the subkey ends at 'until', the back-signature for this primary embedded in the unhashed area."""
    ih, iu = issuer(primary)
    hashed = sub(2, struct.pack(">I", when)) + sub(27, flags) + sub(9, struct.pack(">I", until - sk.created), True) + ih
    unhashed = iu + (sub(32, back) if embed else b"")
    return sig_body(0x18, hashed, unhashed, keyhash(primary.body) + keyhash(sk.body), primary.sign_digest)


PRIM_A, PRIM_B, PRIM_Z = PgpKey(T_PRIMARY), PgpKey(T_PRIMARY), PgpKey(T_PRIMARY)
PRIMARY_CERTS = {lbl: primary_cert(k, f"Example Test Release Root {lbl} (TEST ONLY) <release@example.org>".encode())
                 for lbl, k in (("A", PRIM_A), ("B", PRIM_B), ("Z", PRIM_Z))}
for lbl in "ABZ":
    w(f"pki/test-primary-{lbl.lower()}.pgp", PRIMARY_CERTS[lbl])
ACTIVE = [PRIM_A, PRIM_B]   # the active primaries on the test root list, in its order

# ---------------------------------------------------------------- cases
cases, responses = [], []
SUBKEYS = {}   # response id -> subkey, for the optional self-check below


def hexfp(k):
    return k.fpr.hex()


def proof(typ, request_bytes, store, evidence=None, version=1, **extra):
    p = {"handoff": version, "type": typ, "request_sha256": sha(request_bytes), "store": store}
    p.update(extra)
    if evidence is not None:
        p["evidence"] = evidence
    return p


def add(case, typ, cfg, expect, reason=None, files=(), stub=None):
    c = {"id": case, "type": typ, "config": cfg, "files": list(files), "expect": expect}
    if reason:
        c["reason"] = reason
    if stub:
        c["kms_stub"] = stub
    cases.append(c)


def evidence_for(store, pub, arn=ARN, att=None, card=None):
    if store == "piv":
        return attestation(pub, **({"card": card} if card else {}), **(att or {}))
    if store == "openpgp-card":
        return opgp_attestation(pub, **({"card": card} if card else {}))
    if store == "aws-kms":
        return {"key_arn": arn, "public_key": b64(spki(pub))}
    return None


def x509_case(case, key=None, store="piv", cfg="production", expect="refuse", reason=None, csr=None, csr_der=None,
              ev=None, version=1, extra_member=None, digest_of=None, stub=None, evidence_pub=None, arn=ARN, pem_extra=b"", **att):
    key = key or ec384()
    csr = csr or make_csr(key)
    der = csr_der or csr.public_bytes(DER)
    evidence = ev or evidence_for(store, evidence_pub or key.public_key(), arn=arn, att=att)
    p = proof("x509-intermediate", digest_of or der, store, evidence, version)
    if extra_member:
        p["unexpected"] = extra_member
    w(f"requests/{case}.csr.pem", pem_csr(der) + pem_extra)
    wj(f"requests/{case}.proof.json", p)
    files = [f"requests/{case}.csr.pem", f"requests/{case}.proof.json"]
    st = None
    if stub is not None:
        st = f"requests/{case}.kms-stub.json"
        wj(st, stub)
    add(case, "x509-intermediate", cfg, expect, reason, files, st)
    return csr, key


def x509_response(case, request_case, cert, expect, reason=None, csr=None, issuer_cert=ROOT_A):
    path = f"responses/{case}.cert.pem"
    body = cert.public_bytes(PEM)
    w(path, body)
    res = {"handoff": 1, "type": "x509-intermediate", "request_sha256": sha(csr.public_bytes(DER)), "outcome": "issued",
           "artifacts": [{"name": f"{case}.cert.pem", "sha256": sha(body)}], "valid_from": ts(cert.not_valid_before_utc),
           "valid_until": ts(cert.not_valid_after_utc), "issuer": sha(issuer_cert.public_key().public_bytes(DER, SPKI)), "trust_sequence": SEQUENCE}
    wj(f"responses/{case}.result.json", res)
    r = {"id": case, "type": "x509-intermediate", "request": request_case, "files": [path, f"responses/{case}.result.json"], "expect": expect}
    if reason:
        r["reason"] = reason
    responses.append(r)


# ---- X.509 requests
csr, key = x509_case("x509-piv-valid", expect="accept")
x509_response("x509-piv-valid", "x509-piv-valid", issue(csr), "install", csr=csr)
k = ec384(); c = make_csr(k)
x509_case("x509-kms-valid", key=k, csr=c, store="aws-kms", expect="accept", stub=kms_stub(k.public_key()))
x509_response("x509-kms-valid", "x509-kms-valid", issue(c), "install", csr=c)
# a key in another account: the certifier assumes the read-only role its policy lists for that account
k = ec384(); c = make_csr(k)
x509_case("x509-kms-cross-account", key=k, csr=c, store="aws-kms", arn=ARN_OTHER, expect="accept",
          stub=kms_stub(k.public_key(), arn=ARN_OTHER, via_role=READ_ROLE))
# a key in an account for which the policy lists no read role: the certifier cannot read it
k = ec384(); c = make_csr(k)
x509_case("x509-kms-cross-account-no-role", key=k, csr=c, store="aws-kms", arn=ARN_UNLISTED,
          stub=kms_stub(k.public_key(), arn=ARN_UNLISTED, denied=True), reason="proof-invalid")
k = ec384(); c = make_csr(k)
x509_case("x509-software-valid", key=k, csr=c, store="software", cfg="development", expect="accept")
x509_response("x509-software-valid", "x509-software-valid", issue(c), "install", csr=c)
# the same files under the production configuration: software keys are not allowed there
src = cases[-1]
cases.append({"id": "x509-software-in-production", "type": "x509-intermediate", "config": "production", "files": src["files"],
              "expect": "refuse", "reason": "store-not-allowed"})
# the same files again, passing every check, but the person at the ceremony declines the request (check 10)
cases.append({"id": "x509-software-declined", "type": "x509-intermediate", "config": "development", "files": src["files"],
              "confirmation": "declined", "expect": "refuse", "reason": "declined"})

k = ec384(); c = make_csr(k)
x509_case("x509-csr-bad-signature", key=k, csr=c, csr_der=tamper_csr(c), cfg="development", store="software", reason="possession-invalid")
x509_case("x509-p256", key=ec256(), cfg="development", store="software", reason="algorithm-unsupported")
x509_case("x509-version-2", version=2, reason="version-unsupported")
k = ec384(); c = make_csr(k); other = make_csr(ec384(), cn="another request")
x509_case("x509-request-mismatch", key=k, csr=c, digest_of=other.public_bytes(DER), reason="request-mismatch")
x509_case("x509-unknown-member", extra_member=True, reason="malformed")
k = ec384(); x509_case("x509-piv-key-mismatch", key=k, evidence_pub=ec384().public_key(), reason="key-mismatch")
k = ec384(); x509_case("x509-piv-untrusted-chain", key=k, ev=attestation(k.public_key(), card=OTHER_CARD), reason="proof-invalid")
x509_case("x509-piv-pin-never", policy=bytes([1, 1]), reason="policy")
x509_case("x509-piv-old-firmware", firmware=bytes([5, 4, 3]), reason="policy")
k = ec384(); x509_case("x509-no-name-constraints", key=k, csr=make_csr(k, nc=()), reason="policy")
k = ec384(); x509_case("x509-name-constraint-outside", key=k, csr=make_csr(k, nc=("other.example",)), reason="policy")
# Excluded subtrees (issue #70). The one accepted form excludes every IP address: 0.0.0.0/0 and ::/0, both, beside the permitted
# URI host. The requester sluis writes it when its boundary declares no IP range. Any other excluded subtree is refused.
# Made in a stream of their own, with a software key under the development configuration, so that no other file changes.
with stream("x509-ip-excluded"):
    ALL_IP = ("0.0.0.0/0", "::/0")
    k = ec384(); x509_case("x509-ip-all-excluded", key=k, csr=make_csr(k, excluded=ALL_IP), store="software", cfg="development", expect="accept")
    k = ec384(); x509_case("x509-ip-v4-excluded-only", key=k, csr=make_csr(k, excluded=ALL_IP[:1]), store="software", cfg="development", reason="policy")
    k = ec384(); x509_case("x509-ip-all-excluded-and-dns", key=k, csr=make_csr(k, excluded=ALL_IP + (x509.DNSName("other.example"),)),
                           store="software", cfg="development", reason="policy")
    k = ec384(); x509_case("x509-dns-excluded", key=k, csr=make_csr(k, excluded=(x509.DNSName("other.example"),)),
                           store="software", cfg="development", reason="policy")
k = ec384(); x509_case("x509-kms-key-mismatch", key=k, store="aws-kms", evidence_pub=ec384().public_key(),
                       stub=kms_stub(k.public_key()), reason="key-mismatch")
k = ec384(); x509_case("x509-kms-two-actors", key=k, store="aws-kms", stub=kms_stub(k.public_key(), two_actors=True), reason="policy")
# Extended key usage. Every request above states serverAuth (EKU_DEFAULT). These differ from x509-software-valid in the key
# purposes alone: the two allowed ones together, and clientAuth alone, are accepted and certified exactly as requested; a
# request that states none, anyExtendedKeyUsage, a purpose outside the two, or an allowed one beside a purpose outside, is
# refused with `policy`. Made in a stream of their own, with a software key under the development configuration, so that no
# other file changes.
with stream("x509-eku"):
    EKU_CSRS = {}   # the requests that answers below refer to
    for case, purposes in (("x509-eku-server-and-client", (SERVER_AUTH, CLIENT_AUTH)), ("x509-eku-client-only", (CLIENT_AUTH,))):
        k = ec384(); c = make_csr(k, eku=purposes); EKU_CSRS[case] = c
        x509_case(case, key=k, csr=c, store="software", cfg="development", expect="accept")
        x509_response(case, case, issue(c), "install", csr=c)
    for case, purposes in (("x509-eku-missing", None), ("x509-eku-any", (ANY_EKU,)), ("x509-eku-code-signing", (CODE_SIGNING,)),
                           ("x509-eku-server-and-code-signing", (SERVER_AUTH, CODE_SIGNING)), ("x509-eku-server-and-any", (SERVER_AUTH, ANY_EKU))):
        k = ec384(); x509_case(case, key=k, csr=make_csr(k, eku=purposes), store="software", cfg="development", reason="policy")
    # the extension is not critical, and each purpose is named once
    k = ec384(); x509_case("x509-eku-critical", key=k, csr=make_csr(k, eku_critical=True), store="software", cfg="development", reason="policy")
    k = ec384(); x509_case("x509-eku-purpose-twice", key=k, csr=make_csr(k, eku=(SERVER_AUTH, SERVER_AUTH)), store="software", cfg="development",
                           reason="policy")

# ---- X.509 answers to the request x509-response-request: one from the other root, and four a requester must refuse
# ---- Name constraints, subject and the form of a request (docs/reference/hand-off-contract.md, "The request"). Each case differs from x509-software-valid
# in one thing, and is made with a software key under the development configuration, each group in a stream of its own so
# that no other file changes. Refused ones give `policy` unless the case says otherwise.
# A third configuration, for the names that are refused for their form (the rules of RFC 1034 and 1123 that the contract states).
# Its policy lists the badly formed names themselves, so that no request is refused for being outside the policy: each such
# request is run against `development` (where the name is outside) and against this one (where it is listed, and only the form
# can refuse it).
LISTED_CFG = "development-listed-names"
LISTED_DNS, LISTED_URI = [], []


def list_names(dns=(), uri=()):
    LISTED_DNS.extend(n for n in dns if n not in LISTED_DNS)
    LISTED_URI.extend(n for n in uri if n not in LISTED_URI)


def listed_twin(case, dns=(), uri=()):
    """The same files as `case`, against the configuration whose policy lists the names of the case; refused for the same code."""
    src = next(c for c in cases if c["id"] == case)
    list_names(dns, uri)
    cases.append({"id": case + "-listed", "type": "x509-intermediate", "config": LISTED_CFG, "files": src["files"],
                  "expect": "refuse", "reason": src["reason"]})


def sw_case(case, expect="refuse", reason="policy", form=None, cfg="development", listed=None, **kw):
    """One request with a fresh software key. kw go to make_csr; form is a function (csr, key) -> DER of another form of it;
    listed: (DNS names, URI hosts) that the case's name constraints hold and the third configuration lists, for a refused case
    (it gets a twin) or an accepted one under that configuration."""
    k = ec384(); c = make_csr(k, **kw)
    x509_case(case, key=k, csr=c, csr_der=form(c, k) if form else None, store="software", cfg=cfg, expect=expect,
              reason=None if expect == "accept" else reason)
    if listed and expect == "accept":
        list_names(*listed)
    elif listed:
        listed_twin(case, *listed)


def dns(v):
    return x509.DNSName(v)


with stream("x509-names"):
    # What the policy lists is a DNS name and a URI host, and the host written as a period and a domain (manifest, `policy`).
    sw_case("x509-nc-dns-valid", expect="accept", extra_permitted=[dns(HOST)])
    sw_case("x509-nc-uri-period-domain", expect="accept", nc=(HOST, "." + HOST))
    sw_case("x509-nc-email", extra_permitted=[x509.RFC822Name(HOST)])
    sw_case("x509-nc-ip-range", extra_permitted=[x509.IPAddress(ipaddress.ip_network("10.0.0.0/8"))])
    sw_case("x509-nc-directory-name", extra_permitted=[x509.DirectoryName(x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "acme")]))])
    sw_case("x509-nc-dns-empty", extra_permitted=[dns("")])
    sw_case("x509-nc-dns-upper-case", extra_permitted=[dns(HOST.upper())])
    sw_case("x509-nc-dns-wildcard", raw_permitted=[(0x82, b"*." + HOST.encode())])   # the library does not write a wildcard name
    sw_case("x509-nc-dns-trailing-period", extra_permitted=[dns(HOST + ".")])
    sw_case("x509-nc-dns-leading-period", extra_permitted=[dns("." + HOST)])
    sw_case("x509-nc-dns-numeric-last-label", extra_permitted=[dns("example.123")])
    sw_case("x509-nc-uri-scheme", nc=(HOST, "https://" + HOST))
    for case_id, d, u in (("x509-nc-dns-empty", [""], []), ("x509-nc-dns-upper-case", [HOST.upper()], []), ("x509-nc-dns-wildcard", ["*." + HOST], []),
                          ("x509-nc-dns-trailing-period", [HOST + "."], []), ("x509-nc-dns-leading-period", ["." + HOST], []),
                          ("x509-nc-dns-numeric-last-label", ["example.123"], []), ("x509-nc-uri-scheme", [], ["https://" + HOST])):
        listed_twin(case_id, d, u)

# a subject: the common name as the base request writes it, with the one change of the case
SUBJECT_CN = "acme example intermediate CA"


def subject_of(cn=SUBJECT_CN, cn_type=None, dc=(), dc_type=None, cn_twice=None):
    rdns = [x509.RelativeDistinguishedName([x509.NameAttribute(NameOID.DOMAIN_COMPONENT, d, **({"_type": dc_type} if dc_type else {}))]) for d in dc]
    rdns.append(x509.RelativeDistinguishedName([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "acme")]))
    rdns.append(x509.RelativeDistinguishedName([x509.NameAttribute(NameOID.COMMON_NAME, cn, **({"_type": cn_type} if cn_type else {}))]))
    if cn_twice:
        rdns.append(x509.RelativeDistinguishedName([x509.NameAttribute(NameOID.COMMON_NAME, cn_twice)]))
    return x509.Name(rdns)


with stream("x509-subject"):
    ASN1 = x509.name._ASN1Type
    sw_case("x509-subject-dc-ia5-string", expect="accept", subject=subject_of(dc=("org", "example")))
    sw_case("x509-subject-dc-printable-string", subject=subject_of(dc=("org", "example"), dc_type=ASN1.PrintableString))
    sw_case("x509-subject-bmp-string", subject=subject_of(cn_type=ASN1.BMPString))
    sw_case("x509-subject-non-ascii", subject=subject_of(cn="acme ex\u00e4mple intermediate CA"))
    sw_case("x509-subject-two-spaces", subject=subject_of(cn="acme example  intermediate CA"))
    sw_case("x509-subject-trailing-space", subject=subject_of(cn=SUBJECT_CN + " "))
    sw_case("x509-subject-common-name-twice", subject=subject_of(cn_twice="acme second name"))
    sw_case("x509-subject-root-name", subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "EXAMPLE TEST ROOT A (TEST ONLY)")]))

with stream("x509-request-form"):
    # two extension-request attributes that differ: the basic constraints, key usage and name constraints in one, the extended key
    # usage in the other (a verifier that merges them sees all four; `openssl req -text` shows the first only)
    sw_case("x509-request-extension-request-twice", reason="malformed", form=lambda c, k: csr_rebuild(c, k, attributes=[
        extension_request([e for e in ext_elements(c) if ext_oid(e) != OID_EXT_EKU]), extension_request([e for e in ext_elements(c) if ext_oid(e) == OID_EXT_EKU])]))
    sw_case("x509-request-challenge-password", reason="malformed", form=lambda c, k: csr_form(c, k, extra_attributes=[CHALLENGE_PASSWORD]))
    # a request whose version number is 1 (the contract requires 0)
    sw_case("x509-request-version-number-1", reason="malformed", form=lambda c, k: csr_form(c, k, version=1))
    sw_case("x509-request-sha256", reason="possession-invalid", hash_=hashes.SHA256())
    # the request's key is the key of the issuing root (the certifier's root A), signed by that key
    x509_case("x509-request-root-key", key=ROOT_A_KEY, csr=make_csr(ROOT_A_KEY), store="software", cfg="development", reason="policy")


# ---- more names (RFC 1034, 1123 and 5280 forms), more subjects and more forms of a request. New streams, one for each group.
def long_name(sizes):
    return ".".join(c * n for c, n in zip("abcdefgh", sizes))


with stream("x509-names-more"):
    # accepted: the longest label and the longest name, listed by the third configuration
    sw_case("x509-nc-dns-label-63", expect="accept", cfg=LISTED_CFG, extra_permitted=[dns("a" * 63 + "." + HOST)], listed=(["a" * 63 + "." + HOST], []))
    sw_case("x509-nc-dns-name-253", expect="accept", cfg=LISTED_CFG, extra_permitted=[dns(long_name((63, 63, 63, 61)))], listed=([long_name((63, 63, 63, 61))], []))
    for case_id, text in (("x509-nc-dns-label-over-63", "a" * 64 + "." + HOST), ("x509-nc-dns-name-over-253", long_name((63, 63, 63, 62))),
                          ("x509-nc-dns-hyphen-at-label-start", "-a." + HOST), ("x509-nc-dns-hyphen-at-label-end", "a-." + HOST),
                          ("x509-nc-dns-empty-label", "a.." + HOST), ("x509-nc-dns-underscore", "a_b." + HOST)):
        sw_case(case_id, extra_permitted=[dns(text)], listed=([text], []))
    for case_id, text in (("x509-nc-uri-port", HOST + ":8080"), ("x509-nc-uri-path", HOST + "/ca")):
        sw_case(case_id, nc=(HOST, text), listed=([], [text]))
    # the other kinds of name, each with a content that its type allows
    for case_id, tag, content in (("x509-nc-other-name", 0xA0, der(0x06, bytes.fromhex("2a0304")) + der(0xA0, der(0x0C, b"x"))),
                                  ("x509-nc-x400-address", 0xA3, der(0x30, b"")), ("x509-nc-edi-party-name", 0xA5, der(0xA1, der(0x0C, b"x"))),
                                  ("x509-nc-registered-id", 0x88, bytes.fromhex("2a0304"))):
        sw_case(case_id, raw_permitted=[(tag, content)])
    # a subtree with a minimum other than zero, and one with a maximum (RFC 5280, 4.2.1.10)
    sw_case("x509-nc-subtree-minimum", raw_subtrees=[der(0x30, der(0x82, HOST.encode()) + der(0x80, b"\x01"))])
    sw_case("x509-nc-subtree-maximum", raw_subtrees=[der(0x30, der(0x82, HOST.encode()) + der(0x81, b"\x05"))])

BASE_O = rdn_of(attr(OID_O, UTF8, b"acme"))
BASE_CN = rdn_of(attr(OID_CN, UTF8, SUBJECT_CN.encode()))


def with_subject(*rdns, **kw):
    """sw_case with the request's subject replaced by the given relative names (DER)."""
    return lambda c, k: csr_rebuild(c, k, subject=name_of(*rdns), **kw)


with stream("x509-subject-more"):
    sw_case("x509-subject-country-printable-string", expect="accept", form=with_subject(rdn_of(attr(OID_C, PRINTABLE, b"NL")), BASE_O, BASE_CN))
    sw_case("x509-subject-country-utf8-string", form=with_subject(rdn_of(attr(OID_C, UTF8, b"NL")), BASE_O, BASE_CN))
    sw_case("x509-subject-country-three-characters", form=with_subject(rdn_of(attr(OID_C, PRINTABLE, b"NLD")), BASE_O, BASE_CN))
    sw_case("x509-subject-serial-number-utf8-string", form=with_subject(rdn_of(attr(OID_SERIAL, UTF8, b"12345")), BASE_O, BASE_CN))
    sw_case("x509-subject-dn-qualifier-utf8-string", form=with_subject(rdn_of(attr(OID_DNQ, UTF8, b"acme")), BASE_O, BASE_CN))
    sw_case("x509-subject-email-address-ia5-string", expect="accept", form=with_subject(rdn_of(attr(OID_EMAIL, IA5, b"ca@example.org")), BASE_O, BASE_CN))
    sw_case("x509-subject-email-address-utf8-string", form=with_subject(rdn_of(attr(OID_EMAIL, UTF8, b"ca@example.org")), BASE_O, BASE_CN))
    sw_case("x509-subject-common-name-ia5-string", form=with_subject(BASE_O, rdn_of(attr(OID_CN, IA5, SUBJECT_CN.encode()))))
    sw_case("x509-subject-printable-string-underscore", form=with_subject(BASE_O, rdn_of(attr(OID_CN, PRINTABLE, b"acme_example_ca"))))
    sw_case("x509-subject-other-attribute-type", expect="accept", form=with_subject(rdn_of(attr(OID_OTHER, UTF8, b"acme")), BASE_O, BASE_CN))
    sw_case("x509-subject-common-name-64-characters", expect="accept", form=with_subject(BASE_O, rdn_of(attr(OID_CN, UTF8, b"a" * 64))))
    sw_case("x509-subject-common-name-65-characters", form=with_subject(BASE_O, rdn_of(attr(OID_CN, UTF8, b"a" * 65))))
    sw_case("x509-subject-value-not-a-string", form=with_subject(BASE_O, rdn_of(attr(OID_CN, 0x02, b"\x05"))))
    sw_case("x509-subject-multi-valued-relative-name", expect="accept", form=with_subject(rdn_of(attr(OID_O, UTF8, b"acme"), attr(OID_OU, UTF8, b"ops")), BASE_CN))
    sw_case("x509-subject-organizational-unit-twice", expect="accept", form=with_subject(rdn_of(attr(OID_OU, UTF8, b"ops")), rdn_of(attr(OID_OU, UTF8, b"ca")), BASE_O, BASE_CN))
    sw_case("x509-subject-organizational-unit-twice-in-one-relative-name",
            form=with_subject(rdn_of(attr(OID_OU, UTF8, b"ops"), attr(OID_OU, UTF8, b"ca")), BASE_O, BASE_CN))
    # (no case for a domain component three times: the contract says each may stand twice, and no reference settles what three do)
    sw_case("x509-subject-empty", reason="malformed", form=with_subject())
    sw_case("x509-subject-value-constructed", reason="malformed", form=with_subject(BASE_O, rdn_of(attr_raw(OID_CN, der(0x2C, der(0x0C, b"x"))))))
    sw_case("x509-subject-value-followed-by-an-element", reason="malformed",
            form=with_subject(BASE_O, rdn_of(attr(OID_CN, UTF8, SUBJECT_CN.encode(), after=der(0x05, b"")))))
    sw_case("x509-subject-unsorted-relative-name", reason="malformed",
            form=with_subject(rdn_of(*reversed(sorted([attr(OID_O, UTF8, b"acme"), attr(OID_OU, UTF8, b"ops")])), in_order=True), BASE_CN))
    # the other root key of the bundle: its key and its name
    x509_case("x509-request-root-b-key", key=ROOT_B_KEY, csr=make_csr(ROOT_B_KEY), store="software", cfg="development", reason="policy")
    sw_case("x509-subject-root-b-name", subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "EXAMPLE TEST ROOT B (TEST ONLY)")]))

with stream("x509-request-form-more"):
    sw_case("x509-request-version-number-2", reason="malformed", form=lambda c, k: csr_form(c, k, version=2))
    sw_case("x509-request-extension-twice", form=lambda c, k: csr_rebuild(c, k, attributes=[
        extension_request(ext_elements(c) + [e for e in ext_elements(c) if ext_oid(e) == OID_EXT_EKU])]))
    sw_case("x509-request-extended-key-usage-empty", form=lambda c, k: csr_rebuild(c, k, attributes=[
        extension_request([e for e in ext_elements(c) if ext_oid(e) != OID_EXT_EKU] + [extension(OID_EXT_EKU, der(0x30, b""))])]))
    sw_case("x509-request-extension-request-two-values", reason="malformed", form=lambda c, k: csr_rebuild(c, k, attributes=[
        extension_request(ext_elements(c), [e for e in ext_elements(c) if ext_oid(e) == OID_EXT_EKU])]))
    # the file: one PEM block and nothing else
    k = ec384(); c = make_csr(k)
    x509_case("x509-request-two-pem-blocks", key=k, csr=c, store="software", cfg="development", reason="malformed", pem_extra=pem_csr(c.public_bytes(DER)))
    k = ec384(); c = make_csr(k)
    x509_case("x509-request-text-after-the-pem-block", key=k, csr=c, store="software", cfg="development", reason="malformed", pem_extra=b"# a note\n")


# ---- the rest of the rules that had no case (round 4): own streams again
with stream("x509-subject-round-4"):
    # an organisational unit and a domain component may stand any number of times, each in a relative name of its own
    sw_case("x509-subject-domain-component-three-times", expect="accept",
            form=with_subject(*(rdn_of(attr(OID_DC, IA5, d)) for d in (b"corp", b"example", b"org")), BASE_O, BASE_CN))
    sw_case("x509-subject-empty-value", form=with_subject(BASE_O, rdn_of(attr(OID_CN, UTF8, b""))))
    sw_case("x509-subject-organization-65-characters", form=with_subject(rdn_of(attr(OID_O, UTF8, b"a" * 65)), BASE_CN))
    sw_case("x509-subject-empty-relative-name", reason="malformed", form=with_subject(der(0x31, b""), BASE_O, BASE_CN))
    sw_case("x509-subject-printable-string-at-sign", form=with_subject(BASE_O, rdn_of(attr(OID_CN, PRINTABLE, b"ops@acme"))))
    # a fault of content (a PrintableString with `@`) in the first relative name, a fault of form (not in DER order) in the second:
    # the fault of form is told
    sw_case("x509-subject-content-fault-before-form-fault", reason="malformed", form=with_subject(
        rdn_of(attr(OID_CN, PRINTABLE, b"a@b")), rdn_of(*reversed(sorted([attr(OID_O, UTF8, b"acme"), attr(OID_OU, UTF8, b"ops")])), in_order=True)))

with stream("x509-request-round-4"):
    sw_case("x509-request-extension-request-empty", reason="malformed", form=lambda c, k: csr_rebuild(c, k, attributes=[extension_request([])]))
    sw_case("x509-request-signature-algorithm-not-well-formed", reason="malformed", form=lambda c, k: csr_rebuild(c, k, sigalg=der(0x04, b"\x00")))
    sw_case("x509-nc-subtree-minimum-0", raw_subtrees=[der(0x30, der(0x82, HOST.encode()) + der(0x80, b"\x00"))])


k = ec384(); c = make_csr(k)
x509_case("x509-response-request", key=k, csr=c, store="software", cfg="development", expect="accept")
base = "x509-response-request"
RESP_CSR = c   # the request of the answers below; it states serverAuth
x509_response("x509-response-other-root", base, issue(c, issuer_key=ROOT_B_KEY, issuer=ROOT_B), "install", csr=c, issuer_cert=ROOT_B)
x509_response("x509-response-wrong-key", base, issue(c, pubkey=ec384().public_key()), "refuse", "key-mismatch", csr=c)
x509_response("x509-response-pathlen-1", base, issue(c, pathlen=1), "refuse", "profile", csr=c)
x509_response("x509-response-expired", base, issue(c, nb=dt.datetime(2025, 9, 1, tzinfo=UTC), na=dt.datetime(2026, 10, 1, tzinfo=UTC)), "refuse", "validity", csr=c)
x509_response("x509-response-untrusted-issuer", base, issue(c, issuer_key=ROOT_Z_KEY, issuer=ROOT_Z), "refuse", "issuer", csr=c, issuer_cert=ROOT_Z)


# ---- the floor: the same request certified by a CA that is not ritueel. The answer is a certificate and nothing else: no
# result file, no trust sequence. The requester's anchor is the CA certificate the operator installed (`floor_anchors`).
# The foreign CA writes its key identifiers the way common CA tools do (SHA-1, RFC 5280 method 1), which is outside what the
# requester checks.
def foreign_root(cn):
    k = ec384()
    n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    b = (x509.CertificateBuilder().subject_name(n).issuer_name(n).public_key(k.public_key()).serial_number(serial160())
         .not_valid_before(dt.datetime(2026, 1, 1, tzinfo=UTC)).not_valid_after(dt.datetime(2036, 1, 1, tzinfo=UTC))
         .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
         .add_extension(KU_CA, critical=True)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(k.public_key()), critical=False))
    return k, sign_builder(b, k, hashes.SHA384())


def floor_issue(csr, issuer_key=None, issuer=None, na=UNTIL, copy=True, drop=()):
    """What a CA configured to the floor profile issues: the CSR's subject and requested extensions, copied; or, with
    copy=False, a CA that drops the requested extensions and writes its own CA defaults. drop: extension types a CA that
    copies the rest leaves out (OpenSSL without `-copy_extensions copyall` leaves out all of them)."""
    issuer_key, issuer = issuer_key or FLOOR_KEY, issuer or FLOOR_ROOT
    exts = {type(e.value): e for e in csr.extensions}
    b = (x509.CertificateBuilder().subject_name(csr.subject).issuer_name(issuer.subject).public_key(csr.public_key())
         .serial_number(serial160()).not_valid_before(CLOCK).not_valid_after(na))
    if copy:
        for e in csr.extensions:
            if type(e.value) not in drop:
                b = b.add_extension(e.value, critical=e.critical)
    else:
        b = (b.add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
             .add_extension(exts[x509.KeyUsage].value, critical=True))
    b = (b.add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer.public_key()), critical=False))
    return sign_builder(b, issuer_key, hashes.SHA384())


def floor_response(case, request_case, cert, expect, reason=None):
    path = f"responses/{case}.cert.pem"
    w(path, cert.public_bytes(PEM))
    r = {"id": case, "type": "x509-intermediate", "request": request_case, "floor": True, "files": [path], "expect": expect}
    if reason:
        r["reason"] = reason
    responses.append(r)


with stream("floor"):
    FLOOR_KEY, FLOOR_ROOT = foreign_root("Example Test Foreign CA (TEST ONLY)")
    OTHER_FLOOR_KEY, OTHER_FLOOR_ROOT = foreign_root("Example Test Other Foreign CA (TEST ONLY)")   # never installed
    w("pki/test-foreign-root.pem", FLOOR_ROOT.public_bytes(PEM))
    floor_response("x509-floor-valid", base, floor_issue(c), "install")
    floor_response("x509-floor-extensions-dropped", base, floor_issue(c, copy=False), "refuse", "profile")
    floor_response("x509-floor-other-ca", base, floor_issue(c, issuer_key=OTHER_FLOOR_KEY, issuer=OTHER_FLOOR_ROOT), "refuse", "issuer")
    floor_response("x509-floor-two-years", base, floor_issue(c, na=dt.datetime(2028, 11, 15, 12, tzinfo=UTC)), "refuse", "validity")


# ---- answers whose extended key usage is not what the request asked (the rest of each certificate is valid), in a stream of their own
with stream("x509-eku-answers"):
    x509_response("x509-response-eku-dropped", base, issue(RESP_CSR, eku=None), "refuse", "profile", csr=RESP_CSR)
    x509_response("x509-response-eku-other", base, issue(RESP_CSR, eku=(CLIENT_AUTH,)), "refuse", "profile", csr=RESP_CSR)
    x509_response("x509-response-eku-widened", base, issue(RESP_CSR, eku=(SERVER_AUTH, CLIENT_AUTH)), "refuse", "profile", csr=RESP_CSR)
    floor_response("x509-floor-eku-dropped", base, floor_issue(RESP_CSR, drop=(x509.ExtendedKeyUsage,)), "refuse", "profile")
    x509_response("x509-response-eku-critical", base, issue(RESP_CSR, eku_critical=True), "refuse", "profile", csr=RESP_CSR)
    x509_response("x509-response-eku-reordered", "x509-eku-server-and-client", issue(EKU_CSRS["x509-eku-server-and-client"], eku=(CLIENT_AUTH, SERVER_AUTH)),
                  "refuse", "profile", csr=EKU_CSRS["x509-eku-server-and-client"])


# ---- OpenPGP requests: the subkey, then one back-signature for each primary in `primaries`, in that order
def pgp_case(case, store="piv", cfg="production", expect="refuse", reason=None, sk=None, primaries=None, backs=None,
             version=1, stub=None, evidence_pub=None, proof_primaries=None, card=None, capabilities=("sign",)):
    sk = sk or PgpKey(T_SUBKEY)
    primaries = ACTIVE if primaries is None else primaries
    backs = [backsig(sk, p) for p in primaries] if backs is None else backs
    req = pkt(14, sk.body) + b"".join(pkt(2, b) for b in backs)
    evidence = evidence_for(store, evidence_pub or sk.pub, card=card)
    names = proof_primaries if proof_primaries is not None else [hexfp(p) for p in primaries]
    p = proof("openpgp-subkey", req, store, evidence, version, primaries=names, capabilities=list(capabilities))
    w(f"requests/{case}.subkey.pgp", req)
    wj(f"requests/{case}.proof.json", p)
    files = [f"requests/{case}.subkey.pgp", f"requests/{case}.proof.json"]
    st = None
    if stub is not None:
        st = f"requests/{case}.kms-stub.json"
        wj(st, stub)
    add(case, "openpgp-subkey", cfg, expect, reason, files, st)
    return sk, dict(zip((hexfp(p) for p in primaries), backs)), req


def pgp_response(case, request_case, sk, backs, req, primary=PRIM_A, expect="install", reason=None, until=T_UNTIL, embed=True,
                 capability="sign"):
    back = backs.get(hexfp(primary)) or backsig(sk, primary)
    body = pkt(14, sk.body) + pkt(2, binding(sk, primary, back, until=until, embed=embed, flags=KEY_FLAGS[capability]))
    w(f"responses/{case}.bound.pgp", body)
    SUBKEYS[case] = sk
    res = {"handoff": 1, "type": "openpgp-subkey", "request_sha256": sha(req), "outcome": "issued",
           "artifacts": [{"name": f"{case}.bound.pgp", "sha256": sha(body)}], "valid_from": ts(CLOCK), "valid_until": ts(dt.datetime.fromtimestamp(until, UTC)),
           "issuer": hexfp(primary), "trust_sequence": SEQUENCE}
    wj(f"responses/{case}.result.json", res)
    r = {"id": case, "type": "openpgp-subkey", "request": request_case, "files": [f"responses/{case}.bound.pgp", f"responses/{case}.result.json"], "expect": expect}
    if reason:
        r["reason"] = reason
    responses.append(r)


sk, backs, req = pgp_case("pgp-piv-valid", expect="accept")
pgp_response("pgp-piv-valid", "pgp-piv-valid", sk, backs, req)
sk = PgpKey(T_SUBKEY)
sk, backs, req = pgp_case("pgp-kms-valid", sk=sk, store="aws-kms", expect="accept", stub=kms_stub(sk.pub))
pgp_response("pgp-kms-valid", "pgp-kms-valid", sk, backs, req)
sk, backs, req = pgp_case("pgp-openpgp-card-valid", store="openpgp-card", expect="accept")
pgp_response("pgp-openpgp-card-valid", "pgp-openpgp-card-valid", sk, backs, req)
sk, backs, req = pgp_case("pgp-software-valid", store="software", cfg="development", expect="accept")
pgp_response("pgp-software-valid", "pgp-software-valid", sk, backs, req)

pgp_case("pgp-backsig-missing", backs=[], reason="possession-invalid")
sk = PgpKey(T_SUBKEY)
pgp_case("pgp-backsig-missing-one", sk=sk, backs=[backsig(sk, PRIM_A)], reason="possession-invalid")
sk = PgpKey(T_SUBKEY)
pgp_case("pgp-backsig-wrong-primary", sk=sk, backs=[backsig(sk, PRIM_A), backsig(sk, PRIM_Z)], reason="possession-invalid")
sk = PgpKey(T_SUBKEY)
pgp_case("pgp-backsig-wrong-type", sk=sk, backs=[backsig(sk, PRIM_A), backsig(sk, PRIM_B, stype=0x18)], reason="possession-invalid")
sk = PgpKey(T_SUBKEY)
bad = bytearray(backsig(sk, PRIM_B)); bad[-1] ^= 1
pgp_case("pgp-backsig-tampered", sk=sk, backs=[backsig(sk, PRIM_A), bytes(bad)], reason="possession-invalid")
sk = PgpKey(T_SUBKEY)
pgp_case("pgp-backsig-no-key-id", sk=sk, backs=[backsig(sk, PRIM_A), backsig(sk, PRIM_B, key_id=False)], reason="possession-invalid")
pgp_case("pgp-version-2", version=2, reason="version-unsupported")
pgp_case("pgp-unknown-primary", primaries=[PRIM_A, PRIM_Z], reason="unknown-primary")
pgp_case("pgp-primaries-incomplete", primaries=[PRIM_A], reason="unknown-primary")
pgp_case("pgp-piv-key-mismatch", evidence_pub=ec384().public_key(), reason="key-mismatch")
pgp_case("pgp-openpgp-card-untrusted-chain", store="openpgp-card", card=OTHER_OPGP_CARD, reason="proof-invalid")
# an Ed25519 subkey: the request is well formed and signed, the algorithm is not one of version 1
pgp_case("pgp-ed25519", sk=PgpKey(T_SUBKEY, alg=22), store="software", cfg="development", reason="algorithm-unsupported")
# capabilities: exactly one of sign and authenticate
with stream("authenticate-refused"):
    pgp_case("pgp-capabilities-two", capabilities=("sign", "authenticate"), reason="malformed")
    pgp_case("pgp-capability-encrypt", capabilities=("encrypt",), reason="malformed")

# ---- OpenPGP answers to the request pgp-response-request: one bound by the other primary, and four a requester must refuse
sk, backs, req = pgp_case("pgp-response-request", store="software", cfg="development", expect="accept")
pgp_response("pgp-response-other-primary", "pgp-response-request", sk, backs, req, primary=PRIM_B)
pgp_response("pgp-response-no-backsig", "pgp-response-request", sk, backs, req, embed=False, expect="refuse", reason="profile")
other = PgpKey(T_SUBKEY)
pgp_response("pgp-response-wrong-subkey", "pgp-response-request", other, {}, req, expect="refuse", reason="key-mismatch")
pgp_response("pgp-response-wrong-primary", "pgp-response-request", sk, backs, req, primary=PRIM_Z, expect="refuse", reason="issuer")
# the expiry is shorter than 12 months: a requester that expects about 13 months refuses it
pgp_response("pgp-response-short-expiry", "pgp-response-request", sk, backs, req, until=T_CEREMONY + 60 * 86400, expect="refuse", reason="validity")

# ---- an authentication subkey, born on a person's card: the request asks for `authenticate`, and the binding carries key
# flag 0x20. An answer that binds it for signing instead is refused by the requester.
with stream("authenticate"):
    sk, backs, req = pgp_case("pgp-openpgp-card-authenticate", store="openpgp-card", expect="accept", capabilities=("authenticate",))
    pgp_response("pgp-openpgp-card-authenticate", "pgp-openpgp-card-authenticate", sk, backs, req, capability="authenticate")
    pgp_response("pgp-response-authenticate-bound-for-signing", "pgp-openpgp-card-authenticate", sk, backs, req, capability="sign",
                 expect="refuse", reason="profile")

# ---- SSH CA key requests (type ssh-ca-key): the key as an OpenSSH public key line, and a proof of possession that is an
# SSHSIG signature (OpenSSH PROTOCOL.sshsig) over the bytes of that line in the namespace below.
SSH_NS = b"ssh-ca-key@ritueel.id"


def sshstr(b):
    return struct.pack(">I", len(b)) + b


def sshmpint(n):
    b = n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")
    return (b"\0" + b) if b[0] & 0x80 else b


class SshKey:
    """An SSH public key: ecdsa-sha2-nistp384, or ssh-ed25519 to make a refused vector."""

    def __init__(self, alg="ecdsa-sha2-nistp384"):
        self.alg = alg
        if alg == "ssh-ed25519":
            self.priv = ed25519_key()
            raw = self.priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            self.blob = sshstr(b"ssh-ed25519") + sshstr(raw)
        else:
            self.priv = ec384()
            self.blob = sshstr(alg.encode()) + sshstr(b"nistp384") + sshstr(self.priv.public_key().public_bytes(*POINT))
        self.pub = self.priv.public_key()
        self.text = f"{alg} {b64(self.blob)}"                       # the list's ssh_public_key
        self.line = (self.text + "\n").encode()                       # the bytes of <stem>.sshca.pub
        self.fingerprint = "SHA256:" + b64(hashlib.sha256(self.blob).digest()).rstrip("=")

    def signature(self, data):
        if self.alg == "ssh-ed25519":
            return sshstr(b"ssh-ed25519") + sshstr(self.priv.sign(data))
        r, s_ = decode_dss_signature(self.priv.sign(data, ecdsa(hashes.SHA384())))
        return sshstr(self.alg.encode()) + sshstr(sshstr(sshmpint(r)) + sshstr(sshmpint(s_)))


def sshsig(key, message, ns=SSH_NS):
    """The armoured SSHSIG signature `ssh-keygen -Y sign` writes: hash algorithm sha512, an empty reserved string."""
    signed = b"SSHSIG" + sshstr(ns) + sshstr(b"") + sshstr(b"sha512") + sshstr(hashlib.sha512(message).digest())
    blob = (b"SSHSIG" + struct.pack(">I", 1) + sshstr(key.blob) + sshstr(ns) + sshstr(b"") + sshstr(b"sha512")
            + sshstr(key.signature(signed)))
    body = base64.b64encode(blob).decode()
    return ("-----BEGIN SSH SIGNATURE-----\n" + "".join(body[i:i + 70] + "\n" for i in range(0, len(body), 70))
            + "-----END SSH SIGNATURE-----\n").encode()


SSH_KEYS = {}   # case id -> (SshKey, use): the keys of the accepted requests, which the SSH CA key lists carry


def ssh_case(case, key=None, store="piv", cfg="production", expect="refuse", reason=None, use="user", ev=None, version=1,
             extra_member=None, digest_of=None, stub=None, evidence_pub=None, arn=ARN, sig_message=None, ns=SSH_NS, **att):
    key = key or SshKey()
    evidence = ev or evidence_for(store, evidence_pub or key.pub, arn=arn, att=att)
    p = proof("ssh-ca-key", digest_of or key.line, store, evidence, version)
    if use is not None:
        p["use"] = use
    if extra_member:
        p["unexpected"] = extra_member
    w(f"requests/{case}.sshca.pub", key.line)
    w(f"requests/{case}.sshca.sig", sshsig(key, sig_message or key.line, ns))
    wj(f"requests/{case}.proof.json", p)
    files = [f"requests/{case}.sshca.pub", f"requests/{case}.sshca.sig", f"requests/{case}.proof.json"]
    st = None
    if stub is not None:
        st = f"requests/{case}.kms-stub.json"
        wj(st, stub)
    add(case, "ssh-ca-key", cfg, expect, reason, files, st)
    if expect == "accept":
        SSH_KEYS[case] = (key, use)
    return key


def ssh_response(case, request_case, key, ssh_list, expect="install", reason=None, issuer_label="A"):
    """The answer to an ssh-ca-key request: the key is listed, so there is no artifact; the requester reads the SSH CA key
    list `ssh_list` of the SSH CA key list vectors, which it holds."""
    res = {"handoff": 1, "type": "ssh-ca-key", "request_sha256": sha(key.line), "outcome": "issued", "artifacts": [],
           "valid_from": ts(CLOCK), "issuer": sha(spki({"A": ROOT_A, "B": ROOT_B}[issuer_label].public_key())), "trust_sequence": SEQUENCE}
    wj(f"responses/{case}.result.json", res)
    r = {"id": case, "type": "ssh-ca-key", "request": request_case, "files": [f"responses/{case}.result.json"],
         "ssh_ca_key_list": ssh_list, "expect": expect}
    if reason:
        r["reason"] = reason
    responses.append(r)


k = ssh_case("ssh-piv-valid", expect="accept", use="user")
ssh_response("ssh-piv-valid", "ssh-piv-valid", k, "seq7-a")
k = SshKey()
ssh_case("ssh-kms-valid", key=k, store="aws-kms", expect="accept", use="host", stub=kms_stub(k.pub))
ssh_response("ssh-kms-valid", "ssh-kms-valid", k, "seq7-a")
k = ssh_case("ssh-software-valid", store="software", cfg="development", expect="accept", use="user")
ssh_response("ssh-software-valid", "ssh-software-valid", k, "seq7-a")
src = cases[-1]
cases.append({"id": "ssh-software-in-production", "type": "ssh-ca-key", "config": "production", "files": src["files"],
              "expect": "refuse", "reason": "store-not-allowed"})
ssh_case("ssh-openpgp-card", store="openpgp-card", reason="store-not-allowed")
k = SshKey()
ssh_case("ssh-bad-signature", key=k, store="software", cfg="development", sig_message=b"another request\n", reason="possession-invalid")
ssh_case("ssh-wrong-namespace", store="software", cfg="development", ns=b"file", reason="possession-invalid")
ssh_case("ssh-ed25519", key=SshKey("ssh-ed25519"), store="software", cfg="development", reason="algorithm-unsupported")
ssh_case("ssh-version-2", version=2, reason="version-unsupported")
k = SshKey()
ssh_case("ssh-request-mismatch", key=k, digest_of=SshKey().line, reason="request-mismatch")
ssh_case("ssh-unknown-member", extra_member=True, reason="malformed")
ssh_case("ssh-use-missing", use=None, reason="malformed")
ssh_case("ssh-use-both", use="both", reason="malformed")
ssh_case("ssh-piv-key-mismatch", evidence_pub=ec384().public_key(), reason="key-mismatch")
k = SshKey()
ssh_case("ssh-piv-untrusted-chain", key=k, ev=attestation(k.pub, card=OTHER_CARD), reason="proof-invalid")
ssh_case("ssh-piv-pin-never", policy=bytes([1, 1]), reason="policy")
k = SshKey()
ssh_case("ssh-kms-key-mismatch", key=k, store="aws-kms", evidence_pub=ec384().public_key(), stub=kms_stub(k.pub), reason="key-mismatch")
k = SshKey()
ssh_case("ssh-kms-two-actors", key=k, store="aws-kms", stub=kms_stub(k.pub, two_actors=True), reason="policy")

# ---- answers to the request ssh-response-request: one listed by the other root, and three a requester must refuse
k_resp = ssh_case("ssh-response-request", store="software", cfg="development", expect="accept", use="user")
ssh_response("ssh-response-other-root", "ssh-response-request", k_resp, "seq7-b", issuer_label="B")
ssh_response("ssh-response-key-not-listed", "ssh-response-request", k_resp, "seq7-a-without-key", expect="refuse", reason="key-mismatch")
ssh_response("ssh-response-wrong-use", "ssh-response-request", k_resp, "seq7-a-wrong-use", expect="refuse", reason="profile")
ssh_response("ssh-response-old-list", "ssh-response-request", k_resp, "seq6-b", expect="refuse", reason="issuer")

# ---- optional self-check material: with VERIFY_DIR set, write a detached signature by each response's subkey over a
# fixed text, so that an independent verifier (sqv) can be run on primary-cert + bound.pgp. Not part of the fixtures.
if os.environ.get("VERIFY_DIR"):
    for cid, sk in SUBKEYS.items():
        data = b"hand-off vector check\n"
        ih, iu = issuer(sk)
        sig = sig_body(0x00, sub(2, struct.pack(">I", T_CEREMONY + 3600)) + ih, iu, data, sk.sign_digest)
        os.makedirs(os.environ["VERIFY_DIR"], exist_ok=True)
        open(os.path.join(os.environ["VERIFY_DIR"], cid + ".sig"), "wb").write(pkt(2, sig))
    open(os.path.join(os.environ["VERIFY_DIR"], "data.txt"), "wb").write(b"hand-off vector check\n")

# ---- manifest
policy = {"min_firmware": "5.7.0", "pin_policy": ["once", "always"], "require_name_constraints": True,
          "permitted_uri_hosts": [HOST, "." + HOST], "permitted_dns_names": [HOST], "validity_months": 13, "kms_read_roles": {"111122223333": READ_ROLE}}
wj("manifest.json", {
    "handoff": 1,
    "clock": ts(CLOCK),
    "pinned": {
        "attestation_roots": ["pki/test-attestation-root.pem"],
        "attestation_intermediates": ["pki/test-attestation-intermediate.pem", "pki/test-opgp-attestation-intermediate.pem"],
        "root_list": {"x509": ["pki/test-root-a.pem", "pki/test-root-b.pem"], "openpgp": ["pki/test-primary-a.pgp", "pki/test-primary-b.pgp"]},
        "not_listed": {"x509": ["pki/test-root-z.pem"], "openpgp": ["pki/test-primary-z.pgp"]},
        "floor_anchors": ["pki/test-foreign-root.pem"],
        "trust_sequence": SEQUENCE,
    },
    "configs": {
        "production": {"stores": ["piv", "openpgp-card", "aws-kms"], **policy},
        "development": {"stores": ["piv", "openpgp-card", "aws-kms", "software"], **policy},
        # the development policy, and in its lists the badly formed names of the cases that name this configuration
        LISTED_CFG: {"stores": ["piv", "openpgp-card", "aws-kms", "software"], **{**policy,
                     "permitted_uri_hosts": policy["permitted_uri_hosts"] + LISTED_URI,
                     "permitted_dns_names": policy["permitted_dns_names"] + LISTED_DNS}},
    },
    "requests": cases,
    "responses": responses,
})
print("cases:", len(cases), "responses:", len(responses))


# ================================================================ root list and CA bundle vectors, version 1
_stream[:] = ["root-list", 0]
# The same roots A, B and Z as above. The hand-off answers carry trust sequence 7, and the list `seq7-a` is the
# root list of that trust set: a requester that holds it can install them.
def canonical(obj):
    """RFC 8785 canonical JSON for the values used here: ASCII member names and strings, integers, no floats.
    For those, sorted keys, no whitespace and JSON.stringify's escaping are the whole of the scheme."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


b64u = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
ROOTS = {"A": (ROOT_A_KEY, ROOT_A, PRIM_A), "B": (ROOT_B_KEY, ROOT_B, PRIM_B), "Z": (ROOT_Z_KEY, ROOT_Z, PRIM_Z)}
spki_hex = lambda lbl: sha(spki(ROOTS[lbl][1].public_key()))


def months13(t, n=13):
    """n (13) calendar months later, same day and time, or the last day of the month if it has none."""
    y, m = divmod(t.month - 1 + n, 12)
    y, m = t.year + y, m + 1
    last = (dt.datetime(y + (m == 12), m % 12 + 1, 1, tzinfo=UTC) - dt.timedelta(days=1)).day
    return t.replace(year=y, month=m, day=min(t.day, last))


def entry(lbl):
    return {"label": lbl, "x509_spki_sha256": spki_hex(lbl), "openpgp_fingerprint": ROOTS[lbl][2].fpr.hex()}


def jws(signer, payload, typ="root-list+json"):
    """A detached JWS (RFC 7515, appendix F) in compact form: header..signature. ES384 over the payload's bytes."""
    h, sig = jws_parts(signer, payload, typ)
    return h + ".." + sig


def jws_parts(signer, payload, typ):
    """The protected header and the signature, both Base64url, of one ES384 signature by a root's X.509 key."""
    key, cert, _ = ROOTS[signer]
    header = canonical({"alg": "ES384", "kid": spki_hex(signer), "typ": typ, "x5c": [b64(cert.public_bytes(DER))]})
    signing_input = (b64u(header) + "." + b64u(payload)).encode()
    r, s_ = decode_dss_signature(key.sign(signing_input, ecdsa(hashes.SHA384())))
    return b64u(header), b64u(r.to_bytes(48, "big") + s_.to_bytes(48, "big"))


def jws_general(signers, payload, typ="root-list+json"):
    """A detached JWS in the general JSON serialisation (RFC 7515, section 7.2.1, without the payload member): one
    signature for each signer, in label order, in canonical form."""
    sigs = []
    for lbl in sorted(signers):
        h, sg = jws_parts(lbl, payload, typ)
        sigs.append({"protected": h, "signature": sg})
    return canonical({"signatures": sigs})


def removal_authorisation(lbl):
    """A root's removal authorisation, made at its birth: a compact JWS with the payload attached, signed by the root's
    X.509 key over its own pin, typ root-removal+json, with no sequence and no expiry."""
    payload = canonical({"version": 1, "x509_spki_sha256": spki_hex(lbl)})
    h, sg = jws_parts(lbl, payload, "root-removal+json")
    return f"{h}.{b64u(payload)}.{sg}"


RECORDS = {n: sha(f"example ceremony record {n}\n".encode()) for n in range(1, 10)}   # made-up record digests
lists = []


def removal_entry(lbl, authorisation=None):
    return {"label": lbl, "x509_spki_sha256": spki_hex(lbl), "authorisation": removal_authorisation(lbl) if authorisation is None else authorisation}


def root_list(stem, signers, sequence, roots, signed_at, version=1, last_record=True, extra=None, tamper=None, removals=(),
              expires_at=None, flaw=None, edit=None):
    """expires_at: the expiry when it is not 13 calendar months after signed_at; flaw names, in the manifest, the one thing
    a case refuses the list for: in its dates (`expires_at-not-13-months`, `signed_at-after-clock`) or in its content
    (`label-twice`, `pin-twice`, `pin-twice-in-removals`, `fingerprint-wrong-form`, `last-record-digest-wrong-form`,
    `empty-authorisation`, `sequence-0`). edit: a function that changes the document before it is signed."""
    doc = {"version": version, "sequence": sequence, "signed_at": ts(signed_at), "expires_at": ts(expires_at or months13(signed_at)),
           "roots": [entry(r) for r in roots]}
    if last_record:
        doc["last_record_sha256"] = RECORDS[sequence - 1]
    if removals:
        doc["removals"] = list(removals)
    if extra:
        doc.update(extra)
    if edit:
        edit(doc)   # a content fault that is signed with the list (unlike `tamper`, which changes the list after signing)
    payload = canonical(doc)
    sig = jws_general(signers, payload)
    if tamper:
        payload = canonical(tamper(doc))
    w(f"lists/{stem}.json", payload, RL_OUT)
    w(f"lists/{stem}.jws", sig, RL_OUT)
    lists.append({"id": stem, "signers": sorted(signers), "files": [f"lists/{stem}.json", f"lists/{stem}.jws"], **({"flaw": flaw} if flaw else {})})


# A fourth test root, C, that a list adds; on the root list vectors only.
ROOT_C_KEY, ROOT_C = ritueel_root("C")
PRIM_C = PgpKey(T_PRIMARY)
ROOTS["C"] = (ROOT_C_KEY, ROOT_C, PRIM_C)
PRIMARY_CERTS["C"] = primary_cert(PRIM_C, b"Example Test Release Root C (TEST ONLY) <release@example.org>")

T_INIT, T_SEQ6, T_SEQ8, T_SEQ9 = T_ROOTS, dt.datetime(2026, 6, 1, 12, tzinfo=UTC), dt.datetime(2026, 12, 1, 12, tzinfo=UTC), dt.datetime(2026, 12, 2, 12, tzinfo=UTC)
root_list("init-a", "A", 1, "AB", T_INIT, last_record=False)            # the first list, made by `init`: no record before it
root_list("seq6-b", "B", 6, "AB", T_SEQ6)
root_list("seq7-a", "A", 7, "AB", CLOCK)                                # the trust set of the hand-off answers
root_list("seq7-b", "B", 7, "AB", CLOCK)
root_list("seq8-b-without-a", "B", 8, "B", T_SEQ8, removals=[removal_entry("A")])   # root A revoked: B signs, A's stored authorisation
root_list("seq8-ab-without-a", "AB", 8, "B", T_SEQ8)                    # root A retired: both roots sign
root_list("seq8-abc", "ABC", 8, "ABC", T_SEQ8)                          # root C added: every current root and C sign
root_list("seq9-a", "A", 9, "AB", T_SEQ9)                               # signed by the revoked root
root_list("seq8-z", "Z", 8, "AB", T_SEQ8)                               # signed by a root on no list
root_list("seq8-a-and-z", "AZ", 8, "AB", T_SEQ8)                        # a second signature, by a root on no list
root_list("seq8-a-version-2", "A", 8, "AB", T_SEQ8, version=2)
root_list("seq8-a-unknown-member", "A", 8, "AB", T_SEQ8, extra={"comment": "not a member of version 1"})
root_list("seq8-a-without-b", "A", 8, "A", T_SEQ8)                      # a change of the root set with one signature
root_list("seq8-b-without-a-no-removal", "B", 8, "B", T_SEQ8)           # A neither signs nor has its authorisation attached
root_list("seq8-b-without-a-wrong-removal", "B", 8, "B", T_SEQ8,        # A's entry carries B's authorisation, not A's
          removals=[removal_entry("A", removal_authorisation("B"))])
root_list("seq8-abc-not-signed-by-c", "AB", 8, "ABC", T_SEQ8)           # the added root does not sign
root_list("seq8-abc-by-a-and-c", "AC", 8, "ABC", T_SEQ8)                # a current root does not sign


def swap_b_for_z(doc):
    doc = json.loads(json.dumps(doc))
    doc["roots"][1] = entry("Z")
    return doc


root_list("seq7-a-tampered", "A", 7, "AB", CLOCK, tamper=swap_b_for_z)   # root B replaced by Z after signing
root_list("seq7-a-without-b", "A", 7, "A", CLOCK)                      # a second, different list at sequence 7
# the dates of a list (docs/decisions/0006-bundle-history-and-trust-files.md, rule 49): `expires_at` is exactly 13 calendar months after `signed_at`, and `signed_at` is not after the host's clock
root_list("seq7-a-expires-13m1s", "A", 7, "AB", CLOCK, expires_at=months13(CLOCK) + dt.timedelta(seconds=1), flaw="expires_at-not-13-months")
root_list("seq7-a-expires-12m", "A", 7, "AB", CLOCK, expires_at=months13(CLOCK, 12), flaw="expires_at-not-13-months")
root_list("seq7-a-signed-in-the-future", "A", 7, "AB", CLOCK + dt.timedelta(seconds=1), flaw="signed_at-after-clock")


def plain_month_addition(t, n=13):
    """What adding n months to the month number gives when the day does not exist (2027-01-31 plus 13 months is 2028-02-31, which
    spills into March): the answer of a plain date library, which the contract's rule is not."""
    y, m = divmod(t.month - 1 + n, 12)
    return dt.datetime(t.year + y, m + 1, 1, t.hour, t.minute, t.second, tzinfo=UTC) + dt.timedelta(days=t.day - 1)


# the end of a month: the expiry of a list signed on the 31st, the 30th and a leap day is the last day of the month it falls in
T_JAN31, T_JAN30, T_FEB29 = (dt.datetime(2026, 1, 31, 12, tzinfo=UTC), dt.datetime(2027, 1, 30, 12, tzinfo=UTC), dt.datetime(2028, 2, 29, 12, tzinfo=UTC))
root_list("seq7-a-signed-2026-01-31", "A", 7, "AB", T_JAN31)
root_list("seq7-a-signed-2027-01-30", "A", 7, "AB", T_JAN30)
root_list("seq7-a-signed-2028-02-29", "A", 7, "AB", T_FEB29)
root_list("seq7-a-signed-2026-01-31-plain-month-addition", "A", 7, "AB", T_JAN31, expires_at=plain_month_addition(T_JAN31), flaw="expires_at-not-13-months")
root_list("seq7-a-signed-2027-01-30-plain-month-addition", "A", 7, "AB", T_JAN30, expires_at=plain_month_addition(T_JAN30), flaw="expires_at-not-13-months")


# what check 5 also refuses: a list that is not a set, a form that is not the page's, a sequence below 1
def two_labels(doc):
    doc["roots"][1]["label"] = "A"


def two_pins(doc):
    doc["roots"][1]["x509_spki_sha256"] = doc["roots"][0]["x509_spki_sha256"]


def upper_case_fingerprint(doc):
    doc["roots"][0]["openpgp_fingerprint"] = doc["roots"][0]["openpgp_fingerprint"].upper()


def short_digest(doc):
    doc["last_record_sha256"] = doc["last_record_sha256"][:-1]


root_list("seq7-a-label-twice", "A", 7, "AB", CLOCK, edit=two_labels, flaw="label-twice")
root_list("seq7-a-pin-twice", "A", 7, "AB", CLOCK, edit=two_pins, flaw="pin-twice")
root_list("seq7-a-fingerprint-wrong-form", "A", 7, "AB", CLOCK, edit=upper_case_fingerprint, flaw="fingerprint-wrong-form")
root_list("seq7-a-last-record-digest-wrong-form", "A", 7, "AB", CLOCK, edit=short_digest, flaw="last-record-digest-wrong-form")
root_list("seq0-a", "A", 0, "AB", CLOCK, last_record=False, flaw="sequence-0")
root_list("seq8-b-without-a-removal-twice", "B", 8, "B", T_SEQ8, removals=[removal_entry("A"), removal_entry("A")], flaw="pin-twice-in-removals")
root_list("seq8-b-without-a-empty-authorisation", "B", 8, "B", T_SEQ8, removals=[removal_entry("A", "")], flaw="empty-authorisation")
# the list of seq7-a again, with a second signature by a root key that is on no list (the same bytes of root-list.json)
root_list("seq7-a-and-z", "AZ", 7, "AB", CLOCK)

# the removal authorisations as the holder stores them, one file for each root
removal_files = []
for lbl in "ABC":
    path = f"removals/test-root-{lbl.lower()}.removal.jws"
    w(path, removal_authorisation(lbl), RL_OUT)
    removal_files.append({"label": lbl, "file": path})

rl_cases = []


def rl_case(cid, held, candidate, expect, reason=None, clock=None, warning=None, bundle=None, min_sequence=None):
    c = {"id": cid, "held": held, "candidate": candidate}
    if bundle:
        c["bundle"] = bundle
    if min_sequence:
        c["min_sequence"] = min_sequence
    if clock:
        c["clock"] = ts(clock)
    c["expect"] = expect
    if reason:
        c["reason"] = reason
    if warning:
        c["warning"] = warning
    rl_cases.append(c)


rl_case("first-list", None, "seq7-a", "accept")
rl_case("first-list-from-init", None, "init-a", "accept")
rl_case("update", "seq6-b", "seq7-a", "accept")
rl_case("update-by-the-other-root", "init-a", "seq7-b", "accept")
rl_case("revoke-a-root", "seq7-a", "seq8-b-without-a", "accept", clock=T_SEQ8)
rl_case("retire-a-root", "seq7-a", "seq8-ab-without-a", "accept", clock=T_SEQ8)
rl_case("add-a-root", "seq7-a", "seq8-abc", "accept", clock=T_SEQ8)
rl_case("same-list-again", "seq7-a", "seq7-a", "accept")
rl_case("same-list-again-after-a-revoke", "seq8-b-without-a", "seq8-b-without-a", "accept", clock=T_SEQ8)    # checks 8 to 10 do not run
rl_case("same-list-again-after-a-retire", "seq8-ab-without-a", "seq8-ab-without-a", "accept", clock=T_SEQ8)
rl_case("rollback", "seq7-a", "seq6-b", "refuse", "rollback")
rl_case("same-sequence-different-content", "seq7-a", "seq7-a-without-b", "refuse", "sequence-conflict")
rl_case("signed-by-a-revoked-root", "seq8-b-without-a", "seq9-a", "refuse", "unknown-signer", clock=T_SEQ9)
rl_case("unknown-signer", "seq7-a", "seq8-z", "refuse", "unknown-signer", clock=T_SEQ8)
rl_case("a-second-signer-on-no-list", "seq7-a", "seq8-a-and-z", "refuse", "unknown-signer", clock=T_SEQ8)
rl_case("set-change-with-one-signature", "seq7-a", "seq8-a-without-b", "refuse", "insufficient-signers", clock=T_SEQ8)
rl_case("removal-without-authorisation", "seq7-a", "seq8-b-without-a-no-removal", "refuse", "insufficient-signers", clock=T_SEQ8)
rl_case("removal-with-another-roots-authorisation", "seq7-a", "seq8-b-without-a-wrong-removal", "refuse", "removal-invalid", clock=T_SEQ8)
rl_case("addition-not-signed-by-the-new-root", "seq7-a", "seq8-abc-not-signed-by-c", "refuse", "insufficient-signers", clock=T_SEQ8)
rl_case("addition-without-every-current-root", "seq7-a", "seq8-abc-by-a-and-c", "refuse", "insufficient-signers", clock=T_SEQ8)
rl_case("tampered", "seq6-b", "seq7-a-tampered", "refuse", "signature-invalid")
rl_case("expired", "init-a", "seq6-b", "refuse", "expired", clock=dt.datetime(2027, 8, 1, tzinfo=UTC))
rl_case("version-2", "seq7-a", "seq8-a-version-2", "refuse", "version-unsupported", clock=T_SEQ8)
rl_case("unknown-member", "seq7-a", "seq8-a-unknown-member", "refuse", "malformed", clock=T_SEQ8)
rl_case("expires-13-months-and-a-second-after-signing", "seq6-b", "seq7-a-expires-13m1s", "refuse", "malformed", clock=CLOCK)
rl_case("expires-12-months-after-signing", "seq6-b", "seq7-a-expires-12m", "refuse", "malformed", clock=CLOCK)
rl_case("signed-after-the-clock", "seq6-b", "seq7-a-signed-in-the-future", "refuse", "malformed", clock=CLOCK)
# the host's lowest sequence for its initial pins (`--min-sequence N`): the case member `min_sequence`, with no held list
rl_case("initial-pins-lowest-sequence-above", None, "seq7-a", "refuse", "rollback", min_sequence=8)
rl_case("initial-pins-lowest-sequence-equal", None, "seq7-a", "accept", min_sequence=7)
# SEC: the end of a month, the lists signed on the 31st, the 30th and a leap day (accepted at their own signing time) and two with the plain month addition
rl_case("signed-on-the-31st-of-january", None, "seq7-a-signed-2026-01-31", "accept", clock=T_JAN31)
rl_case("signed-on-the-30th-of-january-before-a-leap-year", None, "seq7-a-signed-2027-01-30", "accept", clock=T_JAN30)
rl_case("signed-on-a-leap-day", None, "seq7-a-signed-2028-02-29", "accept", clock=T_FEB29)
rl_case("expires-by-plain-month-addition-from-the-31st", None, "seq7-a-signed-2026-01-31-plain-month-addition", "refuse", "malformed", clock=T_JAN31)
rl_case("expires-by-plain-month-addition-from-the-30th", None, "seq7-a-signed-2027-01-30-plain-month-addition", "refuse", "malformed", clock=T_JAN30)
# what check 5 also refuses
rl_case("label-twice", "seq6-b", "seq7-a-label-twice", "refuse", "malformed")
rl_case("pin-twice", "seq6-b", "seq7-a-pin-twice", "refuse", "malformed")
rl_case("fingerprint-in-upper-case", "seq6-b", "seq7-a-fingerprint-wrong-form", "refuse", "malformed")
rl_case("last-record-digest-one-digit-short", "seq6-b", "seq7-a-last-record-digest-wrong-form", "refuse", "malformed")
rl_case("sequence-0", None, "seq0-a", "refuse", "malformed")
rl_case("pin-twice-in-removals", "seq7-a", "seq8-b-without-a-removal-twice", "refuse", "malformed", clock=T_SEQ8)
rl_case("empty-authorisation", "seq7-a", "seq8-b-without-a-empty-authorisation", "refuse", "malformed", clock=T_SEQ8)
# the same list again
rl_case("same-list-again-with-an-unknown-signer-beside-a-trusted-one", "seq7-a", "seq7-a-and-z", "accept")
rl_case("same-list-again-after-its-expiry", "seq7-a", "seq7-a", "refuse", "expired", clock=dt.datetime(2028, 1, 1, tzinfo=UTC))
rl_case("held-list-expired", "seq7-a", None, "warn", clock=dt.datetime(2028, 1, 1, tzinfo=UTC), warning="held-expired")

# CA bundles: the trust sequence in the first line, then each root's certificate in the order of the root list
bundles = []


def ca_bundle(sequence, roots, certs=None, suffix="", flaw=None):
    """certs: the certificates in the bundle, when they are not the roots' own (a bundle a host must refuse)."""
    certs = certs or [ROOTS[r][1] for r in roots]
    body = f"# trust-sequence: {sequence}\n".encode() + b"".join(c.public_bytes(PEM) for c in certs)
    path = f"bundles/ca-bundle-{sequence}{suffix}.pem"
    w(path, body, RL_OUT)
    bundles.append({"id": f"ca-bundle-{sequence}{suffix}", "file": path, "sequence": sequence, "roots": list(roots), **({"flaw": flaw} if flaw else {})})


ca_bundle(7, "AB")
ca_bundle(8, "B")

# A CA bundle certificate (docs/decisions/0006-bundle-history-and-trust-files.md, rule 52): a certificate that holds the key of root A and is not what the root key signed. Both are made in memory, so that
# the bundle holds the right key in each case.
with stream("ca-bundle-bad"):
    # the right key, signed by another key (root Z's): it does not verify with its own key
    foreign = ca_cert(ROOT_A.subject, ROOT_A_KEY, ROOT_A.subject, ROOT_Z_KEY, T_ROOTS, T_ROOTS_UNTIL, None, extra=[(KU_CA, True)])
    # the right key, signed by it, and basic constraints that say it is not a CA
    not_ca = sign_builder(
        x509.CertificateBuilder().subject_name(ROOT_A.subject).issuer_name(ROOT_A.subject).public_key(ROOT_A_KEY.public_key())
        .serial_number(serial160()).not_valid_before(T_ROOTS).not_valid_after(T_ROOTS_UNTIL)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(KU_CA, critical=True)
        .add_extension(x509.SubjectKeyIdentifier(ski(ROOT_A_KEY.public_key())), critical=False), ROOT_A_KEY, hashes.SHA384())
    ca_bundle(7, "AB", certs=[foreign, ROOT_B], suffix="-signed-by-another-key", flaw="not-signed-by-its-own-key")
    ca_bundle(7, "AB", certs=[not_ca, ROOT_B], suffix="-not-a-ca", flaw="not-a-ca")
    # the right key, signed by it, a CA certificate, and an issuer name that is not its subject name
    other_issuer = sign_builder(
        x509.CertificateBuilder().subject_name(ROOT_A.subject).issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Example Other Issuer (TEST ONLY)")]))
        .public_key(ROOT_A_KEY.public_key()).serial_number(serial160()).not_valid_before(T_ROOTS).not_valid_after(T_ROOTS_UNTIL)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(KU_CA, critical=True)
        .add_extension(x509.SubjectKeyIdentifier(ski(ROOT_A_KEY.public_key())), critical=False), ROOT_A_KEY, hashes.SHA384())
    ca_bundle(7, "AB", certs=[other_issuer, ROOT_B], suffix="-issuer-is-another-name", flaw="issuer-not-subject")

# a CA bundle that is not the certificates of the list, in the order of the list, under the list's sequence
ca_bundle(7, "ABC", suffix="-extra-certificate", flaw="extra-certificate")
ca_bundle(7, "A", suffix="-missing-certificate", flaw="missing-certificate")
ca_bundle(7, "BA", suffix="-wrong-order", flaw="wrong-order")
ca_bundle(8, "AB", suffix="-of-list-7", flaw="wrong-sequence")   # the first line says 8, and the certificates are those of the list of sequence 7

# the host's check of a CA bundle against the list (`--ca-bundle FILE`): its trust sequence and the keys of the roots, as before, and now
# each certificate verifies with its own key and is a CA certificate
rl_case("ca-bundle-of-the-list", None, "seq7-a", "accept", bundle="ca-bundle-7")
rl_case("ca-bundle-after-a-revoke", "seq7-a", "seq8-b-without-a", "accept", clock=T_SEQ8, bundle="ca-bundle-8")
rl_case("ca-bundle-certificate-signed-by-another-key", None, "seq7-a", "refuse", "ca-bundle-mismatch", bundle="ca-bundle-7-signed-by-another-key")
rl_case("ca-bundle-certificate-not-a-ca", None, "seq7-a", "refuse", "ca-bundle-mismatch", bundle="ca-bundle-7-not-a-ca")
rl_case("ca-bundle-certificate-names-another-issuer", None, "seq7-a", "refuse", "ca-bundle-mismatch", bundle="ca-bundle-7-issuer-is-another-name")
rl_case("ca-bundle-with-a-certificate-too-many", None, "seq7-a", "refuse", "ca-bundle-mismatch", bundle="ca-bundle-7-extra-certificate")
rl_case("ca-bundle-with-a-certificate-missing", None, "seq7-a", "refuse", "ca-bundle-mismatch", bundle="ca-bundle-7-missing-certificate")
rl_case("ca-bundle-in-the-wrong-order", None, "seq7-a", "refuse", "ca-bundle-mismatch", bundle="ca-bundle-7-wrong-order")
rl_case("ca-bundle-with-the-wrong-first-line", None, "seq7-a", "refuse", "ca-bundle-mismatch", bundle="ca-bundle-8-of-list-7")

for lbl in "ABCZ":
    w(f"pki/test-root-{lbl.lower()}.pem", ROOTS[lbl][1].public_bytes(PEM), RL_OUT)
    w(f"pki/test-primary-{lbl.lower()}.pgp", PRIMARY_CERTS[lbl], RL_OUT)
wj("manifest.json", {
    "root_list": 1,
    "clock": ts(CLOCK),
    "roots": [{"label": lbl, "certificate": f"pki/test-root-{lbl.lower()}.pem", "openpgp": f"pki/test-primary-{lbl.lower()}.pgp",
               "x509_spki_sha256": spki_hex(lbl), "openpgp_fingerprint": ROOTS[lbl][2].fpr.hex()} for lbl in "ABCZ"],
    "initial_pins": ["A", "B"],
    "removals": removal_files,
    "lists": lists,
    "cases": rl_cases,
    "bundles": bundles,
}, RL_OUT)
print("root lists:", len(lists), "cases:", len(rl_cases), "bundles:", len(bundles))


# ================================================================ SSH CA key list vectors, version 1
_stream[:] = ["ssh-ca-keys", 0]
# The list at trust sequence 7 holds the keys of the accepted ssh-ca-key requests above, the key of the answer vectors,
# and a break-glass SSH CA for each of the roots A and B. The hand-off answers of type ssh-ca-key name these lists.
BREAK_GLASS = {lbl: SshKey() for lbl in "AB"}


def ssh_entry(name_, key, use, root_label=None):
    e = {"name": name_, "use": use, "ssh_public_key": key.text, "fingerprint": key.fingerprint}
    if root_label:
        e["root"] = root_label
    return e


def listed(without=(), wrong_use=()):
    """The entries of the list at sequence 7, sorted by name: the break-glass keys, then the requests' keys. A name in
    wrong_use is listed with the other use than the request asked for."""
    es = [ssh_entry(f"break-glass-{lbl}", BREAK_GLASS[lbl], "user", lbl) for lbl in "AB"]
    for c, (k, u) in SSH_KEYS.items():
        if c not in without:
            es.append(ssh_entry(c, k, ("host" if u == "user" else "user") if c in wrong_use else u))
    return sorted(es, key=lambda e: e["name"].encode())


ssh_lists = []


def ssh_list(stem, signer, sequence, entries, signed_at, version=1, extra=None, tamper=None, typ="ssh-ca-keys+json", expires_at=None, flaw=None):
    """flaw names, in the manifest, the one thing a case refuses the list for in its dates, as in the root list set."""
    doc = {"version": version, "sequence": sequence, "signed_at": ts(signed_at), "expires_at": ts(expires_at or months13(signed_at)), "keys": entries}
    if extra:
        doc.update(extra)
    payload = canonical(doc)
    sig = jws(signer, payload, typ)
    if tamper:
        payload = canonical(tamper(doc))
    w(f"lists/{stem}.json", payload, SSH_OUT)
    w(f"lists/{stem}.jws", sig, SSH_OUT)
    ssh_lists.append({"id": stem, "signer": signer, "files": [f"lists/{stem}.json", f"lists/{stem}.jws"], **({"flaw": flaw} if flaw else {})})


def user_keys_file(sequence, entries):
    """The file for sshd's TrustedUserCAKeys: the trust sequence in a comment, then every key whose use is user, in list order."""
    return (f"# trust-sequence: {sequence}\n" + "".join(e["ssh_public_key"] + "\n" for e in entries if e["use"] == "user")).encode()


ssh_list("seq6-b", "B", 6, [ssh_entry(f"break-glass-{lbl}", BREAK_GLASS[lbl], "user", lbl) for lbl in "AB"], T_SEQ6)
ssh_list("seq7-a", "A", 7, listed(), CLOCK)
ssh_list("seq7-b", "B", 7, listed(), CLOCK)
ssh_list("seq7-a-without-key", "A", 7, listed(without=("ssh-response-request",)), CLOCK)
ssh_list("seq7-a-wrong-use", "A", 7, listed(wrong_use=("ssh-response-request",)), CLOCK)
# the dates of a list, as for the root list: 13 calendar months exactly, and not signed after the host's clock
ssh_list("seq7-a-expires-13m1s", "A", 7, listed(), CLOCK, expires_at=months13(CLOCK) + dt.timedelta(seconds=1), flaw="expires_at-not-13-months")
ssh_list("seq7-a-expires-12m", "A", 7, listed(), CLOCK, expires_at=months13(CLOCK, 12), flaw="expires_at-not-13-months")
ssh_list("seq7-a-signed-in-the-future", "A", 7, listed(), CLOCK + dt.timedelta(seconds=1), flaw="signed_at-after-clock")
no_bg_a = [e for e in listed() if e["name"] != "break-glass-A"]
ssh_list("seq8-b-without-a", "B", 8, no_bg_a, T_SEQ8)                     # root A revoked: its break-glass key leaves, signed by B
ssh_list("seq8-a-retiring", "A", 8, no_bg_a, T_SEQ8)                      # root A retires and signs the lists that remove it
ssh_list("seq8-a-empty", "A", 8, [], T_SEQ8)                              # every key withdrawn
ssh_list("seq9-a", "A", 9, no_bg_a, T_SEQ9)                               # signed by the revoked root
ssh_list("seq8-z", "Z", 8, listed(), T_SEQ8)                              # signed by a root on no list
ssh_list("seq8-a-version-2", "A", 8, listed(), T_SEQ8, version=2)
ssh_list("seq8-a-unknown-member", "A", 8, listed(), T_SEQ8, extra={"comment": "not a member of version 1"})
dup = listed()
ssh_list("seq8-a-duplicate-key", "A", 8, sorted(dup + [dict(dup[2], name="zzz-copy")], key=lambda e: e["name"].encode()), T_SEQ8)
ssh_list("seq8-a-root-list-type", "A", 8, listed(), T_SEQ8, typ="root-list+json")   # the root list's type in the protected header


def swap_key(doc):
    doc = json.loads(json.dumps(doc))
    doc["keys"][2]["ssh_public_key"] = SshKey().text
    return doc


ssh_list("seq7-a-tampered", "A", 7, listed(), CLOCK, tamper=swap_key)     # a key replaced after signing

w("files/ssh-user-ca-keys-7.pub", user_keys_file(7, listed()), SSH_OUT)
w("files/ssh-user-ca-keys-7-with-host-key.pub", user_keys_file(7, listed()) + (SSH_KEYS["ssh-kms-valid"][0].text + "\n").encode(), SSH_OUT)

ssh_cases = []


def ssh_list_case(cid, held, candidate, expect, reason=None, clock=None, warning=None, roots="AB", rl_sequence=None, rl_signer=None, user_keys=None):
    c = {"id": cid, "held": held, "candidate": candidate, "root_list": {"roots": list(roots)}}
    if rl_sequence:
        c["root_list"].update({"sequence": rl_sequence, "signer": rl_signer})
    if clock:
        c["clock"] = ts(clock)
    if user_keys:
        c["user_keys"] = user_keys
    c["expect"] = expect
    if reason:
        c["reason"] = reason
    if warning:
        c["warning"] = warning
    ssh_cases.append(c)


ssh_list_case("first-list", None, "seq7-a", "accept")
ssh_list_case("update", "seq6-b", "seq7-a", "accept")
ssh_list_case("same-list-signed-by-the-other-root", "seq7-a", "seq7-b", "accept")
ssh_list_case("remove-a-revoked-roots-key", "seq7-a", "seq8-b-without-a", "accept", clock=T_SEQ8, roots="B", rl_sequence=8, rl_signer="B")
ssh_list_case("retiring-root-signs", "seq7-a", "seq8-a-retiring", "accept", clock=T_SEQ8, roots="B", rl_sequence=8, rl_signer="A")
ssh_list_case("every-key-withdrawn", "seq7-a", "seq8-a-empty", "accept", clock=T_SEQ8)
ssh_list_case("same-list-again", "seq7-a", "seq7-a", "accept")
ssh_list_case("same-list-again-after-a-revoke", "seq8-b-without-a", "seq8-b-without-a", "accept", clock=T_SEQ8, roots="B", rl_sequence=8, rl_signer="B")
ssh_list_case("expires-13-months-and-a-second-after-signing", "seq6-b", "seq7-a-expires-13m1s", "refuse", "malformed", clock=CLOCK)
ssh_list_case("expires-12-months-after-signing", "seq6-b", "seq7-a-expires-12m", "refuse", "malformed", clock=CLOCK)
ssh_list_case("signed-after-the-clock", "seq6-b", "seq7-a-signed-in-the-future", "refuse", "malformed", clock=CLOCK)
ssh_list_case("user-keys-file", None, "seq7-a", "accept", user_keys="files/ssh-user-ca-keys-7.pub")
ssh_list_case("rollback", "seq7-a", "seq6-b", "refuse", "rollback")
ssh_list_case("same-sequence-different-content", "seq7-a", "seq7-a-without-key", "refuse", "sequence-conflict")
ssh_list_case("signed-by-a-revoked-root", "seq8-b-without-a", "seq9-a", "refuse", "unknown-signer", clock=T_SEQ9, roots="B", rl_sequence=9, rl_signer="B")
ssh_list_case("retiring-root-signs-after-its-root-list", "seq7-a", "seq8-a-retiring", "refuse", "unknown-signer", clock=T_SEQ8, roots="B", rl_sequence=9, rl_signer="B")
ssh_list_case("unknown-signer", "seq7-a", "seq8-z", "refuse", "unknown-signer", clock=T_SEQ8)
ssh_list_case("tampered", "seq6-b", "seq7-a-tampered", "refuse", "signature-invalid")
ssh_list_case("expired", "seq6-b", "seq7-a", "refuse", "expired", clock=dt.datetime(2028, 1, 1, tzinfo=UTC))
ssh_list_case("version-2", "seq7-a", "seq8-a-version-2", "refuse", "version-unsupported", clock=T_SEQ8)
ssh_list_case("unknown-member", "seq7-a", "seq8-a-unknown-member", "refuse", "malformed", clock=T_SEQ8)
ssh_list_case("duplicate-key", "seq7-a", "seq8-a-duplicate-key", "refuse", "malformed", clock=T_SEQ8)
ssh_list_case("root-list-type", "seq7-a", "seq8-a-root-list-type", "refuse", "malformed", clock=T_SEQ8)
ssh_list_case("user-keys-file-with-a-host-key", None, "seq7-a", "refuse", "user-keys-mismatch", user_keys="files/ssh-user-ca-keys-7-with-host-key.pub")
ssh_list_case("held-list-expired", "seq7-a", None, "warn", clock=dt.datetime(2028, 1, 1, tzinfo=UTC), warning="held-expired")

for lbl in "ABZ":
    w(f"pki/test-root-{lbl.lower()}.pem", ROOTS[lbl][1].public_bytes(PEM), SSH_OUT)
wj("manifest.json", {
    "ssh_ca_keys": 1,
    "clock": ts(CLOCK),
    "roots": [{"label": lbl, "certificate": f"pki/test-root-{lbl.lower()}.pem", "x509_spki_sha256": spki_hex(lbl)} for lbl in "ABZ"],
    "lists": ssh_lists,
    "files": [{"id": "ssh-user-ca-keys-7", "file": "files/ssh-user-ca-keys-7.pub"},
              {"id": "ssh-user-ca-keys-7-with-host-key", "file": "files/ssh-user-ca-keys-7-with-host-key.pub"}],
    "cases": ssh_cases,
}, SSH_OUT)
print("ssh ca key lists:", len(ssh_lists), "cases:", len(ssh_cases))


# ================================================================ CRL vectors, version 1
_stream[:] = ["crl", 0]
# One CRL for each root, signed by that root. The CRL number is the trust sequence at which the root signed it: root A
# signed at sequence 7, root B at sequence 6, and B's CRL is still current because a CRL is valid for 25 months.
def crl_cert(root_lbl):
    key, root_cert, _ = ROOTS[root_lbl]
    csr = make_csr(ec384())
    return issue(csr, issuer_key=key, issuer=root_cert)


CA_A1, CA_B1 = crl_cert("A"), crl_cert("B")
w("certs/ca-a-1.pem", CA_A1.public_bytes(PEM), CRL_OUT)
w("certs/ca-b-1.pem", CA_B1.public_bytes(PEM), CRL_OUT)
CRL_CERTS = [{"id": "ca-a-1", "file": "certs/ca-a-1.pem", "issuer": "A", "serial": f"{CA_A1.serial_number:x}"},
             {"id": "ca-b-1", "file": "certs/ca-b-1.pem", "issuer": "B", "serial": f"{CA_B1.serial_number:x}"}]
crls = []


def crl(stem, signer, number, this, revoked=(), nxt=None, hash_=None, critical_ext=False, tamper=None):
    key, root_cert, _ = ROOTS[signer]
    b = (x509.CertificateRevocationListBuilder().issuer_name(root_cert.subject).last_update(this)
         .next_update(nxt or months13(this, 25))
         .add_extension(x509.AuthorityKeyIdentifier(ski(root_cert.public_key()), None, None), critical=False)
         .add_extension(x509.CRLNumber(number), critical=False))
    for cert in revoked:
        b = b.add_revoked_certificate(x509.RevokedCertificateBuilder().serial_number(cert.serial_number).revocation_date(this)
                                      .add_extension(x509.CRLReason(x509.ReasonFlags.key_compromise), critical=False).build())
    if critical_ext:
        b = b.add_extension(x509.UnrecognizedExtension(ObjectIdentifier("1.3.6.1.4.1.99999.1"), b"\x05\x00"), critical=True)
    der = sign_builder(b, key, hash_ or hashes.SHA384()).public_bytes(DER)
    if tamper:
        der = tamper(der)
    pem = ("-----BEGIN X509 CRL-----\n" + "".join(b64(der)[i:i + 64] + "\n" for i in range(0, len(b64(der)), 64)) + "-----END X509 CRL-----\n")
    w(f"crls/{stem}.pem", pem, CRL_OUT)
    crls.append({"id": stem, "signer": signer, "file": f"crls/{stem}.pem", "number": number, "this_update": ts(this),
                 "next_update": ts(nxt or months13(this, 25)), "revoked": [{"serial": f"{c.serial_number:x}", "reason": "keyCompromise"} for c in revoked]})


def swap_serial(der):
    """Replace the revoked serial by another of the same length, after signing."""
    old = CA_A1.serial_number.to_bytes((CA_A1.serial_number.bit_length() + 7) // 8, "big")
    new = bytearray(old)
    new[-1] ^= 0x01
    assert old in der
    return der.replace(old, bytes(new))


T_B_CRL = dt.datetime(2025, 11, 15, 12, tzinfo=UTC)
crl("a-seq7-empty", "A", 7, CLOCK)
crl("b-seq6-empty", "B", 6, T_B_CRL)
crl("a-seq8-revokes", "A", 8, T_SEQ8, [CA_A1])
crl("a-seq7-revokes", "A", 7, CLOCK, [CA_A1])                              # another CRL with number 7
crl("z-seq8", "Z", 8, T_SEQ8)
crl("a-seq8-tampered", "A", 8, T_SEQ8, [CA_A1], tamper=swap_serial)
crl("a-seq5-expired", "A", 5, dt.datetime(2024, 9, 15, 12, tzinfo=UTC))
crl("a-seq9-not-yet-valid", "A", 9, dt.datetime(2027, 1, 1, 12, tzinfo=UTC))
crl("a-seq8-critical-extension", "A", 8, T_SEQ8, critical_ext=True)
crl("a-seq8-sha256", "A", 8, T_SEQ8, hash_=hashes.SHA256())

crl_cases = []


def crl_case(cid, held, candidate, expect, reason=None, clock=None, warning=None, roots="AB"):
    c = {"id": cid, "held": held, "candidate": candidate, "roots": list(roots)}
    if clock:
        c["clock"] = ts(clock)
    c["expect"] = expect
    if reason:
        c["reason"] = reason
    if warning:
        c["warning"] = warning
    crl_cases.append(c)


crl_case("first-crl", None, "a-seq7-empty", "accept")
crl_case("first-crl-of-the-other-root", None, "b-seq6-empty", "accept")
crl_case("the-other-roots-crl-a-year-on", None, "b-seq6-empty", "accept", clock=dt.datetime(2027, 11, 15, 12, tzinfo=UTC))
crl_case("update", "a-seq7-empty", "a-seq8-revokes", "accept", clock=T_SEQ8)
crl_case("same-crl-again", "a-seq7-empty", "a-seq7-empty", "accept")
crl_case("rollback", "a-seq8-revokes", "a-seq7-empty", "refuse", "rollback", clock=T_SEQ8)
crl_case("same-number-different-content", "a-seq7-empty", "a-seq7-revokes", "refuse", "sequence-conflict")
crl_case("unknown-signer", None, "z-seq8", "refuse", "unknown-signer", clock=T_SEQ8)
crl_case("signed-by-a-revoked-root", None, "a-seq8-revokes", "refuse", "unknown-signer", clock=T_SEQ8, roots="B")
crl_case("tampered", None, "a-seq8-tampered", "refuse", "signature-invalid", clock=T_SEQ8)
crl_case("expired", None, "a-seq5-expired", "refuse", "expired")
crl_case("not-yet-valid", None, "a-seq9-not-yet-valid", "refuse", "not-yet-valid")
crl_case("critical-extension", None, "a-seq8-critical-extension", "refuse", "malformed", clock=T_SEQ8)
crl_case("sha-256-signature", None, "a-seq8-sha256", "refuse", "malformed", clock=T_SEQ8)
crl_case("held-crl-expired", "a-seq7-empty", None, "warn", clock=dt.datetime(2029, 1, 1, tzinfo=UTC), warning="held-expired")

crl_revocation = [
    {"id": "listed", "cert": "ca-a-1", "crl": "a-seq8-revokes", "clock": ts(T_SEQ8), "expect": "revoked"},
    {"id": "not-listed", "cert": "ca-a-1", "crl": "a-seq7-empty", "expect": "good"},
    {"id": "other-root-not-listed", "cert": "ca-b-1", "crl": "b-seq6-empty", "expect": "good"},
]

for lbl in "ABZ":
    w(f"pki/test-root-{lbl.lower()}.pem", ROOTS[lbl][1].public_bytes(PEM), CRL_OUT)
wj("manifest.json", {
    "crl": 1,
    "clock": ts(CLOCK),
    "roots": [{"label": lbl, "certificate": f"pki/test-root-{lbl.lower()}.pem", "x509_spki_sha256": spki_hex(lbl)} for lbl in "ABZ"],
    "certs": CRL_CERTS,
    "crls": crls,
    "cases": crl_cases,
    "revocation": crl_revocation,
}, CRL_OUT)
print("crls:", len(crls), "cases:", len(crl_cases), "revocation:", len(crl_revocation))
