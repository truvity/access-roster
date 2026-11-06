#!/usr/bin/env bash
# This repository is public and its history cannot be unpublished — a
# rewrite changes the SHAs but not what was already fetched. So the rule
# ("mechanism only; particulars are caller inputs or org variables") is
# enforced mechanically rather than remembered.
#
# Vendored from truvity/ci-workflows (hack/leak-canary.sh), which is public
# for the same reason. Keep it in step with that copy.
#
# Every chart value, action input or documented example that names a
# cluster, an account, a hostname or a secret path is an INPUT with a
# neutral default; the consuming installation supplies the particulars
# from its own repository.
#
# Deltas from that copy, each with its reason. Every one MASKS a narrow
# shape on the matching lines and matches the pattern again, so a real
# particular on the same line as an allowed shape still fails:
#
#   - The account-id and ECR-host patterns skip AWS's own documented
#     placeholder accounts (111122223333, 444455556666), the neutral values
#     the docs, the tests and the action's examples use. Only those two.
#   - 'arn:aws' skips an ARN whose account field is one of those two
#     placeholders or a format verb (%s): sluisctl and the action COMPOSE
#     role ARNs from an audience the caller supplies. Any other ARN still
#     matches, including one with no account (an S3 bucket's).
#   - '/secrets/' skips '/var/run/secrets/', the root Kubernetes mounts a
#     pod's ServiceAccount token and projected volumes under, and
#     '/etc/audit/secrets/', where the audit chart projects a Secret's keys.
#     Both are paths inside the container, not SSM parameters.
#   - 'arn:aws' also skips an ARN whose region and account fields are each
#     empty or a <placeholder>, the shape the audit documentation and Go
#     comments write ('arn:aws:iam::<account>:role/...', 's3:::<bucket>').
#     A real account id in the same ARN still matches.
#   - The internal-hostname pattern skips the label key prefix earlier
#     releases wrote, in the two files that must spell it and nowhere
#     else: internal/kube/legacy_labels.go, which moves objects off it at
#     start, and CHANGELOG.md, whose rollback note moves them back. Any
#     other file naming it, or any other host in those two, still matches.
#
#   - The internal-hostname pattern also skips 'schemas.truvity.com/audit/',
#     the legacy schema identifier base that audit's loader still accepts
#     (docs/decisions/0057), in the audit tree only. It is a name that
#     was never served, kept for the compatibility of archived records.
#
# Estate-internal names (a pattern group added with the neutral-names
# change): the owner's rule is that this public tree names no estate, so
# the names are matched as words, case-insensitively, and the script itself
# is excluded as for every other pattern. 'kernel' is deliberately NOT a
# pattern: it names a cluster in the estate but is also the OS kernel in
# legitimate places, and this script has no context-specific patterns.
# 'hive' is word-bounded so archive/archived never match.
#
# Add a pattern here the first time something new turns out to be a
# particular. Never add an exception without one.
set -uo pipefail

account_id='\b[0-9]{12}\b'
ecr_host='\b[0-9]{12}\.dkr\.ecr\.'
arn='arn:aws'
secret_path='/secrets/'
internal_host='\.truvity\.(xyz|com|co)'

documented_placeholders='\b(111122223333|444455556666)\b'
composed_arn='arn:aws(-[a-z]+)?:[a-z0-9-]*:[a-z0-9-]*:(%s|111122223333|444455556666):'
legacy_label_files='^(internal/kube/legacy_labels\.go|CHANGELOG\.md):'
legacy_label_prefix='directory-roster\.truvity\.com/'
legacy_schema_files='^(audit/[^:]*):'
legacy_schema_base='schemas\.truvity\.com/audit/'
placeholder_arn='arn:aws(-[a-z]+)?:[a-z0-9-]*:(<[a-z-]+>)?:(<[a-z-]+>)?:'

# The 12-digit patterns are anchored on word boundaries. Without them,
# `[0-9]{12}` also matches a 12-digit run that happens to fall inside a
# longer hex string -- and a nixpkgs commit SHA is exactly that. The
# devbox bump to 17de0b976395537756f30a3e78f2f06e5cec89ed contains
# `976395537756`, which failed this canary simultaneously in every repo
# that carries it, for a value that is neither a particular nor secret.
# `\b` keeps every real shape (bare, in an ARN, as an ECR host: each is
# bounded by a non-word character) and drops the hex-embedded ones.
estate_names='\b(opwerm|excavador|nexus)\b'
estate_hive='\bhive\b'

patterns=(
  "$account_id"                        # AWS account id
  "$arn"                               # any ARN
  "$ecr_host"                          # ECR registry host
  '\.svc\.cluster\.local'              # in-cluster DNS
  "$secret_path"                       # SSM parameter paths
  'truvity-[a-z0-9-]*-(ci-cache|artifacts|state)'   # S3 buckets
  "$internal_host"                     # internal hostnames
  'glpat-|ghp_|github_pat_'            # tokens, in case of an accident
  "$estate_names"                      # estate-internal names
  "$estate_hive"                       # estate-internal cluster name
  'excavador\.xyz'                     # estate domain
  '\.truvity\.private\b'               # private hostnames
  'truvity/gitops'                     # the private estate repository
  'truvity/kernel'                     # the same repository, renamed
  'INF-[0-9]+'                         # tracker keys (audit/): a key points at a board nobody outside can open
)

# Name patterns match case-insensitively; every other pattern is exact.
flags() {
  case "$1" in
    "$estate_names" | "$estate_hive" | 'excavador\.xyz' | '\.truvity\.private\b' | 'truvity/gitops' | 'truvity/kernel') echo -iE ;;
    *) echo -E ;;
  esac
}

# mask hides the one shape the header allows for a pattern, on hits read
# as grep prints them (file:line:text). A pattern with no delta passes
# through unchanged.
mask() {
  case "$1" in
    "$account_id" | "$ecr_host")
      sed -E "s/$documented_placeholders/<placeholder>/g" ;;
    "$arn")
      sed -E "s/$composed_arn/<composed-arn>/g; s/$placeholder_arn/<placeholder-arn>/g" ;;
    "$secret_path")
      sed -E 's#/(var/run|etc/audit)/secrets/#<pod-mount>/#g' ;;
    "$internal_host")
      sed -E "\\#$legacy_label_files#s#$legacy_label_prefix#<legacy-label-prefix>/#g; \\#$legacy_schema_files#s#$legacy_schema_base#<legacy-schema-base>/#g" ;;
    *)
      cat ;;
  esac
}

fail=0

# Scan TRACKED FILES ONLY. The point of this canary is to stop particulars
# being committed, so git's index is exactly the right scope -- and a
# recursive walk of the working tree is not. It descended into generated,
# gitignored directories: .devbox/state.json carries a
# `nix_print_dev_env_hash` whose hex contains a 12-digit run, which matched
# the AWS-account-id pattern. That made the canary fail on a clean checkout
# for a value that is neither committed nor secret.
#
# This matters more than a nuisance: a canary that cries wolf is one people
# learn to skip, and this one is what stands between us and publishing
# particulars from a public repo.
mapfile -d '' tracked < <(git ls-files -z)

for p in "${patterns[@]}"; do
  # Exclude this script: it necessarily contains the patterns it bans.
  hits=$(printf '%s\0' "${tracked[@]}" \
           | grep -zZv '^hack/leak-canary\.sh$' \
           | xargs -0 -r grep -In $(flags "$p") "$p" 2>/dev/null \
           | mask "$p" | grep $(flags "$p") "$p")
  if [ -n "$hits" ]; then
    echo "LEAK: pattern /$p/ matched — particulars belong in caller inputs or org variables:"
    echo "$hits" | head -5 | sed 's/^/    /'
    fail=1
  fi
done

if [ "$fail" = 0 ]; then
  echo "leak canary clean — ${#patterns[@]} patterns checked, no particulars found"
fi
exit $fail
