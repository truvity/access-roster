#!/usr/bin/env bash
# A test of the operating-system checks of remote.sh (deploy/boards/remote-lib.sh) against fakes of dpkg, rpm, systemctl,
# selinuxenabled and restorecon, and a fake os-release: no board, no package manager. Run from anywhere:
# deploy/boards/prereq-test.sh
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin"

# The fakes. FAKE_PKGS and FAKE_UNITS are space-separated lists of what is "installed"; FAKE_SELINUX=1 makes selinuxenabled succeed.
cat >"$work/bin/dpkg" <<'F'
#!/bin/bash
[ "$1" = -s ] && [[ " $FAKE_PKGS " == *" $2 "* ]]
F
cat >"$work/bin/rpm" <<'F'
#!/bin/bash
[ "$1" = -q ] && [[ " $FAKE_PKGS " == *" $2 "* ]]
F
cat >"$work/bin/systemctl" <<'F'
#!/bin/bash
if [ "$1" = --version ]; then
	[ -n "${FAKE_SYSTEMD:-}" ] && printf 'systemd %s (%s-1)\n+PAM +AUDIT\n' "$FAKE_SYSTEMD" "$FAKE_SYSTEMD"
	exit 0
fi
[ "$1" = cat ] && [[ " $FAKE_UNITS " == *" $2 "* ]]
F
# systemd-creds encrypt --with-key=host --name=N IN OUT: the "blob" says the name and the key; FAKE_CREDS_FAIL=1 makes it fail.
cat >"$work/bin/systemd-creds" <<'F'
#!/bin/bash
[ "${FAKE_CREDS_FAIL:-}" != 1 ] || exit 1
[ "$1" = encrypt ] && [ "$2" = --with-key=host ] && [[ "$3" == --name=* ]] || exit 2
printf 'blob name=%s key=host\n' "${3#--name=}" >"$5"
F
# getent group NAME|GID and getent passwd NAME|UID: the groups of $FAKE_GROUPS (name:gid) and the users of $FAKE_USERS
# (name:uid, or name:uid:gid for a primary group of another number), space-separated lists. FAKE_GETENT_RC makes every lookup exit with that status (3: the database cannot be read).
cat >"$work/bin/getent" <<'F'
#!/bin/bash
[ -z "${FAKE_GETENT_RC:-}" ] || exit "$FAKE_GETENT_RC"
case "$1" in group) list=${FAKE_GROUPS:-} ;; passwd) list=${FAKE_USERS:-} ;; *) exit 1 ;; esac
for e in $list; do
	IFS=: read -r n id gid <<<"$e"
	[ "$n" = "$2" ] || [ "$id" = "$2" ] || continue
	if [ "$1" = group ]; then printf '%s:x:%s:\n' "$n" "$id"; else printf '%s:x:%s:%s::/:/usr/sbin/nologin\n' "$n" "$id" "${gid:-$id}"; fi
	exit 0
done
exit 2
F
cat >"$work/bin/selinuxenabled" <<'F'
#!/bin/bash
[ "${FAKE_SELINUX:-}" = 1 ]
F
cat >"$work/bin/restorecon" <<'F'
#!/bin/bash
printf '%s\n' "$*" >>"$RESTORECON_LOG"
F
chmod +x "$work"/bin/*
fail=0
accept() { # description command...: the command must succeed
	local d=$1
	shift
	if "$@" 2>"$work/err"; then echo "ok   $d"; else echo "FAIL $d"; sed 's/^/     /' "$work/err"; fail=1; fi
}
refuse() { # description pattern command...: the command must fail, and its message must match the pattern
	local d=$1 pat=$2
	shift 2
	if "$@" 2>"$work/err"; then echo "FAIL $d: it succeeded"; fail=1
	elif grep -qE "$pat" "$work/err"; then echo "ok   $d"
	else echo "FAIL $d: the message does not match $pat:"; sed 's/^/     /' "$work/err"; fail=1; fi
}
is() { # description expected command...
	local d=$1 want=$2 got
	shift 2
	got=$("$@")
	if [ "$got" = "$want" ]; then echo "ok   $d"; else echo "FAIL $d: got '$got', want '$want'"; fail=1; fi
}

osrel() { # id id_like
	printf 'ID=%s\nID_LIKE="%s"\n' "$1" "$2" >"$work/os-release"
}
# run executes a command of the library in a subshell with a PATH of the fakes alone, so that nothing of this workstation (a real
# pkcheck, a real dpkg) answers.
run() {
	(
		export PATH="$work/bin" os_release_file="$work/os-release" card_polkit_policy="$work/policy" state_root="$work/state" manifest="$work/manifest"
		# shellcheck source=/dev/null
		. "$here/remote-lib.sh"
		"$@"
	)
}

osrel ubuntu debian
is "Ubuntu is the deb family" deb run os_family
osrel rocky "rhel centos fedora"
is "Rocky is the rpm family" rpm run os_family
osrel nixos ""
is "another system is unknown" unknown run os_family

export FAKE_UNITS="" FAKE_PKGS=""
osrel ubuntu debian
rm -f "$work/policy"
FAKE_PKGS="pcscd libccid" accept "Ubuntu 22.04: pcscd and libccid, no polkit policy: nothing more is needed" run check_card_prerequisites
FAKE_PKGS="pcscd" refuse "a missing libccid is refused and named" 'deb family\): libccid\.' run check_card_prerequisites
FAKE_PKGS="" refuse "both missing: both are named, and the deploy says it installs none" 'pcscd libccid\. The deploy installs no package' run check_card_prerequisites

touch "$work/policy" # pcscd ships its polkit policy: Ubuntu 26.04
FAKE_PKGS="pcscd libccid" refuse "Ubuntu 26.04: polkit is needed when pcscd asks it" 'polkitd' run check_card_prerequisites
FAKE_PKGS="pcscd libccid polkitd" FAKE_UNITS="polkit.service" accept "Ubuntu 26.04 with polkit" run check_card_prerequisites
FAKE_PKGS="pcscd libccid polkitd" FAKE_UNITS="" refuse "polkit installed but with no service and no pkcheck is refused" 'polkitd' run check_card_prerequisites

osrel rocky "rhel centos fedora"
FAKE_PKGS="pcsc-lite pcsc-lite-ccid polkit" FAKE_UNITS="polkit.service" accept "Rocky with pcsc-lite, pcsc-lite-ccid and polkit" run check_card_prerequisites
FAKE_PKGS="pcsc-lite polkit" FAKE_UNITS="polkit.service" refuse "Rocky without the CCID driver: the Rocky name is given" 'rpm family\): pcsc-lite-ccid\.' run check_card_prerequisites
FAKE_PKGS="pcscd libccid polkitd" FAKE_UNITS="polkit.service" refuse "Rocky does not take the Ubuntu names" 'pcsc-lite' run check_card_prerequisites

osrel nixos ""
rm -f "$work/policy"
FAKE_UNITS="pcscd.socket" refuse "an unknown system: the units and files decide, and no CCID driver is refused" 'unknown family\)' run check_card_prerequisites

# credentials
export FAKE_SYSTEMD=252
accept "systemd 252 with systemd-creds meets the floor" run require_credential_encryption
FAKE_SYSTEMD=259 accept "systemd 259 meets the floor" run require_credential_encryption
FAKE_SYSTEMD=249 refuse "systemd 249 (Ubuntu 22.04) is refused: the floor is named" 'systemd 249; the floor is 252' run require_credential_encryption
FAKE_SYSTEMD='' refuse "an unreadable systemd version is refused" 'unknown; the floor is 252' run require_credential_encryption
mv "$work/bin/systemd-creds" "$work/systemd-creds.off"
refuse "no systemd-creds is refused" 'systemd-creds is missing' run require_credential_encryption
mv "$work/systemd-creds.off" "$work/bin/systemd-creds"
printf 'secret' >"$work/plain"
mkdir -p "$work/cred"
# The run subshell has the fakes alone as PATH, and encrypt_credential needs mktemp, chown, chmod, mv and rm.
for t in mktemp chown chmod mv rm; do ln -sf "$(command -v "$t")" "$work/bin/$t"; done
accept "a credential is encrypted under the host key and named for the unit" run encrypt_credential client-dev "$work/plain" "$work/cred/client-dev"
if grep -q 'name=client-dev key=host' "$work/cred/client-dev" && ! grep -q secret "$work/cred/client-dev"; then echo "ok   the file holds the blob and not the plain text"; else echo "FAIL the file: $(cat "$work/cred/client-dev")"; fail=1; fi
if [ "$(stat -c %a "$work/cred/client-dev")" = 400 ]; then echo "ok   and it is 0400"; else echo "FAIL mode $(stat -c %a "$work/cred/client-dev")"; fail=1; fi
rm "$work/cred/client-dev"
FAKE_CREDS_FAIL=1 refuse "a failed encryption is refused and leaves no file" 'could not encrypt the credential client-dev' run encrypt_credential client-dev "$work/plain" "$work/cred/client-dev"
if [ -z "$(ls -A "$work/cred")" ]; then echo "ok   nothing is left in the credentials directory"; else echo "FAIL left: $(ls -A "$work/cred")"; fail=1; fi

# check_pinned_ids
printf 'u sluis-signer-dev 61004 "sluis signer (dev)" - /usr/sbin/nologin\ng sluis-keyc-004-dev 61704\n' >"$work/signer.sysusers"
printf 'u sluis-key-dev 61014 "sluis key (dev)" - /usr/sbin/nologin\n' >"$work/key.sysusers"
# A uid in block 1 (62004) sits in systemd's dynamic range, where DynamicUser= takes numbers; "uid:gid" is the strict form.
printf 'u sluis-signer-b1 62004 "sluis signer (block 1)" - /usr/sbin/nologin\n' >"$work/b1.sysusers"
printf 'u sluis-signer-b1 62004:62004 "sluis signer (block 1)" - /usr/sbin/nologin\n' >"$work/strict.sysusers"
made="sluis-signer-dev:61004 sluis-key-dev:61014"
madeg="sluis-signer-dev:61004 sluis-key-dev:61014" # the users' own groups, which systemd-sysusers makes with them
export FAKE_USERS="" FAKE_GROUPS=""
# verifies: a group of key@'s caller directories with its pinned gid
FAKE_GROUPS="" accept "before: a pinned group that does not exist yet, with its number free, may be made" run check_pinned_ids before "$work/signer.sysusers" "$work/key.sysusers"
FAKE_GROUPS="sluis-keyc-004-dev:61704" accept "before: a pinned group that has its number already" run check_pinned_ids before "$work/signer.sysusers"
FAKE_GROUPS="systemd-dyn:61704" refuse "before: a pinned number that another group has is refused, naming it" '61704, the number of sluis-keyc-004-dev, is already the group systemd-dyn' run check_pinned_ids before "$work/signer.sysusers"
FAKE_GROUPS="sluis-keyc-004-dev:61999" refuse "before: a group of the name with another number is refused" 'sluis-keyc-004-dev has the number 61999, not 61704' run check_pinned_ids before "$work/signer.sysusers"
FAKE_USERS="systemd-dyn:61704" refuse "before: a pinned gid that a user of another name has as its uid is refused, naming it" '61704, the number of sluis-keyc-004-dev, is already the uid of the user systemd-dyn' run check_pinned_ids before "$work/signer.sysusers"
FAKE_USERS="$made" FAKE_GROUPS="$madeg sluis-keyc-004-dev:61704" accept "after: the users and the group have their pinned numbers" run check_pinned_ids after "$work/signer.sysusers" "$work/key.sysusers"
FAKE_USERS="$made" FAKE_GROUPS="sluis-keyc-004-dev:61999" refuse "after: systemd-sysusers gave the group another number: refused" 'sluis-keyc-004-dev has the number 61999, not 61704' run check_pinned_ids after "$work/signer.sysusers"
FAKE_USERS="$made" FAKE_GROUPS="" refuse "after: a pinned group that was not made is refused" 'sluis-keyc-004-dev does not exist' run check_pinned_ids after "$work/signer.sysusers"
# verifies: a user of the uid plan with its pinned uid
FAKE_USERS="sluis-signer-dev:61004" accept "before: a pinned user that has its uid already" run check_pinned_ids before "$work/signer.sysusers"
FAKE_GROUPS="sluis-signer-dev:61004" accept "before: a pinned uid whose number the user's own group has is free" run check_pinned_ids before "$work/signer.sysusers"
FAKE_USERS="systemd-dyn:62004" refuse "before: a block-1 uid that another user has (a DynamicUser=) is refused, naming it" '62004, the uid of sluis-signer-b1, is already the user systemd-dyn' run check_pinned_ids before "$work/b1.sysusers"
FAKE_GROUPS="systemd-dyn:62004" refuse "before: a pinned uid that a group of another name has as its gid is refused, naming it" '62004, the uid of sluis-signer-b1, is already the number of the group systemd-dyn' run check_pinned_ids before "$work/b1.sysusers"
FAKE_GROUPS="systemd-dyn:62004" accept "before: in the strict uid:gid form systemd-sysusers does not weigh the groups, nor does the check" run check_pinned_ids before "$work/strict.sysusers"
FAKE_USERS="systemd-dyn:62004" refuse "before: the strict form still refuses a uid another user has" '62004, the uid of sluis-signer-b1, is already the user systemd-dyn' run check_pinned_ids before "$work/strict.sysusers"
FAKE_USERS="sluis-signer-dev:61999" refuse "before: a user of the name with another uid is refused" 'the user sluis-signer-dev has the uid 61999, not 61004' run check_pinned_ids before "$work/signer.sysusers"
FAKE_USERS="sluis-signer-b1:63999" refuse "after: systemd-sysusers gave the user another uid: refused" 'the user sluis-signer-b1 has the uid 63999, not 62004' run check_pinned_ids after "$work/b1.sysusers"
FAKE_USERS="" refuse "after: a pinned user that was not made is refused" 'the user sluis-signer-b1 does not exist' run check_pinned_ids after "$work/b1.sysusers"
FAKE_USERS="sluis-signer-b1:62004" FAKE_GROUPS="sluis-signer-b1:62004" accept "after: the user has its pinned uid and its own group" run check_pinned_ids after "$work/b1.sysusers"
# verifies: a user's own group, its primary group, has the user's pinned number
FAKE_GROUPS="sluis-signer-b1:63000" refuse "before: a group of the user's name with another number is refused (systemd-sysusers would put the user in it)" 'the group sluis-signer-b1 of the user sluis-signer-b1 has the number 63000, not 62004' run check_pinned_ids before "$work/b1.sysusers"
FAKE_USERS="sluis-signer-b1:62004:63000" FAKE_GROUPS="sluis-signer-b1:62004" refuse "before: a user of the uid whose primary group is another number is refused" 'the user sluis-signer-b1 has the primary group number 63000, not 62004' run check_pinned_ids before "$work/b1.sysusers"
FAKE_USERS="sluis-signer-b1:62004:63000" FAKE_GROUPS="sluis-signer-b1:62004" refuse "after: the user's primary group is another number: refused" 'the user sluis-signer-b1 has the primary group number 63000, not 62004' run check_pinned_ids after "$work/b1.sysusers"
FAKE_USERS="sluis-signer-b1:62004" FAKE_GROUPS="sluis-signer-b1:63000" refuse "after: the user's own group has another number: refused" 'the group sluis-signer-b1 of the user sluis-signer-b1 has the number 63000, not 62004' run check_pinned_ids after "$work/b1.sysusers"
FAKE_USERS="sluis-signer-b1:62004" FAKE_GROUPS="" refuse "after: the user's own group was not made: refused" 'the group sluis-signer-b1 of the user sluis-signer-b1 does not exist' run check_pinned_ids after "$work/b1.sysusers"
FAKE_USERS="sluis-signer-b1:62004" FAKE_GROUPS="" accept "after: the strict uid:gid form needs no group of the user's name" run check_pinned_ids after "$work/strict.sysusers"
FAKE_USERS="sluis-signer-b1:62004:63000" refuse "after: in the strict form the primary group must be the GID" 'the user sluis-signer-b1 has the primary group number 63000, not 62004' run check_pinned_ids after "$work/strict.sysusers"
# verifies: a line of an unknown kind, and a sweep with nothing to check, are refusals
printf '# a comment\n\nu sluis-signer-b1 62004 "sluis signer (block 1)" - /usr/sbin/nologin\nm sluis-signer-b1 sluis-keyc-004-dev\nr - 62000-62999\n' >"$work/kinds.sysusers"
accept "before: comments, blank lines and the m and r kinds are known" run check_pinned_ids before "$work/kinds.sysusers"
printf 'u! sluis-signer-b1 62004 "sluis signer (block 1)" - /usr/sbin/nologin\n' >"$work/locked.sysusers"
refuse "before: a line of a kind the check does not know (u!) is refused, naming it" "does not know \\(locked\\.sysusers: u!\\)" run check_pinned_ids before "$work/b1.sysusers" "$work/locked.sysusers"
refuse "after: the same" "does not know" run check_pinned_ids after "$work/locked.sysusers"
refuse "before: no sysusers file is a refusal, not a pass" 'no sysusers line with a pinned uid or gid was found in 0 file' run check_pinned_ids before
printf '# nothing pinned\ng sluis-key-drv-dev -\n' >"$work/unpinned.sysusers"
refuse "before: files with no pinned number are a refusal, not a pass" 'no sysusers line with a pinned uid or gid was found in 1 file' run check_pinned_ids before "$work/unpinned.sysusers"
refuse "after: the same" 'no sysusers line with a pinned uid or gid' run check_pinned_ids after "$work/unpinned.sysusers"
# verifies: the check fails closed when the lookup cannot be made
FAKE_GETENT_RC=3 refuse "before: a getent that cannot read the databases is a refusal, not a free number" 'getent cannot read the user sluis-signer-dev' run check_pinned_ids before "$work/signer.sysusers"
FAKE_GETENT_RC=3 refuse "after: the same" 'getent cannot read' run check_pinned_ids after "$work/signer.sysusers"
mv "$work/bin/getent" "$work/getent.off"
refuse "before: no getent is a refusal" 'getent is missing' run check_pinned_ids before "$work/signer.sysusers"
refuse "after: no getent is a refusal" 'getent is missing' run check_pinned_ids after "$work/signer.sysusers"
mv "$work/getent.off" "$work/bin/getent"
if grep -q 'check_pinned_ids before' "$here/remote.sh" && grep -A1 -E '^[[:space:]]+systemd-sysusers ' "$here/remote.sh" | grep -q 'check_pinned_ids after'; then echo "ok   remote.sh checks the pinned ids before it writes and right after systemd-sysusers"; else echo "FAIL remote.sh does not call check_pinned_ids before and after systemd-sysusers"; fail=1; fi

# relabel
export RESTORECON_LOG="$work/restorecon.log"
mkdir -p "$work/state"
: >"$RESTORECON_LOG"
FAKE_SELINUX=0 run relabel
if [ ! -s "$RESTORECON_LOG" ]; then echo "ok   SELinux off: restorecon is not run"; else echo "FAIL restorecon ran with SELinux off"; fail=1; fi
mkdir -p "$work/etc/systemd/system" "$work/etc/tmpfiles.d"
: >"$work/etc/systemd/system/sluis-key@.service"
: >"$work/etc/tmpfiles.d/sluis-pcscd-dev.conf"
printf 'file\t%s\nfile\t%s\ndir\t%s\nunit\tsluis-key@dev.service\nfile\t%s\n' "$work/etc/systemd/system/sluis-key@.service" "$work/etc/tmpfiles.d/sluis-pcscd-dev.conf" "$work/etc/tmpfiles.d" "$work/state/not-a-single" >"$work/manifest"
FAKE_SELINUX=1 run relabel
mkdir -p "$work/state/dev/key"
printf 'dir\t%s\n' "$work/state/dev/key" >>"$work/manifest"
: >"$RESTORECON_LOG"
FAKE_SELINUX=1 run relabel
if grep -qx -- "-- $work/state $work/etc/systemd/system/sluis-key@.service $work/etc/tmpfiles.d/sluis-pcscd-dev.conf $work/etc/tmpfiles.d $work/state/dev/key" "$RESTORECON_LOG"; then echo "ok   SELinux on: the state root, the manifest's files and directories (the state directories too), each alone, without -R"; else echo "FAIL restorecon log: $(cat "$RESTORECON_LOG")"; fail=1; fi
if grep -q -- "-R .*$work/state" "$RESTORECON_LOG"; then echo "FAIL the state directory is walked recursively: $(cat "$RESTORECON_LOG")"; fail=1; else echo "ok   and the state directory is never walked"; fi
if grep -q -- "-F\|-RF\|^-R .*etc/systemd\|^-R .*tmpfiles\|-R /etc/systemd\|-R /etc/sysusers\|-R /etc/polkit" "$RESTORECON_LOG"; then echo "FAIL restorecon is recursive or forced over a directory of the system: $(cat "$RESTORECON_LOG")"; fail=1; else echo "ok   and no directory of the system is relabelled recursively, nor forced"; fi
rm "$work/bin/selinuxenabled"
: >"$RESTORECON_LOG"
accept "no selinuxenabled: nothing to do" run relabel
if [ ! -s "$RESTORECON_LOG" ]; then echo "ok   and restorecon is not run"; else echo "FAIL restorecon ran"; fail=1; fi

# rqlite: the drop-in, the addresses, and the plain-HTTP checks of what rqlite.sh sends
# verifies: the drop-in resets ExecStart= and sets the node id, the addresses and, off the bootstrap node, -join
want=$'# Made by sluis (just boards-rqlite). Do not edit: the next run writes it again.\n# No TLS and no authentication yet: the firewall of the board must admit these ports from the peers alone.\n[Service]\nExecStart=\nExecStart=/usr/bin/rqlited -node-id board-b -http-addr 192.0.2.12:4001 -raft-addr 192.0.2.12:4002 -join 192.0.2.13:4002 /var/lib/rqlite/data'
is "a joining node's drop-in" "$want" run rqlite_dropin_text board-b 192.0.2.12 4001 4002 192.0.2.13:4002
got=$(run rqlite_dropin_text board-a 192.0.2.13 4001 4002 "")
if [ "$got" = "${want%%$'\n'ExecStart=/usr/bin/rqlited*}"$'\nExecStart=/usr/bin/rqlited -node-id board-a -http-addr 192.0.2.13:4001 -raft-addr 192.0.2.13:4002 /var/lib/rqlite/data' ]; then echo "ok   the bootstrap node's drop-in has no -join"; else echo "FAIL the bootstrap drop-in: $got"; fail=1; fi
refuse "a node id with a space is refused" "refusing the rqlite node id" run rqlite_dropin_text "core 2" 192.0.2.12 4001 4002 ""
refuse "a name for the board's address is refused" "refusing the rqlite address" run rqlite_dropin_text board-b board.example.com 4001 4002 ""
refuse "an address with an octet above 255 is refused" "refusing the rqlite address" run rqlite_dropin_text board-b 192.0.2.256 4001 4002 ""
refuse "a port of 0 is refused" "refusing the rqlite ports" run rqlite_dropin_text board-b 192.0.2.12 0 4002 ""
refuse "a join address with a flag in it is refused" "refusing the rqlite join address" run rqlite_dropin_text board-b 192.0.2.12 4001 4002 "192.0.2.13:4002 -x"
refuse "a join address that is a name is refused" "refusing the rqlite join address" run rqlite_dropin_text board-b 192.0.2.12 4001 4002 "board-a:4002"
# rqlite_relabel
ln -sf "$(command -v dirname)" "$work/bin/dirname"
printf '#!/bin/bash\nexit 0\n' >"$work/bin/selinuxenabled"
chmod +x "$work/bin/selinuxenabled"
cat >"$work/bin/systemctl" <<'F'
#!/bin/bash
[ "$1" = show ] && [ "$3" = FragmentPath ] && { echo "$FAKE_FRAGMENT"; exit 0; }
exit 0
F
chmod +x "$work/bin/systemctl"
: >"$RESTORECON_LOG"
: >"$work/rqlited.service"
FAKE_FRAGMENT="$work/rqlited.service" run rqlite_relabel
if grep -qx -- "-v -- $work/rqlited.service" "$RESTORECON_LOG"; then echo "ok   rqlite_relabel relabels the files that exist, each alone, and never recursively"; else echo "FAIL restorecon: $(cat "$RESTORECON_LOG")"; fail=1; fi

# avc_check: the AVC records since boot, with fakes of getenforce and ausearch (FAKE_ENFORCING, FAKE_AUSEARCH_OUT, FAKE_AUSEARCH_RC)
cat >"$work/bin/getenforce" <<'F'
#!/bin/bash
echo "${FAKE_ENFORCING:-Enforcing}"
F
cat >"$work/bin/ausearch" <<'F'
#!/bin/bash
[ "$*" = "-m AVC,USER_AVC -ts boot" ] || { echo "unexpected arguments: $*" >&2; exit 2; }
printf '%s' "${FAKE_AUSEARCH_OUT:-<no matches>}"
exit "${FAKE_AUSEARCH_RC:-1}"
F
chmod +x "$work/bin/getenforce" "$work/bin/ausearch"
for t in grep wc; do ln -sf "$(command -v "$t")" "$work/bin/$t"; done
# verifies: a board where SELinux is not enforcing has nothing to check
FAKE_ENFORCING=Permissive accept "avc: permissive: nothing to check" run avc_check
FAKE_ENFORCING=Disabled accept "avc: disabled: nothing to check" run avc_check
accept "avc: enforcing and no record is clean" run avc_check
is "avc: and says so" "avc: no AVC or USER_AVC record since boot" run avc_check
other='----
time->Thu Nov  6 10:00:00 2026
type=AVC msg=audit(1793000000.000:100): avc:  denied  { read } for  pid=900 comm="chronyd" name="drift" dev="vda1" ino=5 scontext=system_u:system_r:chronyd_t:s0 tcontext=system_u:object_r:var_t:s0 tclass=file permissive=0'
FAKE_AUSEARCH_OUT="$other" FAKE_AUSEARCH_RC=0 accept "avc: a denial of another program is printed and does not fail" run avc_check
out=$(FAKE_AUSEARCH_OUT="$other" FAKE_AUSEARCH_RC=0 run avc_check 2>&1)
if [[ "$out" == *"1 AVC/USER_AVC records since boot, 0 naming sluis or rqlite"* ]]; then echo "ok   avc: and is said to name nothing of ours"; else echo "FAIL avc summary: $out"; fail=1; fi
for rec in \
	'type=AVC msg=audit(1793000001.000:101): avc:  denied  { execute } for  pid=901 comm="(rqlited)" path="/usr/bin/rqlited" dev="vda1" ino=6 scontext=system_u:system_r:init_t:s0 tcontext=system_u:object_r:usr_t:s0 tclass=file permissive=0' \
	'type=AVC msg=audit(1793000002.000:102): avc:  denied  { connectto } for  pid=902 comm="key" path="/run/sluis/key/dev/admin.sock" scontext=system_u:system_r:unconfined_service_t:s0 tcontext=system_u:system_r:pcscd_t:s0 tclass=unix_stream_socket permissive=0' \
	'type=USER_AVC msg=audit(1793000003.000:103): pid=1 uid=0 auid=4294967295 ses=4294967295 subj=system_u:system_r:init_t:s0 msg='"'"'avc:  denied  { start } for auid=n/a uid=0 gid=0 path="/etc/systemd/system/sluis-key@.service" scontext=system_u:system_r:init_t:s0 tcontext=system_u:object_r:etc_t:s0 tclass=service'"'"; do
	FAKE_AUSEARCH_OUT="$other
$rec" FAKE_AUSEARCH_RC=0 refuse "avc: a record naming a sluis or rqlite path or domain fails: ${rec:0:60}" 'FAILED: the records above name a sluis or rqlite' run avc_check
done
FAKE_AUSEARCH_OUT='ausearch: cannot open /var/log/audit/audit.log' FAKE_AUSEARCH_RC=10 refuse "avc: an ausearch that fails for another reason is not a clean board" 'ausearch failed \(status 10\)' run avc_check
mv "$work/bin/ausearch" "$work/ausearch.off"
refuse "avc: enforcing with no ausearch is a refusal that names the package" 'install the audit package' run avc_check
FAKE_ENFORCING=Permissive accept "avc: with no ausearch, permissive still has nothing to check" run avc_check
mv "$work/ausearch.off" "$work/bin/ausearch"
if grep -q 'avc_check' "$here/remote.sh" && grep -q 'stage-avc' "$here/boards.sh"; then echo "ok   boards.sh runs the avc check after a deploy"; else echo "FAIL boards.sh does not run the avc check"; fail=1; fi
exit "$fail"
