#!/usr/bin/env bash
# shellcheck disable=SC2001,SC2030,SC2031,SC2015,SC2016 # `A && ok || fail` pairs report a check either way; single quotes hold the code of `bash -c`
# A test of the operating-system checks of remote.sh (deploy/boards/remote-lib.sh) against fakes of dpkg, rpm, systemctl,
# restorecon and the files of SELinux, and a fake os-release: no board, no package manager. Run from anywhere:
# deploy/boards/prereq-test.sh
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin"

# The fakes. FAKE_PKGS and FAKE_UNITS are space-separated lists of what is "installed". SELinux is read from a file, like
# /sys/fs/selinux/enforce on a board: no file is SELinux off, 0 permissive, 1 enforcing (see selinux below).
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

selinux() { # off|permissive|enforcing: what /sys/fs/selinux/enforce would say
	case "$1" in
	off) rm -f "$work/enforce" ;;
	permissive) printf 0 >"$work/enforce" ;;
	enforcing) printf 1 >"$work/enforce" ;;
	esac
}
osrel() { # id id_like
	printf 'ID=%s\nID_LIKE="%s"\n' "$1" "$2" >"$work/os-release"
}
# run executes a command of the library in a subshell with a PATH of the fakes alone, so that nothing of this workstation (a real
# pkcheck, a real dpkg) answers.
run() {
	(
		export PATH="$work/bin" os_release_file="$work/os-release" card_polkit_policy="$work/policy" state_root="$work/state" manifest="$work/manifest" selinux_enforce_file="$work/enforce"
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
selinux off
run relabel
if [ ! -s "$RESTORECON_LOG" ]; then echo "ok   SELinux off (no /sys/fs/selinux/enforce): restorecon is not run"; else echo "FAIL restorecon ran with SELinux off"; fail=1; fi
mkdir -p "$work/etc/systemd/system" "$work/etc/tmpfiles.d"
: >"$work/etc/systemd/system/sluis-key@.service"
: >"$work/etc/tmpfiles.d/sluis-pcscd-dev.conf"
printf 'file\t%s\nfile\t%s\ndir\t%s\nunit\tsluis-key@dev.service\nfile\t%s\n' "$work/etc/systemd/system/sluis-key@.service" "$work/etc/tmpfiles.d/sluis-pcscd-dev.conf" "$work/etc/tmpfiles.d" "$work/state/not-a-single" >"$work/manifest"
selinux enforcing
run relabel
mkdir -p "$work/state/dev/key"
printf 'dir\t%s\n' "$work/state/dev/key" >>"$work/manifest"
: >"$RESTORECON_LOG"
# The PATH of run holds neither getenforce nor selinuxenabled (a thin image has neither): the file alone says SELinux is on.
run relabel
if grep -qx -- "-- $work/state $work/etc/systemd/system/sluis-key@.service $work/etc/tmpfiles.d/sluis-pcscd-dev.conf $work/etc/tmpfiles.d $work/state/dev/key" "$RESTORECON_LOG"; then echo "ok   SELinux on, with no getenforce and no selinuxenabled: the state root, the manifest's files and directories (the state directories too), each alone, without -R"; else echo "FAIL restorecon log: $(cat "$RESTORECON_LOG")"; fail=1; fi
if grep -q -- "-R .*$work/state" "$RESTORECON_LOG"; then echo "FAIL the state directory is walked recursively: $(cat "$RESTORECON_LOG")"; fail=1; else echo "ok   and the state directory is never walked"; fi
if grep -q -- "-F\|-RF\|^-R .*etc/systemd\|^-R .*tmpfiles\|-R /etc/systemd\|-R /etc/sysusers\|-R /etc/polkit" "$RESTORECON_LOG"; then echo "FAIL restorecon is recursive or forced over a directory of the system: $(cat "$RESTORECON_LOG")"; fail=1; else echo "ok   and no directory of the system is relabelled recursively, nor forced"; fi
selinux permissive
: >"$RESTORECON_LOG"
run relabel
if [ -s "$RESTORECON_LOG" ]; then echo "ok   SELinux permissive is still SELinux: the files are labelled"; else echo "FAIL permissive: restorecon did not run"; fail=1; fi
selinux off
: >"$RESTORECON_LOG"
accept "no enforce file: nothing to do" run relabel
if [ ! -s "$RESTORECON_LOG" ]; then echo "ok   and restorecon is not run"; else echo "FAIL restorecon ran"; fail=1; fi

# rqlite: the drop-in, the addresses, and the plain-HTTP checks of what rqlite.sh sends
# verifies: the drop-in resets ExecStart= and sets the addresses and, for a cluster of more than one, -bootstrap-expect and the join
# list of ALL nodes, itself included, and never -node-id (rqlite then uses the Raft address)
j3=192.0.2.11:4002,192.0.2.12:4002,192.0.2.13:4002
hdr=$'# Made by sluis (just boards-rqlite). Do not edit: the next run writes it again.\n# No TLS and no authentication yet: the firewall of the board must admit these ports from the peers alone.\n[Service]\nExecStart='
for n in 11 12 13; do
	is "the drop-in of node 192.0.2.$n of three" "${hdr}"$'\nExecStart=/usr/bin/rqlited -http-addr 192.0.2.'$n$':4001 -raft-addr 192.0.2.'$n$':4002 -bootstrap-expect 3 -join '$j3$' /var/lib/rqlite/data' run rqlite_dropin_text 192.0.2.$n 4001 4002 3 $j3
done
is "the drop-in of a cluster of one has neither flag" "${hdr}"$'\nExecStart=/usr/bin/rqlited -http-addr 192.0.2.11:4001 -raft-addr 192.0.2.11:4002 /var/lib/rqlite/data' run rqlite_dropin_text 192.0.2.11 4001 4002 1 ""
got=$(run rqlite_dropin_text 192.0.2.11 4001 4002 3 $j3)
if [[ "$got" != *"-node-id"* ]]; then echo "ok   no drop-in names a -node-id"; else echo "FAIL a -node-id is in the drop-in"; fail=1; fi
# No node of a cluster of more than one can come out without the whole list: that is what stops a split brain.
refuse "a cluster of three with no join list is refused (a node without state would form a cluster of its own)" "must name all 3 nodes" run rqlite_dropin_text 192.0.2.11 4001 4002 3 ""
refuse "a join list that leaves this node out is refused" "must name all 3 nodes" run rqlite_dropin_text 192.0.2.11 4001 4002 3 192.0.2.12:4002,192.0.2.13:4002,192.0.2.14:4002
refuse "a join list of the wrong length is refused" "must name all 3 nodes" run rqlite_dropin_text 192.0.2.11 4001 4002 3 192.0.2.11:4002,192.0.2.12:4002
refuse "a join list with a node twice is refused" "listed twice" run rqlite_dropin_text 192.0.2.11 4001 4002 3 192.0.2.11:4002,192.0.2.11:4002,192.0.2.12:4002
refuse "a cluster of one with a join list is refused" "takes no join list" run rqlite_dropin_text 192.0.2.11 4001 4002 1 192.0.2.11:4002
refuse "a cluster size of 0 is refused" "refusing the rqlite cluster size" run rqlite_dropin_text 192.0.2.11 4001 4002 0 ""
refuse "a name for the board's address is refused" "refusing the rqlite address" run rqlite_dropin_text board.example.com 4001 4002 1 ""
refuse "an address with an octet above 255 is refused" "refusing the rqlite address" run rqlite_dropin_text 192.0.2.256 4001 4002 1 ""
refuse "an address with a leading zero is refused" "refusing the rqlite address" run rqlite_dropin_text 192.0.2.010 4001 4002 1 ""
refuse "a port of 0 is refused" "refusing the rqlite ports" run rqlite_dropin_text 192.0.2.12 0 4002 1 ""
refuse "the HTTP port equal to the Raft port is refused" "must differ" run rqlite_dropin_text 192.0.2.12 4002 4002 1 ""
refuse "a join address with a flag in it is refused" "refusing the rqlite join address" run rqlite_dropin_text 192.0.2.11 4001 4002 2 "192.0.2.11:4002,192.0.2.13:4002 -x"
refuse "a join address that is a name is refused" "refusing the rqlite join address" run rqlite_dropin_text 192.0.2.11 4001 4002 2 "192.0.2.11:4002,board-a:4002"
accept "192.0.2.0 and 192.0.2.255 are addresses" run rqlite_valid_ipv4 192.0.2.255
# rqlite_relabel
ln -sf "$(command -v dirname)" "$work/bin/dirname"
selinux enforcing
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

# avc_check: the AVC records since boot, with fakes of ausearch (FAKE_AUSEARCH_OUT, FAKE_AUSEARCH_RC), of systemctl is-active auditd
# (FAKE_AUDITD) and of auditctl -s (FAKE_AUDIT_ENABLED). SELinux is the file of selinux() above: no getenforce is needed.
cat >"$work/bin/systemctl" <<'F'
#!/bin/bash
[ "$1" = is-active ] && [ "$2" = auditd ] && { echo "${FAKE_AUDITD:-active}"; [ "${FAKE_AUDITD:-active}" = active ]; exit; }
[ "$1" = show ] && [ "$3" = FragmentPath ] && { echo "$FAKE_FRAGMENT"; exit 0; }
exit 0
F
cat >"$work/bin/auditctl" <<'F'
#!/bin/bash
[ "$1" = -s ] || exit 2
printf 'enabled %s\nfailure 1\npid 812\nrate_limit 0\nbacklog_limit 8192\n' "${FAKE_AUDIT_ENABLED:-1}"
F
cat >"$work/bin/ausearch" <<'F'
#!/bin/bash
[ "$*" = "-m AVC,USER_AVC -ts boot" ] || { echo "unexpected arguments: $*" >&2; exit 2; }
printf '%s' "${FAKE_AUSEARCH_OUT:-<no matches>}"
exit "${FAKE_AUSEARCH_RC:-1}"
F
chmod +x "$work/bin/systemctl" "$work/bin/auditctl" "$work/bin/ausearch"
for t in grep wc sed head; do ln -sf "$(command -v "$t")" "$work/bin/$t"; done
# the executables of the deploy, from the manifest: the comm of a process is the basename, cut to 15 characters
printf 'file\t/opt/sluis/bin/actors/store\nfile\t/opt/sluis/bin/actors/key\nfile\t/opt/sluis/bin/drivers/key/yubikey-piv\nfile\t/opt/sluis/bin/drivers/store/rqlite\nfile\t/opt/sluis/bin/drivers/store/credential-with-a-long-name\nfile\t/etc/sluis/other\nunit\tsluis-key@dev.service\n' >"$work/manifest"
selinux permissive
accept "avc: permissive: nothing to check" run avc_check
selinux off
accept "avc: SELinux off (no enforce file): nothing to check" run avc_check
selinux enforcing
accept "avc: enforcing and no record is clean (with no getenforce on the board)" run avc_check
is "avc: and says so" "avc: no AVC or USER_AVC record since boot" run avc_check
other='----
time->Thu Nov  6 10:00:00 2026
type=AVC msg=audit(1793000000.000:100): avc:  denied  { read } for  pid=900 comm="chronyd" name="drift" dev="vda1" ino=5 scontext=system_u:system_r:chronyd_t:s0 tcontext=system_u:object_r:var_t:s0 tclass=file permissive=0 hostname=sluis-board-a'
FAKE_AUSEARCH_OUT="$other" FAKE_AUSEARCH_RC=0 accept "avc: a denial of another program is printed and does not fail, also when the host name has sluis in it" run avc_check
out=$(FAKE_AUSEARCH_OUT="$other" FAKE_AUSEARCH_RC=0 run avc_check 2>&1)
if [[ "$out" == *"1 AVC/USER_AVC records since boot, 0 denials of sluis or what it needs, 1 others"* && "$out" == *"avc: warning: type=AVC"* ]]; then echo "ok   avc: and is a warning in the summary"; else echo "FAIL avc summary: $out"; fail=1; fi
# The records that must fail: each is a denial of ours by one of the rules.
for rec in \
	'type=AVC msg=audit(1793000001.000:101): avc:  denied  { execute } for  pid=901 comm="(rqlited)" path="/usr/bin/rqlited" dev="vda1" ino=6 scontext=system_u:system_r:init_t:s0 tcontext=system_u:object_r:usr_t:s0 tclass=file permissive=0' \
	'type=AVC msg=audit(1793000002.000:102): avc:  denied  { connectto } for  pid=902 comm="yubikey-piv" path="/run/pcscd/pcscd.comm" scontext=system_u:system_r:unconfined_service_t:s0 tcontext=system_u:system_r:pcscd_t:s0 tclass=unix_stream_socket permissive=0' \
	'type=AVC msg=audit(1793000004.000:104): avc:  denied  { read } for  pid=904 comm="pcscd" name="usb" scontext=system_u:system_r:pcscd_t:s0 tcontext=system_u:object_r:usb_device_t:s0 tclass=chr_file permissive=0' \
	'type=AVC msg=audit(1793000005.000:105): avc:  denied  { write } for  pid=905 comm="systemd-creds" name="credential.secret" scontext=system_u:system_r:unconfined_service_t:s0 tcontext=system_u:object_r:systemd_userdbd_runtime_t:s0 tclass=file permissive=0' \
	'type=AVC msg=audit(1793000006.000:106): avc:  denied  { search } for  pid=906 comm="polkitd" name="pcscd" scontext=system_u:system_r:policykit_t:s0 tcontext=system_u:object_r:pcscd_var_run_t:s0 tclass=dir permissive=0' \
	'type=AVC msg=audit(1793000007.000:107): avc:  denied  { read } for  pid=907 comm="store" name="x" scontext=system_u:system_r:svirt_t:s0 tcontext=system_u:object_r:var_t:s0 tclass=file permissive=0' \
	'type=AVC msg=audit(1793000008.000:108): avc:  denied  { read } for  pid=908 comm="credential-with" name="x" scontext=system_u:system_r:svirt_t:s0 tcontext=system_u:object_r:var_t:s0 tclass=file permissive=0' \
	'type=AVC msg=audit(1793000009.000:109): avc:  denied  { read } for  pid=909 comm="cat" path="/var/lib/sluis-state/dev/key/x" scontext=system_u:system_r:svirt_t:s0 tcontext=system_u:object_r:var_t:s0 tclass=file permissive=0' \
	'type=USER_AVC msg=audit(1793000003.000:103): pid=1 uid=0 auid=4294967295 ses=4294967295 subj=system_u:system_r:init_t:s0 msg='"'"'avc:  denied  { start } for auid=n/a uid=0 gid=0 path="/etc/systemd/system/sluis-key@.service" scontext=system_u:system_r:init_t:s0 tcontext=system_u:object_r:etc_t:s0 tclass=service exe="/usr/lib/systemd/systemd"'"'"; do
	FAKE_AUSEARCH_OUT="$other
$rec" FAKE_AUSEARCH_RC=0 refuse "avc: an enforced denial of ours fails: ${rec:0:70}" 'FAILED: the records above marked DENIED' run avc_check
	if [[ "$(FAKE_AUSEARCH_OUT="$other
$rec" FAKE_AUSEARCH_RC=0 run avc_check 2>/dev/null)" == *"avc: DENIED: ${rec:0:40}"* ]]; then echo "ok   avc: and the record is marked DENIED, the other one a warning"; else echo "FAIL avc: the record is not marked DENIED: ${rec:0:70}"; fail=1; fi
done
# permissive=1 (a domain that was made permissive on purpose) and a name that merely resembles ours are only warnings.
FAKE_AUSEARCH_OUT='type=AVC msg=audit(1793000010.000:110): avc:  denied  { read } for  pid=910 comm="yubikey-piv" name="x" scontext=system_u:system_r:unconfined_service_t:s0 tcontext=system_u:object_r:var_t:s0 tclass=file permissive=1' FAKE_AUSEARCH_RC=0 accept "avc: a record with permissive=1 was not enforced: a warning" run avc_check
FAKE_AUSEARCH_OUT='type=AVC msg=audit(1793000011.000:111): avc:  denied  { read } for  pid=911 comm="stored" name="x" scontext=system_u:system_r:svirt_t:s0 tcontext=system_u:object_r:var_t:s0 tclass=file permissive=0' FAKE_AUSEARCH_RC=0 accept "avc: a comm that is only a prefix of one of ours is not ours" run avc_check
FAKE_AUSEARCH_OUT='ausearch: cannot open /var/log/audit/audit.log' FAKE_AUSEARCH_RC=10 refuse "avc: an ausearch that fails for another reason is not a clean board" 'ausearch failed \(status 10\)' run avc_check
# auditd: without it "no matches" proves nothing
FAKE_AUDITD=inactive refuse "avc: auditd not running is refused, with the reason" 'denials before auditd started are not visible' run avc_check
FAKE_AUDITD=inactive FAKE_AUSEARCH_OUT="$other" FAKE_AUSEARCH_RC=0 refuse "avc: and not even a record makes it pass" 'auditd is not recording' run avc_check
FAKE_AUDIT_ENABLED=0 refuse "avc: auditd running with the kernel's audit disabled (auditctl -s: enabled 0) is refused" 'denials before auditd started are not visible' run avc_check
FAKE_AUDIT_ENABLED=2 accept "avc: an immutable audit configuration (auditctl -s: enabled 2) records, and passes" run avc_check
FAKE_AUDIT_ENABLED=3 refuse "avc: and enabled 3 is not a value that auditctl prints: refused" 'denials before auditd started are not visible' run avc_check
mv "$work/bin/auditctl" "$work/auditctl.off"
refuse "avc: no auditctl is refused too: the state of audit is unknown" 'audit enabled=.unknown' run avc_check
mv "$work/auditctl.off" "$work/bin/auditctl"
mv "$work/bin/ausearch" "$work/ausearch.off"
refuse "avc: enforcing with no ausearch is a refusal that names the package" 'install the audit package' run avc_check
selinux permissive
accept "avc: with no ausearch, permissive still has nothing to check" run avc_check
selinux enforcing
mv "$work/ausearch.off" "$work/bin/ausearch"
if grep -q 'avc_check' "$here/remote.sh" && grep -q 'stage-avc' "$here/boards.sh"; then echo "ok   boards.sh runs the avc check after a deploy"; else echo "FAIL boards.sh does not run the avc check"; fail=1; fi

# --- remote.sh rqlite-install, rqlite-status and rqlite-undeploy, against a fake systemctl and fake package managers ---------------
# remote.sh runs as a script, with a PATH of fakes and the paths of rqlite moved into the work directory. The fakes log every call
# that changes the board (RQ_LOG), in order, with a note of whether the drop-in was still there when the package manager ran.
rq=$work/rq
rqbin=$rq/bin
mkdir -p "$rqbin" "$rq/root/usr/bin" "$rq/root/var/lib/rqlite/data" "$rq/stage/rqlite" "$rq/root/etc/systemd/system"
for t in bash dirname uname cmp sed head rm rmdir mkdir cat grep sha256sum mktemp date chmod; do ln -sf "$(command -v "$t")" "$rqbin/$t"; done
cat >"$rqbin/systemctl" <<'F'
#!/bin/bash
echo "systemctl $*" >>"$RQ_LOG"
case "$1" in
cat) [ "${RQ_UNIT:-yes}" = yes ]; exit ;;
is-active) echo "${RQ_ACTIVE:-inactive}"; [ "${RQ_ACTIVE:-inactive}" = active ]; exit ;;
is-enabled) echo enabled ;;
show) echo "" ;;
esac
exit 0
F
cat >"$rqbin/apt-get" <<'F'
#!/bin/bash
if [ -e "$RQ_DROPIN" ]; then d=dropin-present; else d=dropin-gone; fi
echo "apt-get $* ($d)" >>"$RQ_LOG"
[ -z "${RQ_APT_FAIL:-}" ] || exit 100
if [ "$1" = install ]; then : >"$RQ_BIN"; chmod +x "$RQ_BIN"; fi
exit 0
F
cat >"$rqbin/dnf" <<'F'
#!/bin/bash
if [ -e "$RQ_DROPIN" ]; then d=dropin-present; else d=dropin-gone; fi
echo "dnf $* ($d)" >>"$RQ_LOG"
[ -z "${RQ_APT_FAIL:-}" ] || exit 1
if [ "$1" = install ]; then : >"$RQ_BIN"; chmod +x "$RQ_BIN"; fi
exit 0
F
cat >"$rqbin/id" <<'F'
#!/bin/bash
[ "$1" = -u ] && [ "$2" = rqlite ] && [ -z "${RQ_NO_USER:-}" ]
F
cat >"$rqbin/getent" <<'F'
#!/bin/bash
[ "$1" = group ] && [ "$2" = rqlite ] && [ -z "${RQ_NO_USER:-}" ] && echo rqlite:x:900:
F
for c in userdel groupdel; do printf '#!/bin/bash\necho "%s $*" >>"$RQ_LOG"\n' "$c" >"$rqbin/$c"; done
# install without -o and -g (the test is not root)
cat >"$rqbin/install" <<F
#!/bin/bash
args=()
while [ \$# -gt 0 ]; do case "\$1" in -o | -g) shift 2 ;; *) args+=("\$1"); shift ;; esac; done
exec $(command -v install) "\${args[@]}"
F
cat >"$rqbin/ip" <<'F'
#!/bin/bash
printf '1: lo    inet 127.0.0.1/8 scope host lo\n2: eth0    inet %s/24 brd 192.0.2.255 scope global eth0\n' "${RQ_BOARD_IP:-192.0.2.12}"
F
chmod +x "$rqbin"/systemctl "$rqbin"/apt-get "$rqbin"/dnf "$rqbin"/id "$rqbin"/getent "$rqbin"/userdel "$rqbin"/groupdel "$rqbin"/install "$rqbin"/ip
export RQ_LOG=$rq/log RQ_DROPIN=$rq/root/etc/systemd/system/rqlited.service.d/10-sluis.conf RQ_BIN=$rq/root/usr/bin/rqlited
pkg=rqlite_10.6.6_arm64.deb
printf 'a package\n' >"$rq/stage/rqlite/$pkg"
pkgsha=$(sha256sum "$rq/stage/rqlite/$pkg" | cut -d' ' -f1)
# rqx runs remote.sh as the board does: a PATH of fakes, the moved paths, the settings of rqlite.sh in the environment.
rqx() { # mode [VAR=value]...
	local mode=$1
	shift
	env -i PATH="$rqbin" HOME="$rq" \
		rqlite_dropin_dir="$rq/root/etc/systemd/system/rqlited.service.d" rqlite_var_dir="$rq/root/var/lib/rqlite" rqlite_bin="$RQ_BIN" \
		os_release_file="$work/os-release" selinux_enforce_file="$work/enforce" RQ_LOG="$RQ_LOG" RQ_DROPIN="$RQ_DROPIN" RQ_BIN="$RQ_BIN" \
		RQLITE_NODE_IP=192.0.2.12 RQLITE_HTTP_PORT=4001 RQLITE_RAFT_PORT=4002 RQLITE_EXPECT=3 RQLITE_JOIN="$j3" RQLITE_SHA256="$pkgsha" \
		"$@" "$rqbin/bash" "$here/remote.sh" "$mode" "$rq/stage"
}
rqreset() { rm -rf "$rq/root/etc/systemd/system/rqlited.service.d" "$RQ_BIN"; mkdir -p "$rq/root/var/lib/rqlite/data"; : >"$RQ_LOG"; }
osrel ubuntu debian
selinux off

# install
rqreset
if rqx rqlite-install RQ_BOARD_IP=192.0.2.12 RQ_ACTIVE=active >"$work/out" 2>&1; then echo "ok   rqlite-install: a first install succeeds"; else echo "FAIL rqlite-install: $(cat "$work/out")"; fail=1; fi
want_unit="${hdr}"$'\nExecStart=/usr/bin/rqlited -http-addr 192.0.2.12:4001 -raft-addr 192.0.2.12:4002 -bootstrap-expect 3 -join '$j3$' /var/lib/rqlite/data'
want_unit=${want_unit//\/usr\/bin\/rqlited/$RQ_BIN}
want_unit=${want_unit// \/var\/lib\/rqlite\/data/ $rq/root/var/lib/rqlite/data}
is "rqlite-install: the drop-in is written (the binary path moved into the test)" "$want_unit" cat "$RQ_DROPIN"
if grep -q '^apt-get install -y -- .*rqlite_10.6.6_arm64.deb' "$RQ_LOG" && grep -q '^systemctl enable rqlited.service' "$RQ_LOG" && grep -q '^systemctl restart rqlited.service' "$RQ_LOG"; then echo "ok   rqlite-install: the package is installed, the unit enabled and (re)started"; else echo "FAIL rqlite-install log: $(cat "$RQ_LOG")"; fail=1; fi
: >"$RQ_LOG"
rqx rqlite-install RQ_ACTIVE=active >"$work/out" 2>&1 || { echo "FAIL a second install: $(cat "$work/out")"; fail=1; }
if ! grep -q '^systemctl restart' "$RQ_LOG" && grep -q '^systemctl enable' "$RQ_LOG"; then echo "ok   rqlite-install: a second run with the same drop-in and a running node does not restart it, and enables it again"; else echo "FAIL second run: $(cat "$RQ_LOG")"; fail=1; fi
: >"$RQ_LOG"
rqx rqlite-install RQ_ACTIVE=inactive >"$work/out" 2>&1 || true
if grep -q '^systemctl restart' "$RQ_LOG"; then echo "ok   rqlite-install: a node that is not running is started (after a package upgrade stopped it)"; else echo "FAIL not started: $(cat "$RQ_LOG")"; fail=1; fi
rqreset
refuse "rqlite-install: a package that does not have its pin is refused before anything is installed" 'does not have the pinned sha256' rqx rqlite-install RQLITE_SHA256=0000000000000000000000000000000000000000000000000000000000000000
[ ! -s "$RQ_LOG" ] && [ ! -e "$RQ_DROPIN" ] && echo "ok   rqlite-install: and nothing was installed or written" || { echo "FAIL a refused package left traces: $(cat "$RQ_LOG")"; fail=1; }
refuse "rqlite-install: an address the board does not have is refused before anything is installed" 'this board has no address 192.0.2.99' rqx rqlite-install RQLITE_NODE_IP=192.0.2.99 RQLITE_JOIN=192.0.2.99:4002,192.0.2.12:4002,192.0.2.13:4002
[ ! -s "$RQ_LOG" ] && echo "ok   rqlite-install: and the package manager was not run" || { echo "FAIL traces: $(cat "$RQ_LOG")"; fail=1; }
refuse "rqlite-install: a cluster of three without a join list is refused" 'must name all 3 nodes' rqx rqlite-install RQLITE_JOIN=
[ ! -s "$RQ_LOG" ] && echo "ok   rqlite-install: and nothing was installed" || { echo "FAIL traces: $(cat "$RQ_LOG")"; fail=1; }
# a drop-in of the earlier shape (-node-id) is refused: its Raft state does not fit the new flags
mkdir -p "$(dirname "$RQ_DROPIN")"
printf '[Service]\nExecStart=\nExecStart=/usr/bin/rqlited -node-id core -http-addr 192.0.2.12:4001 -raft-addr 192.0.2.12:4002 /var/lib/rqlite/data\n' >"$RQ_DROPIN"
refuse "rqlite-install: a drop-in with -node-id (the earlier shape) is refused, with the way out" 'SLUIS_PURGE_STATE=1' rqx rqlite-install
[ ! -s "$RQ_LOG" ] && echo "ok   rqlite-install: and left alone" || { echo "FAIL traces: $(cat "$RQ_LOG")"; fail=1; }

# status
rqreset
accept "rqlite-status: not installed fails" bash -c '! "$@"' _ rqx rqlite-status RQ_UNIT=no
rqx rqlite-status RQ_UNIT=no >"$work/out" 2>&1 || true
grep -q 'not installed' "$work/out" && echo "ok   rqlite-status: and says so" || { echo "FAIL: $(cat "$work/out")"; fail=1; }
: >"$RQ_BIN"; chmod +x "$RQ_BIN"
accept "rqlite-status: active is success" rqx rqlite-status RQ_ACTIVE=active
rqx rqlite-status RQ_ACTIVE=inactive >"$work/out" 2>&1 && { echo "FAIL rqlite-status: an installed unit that is not running succeeded"; fail=1; } || { grep -q 'inactive' "$work/out" && echo "ok   rqlite-status: an installed unit that is not running fails, and says inactive" || { echo "FAIL: $(cat "$work/out")"; fail=1; }; }

# undeploy: the gate is the drop-in
rqreset
: >"$RQ_BIN"; chmod +x "$RQ_BIN"
rqx rqlite-undeploy >"$work/out" 2>&1
if ! grep -q 'disable\|stop\|apt-get\|userdel' "$RQ_LOG" && grep -q 'did not install it' "$work/out"; then echo "ok   rqlite-undeploy: an rqlited that this tool did not install (no drop-in) is neither stopped nor disabled"; else echo "FAIL foreign rqlited touched: $(cat "$RQ_LOG") $(cat "$work/out")"; fail=1; fi
: >"$RQ_LOG"
rqx rqlite-undeploy SLUIS_PURGE_STATE=1 >"$work/out" 2>&1
if ! grep -q 'disable\|apt-get\|userdel' "$RQ_LOG" && [ -d "$rq/root/var/lib/rqlite/data" ] && [ -e "$RQ_BIN" ]; then echo "ok   rqlite-undeploy: and not purged either: no package removal, the data and the binary stay"; else echo "FAIL foreign rqlited purged: $(cat "$RQ_LOG")"; fail=1; fi
rqx rqlite-undeploy RQ_UNIT=no >"$work/out" 2>&1
grep -q 'not installed' "$work/out" && echo "ok   rqlite-undeploy: no unit at all is 'not installed'" || { echo "FAIL: $(cat "$work/out")"; fail=1; }
# a purge that stopped half way: the package is gone, so is the unit file, the drop-in and the data are left. The drop-in decides, not
# the unit: the next run finishes the purge instead of calling the board "not installed".
mkdir -p "$(dirname "$RQ_DROPIN")" "$rq/root/var/lib/rqlite/data"
printf '[Service]\n' >"$RQ_DROPIN"
: >"$RQ_LOG"
rqx rqlite-undeploy RQ_UNIT=no SLUIS_PURGE_STATE=1 >"$work/out" 2>&1 || { echo "FAIL half purge, finished: $(cat "$work/out")"; fail=1; }
if ! grep -q 'not installed' "$work/out" && grep -q '^apt-get remove -y rqlite' "$RQ_LOG" && [ ! -e "$RQ_DROPIN" ] && [ ! -d "$rq/root/var/lib/rqlite" ] && grep -q '^userdel rqlite' "$RQ_LOG" && grep -q '^groupdel rqlite' "$RQ_LOG" && grep -q 'rqlite: removed' "$work/out"; then echo "ok   rqlite-undeploy: a half-finished purge (drop-in and data left, no unit file) is finished by the next run, not called 'not installed'"; else echo "FAIL half purge: $(cat "$RQ_LOG") $(cat "$work/out")"; fail=1; fi
mkdir -p "$rq/root/var/lib/rqlite/data"
mkdir -p "$(dirname "$RQ_DROPIN")"
printf '[Service]\n' >"$RQ_DROPIN"
: >"$RQ_LOG"
rqx rqlite-undeploy RQ_UNIT=no >"$work/out" 2>&1 || true
if ! grep -q 'not installed' "$work/out" && [ -e "$RQ_DROPIN" ] && [ -d "$rq/root/var/lib/rqlite/data" ] && ! grep -q 'apt-get' "$RQ_LOG"; then echo "ok   rqlite-undeploy: and without the purge a drop-in with no unit is not called 'not installed' either; nothing is removed"; else echo "FAIL drop-in without unit: $(cat "$RQ_LOG") $(cat "$work/out")"; fail=1; fi
rm -rf "$(dirname "$RQ_DROPIN")"
# with the drop-in, without the purge
mkdir -p "$(dirname "$RQ_DROPIN")"
printf '[Service]\n' >"$RQ_DROPIN"
: >"$RQ_LOG"
rqx rqlite-undeploy >"$work/out" 2>&1
if grep -q '^systemctl disable --now rqlited.service' "$RQ_LOG" && ! grep -q 'apt-get' "$RQ_LOG" && [ -e "$RQ_DROPIN" ] && [ -d "$rq/root/var/lib/rqlite/data" ]; then echo "ok   rqlite-undeploy: with the drop-in and no purge it stops and disables, and keeps the package, the drop-in and the data"; else echo "FAIL undeploy: $(cat "$RQ_LOG")"; fail=1; fi
# with the purge: the drop-in goes last
: >"$RQ_LOG"
rqx rqlite-undeploy SLUIS_PURGE_STATE=1 >"$work/out" 2>&1 || { echo "FAIL purge: $(cat "$work/out")"; fail=1; }
if grep -q '^apt-get remove -y rqlite (dropin-present)' "$RQ_LOG" && [ ! -e "$RQ_DROPIN" ] && [ ! -d "$rq/root/var/lib/rqlite" ] && grep -q '^userdel rqlite' "$RQ_LOG" && grep -q '^groupdel rqlite' "$RQ_LOG"; then echo "ok   rqlite-undeploy: a purge removes the package while the drop-in is still there, then the data, the user, the group and the drop-in last"; else echo "FAIL purge: $(cat "$RQ_LOG")"; fail=1; fi
# a package manager that fails leaves the drop-in, so that the next run purges again
rqreset
mkdir -p "$(dirname "$RQ_DROPIN")" "$rq/root/var/lib/rqlite/data"
printf '[Service]\n' >"$RQ_DROPIN"
rqx rqlite-undeploy SLUIS_PURGE_STATE=1 RQ_APT_FAIL=1 >"$work/out" 2>&1 && { echo "FAIL a failed removal succeeded"; fail=1; }
if [ -e "$RQ_DROPIN" ] && [ -d "$rq/root/var/lib/rqlite/data" ] && ! grep -q 'userdel' "$RQ_LOG"; then echo "ok   rqlite-undeploy: a removal that fails leaves the drop-in, the data and the user, so the next run finishes the purge"; else echo "FAIL half purge: $(cat "$RQ_LOG")"; fail=1; fi
# --- settle_units: the wait for the units after the start (remote-lib.sh) -------------------------------------------------------------
# A fake systemctl show: each unit has $SC/<unit>.state, a list of "ActiveState SubState NRestarts" lines, one for each poll; the last
# one repeats. A fake journalctl -u: $SC/<unit>.journal. The timings are short; the rules are the ones of the board.
sc=$work/settle
sbin=$work/settle-bin
mkdir -p "$sc" "$sbin"
cat >"$sbin/systemctl" <<'F'
#!/bin/bash
[ "$1" = show ] && [ "$2" = -p ] || exit 2
u=${*: -1}
f=$SC/$u.state
[ -e "$f" ] || { printf 'ActiveState=inactive\nSubState=dead\nNRestarts=0\n'; exit 0; }
n=$(($(cat "$f.n" 2>/dev/null || echo 0) + 1))
echo "$n" >"$f.n"
line=$(sed -n "${n}p" "$f")
[ -n "$line" ] || line=$(tail -n 1 "$f")
read -r a s r <<<"$line"
printf 'ActiveState=%s\nSubState=%s\nNRestarts=%s\n' "$a" "$s" "$r"
F
cat >"$sbin/journalctl" <<'F'
#!/bin/bash
[ "$1" = -u ] || exit 2
cat "$SC/$2.journal" 2>/dev/null || true
F
chmod +x "$sbin/systemctl" "$sbin/journalctl"
for t in sleep awk sed cat tail; do ln -sf "$(command -v "$t")" "$sbin/$t"; done
settle_reset() { rm -f "$sc"/*; }
steady() { printf 'active running 0\n' >"$sc/$1.state"; } # an active unit that never restarts
settle() { # the units..., run in a subshell with the fakes alone; prints what settle_units printed and "rc=N"
	(
		export PATH="$sbin" SC="$sc" boundary=dev settle_timeout=2 settle_step=0.05 settle_stable=3
		# shellcheck source=/dev/null
		. "$here/remote-lib.sh"
		rc=0
		settle_units "$@" || rc=$?
		echo "rc=$rc"
	) 2>&1
}
key=sluis-key@dev.service card=sluis-drv-key-yubikey-piv@dev.service store=sluis-store@dev.service writer=sluis-writer@dev.service
sexpect() { # description output pattern...: the output must match every pattern (grep -E) and none that starts with !
	local d=$1 out=$2 p
	shift 2
	for p in "$@"; do
		if [[ "$p" == '!'* ]]; then
			if grep -qE -- "${p:1}" <<<"$out"; then echo "FAIL $d: the output has ${p:1}:"; sed 's/^/     /' <<<"$out"; fail=1; return; fi
		elif ! grep -qE -- "$p" <<<"$out"; then echo "FAIL $d: the output lacks $p:"; sed 's/^/     /' <<<"$out"; fail=1; return; fi
	done
	echo "ok   $d"
}

settle_reset
steady "$store"; steady "$writer"
out=$(settle "$store" "$writer")
sexpect "settle: units that are active and stand still settle, exit 0" "$out" "^unit $store active" "^unit $writer active" '^rc=0$' '!FAILED'

settle_reset
steady "$store"
printf 'activating start 0\nactivating start 0\nactive running 0\n' >"$sc/$writer.state"
out=$(settle "$store" "$writer")
sexpect "settle: a unit that is slow to start settles once it is active, exit 0" "$out" "^unit $writer active" '^rc=0$'

settle_reset
steady "$store"
# active (running) at every sample, but one more restart each time: what is-active would call active
printf 'active running 1\nactive running 2\nactive running 3\nactive running 4\nactive running 5\nactive running 6\nactive running 7\nactive running 8\nactive running 9\nactive running 10\nactive running 11\nactive running 12\nactive running 13\nactive running 14\nactive running 15\nactive running 16\nactive running 17\nactive running 18\nactive running 19\nactive running 20\nactive running 21\nactive running 22\nactive running 23\nactive running 24\nactive running 25\nactive running 26\nactive running 27\nactive running 28\nactive running 29\nactive running 30\nactive running 31\nactive running 32\nactive running 33\nactive running 34\nactive running 35\nactive running 36\nactive running 37\nactive running 38\nactive running 39\nactive running 40\nactive running 41\n' >"$sc/$writer.state"
printf 'writer: credential serve: the credentials directory must be owned by the uid of this process\n' >"$sc/$writer.journal"
out=$(settle "$store" "$writer")
sexpect "settle: a unit whose NRestarts keeps rising fails, with its journal, though it is 'active' at each sample" "$out" "^unit $writer FAILED: .*restarted [0-9]+ times" "journal $writer: writer: credential serve: the credentials directory must be owned" "^unit $store active" '^rc=1$'

settle_reset
steady "$store"
printf 'activating auto-restart 3\n' >"$sc/$writer.state"
printf 'Started sluis writer\nunavailable: store\n' >"$sc/$writer.journal"
out=$(settle "$store" "$writer")
sexpect "settle: a unit that stays 'activating (auto-restart)' fails, with its journal" "$out" "^unit $writer FAILED: .*activating \(auto-restart\)" "journal $writer: unavailable: store" '^rc=1$'

settle_reset
steady "$store"
printf 'failed failed 5\n' >"$sc/$writer.state"
out=$(settle "$store" "$writer")
sexpect "settle: a failed unit fails" "$out" "^unit $writer FAILED: .*failed" '^rc=1$'

# The locked card board.
settle_reset
steady "$card"; steady "$store"
printf 'activating auto-restart 7\n' >"$sc/$key.state"
printf 'key-store driver ensure wrapping: failed_precondition: locked\n' >"$sc/$key.journal"
out=$(settle "$card" "$key" "$store")
sexpect "settle: the card driver up and key@ stopped by the lock is the outcome 'locked': exit 10, nothing FAILED" "$out" "^unit $key locked: .*boards-unlock" "^unit $card active" "^unit $store active" '^rc=10$' '!FAILED'

settle_reset
steady "$card"
printf 'activating auto-restart 7\n' >"$sc/$key.state"
printf 'key-store driver ensure wrapping: failed_precondition: locked\n' >"$sc/$key.journal"
printf 'activating auto-restart 4\n' >"$sc/$store.state"
printf 'dial unix /run/sluis/key/dev/store.sock: connect: no such file or directory\n' >"$sc/$store.journal"
out=$(settle "$card" "$key" "$store")
sexpect "settle: a unit that stumbled on key@ while the board is locked waits with it: exit 10" "$out" "^unit $store waits for key@, which is locked" '^rc=10$' '!FAILED'

settle_reset
steady "$card"
printf 'activating auto-restart 7\n' >"$sc/$key.state"
printf 'key-store driver ensure wrapping: failed_precondition: locked\n' >"$sc/$key.journal"
printf 'activating auto-restart 4\n' >"$sc/$store.state"
printf 'credential serve: the credentials directory must be owned by the uid of this process\n' >"$sc/$store.journal"
out=$(settle "$card" "$key" "$store")
sexpect "settle: a locked board does not hide a unit with a fault of its own: it fails, exit 1, and key@ is still said to be locked" "$out" "^unit $store FAILED" "journal $store: credential serve: the credentials directory" "^unit $key locked" '^rc=1$'

settle_reset
steady "$card"
printf 'activating auto-restart 7\n' >"$sc/$key.state"
printf 'something else broke: failed_precondition: store\n' >"$sc/$key.journal"
out=$(settle "$card" "$key")
sexpect "settle: key@ in a loop for another reason than the lock fails, with its journal" "$out" "^unit $key FAILED" "journal $key: something else broke" '^rc=1$' '!^unit [^ ]+ locked'

settle_reset
printf 'activating auto-restart 2\n' >"$sc/$card.state"
printf 'activating auto-restart 7\n' >"$sc/$key.state"
printf 'key-store driver ensure wrapping: failed_precondition: locked\n' >"$sc/$key.journal"
printf 'card driver: no reader\n' >"$sc/$card.journal"
out=$(settle "$card" "$key")
sexpect "settle: no card driver up, no 'locked': both fail" "$out" "^unit $card FAILED" "^unit $key FAILED" '^rc=1$' '!^unit [^ ]+ locked'

settle_reset
steady "$store"; steady "$key"
printf 'failed_precondition: locked\n' >"$sc/$key.journal"
out=$(settle "$store" "$key")
sexpect "settle: a key@ that is active is active, whatever its old journal says (software boards have no card driver)" "$out" "^unit $key active" '^rc=0$' '!^unit [^ ]+ locked'
exit "$fail"
