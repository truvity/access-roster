#!/usr/bin/env bash
# shellcheck disable=SC2001,SC2030,SC2031,SC2015,SC2016,SC2317,SC2329 # `A && ok || fail` pairs report a check either way; single quotes hold the code of `bash -c`
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
		export PATH="$work/bin" os_release_file="$work/os-release" card_polkit_policy="$work/policy" card_ccid_glob="$work/drivers/ifd-ccid.bundle" state_root="$work/state" manifest="$work/manifest" selinux_enforce_file="$work/enforce"
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
mkdir -p "$work/drivers/ifd-ccid.bundle" # the driver is where the test says, and a host's own is never looked at
FAKE_UNITS="pcscd.socket" accept "an unknown system with the card service and a CCID driver is accepted" run check_card_prerequisites
FAKE_UNITS="" refuse "an unknown system with a CCID driver and no card service is refused, and names the service" 'the card service \(pcscd\)' run check_card_prerequisites
rm -rf "$work/drivers"

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
printf 'file\t/usr/libexec/sluis/actors/store\nfile\t/usr/libexec/sluis/actors/key\nfile\t/usr/libexec/sluis/drivers/key/yubikey-piv\nfile\t/usr/libexec/sluis/drivers/store/rqlite\nfile\t/usr/libexec/sluis/drivers/store/credential-with-a-long-name\nfile\t/etc/sluis/other\nunit\tsluis-key@dev.service\n' >"$work/manifest"
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
case " $* " in
*" Requires "*)
	# the unit graph: $SC/<unit>.deps holds the lines "Requires=a b", "After=c"
	cat "$SC/$u.deps" 2>/dev/null || true
	exit 0
	;;
esac
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
# journalctl -u UNIT [--since STAMP] ...: each line of $SC/<unit>.journal starts with its timestamp (two fields), which --since
# compares as the text it is, as the timestamps sort that way.
# journalctl _SYSTEMD_UNIT=UNIT ... reads the same file: the process's own lines; the tests keep no line of systemd about a unit.
case "$1" in
-u) u=$2 ;;
_SYSTEMD_UNIT=*) u=${1#_SYSTEMD_UNIT=} ;;
*) exit 2 ;;
esac
since=""
while [ "$#" -gt 0 ]; do
	[ "$1" = --since ] && since=$2
	shift
done
while IFS= read -r line; do
	stamp=${line%% *}
	rest=${line#* }
	stamp="$stamp ${rest%% *}"
	[ -z "$since" ] || [[ "$stamp" > "$since" || "$stamp" == "$since" ]] || continue
	printf '%s\n' "${rest#* }"
done <"$SC/$u.journal" 2>/dev/null || true
F
# The fake sluis CLI of the board: `sluis node status NODE --boundary B` says what $SC/lock holds: locked, unlocked, or a failure
# (any other word is the status it exits with, and "garbage" prints a line that is neither). $SC/cli.calls counts the calls.
cat >"$sbin/sluis" <<'F'
#!/bin/bash
[ "$1 $2" = "node status" ] || exit 2
echo x >>"$SC/cli.calls"
case "$(cat "$SC/lock" 2>/dev/null || echo unlocked)" in
hang) sleep 30 ;;
locked | unlocked)
	# The line about the PIN attempts comes first, as the CLI prints it; the lock line is the last line, and the only one the deploy reads.
	echo "node $3: PIN attempts left: 1, ONE MORE WRONG PIN BLOCKS THE CARD (the PUK procedure is the owners')"
	echo "node $3 is $(cat "$SC/lock" 2>/dev/null || echo unlocked)" ;;
garbage) echo "hello" ;;
*) echo "node node status: the admin socket cannot be reached (is the driver running, and are you root?)" >&2; exit 1 ;;
esac
F
chmod +x "$sbin/systemctl" "$sbin/journalctl" "$sbin/sluis"
for t in sleep awk sed cat tail grep timeout; do ln -sf "$(command -v "$t")" "$sbin/$t"; done
settle_reset() { rm -f "$sc"/*; }
journal() { printf '2026-11-06 12:00:10.000000 %s\n' "$2" >>"$sc/$1.journal"; } # a line of this deploy
stale() { printf '2026-11-06 11:00:00.000000 %s\n' "$2" >>"$sc/$1.journal"; } # a line of an earlier deploy
depends() { printf '%s\n' "$2" >>"$sc/$1.deps"; }
steady() { printf 'active running 0\n' >"$sc/$1.state"; } # an active unit that never restarts
lock() { printf '%s\n' "$1" >"$sc/lock"; } # what the card driver says: locked, unlocked, or a word that makes the fake CLI fail
keygroup() { depends "$1" "SupplementaryGroups=sluis-drv-writer-spool-dev sluis-key-dev sluis-store-dev"; } # may call key@
looping() { printf 'activating auto-restart %s\n' "$2" >"$sc/$1.state"; } # a unit in a restart loop
settle() { # the units..., run in a subshell with the fakes alone; prints what settle_units printed and "rc=N"
	(
		export PATH="$sbin" SC="$sc" boundary=dev settle_timeout=2 settle_step=0.05 settle_stable=3 settle_since="2026-11-06 12:00:00.000000"
		export lock_cli="${SETTLE_LOCK_CLI:-$sbin/sluis}" lock_node=board-a lock_timeout=1
		# shellcheck source=/dev/null
		. "$here/remote-lib.sh"
		rc=0
		settle_units "$@" || rc=$?
		echo "rc=$rc"
	) 2>&1
}
lock_prefix='SLUIS-BOARD-LOCK: '
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
sexpect "settle: units that are active and stand still settle, exit 0" "$out" "^unit $store active" "^unit $writer active" '^rc=0$' '!FAILED' '^SLUIS-BOARD-STATE: ok$'

settle_reset
steady "$store"
printf 'activating start 0\nactivating start 0\nactive running 0\n' >"$sc/$writer.state"
out=$(settle "$store" "$writer")
sexpect "settle: a unit that is slow to start settles once it is active, exit 0" "$out" "^unit $writer active" '^rc=0$'

settle_reset
steady "$store"
# active (running) at every sample, but one more restart each time: what is-active would call active
printf 'active running 1\nactive running 2\nactive running 3\nactive running 4\nactive running 5\nactive running 6\nactive running 7\nactive running 8\nactive running 9\nactive running 10\nactive running 11\nactive running 12\nactive running 13\nactive running 14\nactive running 15\nactive running 16\nactive running 17\nactive running 18\nactive running 19\nactive running 20\nactive running 21\nactive running 22\nactive running 23\nactive running 24\nactive running 25\nactive running 26\nactive running 27\nactive running 28\nactive running 29\nactive running 30\nactive running 31\nactive running 32\nactive running 33\nactive running 34\nactive running 35\nactive running 36\nactive running 37\nactive running 38\nactive running 39\nactive running 40\nactive running 41\n' >"$sc/$writer.state"
journal "$writer" 'writer: credential serve: the credentials directory must be owned by the uid of this process'
out=$(settle "$store" "$writer")
sexpect "settle: a unit whose NRestarts keeps rising fails, with its journal, though it is 'active' at each sample" "$out" "^unit $writer FAILED: .*restarted [0-9]+ times" "journal $writer: writer: credential serve: the credentials directory must be owned" "^unit $store active" '^rc=1$' '^SLUIS-BOARD-STATE: failed$'

settle_reset
steady "$store"
printf 'activating auto-restart 3\n' >"$sc/$writer.state"
journal "$writer" 'Started sluis writer'
journal "$writer" 'unavailable: store'
out=$(settle "$store" "$writer")
sexpect "settle: a unit that stays 'activating (auto-restart)' fails, with its journal" "$out" "^unit $writer FAILED: .*activating \(auto-restart\)" "journal $writer: unavailable: store" '^rc=1$'

settle_reset
steady "$store"
printf 'failed failed 5\n' >"$sc/$writer.state"
out=$(settle "$store" "$writer")
sexpect "settle: a failed unit fails" "$out" "^unit $writer FAILED: .*failed" '^rc=1$'

# --- The lock: from the card driver (sluis node status), not from the journal ---------------------------------------------------------
# The writer's journal when it starts on a locked board: the error that ends it (key@ refuses while the driver holds no PIN).
waiting='writer: serve: sign the checkpoint: unavailable: driver'

# unlocked: ok, and the state line is the last one
settle_reset
lock unlocked
steady "$card"; steady "$key"; steady "$store"
out=$(settle "$card" "$key" "$store")
sexpect "settle: a card board with every unit up and the driver unlocked is ok, exit 0" "$out" '^lock: the card driver is unlocked' "^${lock_prefix}unlocked$" '^SLUIS-BOARD-STATE: ok$' '^rc=0$' '!FAILED' '!waits for the PIN'

# the board of the real run: locked, all units active (key@ stays up and logs "locked: asked the peers"): locked, not ok
settle_reset
lock locked
steady "$card"; steady "$key"; steady "$store"; steady "$writer"
journal "$key" '{"level":"INFO","msg":"locked: asked the peers for the PIN"}'
out=$(settle "$card" "$key" "$store" "$writer")
sexpect "settle: every unit active but the driver locked is the outcome 'locked', never ok: exit 10" "$out" '^lock: the card driver is locked' "^${lock_prefix}locked$" '^SLUIS-BOARD-STATE: locked$' '^rc=10$' '!FAILED' '!STATE: ok'

# a deploy restarted the driver: locked, the writer restarts because it cannot sign
settle_reset
lock locked
steady "$card"; steady "$key"; steady "$store"
looping "$writer" 33
keygroup "$writer"
journal "$writer" '{"level":"INFO","msg":"writer starting"}'
journal "$writer" "$waiting"
out=$(settle "$card" "$key" "$store" "$writer")
sexpect "settle: a writer that restarts only because the driver is locked is waiting, not failed: exit 10" "$out" "^unit $writer waits for the PIN: .*restarted 33 times.*boards-unlock" "^unit $store active" '^SLUIS-BOARD-STATE: locked$' '^rc=10$' '!FAILED'

# the same, and the writer's last line is an info log of its next start: it is still waiting
settle_reset
lock locked
steady "$card"; steady "$key"
looping "$writer" 33
keygroup "$writer"
journal "$writer" "$waiting"
journal "$writer" '{"time":"2026-11-06T12:00:11Z","level":"INFO","msg":"writer starting"}'
journal "$writer" '{"time":"2026-11-06T12:00:11Z","level":"WARN","msg":"the key is not ready"}'
out=$(settle "$card" "$key" "$writer")
sexpect "settle: info and warning log lines after the error do not hide it" "$out" "^unit $writer waits for the PIN" '^SLUIS-BOARD-STATE: locked$' '^rc=10$'

# the graph tells it too: After= key@ (or the card driver), with no group
settle_reset
lock locked
steady "$card"; steady "$key"
looping "$store" 4
depends "$store" "After=$card $key"
journal "$store" 'store: unwrap: unavailable: driver'
out=$(settle "$card" "$key" "$store")
sexpect "settle: a unit ordered after key@ in the unit graph, with the refusal as its last line, is waiting" "$out" "^unit $store waits for the PIN" '^SLUIS-BOARD-STATE: locked$' '^rc=10$' '!FAILED'

# key@ itself, when it exits with the lock (an older key@, or a driver that refuses Ensure)
settle_reset
lock locked
steady "$card"
looping "$key" 7
journal "$key" 'key-store driver ensure wrapping: failed_precondition: locked'
out=$(settle "$card" "$key")
sexpect "settle: key@ that exits with the lock while the driver is locked is waiting too" "$out" "^unit $key waits for the PIN" '^SLUIS-BOARD-STATE: locked$' '^rc=10$' '!FAILED'

# a waiting unit that also has a fault of its own: failed (the other waiting unit is still said to be waiting)
settle_reset
lock locked
steady "$card"; steady "$key"
looping "$writer" 33
keygroup "$writer"
journal "$writer" "$waiting"
looping "$store" 9
keygroup "$store"
journal "$store" 'unavailable: driver'
journal "$store" 'store: credential serve: the credentials directory must be owned by the uid of this process'
out=$(settle "$card" "$key" "$writer" "$store")
sexpect "settle: a unit that needs key@ but ends with a fault of its own is FAILED on a locked board, exit 1" "$out" "^unit $store FAILED" "journal $store: store: credential serve: the credentials directory" "^unit $writer waits for the PIN" '^lock: the card driver is locked' '^SLUIS-BOARD-STATE: failed$' '^rc=1$'

# a fault that comes after the wait is the unit's last word
settle_reset
lock locked
steady "$card"; steady "$key"
looping "$writer" 5
keygroup "$writer"
journal "$writer" "$waiting"
journal "$writer" 'writer: serve: the audit blob is read-only'
out=$(settle "$card" "$key" "$writer")
sexpect "settle: a unit whose last word is another error than the lock's is FAILED, though it logged the lock's before" "$out" "^unit $writer FAILED" '^SLUIS-BOARD-STATE: failed$' '^rc=1$'

# a unit with no word at all (journal lost, or it dies before it writes): not proven to be waiting
settle_reset
lock locked
steady "$card"; steady "$key"
looping "$writer" 5
keygroup "$writer"
out=$(settle "$card" "$key" "$writer")
sexpect "settle: a unit that says nothing is not taken for a waiting one" "$out" "^unit $writer FAILED" '^rc=1$'

# a unit that logs the refusal but is not tied to key@ in the graph or by group
settle_reset
lock locked
steady "$card"; steady "$key"
looping "$store" 4
depends "$store" "After=sluis-drv-store-credential@dev.service"
depends "$store" "Requires=sluis-drv-store-credential@dev.service"
depends "$store" "SupplementaryGroups=sluis-store-dev"
journal "$store" 'unavailable: driver'
out=$(settle "$card" "$key" "$store")
sexpect "settle: the refusal in the journal of a unit that is not tied to key@ is not enough" "$out" "^unit $store FAILED" '^SLUIS-BOARD-STATE: failed$' '^rc=1$'

# the driver is unlocked: the same unit is not waiting for anything, it has a fault
settle_reset
lock unlocked
steady "$card"; steady "$key"
looping "$writer" 33
keygroup "$writer"
journal "$writer" "$waiting"
out=$(settle "$card" "$key" "$writer")
sexpect "settle: a writer that restarts while the driver is unlocked is FAILED, whatever it says" "$out" "^unit $writer FAILED" '^lock: the card driver is unlocked' '^SLUIS-BOARD-STATE: failed$' '^rc=1$' '!waits for the PIN'

# key@ in a loop for another reason than the lock
settle_reset
lock locked
steady "$card"
looping "$key" 7
journal "$key" 'something else broke: failed_precondition: store'
out=$(settle "$card" "$key")
sexpect "settle: key@ in a loop for another reason than the lock fails, with its journal, on a locked board" "$out" "^unit $key FAILED" "journal $key: something else broke" '^rc=1$' '!waits for the PIN'

# a line of an earlier deploy is no evidence
settle_reset
lock locked
steady "$card"; steady "$key"
looping "$writer" 5
keygroup "$writer"
stale "$writer" "$waiting"
journal "$writer" 'writer: serve: store unavailable'
out=$(settle "$card" "$key" "$writer")
sexpect "settle: a refusal that an earlier deploy left in the journal does not make a unit wait" "$out" "^unit $writer FAILED" "journal $writer: writer: serve: store unavailable" '^rc=1$' '!waits for the PIN'

# the card driver itself is down: nothing to wait for
settle_reset
lock locked
looping "$card" 2
steady "$key"
journal "$card" 'card driver: no reader'
out=$(settle "$card" "$key")
sexpect "settle: a card driver that does not stay up is FAILED, locked or not" "$out" "^unit $card FAILED" "journal $card: card driver: no reader" '^SLUIS-BOARD-STATE: failed$' '^rc=1$'

# a lock nobody has looked at is never ok
settle_reset
lock broken
steady "$card"; steady "$key"; steady "$store"
out=$(settle "$card" "$key" "$store")
sexpect "settle: a lock state that cannot be read is failed, not ok" "$out" '^lock: UNKNOWN: .*status 1' "^${lock_prefix}unknown$" '^SLUIS-BOARD-STATE: failed$' '^rc=1$' '!STATE: ok'

settle_reset
lock garbage
steady "$card"; steady "$key"
out=$(settle "$card" "$key")
sexpect "settle: an answer that is neither locked nor unlocked is not believed" "$out" '^lock: UNKNOWN: .*something else' '^SLUIS-BOARD-STATE: failed$' '^rc=1$'

settle_reset
steady "$card"; steady "$key"
out=$(SETTLE_LOCK_CLI="$sbin/no-such-sluis" settle "$card" "$key")
sexpect "settle: a board without the sluis CLI cannot be said to be unlocked: failed, with the fix" "$out" "^lock: UNKNOWN: .*is not on the board: run 'just build-arm64'" '^SLUIS-BOARD-STATE: failed$' '^rc=1$'

# a card service that hangs: the CLI is cut off after lock_timeout, and the lock is unknown
settle_reset
lock hang
steady "$card"; steady "$key"
out=$(settle "$card" "$key")
sexpect "settle: a CLI that does not answer in time is cut off, and the lock is unknown: failed" "$out" '^lock: UNKNOWN: .*did not answer in 1 s' '^SLUIS-BOARD-STATE: failed$' '^rc=1$'

# a board with the software key has no PIN, and the CLI is not asked
settle_reset
rm -f "$sc/lock"
steady "$key"; steady "$store"
out=$(settle "$store" "$key")
sexpect "settle: a software board has no lock: ok, exit 0" "$out" '^lock: no card driver' "^${lock_prefix}none$" '^SLUIS-BOARD-STATE: ok$' '^rc=0$'
[ ! -e "$sc/cli.calls" ] && echo "ok   settle: the CLI is not asked on a board without the card driver" || { echo "FAIL the CLI was asked on a software board"; fail=1; }

settle_reset
lock locked
steady "$store"; steady "$key"
journal "$key" 'failed_precondition: locked'
out=$(settle "$store" "$key")
sexpect "settle: no card driver in the plan, no 'locked', whatever the journal says" "$out" "^unit $key active" '^rc=0$' '!waits for the PIN' '!STATE: locked'

# the other units' faults still show on a software board
settle_reset
steady "$key"
looping "$writer" 5
journal "$writer" "$waiting"
keygroup "$writer"
out=$(settle "$key" "$writer")
sexpect "settle: on a software board a unit that restarts is FAILED, with its journal" "$out" "^unit $writer FAILED" "journal $writer: $waiting" '^rc=1$'

# --- The restart back-off of the actor units is systemd 254's: an older board has the two lines taken out ---------------------------
vbin=$work/version-bin
mkdir -p "$vbin"
ln -sf "$(command -v sed)" "$vbin/sed"
unit_text() { printf '[Service]\nRestart=on-failure\nRestartSec=2s\nRestartSteps=5\nRestartMaxDelaySec=30\nEnvironment=X=1\n'; }
backoff_on() { # "systemd N (...)" or "": prints the unit after drop_restart_backoff on a board with that systemctl --version
	printf '#!/bin/bash\n[ "$1" = --version ] && [ -n %q ] && echo %q\n' "$1" "$1" >"$vbin/systemctl"
	chmod +x "$vbin/systemctl"
	unit_text >"$work/backoff.service"
	# shellcheck source=/dev/null
	(PATH="$vbin"; . "$here/remote-lib.sh"; drop_restart_backoff "$work/backoff.service")
	cat "$work/backoff.service"
}
for v in "systemd 252 (252.22-1)" "systemd 249 (249.11)" "" "systemd x"; do
	out=$(backoff_on "$v")
	if grep -q 'Restart\(Steps\|MaxDelaySec\)' <<<"$out" || ! grep -q '^RestartSec=2s$' <<<"$out" || ! grep -q '^Environment=X=1$' <<<"$out"; then echo "FAIL backoff: systemd '${v:-unknown}' keeps the 254 lines, or loses others: $out"; fail=1; else echo "ok   backoff: systemd '${v:-unknown}': RestartSteps and RestartMaxDelaySec are taken out, the rest stays"; fi
done
for v in "systemd 254 (254.5)" "systemd 257 (257-9)" "systemd 259 (259-1)"; do
	out=$(backoff_on "$v")
	if [ "$out" = "$(unit_text)" ]; then echo "ok   backoff: systemd '$v' keeps the unit as it is"; else echo "FAIL backoff: systemd '$v' changed the unit: $out"; fail=1; fi
done

# --- remote.sh status: the lock of the card, from the card driver ---------------------------------------------------------------------
# A fake systemctl that knows is-enabled and list-units (the card unit is enabled when $SC/card exists) and the fake CLI above.
stbin=$work/status-bin
mkdir -p "$stbin"
cat >"$stbin/systemctl" <<'F'
#!/bin/bash
case "$1" in
is-enabled) [ -e "$SC/card" ] ;;
list-units) exit 0 ;;
*) exit 0 ;;
esac
F
chmod +x "$stbin/systemctl"
for t in awk sed cat tail grep uname dirname timeout sleep; do ln -sf "$(command -v "$t")" "$stbin/$t"; done
ln -sf "$sbin/sluis" "$stbin/sluis"
mkdir -p "$work/status-stage/files"
status_of() { # prints what remote.sh status printed, and "rc=N"
	local rc=0
	env -i PATH="$stbin" SC="$sc" lock_cli="${SETTLE_LOCK_CLI:-$stbin/sluis}" lock_node=board-a "$(command -v bash)" "$here/remote.sh" status "$work/status-stage" 2>&1 || rc=$?
	echo "rc=$rc"
}
settle_reset
touch "$sc/card"; lock locked
out=$(status_of)
sexpect "status: a locked card board says so, from the driver, and is not a failure" "$out" '^lock: the card driver is locked' "^${lock_prefix}locked$" '^rc=0$'
settle_reset
touch "$sc/card"; lock unlocked
out=$(status_of)
sexpect "status: an unlocked card board says so" "$out" '^lock: the card driver is unlocked' "^${lock_prefix}unlocked$"
settle_reset
touch "$sc/card"; lock broken
out=$(status_of)
sexpect "status: a card board whose driver cannot be asked is UNKNOWN, and status fails" "$out" '^lock: UNKNOWN' "^${lock_prefix}unknown$" '^rc=1$'
settle_reset
lock locked
out=$(status_of)
sexpect "status: a board without the card driver has no lock, and the CLI is not asked" "$out" '^lock: no card driver' "^${lock_prefix}none$" '^rc=0$'
[ ! -e "$sc/cli.calls" ] && echo "ok   status: the CLI is not run on a board without the card driver" || { echo "FAIL the CLI was run on a software board"; fail=1; }

# --- remote.sh firewall-*: the rqlite firewall on a board, against a fake nft, systemctl, systemd-run and ip -------------------------
# The fakes keep a board's state in files: what nft has loaded (a copy of the last file it was given), whether the unit is enabled and
# active, and whether the dead-man timer is armed (with the command it was given). Every call that changes the board is logged in order
# (FW_LOG), so the test can say what came first. The timer is "fired" by running the command it was given, with the same fakes.
fw=$work/fw
fwbin=$fw/bin
fwst=$fw/state
fwlog=$fw/log
mkdir -p "$fwbin" "$fwst" "$fw/root/etc/sluis" "$fw/root/etc/systemd/system" "$fw/stage/firewall"
for t in bash dirname uname cmp sed head tr paste sort cat grep mktemp chmod rm mv cp mkdir touch date; do ln -sf "$(command -v "$t")" "$fwbin/$t"; done
mkdir -p "$fw/root/run"
cat >"$fwbin/nft" <<'F'
#!/bin/bash
echo "nft $*" >>"$FW_LOG"
case "$1 $2 $3" in
"-c -f "*) [ -z "${FW_NFT_BAD:-}" ] || { echo "Error: syntax error, unexpected junk" >&2; exit 1; }; grep -q '^table inet sluis_rqlite {' "$3" ;;
"-f "*) [ -z "${FW_NFT_LOAD_FAIL:-}" ] || { echo "Error: Operation not permitted" >&2; exit 1; }
	cp "$2" "$FW_STATE/loaded"
	# FW_NFT_LOAD_MANGLE: a table that is not the one in the file (the drop rule is missing), as a bug or a race would leave it
	[ -z "${FW_NFT_LOAD_MANGLE:-}" ] || sed -i '/counter drop/d' "$FW_STATE/loaded" ;;
"list table inet") [ -e "$FW_STATE/loaded" ] && sed 's/counter drop/counter packets 7 bytes 420 drop/' "$FW_STATE/loaded" ;;
"list set inet") [ -e "$FW_STATE/loaded" ] && cat "$FW_STATE/loaded" ;;
"list chain inet") [ -e "$FW_STATE/loaded" ] && echo "		tcp dport { 4001, 4002 } counter packets 7 bytes 420 drop" ;;
"delete table inet") [ -e "$FW_STATE/loaded" ] && rm -f "$FW_STATE/loaded" ;;
*) echo "fake nft: unexpected: $*" >&2; exit 2 ;;
esac
F
cat >"$fwbin/systemctl" <<'F'
#!/bin/bash
echo "systemctl $*" >>"$FW_LOG"
u=sluis-rqlite-firewall.service
args=()
for a in "$@"; do case "$a" in --quiet | --now | --no-pager) ;; *) args+=("$a") ;; esac; done
set -- "${args[@]}"
case "$1 $2" in
"is-enabled $u") [ -e "$FW_STATE/enabled" ] ;;
"is-active $u") [ -e "$FW_STATE/active" ] ;;
"is-active sluis-rqlite-firewall-revert.timer") [ -e "$FW_STATE/timer" ] ;;
"enable $u") [ -z "${FW_ENABLE_FAIL:-}" ] && touch "$FW_STATE/enabled" ;;
"disable $u") rm -f "$FW_STATE/enabled" "$FW_STATE/active" "$FW_STATE/loaded" ;;
"start $u" | "reload $u") [ -z "${FW_START_FAIL:-}" ] || exit 1; touch "$FW_STATE/active"; cp "$FW_RULES" "$FW_STATE/loaded" ;;
"stop sluis-rqlite-firewall-revert.timer") rm -f "$FW_STATE/timer" ;;
"stop $u") rm -f "$FW_STATE/active" "$FW_STATE/loaded" ;;
"cat $u") [ -e "$FW_UNIT_FILE" ] ;;
"show sluis-rqlite-firewall-revert.timer") echo "Sat 2026-11-07 12:05:00 UTC" ;;
"show $u") echo "${FW_ACTIVE_ENTER:-100}" ;;
"show rqlited.service") echo "${FW_RQLITED_EXIT:-200}" ;;
*) true ;;
esac
F
cat >"$fwbin/systemd-run" <<'F'
#!/bin/bash
echo "systemd-run $*" >>"$FW_LOG"
[ -z "${FW_ARM_FAIL:-}" ] || exit 1
for a in "$@"; do last=$a; done
printf '%s\n' "$last" >"$FW_STATE/revert.sh"
printf '%s\n' "$@" >"$FW_STATE/revert.args"
# FW_ARM_LIE: systemd-run says yes and leaves no timer
[ -n "${FW_ARM_LIE:-}" ] || touch "$FW_STATE/timer"
F
printf '#!/bin/bash\necho "unit failed: nft said no"\n' >"$fwbin/journalctl"
cat >"$fwbin/ip" <<'F'
#!/bin/bash
case "$*" in
"-o -4 addr show") printf '1: lo    inet 127.0.0.1/8 scope host lo\n2: eth0    inet 192.0.2.12/24 brd 192.0.2.255 scope global eth0\n' ;;
"-o -4 route get "*) printf '%s via 192.0.2.1 dev eth0 src %s uid 0\n' "$4" "${FW_SRC:-192.0.2.12}" ;;
esac
F
cat >"$fwbin/install" <<F
#!/bin/bash
args=()
while [ \$# -gt 0 ]; do case "\$1" in -o | -g) shift 2 ;; *) args+=("\$1"); shift ;; esac; done
exec $(command -v install) "\${args[@]}"
F
chmod +x "$fwbin"/nft "$fwbin"/systemctl "$fwbin"/systemd-run "$fwbin"/journalctl "$fwbin"/ip "$fwbin"/install
fwroot=$fw/root
fw_gen() { # what firewall-lib.sh prints: ruleset|unit, then the arguments of the function
	local what=$1
	shift
	(
		# shellcheck source=/dev/null
		. "$here/remote-lib.sh"
		# shellcheck source=/dev/null
		. "$here/firewall-lib.sh"
		"firewall_$what" "$@"
	)
}
fw_stage() { # admin: the stage that firewall.sh sends, for the three boards and this administration host (none: empty)
	fw_gen ruleset 4001 4002 "$1" 192.0.2.11 192.0.2.12 192.0.2.13 >"$fw/stage/firewall/rqlite-firewall.nft"
	fw_gen unit 4001 4002 >"$fw/stage/firewall/sluis-rqlite-firewall.service"
}
fwx() { # mode [VAR=value]...: remote.sh as the board runs it, with the paths moved into the work directory
	local mode=$1
	shift
	env -i PATH="$fwbin" HOME="$fw" firewall_nft="$fwbin/nft" firewall_bash="$fwbin/bash" firewall_dir="$fwroot/etc/sluis" \
		firewall_unit_dir="$fwroot/etc/systemd/system" firewall_run_dir="$fwroot/run" selinux_enforce_file="$work/enforce" os_release_file="$work/os-release" \
		FW_STATE="$fwst" FW_LOG="$fwlog" FW_RULES="$fwroot/etc/sluis/rqlite-firewall.nft" FW_UNIT_FILE="$fwroot/etc/systemd/system/sluis-rqlite-firewall.service" \
		FW_SELF=192.0.2.12 FW_PEERS="192.0.2.11 192.0.2.12 192.0.2.13" FW_ADMIN=203.0.113.5 FW_SECONDS=300 FW_SSH_CLIENT=203.0.113.5 FW_SSH_PORT=22 FW_HTTP=4001 FW_RAFT=4002 \
		"$@" "$fwbin/bash" "$here/remote.sh" "$mode" "$fw/stage"
}
fwreset() { rm -rf "$fwst" "$fwroot/etc/sluis" "$fwroot/etc/systemd/system" "$fwroot/run"; mkdir -p "$fwst" "$fwroot/etc/sluis" "$fwroot/etc/systemd/system" "$fwroot/run"; : >"$fwlog"; }
fw_fire() { # [VAR=value]...: the dead-man timer runs: the command it was given, with the same fakes, and then it is gone
	env -i PATH="$fwbin" "$@" FW_STATE="$fwst" FW_LOG="$fwlog" FW_UNIT_FILE="$fwroot/etc/systemd/system/sluis-rqlite-firewall.service" FW_RULES="$fwroot/etc/sluis/rqlite-firewall.nft" \
		"$fwbin/bash" -c "$(cat "$fwst/revert.sh")" >"$work/fire.out" 2>&1
	rm -f "$fwst/timer"
}
fw_state_of() { { fwx firewall-status 2>&1 || true; } | sed -n 's/^SLUIS-FIREWALL: //p'; }
fw_none() { # the check that a refused apply changed nothing
	[ ! -e "$fwst/loaded" ] && [ ! -e "$fwst/timer" ] && [ ! -e "$fwroot/etc/sluis/rqlite-firewall.nft.pending" ] && ! grep -q '^nft -f' "$fwlog"
}
selinux off
osrel ubuntu debian

# A first apply: the timer is armed BEFORE the rules are loaded, the rules are loaded and not kept.
fwreset
fw_stage 203.0.113.5
if fwx firewall-apply >"$work/out" 2>&1; then echo "ok   firewall-apply: a first apply succeeds"; else echo "FAIL firewall-apply: $(cat "$work/out")"; fail=1; fi
[ -e "$fwst/loaded" ] && cmp -s "$fwst/loaded" "$fw/stage/firewall/rqlite-firewall.nft" && echo "ok   firewall-apply: the rules are loaded as they were sent" || { echo "FAIL firewall-apply: nothing loaded"; fail=1; }
[ -e "$fwst/timer" ] && echo "ok   firewall-apply: the dead-man timer is armed" || { echo "FAIL firewall-apply: no timer"; fail=1; }
arm_line=$(grep -n '^systemd-run' "$fwlog" | head -n 1 | cut -d: -f1)
load_line=$(grep -n '^nft -f' "$fwlog" | head -n 1 | cut -d: -f1)
if [ -n "$arm_line" ] && [ -n "$load_line" ] && [ "$arm_line" -lt "$load_line" ]; then echo "ok   firewall-apply: the timer is armed before the rules are loaded, so no moment has rules without a timer"; else echo "FAIL firewall-apply: order: $(cat "$fwlog")"; fail=1; fi
grep -qx -- '--on-active=300s' "$fwst/revert.args" && echo "ok   firewall-apply: the timer waits the seconds it was given" || { echo "FAIL firewall-apply: $(cat "$fwst/revert.args")"; fail=1; }
[ ! -e "$fwroot/etc/sluis/rqlite-firewall.nft" ] && [ -e "$fwroot/etc/sluis/rqlite-firewall.nft.pending" ] && echo "ok   firewall-apply: the rules are pending, not kept: no file the unit loads at boot" || { echo "FAIL firewall-apply: a file the unit loads exists"; fail=1; }
[ -e "$fwroot/etc/systemd/system/sluis-rqlite-firewall.service" ] && [ ! -e "$fwst/enabled" ] && echo "ok   firewall-apply: the unit is written and not enabled, so unconfirmed rules do not survive a reboot" || { echo "FAIL firewall-apply: unit/enable"; fail=1; }
grep -q 'NOT KEPT YET' "$work/out" && grep -q 'within 300 s' "$work/out" && echo "ok   firewall-apply: it says that nothing is kept and for how long" || { echo "FAIL firewall-apply: message: $(cat "$work/out")"; fail=1; }
is "firewall-status: an applied change is unconfirmed" unconfirmed fw_state_of
if fwx firewall-status >"$work/out" 2>&1; then echo "FAIL firewall-status: unconfirmed exited 0"; fail=1; else grep -q 'Raft port admits 192.0.2.11 192.0.2.12 192.0.2.13 203.0.113.5; client port admits 203.0.113.5; dropped 7 packets' "$work/out" && grep -qx 'SLUIS-FIREWALL-RAFT: 192.0.2.11 192.0.2.12 192.0.2.13 203.0.113.5' "$work/out" && grep -qx 'SLUIS-FIREWALL-HTTP: 203.0.113.5' "$work/out" && grep -qx 'SLUIS-FIREWALL-DROPS: 7' "$work/out" && grep -q 'takes the change back in [0-9]* s' "$work/out" && echo "ok   firewall-status: unconfirmed fails, and shows what is admitted and the drops" || { echo "FAIL firewall-status: $(cat "$work/out")"; fail=1; }; fi
# The timer fires on an apply that was never confirmed: no rules, no pending file.
fw_fire
[ ! -e "$fwst/loaded" ] && [ ! -e "$fwroot/etc/sluis/rqlite-firewall.nft.pending" ] && grep -q 'not confirmed in time' "$work/fire.out" && echo "ok   the dead-man timer removes the rules of a first apply that nobody confirmed, and says so" || { echo "FAIL timer: $(cat "$work/fire.out")"; fail=1; }
is "firewall-status: after the timer, absent" absent fw_state_of

# Apply, confirm, and the same apply again.
fwreset
fwx firewall-apply >/dev/null 2>&1
if fwx firewall-confirm >"$work/out" 2>&1; then echo "ok   firewall-confirm: keeps the loaded rules"; else echo "FAIL firewall-confirm: $(cat "$work/out")"; fail=1; fi
cmp -s "$fwroot/etc/sluis/rqlite-firewall.nft" "$fw/stage/firewall/rqlite-firewall.nft" && [ ! -e "$fwroot/etc/sluis/rqlite-firewall.nft.pending" ] && [ -e "$fwst/enabled" ] && [ ! -e "$fwst/timer" ] && echo "ok   firewall-confirm: the file the unit loads at boot is the confirmed rules, the unit is enabled, the timer is stopped" || { echo "FAIL confirm: files"; fail=1; }
grep -q '^systemctl start sluis-rqlite-firewall.service' "$fwlog" && echo "ok   firewall-confirm: the rules went through the unit (the path of a boot) before they were kept" || { echo "FAIL confirm: the unit was not started: $(cat "$fwlog")"; fail=1; }
is "firewall-status: confirmed is ok" ok fw_state_of
fwx firewall-status >/dev/null 2>&1 && echo "ok   firewall-status: ok exits 0" || { echo "FAIL firewall-status: ok exited non-zero"; fail=1; }
: >"$fwlog"
if fwx firewall-apply >"$work/out" 2>&1 && grep -q 'unchanged' "$work/out" && ! grep -q '^systemd-run\|^nft -f' "$fwlog"; then echo "ok   firewall-apply: the same rules again change nothing (no timer, no load)"; else echo "FAIL idempotence: $(cat "$work/out") $(cat "$fwlog")"; fail=1; fi
fwx firewall-confirm 2>&1 | grep -q 'already confirmed' && echo "ok   firewall-confirm: a second confirm is a no-op" || { echo "FAIL second confirm"; fail=1; }

# A changed apply over kept rules: the timer takes it back to the kept rules, not to nothing.
cp "$fw/stage/firewall/rqlite-firewall.nft" "$work/kept.nft"
fw_stage ""
fwx firewall-apply FW_ADMIN= >"$work/out" 2>&1 || { echo "FAIL changed apply: $(cat "$work/out")"; fail=1; }
grep -q 'no administration host is set' "$work/out" && echo "ok   firewall-apply: with no administration host it says plainly that the administration host gets no access" || { echo "FAIL no-admin message"; fail=1; }
grep -q '203.0.113.5' "$fwst/loaded" && { echo "FAIL the administration host is in rules that name none"; fail=1; } || echo "ok   firewall-apply: and the rules loaded do not have it"
is "firewall-status: kept rules plus an unconfirmed change is unconfirmed" unconfirmed fw_state_of
fw_fire
cmp -s "$fwst/loaded" "$work/kept.nft" && [ -e "$fwst/enabled" ] && echo "ok   the dead-man timer puts back the last confirmed rules over an unconfirmed change" || { echo "FAIL timer over kept rules: $(cat "$work/fire.out")"; fail=1; }
is "firewall-status: and the board is ok again" ok fw_state_of

# What a refused apply leaves: nothing.
fwreset
fw_stage 203.0.113.5
refuse "firewall-apply: a board without nft is refused, with the fix" 'install nftables' fwx firewall-apply firewall_nft="$fwbin/no-such-nft"
fw_none && echo "ok   firewall-apply: and nothing changed" || { echo "FAIL traces after no-nft: $(cat "$fwlog")"; fail=1; }
refuse "firewall-apply: rules that nft -c refuses are refused before anything is loaded" 'nft refuses the rules' fwx firewall-apply FW_NFT_BAD=1
fw_none && echo "ok   firewall-apply: and nothing changed" || { echo "FAIL traces after nft -c: $(cat "$fwlog")"; fail=1; }
refuse "firewall-apply: a board that would send to a peer from an address the rules do not admit is refused, naming it" 'sends from 192.0.2.99' fwx firewall-apply FW_SRC=192.0.2.99
fw_none && echo "ok   firewall-apply: and nothing changed" || { echo "FAIL traces after route: $(cat "$fwlog")"; fail=1; }
fw_gen ruleset 4001 4002 "" 192.0.2.11 192.0.2.13 >"$fw/stage/firewall/rqlite-firewall.nft"
refuse "firewall-apply: rules that do not admit the board itself are refused" 'do not admit this board' fwx firewall-apply
fw_stage 203.0.113.5
refuse "firewall-apply: an address the board does not own is refused" 'this board has no address 192.0.2.13' fwx firewall-apply FW_SELF=192.0.2.13
fw_none && echo "ok   firewall-apply: and nothing changed" || { echo "FAIL traces: $(cat "$fwlog")"; fail=1; }
refuse "firewall-apply: a systemd-run that says yes and leaves no timer is not a timer: no rules are loaded" 'rules were not loaded' fwx firewall-apply FW_ARM_LIE=1
fw_none && echo "ok   firewall-apply: and nothing is left" || { echo "FAIL traces after a timer that was not there: $(cat "$fwlog")"; fail=1; }
refuse "firewall-apply: a timer that cannot be armed means no rules are loaded" 'rules were not loaded' fwx firewall-apply FW_ARM_FAIL=1
fw_none && echo "ok   firewall-apply: and nothing is left" || { echo "FAIL traces after arm failure: $(cat "$fwlog")"; fail=1; }
refuse "firewall-apply: rules that nft cannot load put the board back as it was" 'could not load the rules' fwx firewall-apply FW_NFT_LOAD_FAIL=1
[ ! -e "$fwst/loaded" ] && [ ! -e "$fwst/timer" ] && echo "ok   firewall-apply: and no timer is left running" || { echo "FAIL traces after load failure"; fail=1; }
if fwx firewall-apply FW_SSH_CLIENT=198.51.100.7 >"$work/out" 2>&1 && grep -q 'warning: this ssh session comes from 198.51.100.7, not from the administration host' "$work/out"; then echo "ok   firewall-apply: an ssh session from another address than the administration host is warned about, not refused"; else echo "FAIL ssh client warning: $(cat "$work/out")"; fail=1; fi

# Confirm: refused when there is nothing to keep, when the rules are gone, and when the unit cannot load them.
fwreset
refuse "firewall-confirm: nothing pending is refused" 'nothing to confirm' fwx firewall-confirm
fwx firewall-apply >/dev/null 2>&1
rm -f "$fwst/loaded"
refuse "firewall-confirm: rules that the timer already took are refused" 'run boards-firewall again' fwx firewall-confirm
[ ! -e "$fwst/enabled" ] && [ ! -e "$fwroot/etc/sluis/rqlite-firewall.nft" ] && echo "ok   firewall-confirm: and nothing was kept" || { echo "FAIL confirm kept something"; fail=1; }
fwreset
fwx firewall-apply >/dev/null 2>&1
refuse "firewall-confirm: a unit that cannot load the rules keeps nothing and says where to look" 'boards-avc' fwx firewall-confirm FW_START_FAIL=1
[ ! -e "$fwst/enabled" ] && [ ! -e "$fwroot/etc/sluis/rqlite-firewall.nft" ] && [ -e "$fwst/timer" ] && echo "ok   firewall-confirm: the rules file is not kept, the unit is not enabled and the timer is still armed" || { echo "FAIL failed unit: files"; fail=1; }

# Remove, twice.
fwreset
fwx firewall-apply >/dev/null 2>&1
fwx firewall-confirm >/dev/null 2>&1
if fwx firewall-remove >"$work/out" 2>&1; then echo "ok   firewall-remove succeeds"; else echo "FAIL remove: $(cat "$work/out")"; fail=1; fi
[ ! -e "$fwst/loaded" ] && [ ! -e "$fwst/enabled" ] && [ ! -e "$fwst/timer" ] && [ ! -e "$fwroot/etc/sluis/rqlite-firewall.nft" ] && [ ! -e "$fwroot/etc/systemd/system/sluis-rqlite-firewall.service" ] && echo "ok   firewall-remove: no rules, no unit, no timer, no file" || { echo "FAIL remove left something"; fail=1; }
fwx firewall-remove >/dev/null 2>&1 && echo "ok   firewall-remove: a second remove, on a board with none, succeeds" || { echo "FAIL second remove"; fail=1; }
is "firewall-status: after the remove, absent" absent fw_state_of

# Status: rules lost after a boot (the unit is enabled, the table is gone) are broken, not absent.
fwreset
fwx firewall-apply >/dev/null 2>&1
fwx firewall-confirm >/dev/null 2>&1
rm -f "$fwst/loaded"
is "firewall-status: kept and enabled but not loaded (a flush of the ruleset) is broken" broken fw_state_of

# The table, not only its set: a deleted drop rule, a flushed chain, a changed priority, another hook or another address are not "kept".
# Each is made on a board whose rules are confirmed; status must not say ok, and an apply of the same rules must not call them unchanged.
fw_confirmed() { fwreset; fw_stage 203.0.113.5; fwx firewall-apply >/dev/null 2>&1; fwx firewall-confirm >/dev/null 2>&1; }
for m in "the drop rule is deleted|/counter drop/d" "the log rule and the drop rule are deleted|/limit rate/d;/counter drop/d" "the priority is changed|s/priority -10/priority 10/" "the chain is on another hook|s/hook input/hook forward/" "the chain is flushed|/iifname/d;/tcp dport/d" "an address of the Raft set is changed|s/192.0.2.13, 203/192.0.2.99, 203/" "the loopback accept is deleted|/iifname/d"; do
	fw_confirmed
	is "firewall-status: before: ok" ok fw_state_of
	sed -i "${m#*|}" "$fwst/loaded"
	st=$(fw_state_of)
	if [ "$st" != ok ] && [ -n "$st" ]; then echo "ok   firewall-status: ${m%%|*}: the board is $st, not ok"; else echo "FAIL firewall-status: ${m%%|*}: the board still says '$st'"; fail=1; fi
	: >"$fwlog"
	fwx firewall-apply >"$work/out" 2>&1 || true
	if ! grep -q 'unchanged' "$work/out" && grep -q '^nft -f' "$fwlog"; then echo "ok   firewall-apply: ${m%%|*}: the same rules are not called unchanged, and are loaded again"; else echo "FAIL firewall-apply: ${m%%|*}: unchanged shortcut: $(cat "$work/out")"; fail=1; fi
done
# A table that is loaded and is not the one in the file is caught when it is loaded, not only later.
fwreset
fw_stage 203.0.113.5
refuse "firewall-apply: a loaded table that lacks the drop rule is taken back at once" 'not the one in the file' fwx firewall-apply FW_NFT_LOAD_MANGLE=1
[ ! -e "$fwst/loaded" ] && [ ! -e "$fwst/timer" ] && echo "ok   firewall-apply: and the board is as it was" || { echo "FAIL a mangled table was left"; fail=1; }

# The timer over a confirmed file that will not load: no rules, not the unconfirmed ones.
fw_confirmed
fw_stage ""
fwx firewall-apply FW_ADMIN= >/dev/null 2>&1
fw_fire FW_NFT_LOAD_FAIL=1
[ ! -e "$fwst/loaded" ] && echo "ok   the dead-man timer, over kept rules that nft cannot load, removes the table (fail open) and does not leave the unconfirmed one" || { echo "FAIL timer fallback: $(cat "$work/fire.out")"; fail=1; }

# A confirm whose enable fails puts the files back and leaves the timer: on a board with no kept rules, and on one with kept rules.
fwreset
fw_stage 203.0.113.5
fwx firewall-apply >/dev/null 2>&1
refuse "firewall-confirm: an enable that fails after the unit started is refused, with the way it stands" 'cannot enable' fwx firewall-confirm FW_ENABLE_FAIL=1
if [ ! -e "$fwroot/etc/sluis/rqlite-firewall.nft" ] && [ -e "$fwroot/etc/sluis/rqlite-firewall.nft.pending" ] && [ ! -e "$fwst/enabled" ] && [ ! -e "$fwst/active" ] && [ -e "$fwst/timer" ] && [ -e "$fwst/loaded" ]; then echo "ok   firewall-confirm: and the files are as before, the unit is stopped, the pending rules are still loaded and the timer is armed"; else echo "FAIL enable failure: $(find "$fwroot/etc/sluis" "$fwst" -type f | tr '\n' ' ')"; fail=1; fi
is "firewall-status: and the board is unconfirmed" unconfirmed fw_state_of
fwx firewall-confirm >/dev/null 2>&1 && echo "ok   firewall-confirm: and a confirm that works afterwards keeps the rules" || { echo "FAIL confirm after a rollback"; fail=1; }
cp "$fw/stage/firewall/rqlite-firewall.nft" "$work/kept.nft"
fw_stage ""
fwx firewall-apply FW_ADMIN= >/dev/null 2>&1
fwx firewall-confirm FW_ENABLE_FAIL=1 >/dev/null 2>&1 || true
cmp -s "$fwroot/etc/sluis/rqlite-firewall.nft" "$work/kept.nft" && [ -e "$fwroot/etc/sluis/rqlite-firewall.nft.pending" ] && [ -e "$fwst/timer" ] && echo "ok   firewall-confirm: over kept rules an enable that fails puts the kept rules back and keeps the change pending, timer armed" || { echo "FAIL enable failure over kept rules"; fail=1; }

# A pending file that a reboot or the timer left behind is said to be that, and is not BROKEN.
fw_confirmed
fw_stage ""
fwx firewall-apply FW_ADMIN= >/dev/null 2>&1
rm -f "$fwst/timer" "$fwroot/run/"*deadline # a reboot: the timer and its deadline are gone, the pending file stays, the unit loaded the kept rules
cp "$work/kept.nft" "$fwst/loaded"
if fwx firewall-status >"$work/out" 2>&1 && grep -q 'an unconfirmed change was cut short' "$work/out" && grep -qx 'SLUIS-FIREWALL: ok' "$work/out"; then echo "ok   firewall-status: kept rules and a stale pending file are ok, with a note that says what the file is"; else echo "FAIL stale pending over kept rules: $(cat "$work/out")"; fail=1; fi
fwreset
fw_stage 203.0.113.5
fwx firewall-apply >/dev/null 2>&1
rm -f "$fwst/timer" "$fwst/loaded" "$fwroot/run/"*deadline # a reboot before any confirm: nothing is loaded
fwx firewall-status >"$work/out" 2>&1 || true
if grep -qx 'SLUIS-FIREWALL: absent' "$work/out" && grep -q 'an unconfirmed change was cut short' "$work/out"; then echo "ok   firewall-status: with no kept rules a stale pending file is absent, with the note, and not broken"; else echo "FAIL stale pending: $(cat "$work/out")"; fail=1; fi

# A port that is the port of ssh is refused before anything changes.
fwreset
fw_stage 203.0.113.5
refuse "firewall-apply: an rqlite port of 22 is refused" 'port of ssh' fwx firewall-apply FW_HTTP=22
refuse "firewall-apply: an rqlite port that is the port of this ssh session is refused" 'port of ssh' fwx firewall-apply FW_SSH_PORT=4002
fw_none && echo "ok   firewall-apply: and nothing changed" || { echo "FAIL traces after the ssh port: $(cat "$fwlog")"; fail=1; }

# The order at boot.
if fwx firewall-boot-order FW_ACTIVE_ENTER=100 FW_RQLITED_EXIT=200 >"$work/out" 2>&1 && grep -q 'rules came first' "$work/out"; then echo "ok   firewall-boot-order: a unit that was active before rqlited began is ok"; else echo "FAIL boot order: $(cat "$work/out")"; fail=1; fi
if fwx firewall-boot-order FW_ACTIVE_ENTER=300 FW_RQLITED_EXIT=200 >"$work/out" 2>&1; then echo "FAIL boot order: a late unit was ok"; fail=1; else grep -q 'AFTER rqlited' "$work/out" && echo "ok   firewall-boot-order: a unit that was active after rqlited began is wrong" || { echo "FAIL boot order message"; fail=1; }; fi
# --- the move of the executables from /opt/sluis/bin to /usr/libexec/sluis ----------------------------------------------------------
# A board deployed before the layout of the packages has its executables, and its manifest lists them, below the legacy directory.
# The deploy takes them away, with the directories it made if they are empty, and the lines of the manifest, and nothing else.
lg=$work/legacy
mkdir -p "$lg/opt/sluis/bin/actors" "$lg/opt/sluis/bin/drivers/key" "$lg/opt/sluis/bin/cli" "$lg/usr/libexec/sluis/actors"
: >"$lg/opt/sluis/bin/actors/key"
: >"$lg/opt/sluis/bin/drivers/key/software"
: >"$lg/opt/sluis/bin/cli/sluis"
: >"$lg/opt/sluis/bin/actors/kept-by-hand-not-listed"
: >"$lg/usr/libexec/sluis/actors/key"
: >"$lg/etc-other"
{
	for f in actors/key drivers/key/software cli/sluis; do printf 'file\t%s\n' "$lg/opt/sluis/bin/$f"; done
	for d in actors drivers/key drivers cli; do printf 'dir\t%s\n' "$lg/opt/sluis/bin/$d"; done
	printf 'file\t%s\nfile\t%s\nunit\tsluis-key@dev.service\n' "$lg/usr/libexec/sluis/actors/key" "$lg/etc-other"
} >"$lg/manifest"
retire() { # prints the result of the move in the work directory
	(
		export PATH="$work/bin:$PATH" manifest="$lg/manifest" legacy_bin_dir="$lg/opt/sluis/bin" bin_dir="$lg/usr/libexec/sluis"
		# shellcheck source=/dev/null
		. "$here/remote-lib.sh"
		retire_legacy_bin_dir
	)
}
accept "legacy: the move succeeds" retire
[ ! -e "$lg/opt/sluis/bin/actors/key" ] && [ ! -e "$lg/opt/sluis/bin/drivers/key/software" ] && [ ! -e "$lg/opt/sluis/bin/cli/sluis" ] && echo "ok   legacy: the listed executables are gone" || { echo "FAIL legacy: a listed executable stayed"; fail=1; }
[ -e "$lg/opt/sluis/bin/actors/kept-by-hand-not-listed" ] && echo "ok   legacy: a file the manifest does not list stays, and so does the directory that holds it" || { echo "FAIL legacy: an unlisted file went"; fail=1; }
[ ! -d "$lg/opt/sluis/bin/drivers" ] && [ ! -d "$lg/opt/sluis/bin/cli" ] && echo "ok   legacy: the empty directories it made are gone" || { echo "FAIL legacy: an empty directory stayed"; fail=1; }
[ -e "$lg/usr/libexec/sluis/actors/key" ] && echo "ok   legacy: the new tree is not touched" || { echo "FAIL legacy: the new tree was touched"; fail=1; }
if ! grep -q 'opt/sluis' "$lg/manifest" && grep -q "$lg/usr/libexec/sluis/actors/key" "$lg/manifest" && grep -q etc-other "$lg/manifest" && grep -q 'unit.sluis-key@dev.service' "$lg/manifest"; then echo "ok   legacy: the manifest lost the old lines and kept the others"; else echo "FAIL legacy: the manifest still lists the old tree, or lost a line that is not about it"; fail=1; fi
printf 'file\t%s\n' "$lg/opt/sluis/bin/actors/../../../../etc-other" >"$lg/manifest"
refuse "legacy: a name with .. in it is refused" 'refusing' retire
[ -e "$lg/etc-other" ] && echo "ok   legacy: and nothing outside the old tree went" || { echo "FAIL legacy: a file outside the old tree went"; fail=1; }
rm -f "$lg/manifest"
accept "legacy: a board with no manifest has nothing to move" retire
exit "$fail"
