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
exit "$fail"
