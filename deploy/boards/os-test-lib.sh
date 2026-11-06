#!/usr/bin/env bash
# shellcheck disable=SC2016 # the command lines run on the system under test
# shellcheck disable=SC2154 # the callers define work, ct (or target), fam, x, ok and bad
# The steps that os-container-test.sh and os-vm-test.sh share: a repository with stand-in executables, a seed, the deploy of the
# card variant through a stand-in for ssh, and the checks of its result. Sourced, never run. The caller defines:
#   fam        deb or rpm
#   work       a scratch directory (the caller removes it)
#   x CMD      runs a command line as root on the system under test
#   ok, bad    report a passed and a failed check (bad sets fail=1)
#   os_ssh_stub DIR   writes an executable `ssh` into DIR that runs the board's command on the system under test
#   os_env     exports what the stand-in for ssh needs (called inside the deploy subshell)

# The packages of the card path and the stand-in for sudo (the system under test is reached as root, or as a user with sudo).
os_card_packages() {
	case "$fam" in
	deb) echo 'DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends pcscd libccid polkitd >/dev/null' ;;
	rpm) echo 'dnf -y -q install pcsc-lite pcsc-lite-ccid polkit >/dev/null' ;;
	esac
}

# os_credentials_work: whether this system sets up a credentials directory for a unit at all, tried with a plain LoadCredential=.
# (Rocky 10's systemd in a Docker container does not on the hosts tried.)
os_credentials_work() {
	local r=1
	x 'echo probe >/etc/sluis-probe-credential'
	if x "systemd-run --wait --pipe --quiet -p LoadCredential=probe:/etc/sluis-probe-credential -- /bin/sh -c 'cat \"\$CREDENTIALS_DIRECTORY/probe\"'" 2>/dev/null | grep -qx probe; then r=0; fi
	x 'rm -f /etc/sluis-probe-credential'
	return "$r"
}

# os_prepare_repo: the repository the scripts run in (the dist they stage is this test's), the stand-in executables of the
# three units of the card variant, and a seed of one document whose protected header names a kind, a bootstrap file and three
# credentials. The stand-in of a unit says what it received through LoadCredentialEncrypted=; the stand-in of the card driver
# also asks pcscd for a context under its own uid, with the groups and the sandbox of its unit, and says the answer.
os_prepare_repo() {
	local b c hdr
	mkdir -p "$work/bin" "$work/repo/deploy" "$work/repo/dist/arm64" "$work/seed/config" "$work/seed/credentials/sluis-drv-store-credential" "$work/state"
	cp -r "$root/deploy/boards" "$work/repo/deploy/boards"
	git -C "$work/repo" init -q
	for b in drivers/store/credential drivers/key/yubikey-piv actors/key; do
		mkdir -p "$work/repo/dist/arm64/$(dirname "$b")"
		{
			printf '#!/bin/sh\n'
			printf 'for c in "$CREDENTIALS_DIRECTORY"/*; do [ -f "$c" ] && echo "credential $(basename "$c")=$(cat "$c")"; done\n'
			if [ "$b" = drivers/key/yubikey-piv ]; then
				printf '%s\n' "python3 -I -c 'import ctypes;l=ctypes.CDLL(\"libpcsclite.so.1\");l.SCardEstablishContext.restype=ctypes.c_long;c=ctypes.c_long(0);r=l.SCardEstablishContext(ctypes.c_uint32(2),None,None,ctypes.byref(c));print(\"unit SCardEstablishContext: 0x%08x\"%(r&0xFFFFFFFF))' 2>&1"
			fi
			printf 'exec sleep 100000\n'
		} >"$work/repo/dist/arm64/$b"
		chmod 0755 "$work/repo/dist/arm64/$b"
	done
	# The CLI of the board, which the deploy asks for the lock of the card (sluis node status). The stand-in of the card driver holds
	# no PIN and has no admin socket, so this one says what a board with a card that is unlocked says: no card is read here, and what
	# the real CLI makes of the real driver is the Go test of cli/sluis. Without it the deploy cannot say "ok" and ends "failed".
	mkdir -p "$work/repo/dist/arm64/cli"
	printf '#!/bin/sh\n[ "$1 $2" = "node status" ] && echo "node $3 is unlocked"\n' >"$work/repo/dist/arm64/cli/sluis"
	chmod 0755 "$work/repo/dist/arm64/cli/sluis"
	# The real credential driver, where the system sets up credentials for a unit at all: the stand-in only cats the files, which any
	# directory lets through, so it cannot see how systemd hands the directory over (root:root with a POSIX ACL where the filesystem
	# has ACLs, the service user's own where it has not). OS_CREDENTIAL_DRIVER is a static build for this machine's architecture.
	OS_REAL_DRIVER=0
	if [ -n "${OS_CREDENTIAL_DRIVER:-}" ]; then
		if os_credentials_work; then
			install -m 0755 "$OS_CREDENTIAL_DRIVER" "$work/repo/dist/arm64/drivers/store/credential"
			OS_REAL_DRIVER=1
		else
			echo "note the real credential driver is not run: this system does not set up credentials for any unit (${OS_CREDENTIALS_MISSING_REASON:-no reason given})"
		fi
	fi
	hdr=$(printf '{"alg":"ES384","kind":"config"}' | base64 -w0 | tr '+/' '-_' | tr -d =)
	printf '{"payload":"e30","signatures":[{"protected":"%s","signature":"AA"}]}\n' "$hdr" >"$work/seed/config/doc.jws"
	printf 'boundary: dev\n' >"$work/seed/bootstrap.yaml"
	for c in client-dev client-example-app upstream-workforce; do printf 'plain-%s-value' "$c" >"$work/seed/credentials/sluis-drv-store-credential/$c"; done
	os_ssh_stub "$work/bin"
}

# os_deploy runs the card variant of boards.sh deploy against the system under test; the output is in $work/deploy.log.
os_deploy() {
	(
		cd "$work/repo" || exit 1
		export PATH="$work/bin:$PATH" SLUIS_BOARDS=board.example.test SLUIS_BOARD_SSH_USER=nobody
		export SLUIS_BOARDS_KEY_DRIVER=yubikey-piv SLUIS_BOARD_CARD_SERIALS=board.example.test=1234567
		export SLUIS_BOARDS_ONLY="drivers/store/credential drivers/key/yubikey-piv actors/key" SLUIS_BOARDS_SEED="$work/seed" SLUIS_BOARDS_STATE="$work/state"
		os_env
		deploy/boards/boards.sh deploy
	) >"$work/deploy.log" 2>&1
}

# 1. No card packages: refused, with the names, and nothing written.
os_check_refusal() {
	local want
	if os_deploy; then bad "a deploy without the card packages succeeded"; else
		case "$fam" in deb) want='pcscd libccid' ;; rpm) want='pcsc-lite pcsc-lite-ccid' ;; esac
		if grep -q "the card driver needs, on this board ($fam family): .*$want" "$work/deploy.log"; then ok "a deploy without the card packages is refused, naming them"; else bad "the refusal does not name the packages"; sed 's/^/     /' "$work/deploy.log"; fi
	fi
	if x 'test ! -e /opt/sluis && test ! -e /etc/sluis'; then ok "and nothing was written before the refusal"; else bad "files were written before the refusal"; fi
}

# The real credential driver (OS_REAL_DRIVER=1) is the program of the unit sluis-drv-store-credential@dev, so the deploy above has
# already started it with the directory systemd made for it, under the unit's user and sandbox, and waited until it had not restarted for about 6 s. What
# is added here: how systemd made the directory on this system (said, so that the log of a job shows which case was run: the
# service user's own where the filesystem has no ACLs, root's with a POSIX ACL where it has: MEASURED on Ubuntu 26.04, systemd 259),
# that the driver did not refuse it, and `credential check` in a unit of its own with the same user and the same three encrypted
# credentials, which opens the directory by the rules of serve and reads every file in it by the rules of a Read: a file with the
# mode and the ACL that systemd gives it must pass the owner and mode rule too, and the driver prints no value.
os_check_real_credential_driver() {
	local c args="" out pid journal
	pid=$(x 'systemctl show -p MainPID --value sluis-drv-store-credential@dev.service')
	if [ -n "$pid" ] && [ "$pid" != 0 ]; then
		echo "     the credentials directory of the unit, as the unit sees it (nsenter into its mount namespace):"
		x "nsenter -t $pid -m -- sh -c 'ls -ld /run/credentials/sluis-drv-store-credential@dev.service; ls -l /run/credentials/sluis-drv-store-credential@dev.service/'" 2>&1 | sed 's/^/       /'
	fi
	# The journal is read whole into a variable first: under pipefail a grep -q that quits early would fail the pipeline.
	journal=$(x "journalctl -u sluis-drv-store-credential@dev.service -o cat --no-pager" || true)
	if grep -q 'credentials directory must be owned' <<<"$journal"; then
		bad "the credential driver refused the credentials directory systemd made for its unit"
		tail -n 5 <<<"$journal" | sed 's/^/     /'
	else ok "the real credential driver was not refused by the credentials directory of its unit"; fi
	for c in client-dev client-example-app upstream-workforce; do args="$args -p LoadCredentialEncrypted=$c:/etc/sluis/credentials/dev/sluis-drv-store-credential/$c"; done
	out=$(x "systemd-run --wait --pipe --quiet -p User=sluis-drv-store-credential-dev -p RestrictSUIDSGID=yes -p UMask=0077 $args -- /opt/sluis/bin/drivers/store/credential check" 2>&1) || true
	if grep -qx 'credentials directory ok: 3 credentials readable' <<<"$out"; then ok "credential check, in a unit with the same user and credentials, opens the directory and reads the three credentials"; else bad "credential check refused: $out"; fi
}

# 2. The deploy, the credentials and the reflash.
os_check_deploy() {
	local cred=/etc/sluis/credentials/dev/sluis-drv-store-credential/client-dev u
	if os_deploy; then ok "the card variant deploys: the units verify and start"; else bad "the deploy failed"; sed 's/^/     /' "$work/deploy.log" | tail -40; fi
	x 'systemctl list-units "sluis-*" --no-legend --plain' | sed 's/^/     /'
	if x "test \"\$(stat -c %a $cred)\" = 400 && ! grep -q plain- $cred && test -s $cred"; then ok "the credential is on the board encrypted, 0400"; else bad "the credential file is not an encrypted 0400 file"; fi
	if x "systemd-creds decrypt --name=client-dev $cred -" | grep -qx 'plain-client-dev-value'; then ok "it decrypts under the board's host key to what the seed held"; else bad "the credential does not decrypt"; fi
	# PID 1 loads the file the way systemd-creds decrypts it (above); the unit must receive it. A probe with a plain LoadCredential=
	# says whether this system sets up credentials at all. Where it does not, that is a failure, except where the caller has said
	# so with OS_CREDENTIALS_MAY_BE_MISSING=1 and the reason (Rocky 10's systemd in a Docker container: the virtual machine
	# test proves receipt on the real distribution).
	x 'echo probe >/etc/sluis-probe-credential'
	if x "systemd-run --wait --pipe --quiet -p LoadCredential=probe:/etc/sluis-probe-credential -- /bin/sh -c 'cat \"\$CREDENTIALS_DIRECTORY/probe\"'" 2>/dev/null | grep -qx probe; then
		if [ "$OS_REAL_DRIVER" = 1 ]; then
			os_check_real_credential_driver
		elif x "journalctl -u sluis-drv-store-credential@dev.service -o cat --no-pager" | grep -qx 'credential client-dev=plain-client-dev-value'; then ok "the unit received the credential through LoadCredentialEncrypted="; else bad "the unit did not receive the credential"; fi
	elif [ "${OS_CREDENTIALS_MAY_BE_MISSING:-0}" = 1 ]; then
		echo "note this system does not set up credentials for any unit (a plain LoadCredential= fails too): $OS_CREDENTIALS_MISSING_REASON"
	else
		bad "this system does not set up credentials for any unit (a plain LoadCredential= fails too), so no unit receives its credentials"
	fi
	x 'rm -f /etc/sluis-probe-credential'
	for u in sluis-drv-store-credential@dev sluis-drv-key-yubikey-piv@dev sluis-key@dev; do
		if [ "$(x "systemctl is-active $u.service" || true)" = active ]; then ok "$u is active"; else bad "$u is not active"; fi
	done
	# The card driver's unit asked pcscd for a context itself, under its uid, its groups and its sandbox.
	if x "journalctl -u sluis-drv-key-yubikey-piv@dev.service -o cat --no-pager" | grep -qx 'unit SCardEstablishContext: 0x00000000'; then ok "the card driver's unit reached pcscd from its own sandbox"; else bad "the card driver's unit did not reach pcscd"; x "journalctl -u sluis-drv-key-yubikey-piv@dev.service -o cat --no-pager | tail -5"; fi
	# A reflash makes a new host key: the old file no longer opens, and the next deploy encrypts it again.
	x 'rm -f /var/lib/systemd/credential.secret'
	if x "systemd-creds decrypt --name=client-dev $cred - >/dev/null 2>&1"; then bad "the credential still opens after the host key was replaced"; else ok "after a reflash (a new host key) the old file does not open"; fi
	if os_deploy; then ok "the next deploy goes through"; else bad "the deploy after the reflash failed"; sed 's/^/     /' "$work/deploy.log" | tail -20; fi
	if x "systemd-creds decrypt --name=client-dev $cred -" | grep -qx 'plain-client-dev-value'; then ok "and the credential opens again: it was encrypted again"; else bad "the credential does not open after the second deploy"; fi
}

# 3. The two locks against a real pcscd.
os_check_card_locks() {
	local policy=/usr/share/polkit-1/actions/org.debian.pcsc-lite.policy rules=/etc/polkit-1/rules.d/49-sluis-pcsc.rules
	local expect_user has_policy sock r who
	case "$fam" in deb) expect_user=pcscd ;; rpm) expect_user=root ;; esac
	x "test -e $policy" && has_policy=1 || has_policy=0
	echo "     pcscd's polkit policy file: $([ "$has_policy" = 1 ] && echo present || echo absent)"
	if [ "$has_policy" = 1 ]; then
		if x "test -s $rules"; then ok "the polkit rule is installed (pcscd ships its policy)"; else bad "the polkit rule is missing"; fi
	else
		if x "test ! -e $rules"; then ok "no polkit rule where pcscd has no policy"; else bad "a polkit rule was installed without a policy"; fi
	fi
	sock=$(x 'stat -c "%a %U %G" /run/pcscd/pcscd.comm')
	if [ "$sock" = "660 root sluis-pcsc-dev" ]; then ok "the card service's socket is 0660 root:sluis-pcsc-dev"; else bad "the socket is '$sock'"; fi
	x 'cat >/usr/local/lib/scard.py' <<'PY'
import ctypes, sys
lib = ctypes.CDLL("libpcsclite.so.1")
lib.SCardEstablishContext.restype = ctypes.c_long
ctx = ctypes.c_long(0)
r = lib.SCardEstablishContext(ctypes.c_uint32(2), None, None, ctypes.byref(ctx)) # SCARD_SCOPE_SYSTEM
print("SCardEstablishContext: 0x%08x" % (r & 0xFFFFFFFF))
sys.exit(0 if r == 0 else 1)
PY
	x 'useradd -r -M -s /usr/sbin/nologin sluis-peer; useradd -r -M -s /usr/sbin/nologin sluis-stranger' >/dev/null
	# reach user groups: the call, under that uid and exactly those supplementary groups ("-" for none). The card driver's unit
	# joins the socket's group with SupplementaryGroups=, so nobody is a member of it in /etc/group.
	reach() { x "setpriv --reuid=$1 --regid=$1 $([ "$2" = - ] && echo --clear-groups || echo "--groups=$2") python3 -I /usr/local/lib/scard.py" 2>&1; }
	if r=$(reach root -); then ok "root reaches the card service: $r"; else bad "root was refused: $r"; fi
	who=$(x 'systemctl show -p User --value pcscd.service')
	who=${who:-root}
	if [ "$who" = "$expect_user" ]; then ok "pcscd runs as $who"; else bad "pcscd runs as '$who', the table says $expect_user"; fi
	if r=$(reach sluis-drv-key-yubikey-piv-dev sluis-pcsc-dev); then ok "the card driver's user reaches it: $r"; else bad "the card driver's user was refused: $r"; fi
	if r=$(reach sluis-stranger -); then bad "another user reached the card service: $r"; else ok "another user does not (the socket group)"; fi
	sock=$(x 'stat -c "%a %U %G" /run/pcscd/pcscd.comm')
	if [ "$sock" = "660 root sluis-pcsc-dev" ]; then ok "and it is still so after pcscd ran"; else bad "the socket became '$sock' while pcscd ran"; fi
	# pcscd started again, and a boot (a /run that is empty again, the tmpfiles of the boot, the socket made, the first start): the
	# socket keeps its group. systemd hands a runtime directory to the user of the service when it is not that user's already, so
	# this is the case that a missing tmpfiles entry would break.
	x 'systemctl restart pcscd.service'
	reach root - >/dev/null || true
	sock=$(x 'stat -c "%a %U %G" /run/pcscd/pcscd.comm')
	if [ "$sock" = "660 root sluis-pcsc-dev" ]; then ok "the socket keeps its group after pcscd was restarted"; else bad "the socket is '$sock' after a restart of pcscd"; fi
	x 'systemctl stop pcscd.service pcscd.socket; rm -rf /run/pcscd; systemd-tmpfiles --create; systemctl start pcscd.socket'
	reach root - >/dev/null || true
	sock=$(x 'stat -c "%a %U %G" /run/pcscd/pcscd.comm')
	if [ "$sock" = "660 root sluis-pcsc-dev" ]; then ok "the socket keeps its group at the first start after a boot"; else bad "the socket is '$sock' at the first start after a boot"; fi
	if r=$(reach sluis-drv-key-yubikey-piv-dev sluis-pcsc-dev); then ok "and the card driver's user reaches it: $r"; else bad "the card driver's user was refused after the boot: $r"; fi
	# The card driver and key@ require pcscd.socket, so stopping it stopped them: start them again, as a boot would.
	x 'systemctl start sluis-key@dev.service; sleep 2'
	if [ "$has_policy" = 1 ]; then
		if r=$(reach sluis-peer sluis-pcsc-dev); then bad "a member of the socket's group that is not the card driver reached it: $r"; else ok "a member of the socket's group that is not the card driver does not (the polkit rule): $r"; fi
		x "mv $rules /etc/rule.off; sleep 3"
		if r=$(reach sluis-drv-key-yubikey-piv-dev sluis-pcsc-dev); then echo "     without the rule the card driver's user still reaches it: $r"; echo "MEASURED without-rule=reaches"; else ok "without the rule even the card driver's user is refused (the policy default): $r"; fi
		x "mv /etc/rule.off $rules; sleep 3"
		if r=$(reach sluis-drv-key-yubikey-piv-dev sluis-pcsc-dev); then ok "and with the rule back it reaches it again"; else bad "the rule back did not restore access: $r"; fi
	fi
}
