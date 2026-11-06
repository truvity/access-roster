#!/usr/bin/env bash
# shellcheck disable=SC2154 # rqlite_unit, rqlite_dropin, rqlite_dropin_dir, rqlite_var_dir and rqlite_bin are remote-lib.sh's
# The part of boards.sh that runs on a board, as root:
#   remote.sh deploy|preflight|undeploy|status|avc STAGE
#   remote.sh rqlite-install|rqlite-undeploy|rqlite-status STAGE          (rqlite.sh and boards.sh; see "rqlite" below)
# It is shipped to the board inside the stage and is never installed. deploy and undeploy change only what the manifest lists,
# and refuse to touch anything outside the paths and names that deploy makes. rqlite is not in that set: rqlited.service belongs
# to the upstream package, and only the rqlite-* modes touch it, and only through the drop-in that rqlite-install wrote.
set -euo pipefail

mode=${1:?usage: remote.sh deploy|preflight|undeploy|status|avc|rqlite-install|rqlite-undeploy|rqlite-status STAGE}
stage=${2:?usage: remote.sh deploy|preflight|undeploy|status|avc|rqlite-install|rqlite-undeploy|rqlite-status STAGE}
boundary=dev
bin_dir=/opt/sluis/bin
manifest=/etc/sluis/deployed-$boundary.manifest
state_root=/var/lib/sluis-state

# The files of a board that runs the card driver (boards.sh, SLUIS_BOARDS_KEY_DRIVER=yubikey-piv), besides its unit and
# the key@ unit that requires it: the first closes the card service to everyone but the card driver's group and root, the
# second does the same through polkit on a board whose pcscd is built with it.
card_serial_env=/etc/sluis/yubikey-piv-$boundary.env
card_pcscd_dropin=/etc/systemd/system/pcscd.socket.d/10-sluis.conf
card_pcscd_tmpfiles=/etc/tmpfiles.d/sluis-pcscd-"$boundary".conf
card_polkit_rules=/etc/polkit-1/rules.d/49-sluis-pcsc.rules
card_polkit_policy=/usr/share/polkit-1/actions/org.debian.pcsc-lite.policy

# The checks of the board's operating system (os_family, check_card_prerequisites, check_pinned_ids, relabel) are in remote-lib.sh, which travels
# in the stage beside this file; they read $card_polkit_policy and $state_root.
# shellcheck source=/dev/null
. "$(dirname "$0")/remote-lib.sh"

# What deploy may add, and so what undeploy may remove. Anything else in the manifest is refused.
allowed_path() {
	case "$1" in
	"$bin_dir"/actors/* | "$bin_dir"/drivers/* | "$bin_dir"/cli/*) return 0 ;;
	/etc/systemd/system/sluis-*@.service) return 0 ;;
	/etc/sysusers.d/sluis-*-"$boundary".conf | /etc/tmpfiles.d/sluis-*-"$boundary".conf) return 0 ;;
	/etc/sluis/config/"$boundary"/*.jws | /etc/sluis/bootstrap.d/"$boundary".yaml | /etc/sluis/rqlite-"$boundary".env) return 0 ;;
	/etc/sluis/credentials/"$boundary"/sluis-*/*) return 0 ;;
	"$card_pcscd_dropin" | "$card_pcscd_tmpfiles" | "$card_polkit_rules" | "$card_serial_env") return 0 ;;
	esac
	return 1
}
allowed_dir() {
	case "$1" in
	"$bin_dir"/actors | "$bin_dir"/drivers | "$bin_dir"/drivers/* | "$bin_dir"/cli) return 0 ;;
	/run/sluis | /run/sluis/*) return 0 ;;
	/etc/sluis | /etc/sysusers.d) return 0 ;;
	/etc/systemd/system/pcscd.socket.d | /etc/polkit-1/rules.d | /etc/tmpfiles.d) return 0 ;;
	/etc/sluis/config | /etc/sluis/config/"$boundary" | /etc/sluis/bootstrap.d) return 0 ;;
	/etc/sluis/credentials | /etc/sluis/credentials/"$boundary" | /etc/sluis/credentials/"$boundary"/sluis-*) return 0 ;;
	"$state_root" | "$state_root"/*) return 0 ;;
	esac
	return 1
}
allowed_name() { [[ "$1" =~ ^sluis-[a-z0-9-]+-$boundary$ ]]; }

note() { # add "kind<TAB>value" to the manifest before the thing is made, so that a crash leaves it listed
	mkdir -p "$(dirname "$manifest")"
	printf '%s\t%s\n' "$1" "$2" >>"$manifest"
}
sort_manifest() {
	[ -f "$manifest" ] || return 0
	sort -u -o "$manifest" "$manifest"
}

# preflight checks, before the first file is written, what the board must be for this stage: a deploy that stops half way
# leaves a unit that boards.sh reads as a switch that stopped half way, and refuses to go on from. It writes nothing, so
# boards.sh runs it alone (`remote.sh preflight`) on a board that switches its key driver before it marks the board pending.
preflight() {
	local -a staged_sysusers
	# What the board's image must carry.
	if [ -d "$stage/files/card" ]; then
		check_card_prerequisites || return 1
	fi
	# The units read their credentials with LoadCredentialEncrypted=, which a systemd older than 252 does not know: any unit that
	# has the line needs the floor, whether or not this deploy stages a credential file.
	if [ -d "$stage/files/etc/credentials" ] || grep -qsE '^LoadCredentialEncrypted=' "$stage"/files/systemd/*; then
		require_credential_encryption || return 1
	fi
	# A pinned uid or gid that is taken would make systemd-sysusers pick another one (check_pinned_ids).
	shopt -s nullglob
	staged_sysusers=("$stage"/files/sysusers/*)
	shopt -u nullglob
	check_pinned_ids before "${staged_sysusers[@]}" || return 1
}

case "$mode" in
preflight)
	[ -d "$stage/files" ] || { echo "remote: no stage in $stage" >&2; exit 1; }
	preflight || exit 1
	;;
deploy)
	[ -d "$stage/files" ] && [ -f "$stage/plan.tsv" ] || { echo "remote: no stage in $stage" >&2; exit 1; }
	[ -s "$stage/plan.tsv" ] || { echo "remote: the plan is empty" >&2; exit 1; }
	preflight || exit 1
	# /etc/sysusers.d does not exist on every image; both directories are listed if deploy has to make them.
	for d in /etc/sluis /etc/sysusers.d; do
		if [ ! -d "$d" ]; then
			note dir "$d" # this makes /etc/sluis for the manifest, so the note comes first
			install -d -m 0755 "$d"
		fi
	done
	[ -f "$manifest" ] || : >"$manifest"

	# Binaries.
	while IFS= read -r f; do
		rel=${f#"$stage/files/bin/"}
		dest=$bin_dir/$rel
		allowed_path "$dest" || { echo "remote: refusing $dest" >&2; exit 1; }
		d=$(dirname "$dest")
		while [ "$d" != "$bin_dir" ] && [ ! -d "$d" ]; do
			# Record every directory that has to be made, shallowest last, so undeploy removes the deepest first.
			note dir "$d"
			d=$(dirname "$d")
		done
		install -d -m 0755 -o root -g root "$(dirname "$dest")"
		note file "$dest"
		install -m 0755 -o root -g root "$f" "$dest"
	done < <(find "$stage/files/bin" -type f | sort)

	# Units, users, groups and directories.
	for f in "$stage"/files/systemd/*; do
		dest=/etc/systemd/system/$(basename "$f")
		allowed_path "$dest" || { echo "remote: refusing $dest" >&2; exit 1; }
		note file "$dest"
		install -m 0644 -o root -g root "$f" "$dest"
	done
	sysusers=()
	for f in "$stage"/files/sysusers/*; do
		dest=/etc/sysusers.d/$(basename "$f")
		allowed_path "$dest" || { echo "remote: refusing $dest" >&2; exit 1; }
		while read -r kind name _; do
			[ "$kind" = u ] || [ "$kind" = g ] || continue
			allowed_name "$name" || { echo "remote: refusing the name $name" >&2; exit 1; }
			if [ "$kind" = u ]; then
				id -u "$name" >/dev/null 2>&1 || note user "$name"
			else
				getent group "$name" >/dev/null || note group "$name"
			fi
		done <"$f"
		note file "$dest"
		install -m 0644 -o root -g root "$f" "$dest"
		sysusers+=("$dest")
	done
	systemd-sysusers "${sysusers[@]}"
	check_pinned_ids after "${sysusers[@]}" || exit 1
	tmpfiles=()
	for f in "$stage"/files/tmpfiles/*; do
		dest=/etc/tmpfiles.d/$(basename "$f")
		allowed_path "$dest" || { echo "remote: refusing $dest" >&2; exit 1; }
		while read -r kind path _; do
			[ "$kind" = d ] || continue
			allowed_dir "$path" || { echo "remote: refusing the directory $path" >&2; exit 1; }
			# /run/sluis and the state root are named for sluis alone, so they are always listed: a state directory
			# that an earlier undeploy kept must not fall out of the manifest. The other directories are listed
			# only when deploy makes them.
			case "$path" in
			/run/sluis | /run/sluis/* | "$state_root" | "$state_root"/*) note dir "$path" ;;
			*) [ -d "$path" ] || note dir "$path" ;;
			esac
		done <"$f"
		note file "$dest"
		install -m 0644 -o root -g root "$f" "$dest"
		tmpfiles+=("$dest")
	done
	systemd-tmpfiles --create "${tmpfiles[@]}"
	sort_manifest

	# The card variant: pcscd and its drivers, the drop-in and the polkit rule. Without it, the files of an earlier card
	# deploy are taken away (the key@ template of this deploy already names the software driver again).
	card_changed=0
	if [ -d "$stage/files/card" ]; then
		# The card service, its reader driver and, where pcscd asks polkit, polkit are the image's: checked above, never installed.
		install_card() { # source dest [mode]
			allowed_path "$2" || { echo "remote: refusing $2" >&2; exit 1; }
			d=$(dirname "$2")
			if [ ! -d "$d" ]; then
				note dir "$d"
				install -d -m 0755 -o root -g root "$d"
			fi
			note file "$2"
			install -m "${3:-0644}" -o root -g root "$1" "$2"
		}
		install_card "$stage/files/card/pcscd-socket.dropin" "$card_pcscd_dropin"
		# A pcscd that runs as a user of its own (Ubuntu 26.04) has RuntimeDirectory=pcscd in its unit, and at its start systemd
		# hands /run/pcscd and what is in it, the socket included, to that user when the directory is not already the user's
		# (MEASURED 2026-11-04: the socket became pcscd:pcscd and the card driver was refused). The directory is made the user's
		# before the socket binds, by tmpfiles at boot and now, so that systemd leaves the socket alone and its group, from the
		# socket drop-in, stays. Nothing runs as root at the start of pcscd. A pcscd that runs as root needs no entry.
		pcscd_user=$(systemctl show -p User --value pcscd.service 2>/dev/null || true)
		if [ -n "$pcscd_user" ]; then
			if ! [[ "$pcscd_user" =~ ^[a-z_][a-z0-9_-]*$ ]] || ! pcscd_group=$(id -gn "$pcscd_user"); then
				echo "remote: pcscd.service runs as an unusable user '$pcscd_user'" >&2
				exit 1
			fi
			printf '# Made by sluis deploy: the runtime directory of pcscd belongs to the user pcscd runs as.\nd /run/pcscd 0755 %s %s -\n' "$pcscd_user" "$pcscd_group" >"$stage/files/card/pcscd-tmpfiles.conf"
			install_card "$stage/files/card/pcscd-tmpfiles.conf" "$card_pcscd_tmpfiles"
			systemd-tmpfiles --create "$card_pcscd_tmpfiles"
		elif [ -e "$card_pcscd_tmpfiles" ]; then
			rm -f -- "$card_pcscd_tmpfiles"
		fi
		install_card "$stage/files/card/yubikey-piv.env" "$card_serial_env" 0600 # the card the driver is bound to; systemd reads it as root
		# A pcscd that ships its polkit policy asks polkit about every client and refuses a system service by default (Ubuntu 26.04,
		# Rocky 10): the rule is what admits the card driver, and the socket group is the second lock. A pcscd without polkit (Ubuntu
		# 22.04) has the socket group alone.
		if [ -e "$card_polkit_policy" ]; then
			install_card "$stage/files/card/pcsc-polkit.rules" "$card_polkit_rules"
		fi
		card_changed=1
	else
		for f in "$card_pcscd_dropin" "$card_pcscd_tmpfiles" "$card_polkit_rules" "$card_serial_env"; do
			if [ -e "$f" ]; then
				rm -f -- "$f"
				echo "removed $f"
				card_changed=1
			fi
		done
	fi
	sort_manifest

	# The seed: the signed config and the bootstrap file (root's, public), the credentials (root's, mode 0400, read by
	# systemd's LoadCredentialEncrypted=), and the rqlite address of this board. Every file is listed before it is made.
	if [ -d "$stage/files/etc" ]; then
		mkdir_noted() { # dir mode
			if [ ! -d "$1" ]; then
				note dir "$1"
				install -d -m "$2" -o root -g root "$1"
			fi
		}
		mkdir_noted /etc/sluis/config 0755
		mkdir_noted "/etc/sluis/config/$boundary" 0755
		mkdir_noted /etc/sluis/bootstrap.d 0755
		for old in "/etc/sluis/config/$boundary"/*.jws; do # a document the new seed no longer holds must not stay
			[ -e "$old" ] || continue
			[ -e "$stage/files/etc/config/$(basename "$old")" ] || rm -f -- "$old"
		done
		for f in "$stage"/files/etc/config/*.jws; do
			dest=/etc/sluis/config/$boundary/$(basename "$f")
			allowed_path "$dest" || { echo "remote: refusing $dest" >&2; exit 1; }
			note file "$dest"
			install -m 0644 -o root -g root "$f" "$dest"
		done
		dest=/etc/sluis/bootstrap.d/$boundary.yaml
		note file "$dest"
		install -m 0644 -o root -g root "$stage/files/etc/bootstrap.yaml" "$dest"
		dest=/etc/sluis/rqlite-$boundary.env
		note file "$dest"
		install -m 0644 -o root -g root "$stage/files/etc/rqlite.env" "$dest"
		if [ -d "$stage/files/etc/credentials" ]; then
			mkdir_noted /etc/sluis/credentials 0700
			mkdir_noted "/etc/sluis/credentials/$boundary" 0700
			for d in "$stage"/files/etc/credentials/*/; do
				owner=$(basename "$d")
				mkdir_noted "/etc/sluis/credentials/$boundary/$owner" 0700
				for f in "$d"*; do
					dest=/etc/sluis/credentials/$boundary/$owner/$(basename "$f")
					allowed_path "$dest" || { echo "remote: refusing $dest" >&2; exit 1; }
					note file "$dest"
					# The units read the credential with LoadCredentialEncrypted=, so it is encrypted here, on the board, under
					# the board's own host key (/var/lib/systemd/credential.secret, which systemd-creds makes on first use). A
					# reflash makes a new key, and a file encrypted under the old one no longer opens: the next deploy encrypts
					# every credential again, always, from the staged plain file, which the stage removal then deletes.
					encrypt_credential "$(basename "$f")" "$f" "$dest"
				done
			done
		fi
		sort_manifest
	fi

	relabel

	# Verify before anything starts.
	units=()
	while IFS=$'\t' read -r instance _; do
		units+=("$instance")
	done <"$stage/plan.tsv"
	systemctl daemon-reload
	if [ "$card_changed" = 1 ]; then
		# The card service takes its socket's group from the drop-in only when it is started again.
		systemctl stop pcscd.service pcscd.socket 2>/dev/null || true
		systemctl start pcscd.socket
	fi
	for u in "${units[@]}"; do
		if ! out=$(systemd-analyze verify "$u" 2>&1); then
			printf '%s\n' "$out" | sed "s|^|verify $u: |" >&2
			echo "remote: systemd-analyze verify refused $u; nothing was started" >&2
			sort_manifest
			exit 1
		fi
		[ -z "$out" ] || printf '%s\n' "$out" | sed "s|^|verify $u: |"
		echo "verify $u: ok (the unit file only; it has not been started)"
		note unit "$u"
	done
	sort_manifest
	for u in "${units[@]}"; do
		systemctl enable "$u" 2>&1 | sed "s|^|enable $u: |"
	done
	# The two key drivers serve one socket: the one this deploy does not start is stopped and disabled. This comes after the
	# verify and after the new driver is enabled, so that a refused verify leaves the old driver enabled and running, and a
	# board never has both disabled (boards.sh reads that as a half-made switch and refuses to go on).
	for other in sluis-drv-key-software@$boundary.service sluis-drv-key-yubikey-piv@$boundary.service; do
		printf '%s\n' "${units[@]}" | grep -qx "$other" && continue
		if systemctl cat "$other" >/dev/null 2>&1; then
			systemctl disable --now "$other" 2>&1 | sed "s|^|disable $other: |" || true
		fi
	done
	# Stop in reverse order and start in the order of the plan, drivers first. A restart of each unit in turn would
	# restart the actors that Requires= it again and again, and the start limit (5 in 10 s) would put them out.
	for ((i = ${#units[@]} - 1; i >= 0; i--)); do
		systemctl stop "${units[$i]}" || true
	done
	systemctl reset-failed "${units[@]}" || true
	# The journal is read from here on only: what an earlier deploy left in it is not evidence about this run.
	# shellcheck disable=SC2034 # settle_units (remote-lib.sh) reads it
	settle_since=$(date '+%Y-%m-%d %H:%M:%S.%6N')
	for u in "${units[@]}"; do
		systemctl start "$u" || true
	done
	# The actors dial each other when they start and retry every two seconds until the peer is up, so give them time: the wait ends
	# when every unit is active and has not restarted for about 6 s, or after settle_timeout (60 s). A unit that restarts, or is not active
	# by then, fails the deploy with the last lines of its journal. The one state that does not is a card board that is locked,
	# waiting for its PIN (settle_units in remote-lib.sh): the card driver says it (sluis node status), every unit that has not settled
	# is waiting for the driver, and the last line is "SLUIS-BOARD-STATE: locked"; the exit status is settle_locked_status (10), and
	# boards.sh reads the line first and says what to do next. A card board that is unlocked ends "ok". Everything printed above
	# this line was a static check or a start, and says nothing about a run.
	echo "settling: waiting up to ${settle_timeout}s for ${#units[@]} units to be active and not to restart for about 6 s"
	rc=0
	settle_units "${units[@]}" || rc=$?
	exit "$rc"
	;;

undeploy)
	[ -f "$manifest" ] || { echo "remote: nothing deployed (no $manifest)"; exit 0; }
	# Stop what deploy started, in reverse order of the manifest's sort: the order does not matter for a stop.
	while IFS=$'\t' read -r kind value; do
		[ "$kind" = unit ] || continue
		allowed_name "${value%@*}-$boundary" || { echo "remote: refusing the unit $value" >&2; exit 1; }
		systemctl disable --now "$value" 2>&1 | sed "s|^|disable $value: |" || true
	done <"$manifest"
	while IFS=$'\t' read -r kind value; do
		case "$kind" in
		file)
			allowed_path "$value" || { echo "remote: refusing $value" >&2; exit 1; }
			rm -f -- "$value"
			echo "removed $value"
			;;
		esac
	done <"$manifest"
	systemctl daemon-reload
	if grep -q "pcscd\.\(socket\|service\)\.d" "$manifest"; then
		systemctl stop pcscd.service pcscd.socket 2>/dev/null || true
		systemctl start pcscd.socket || true
	fi
	# Users and groups that deploy made.
	while IFS=$'\t' read -r kind value; do
		case "$kind" in
		user)
			allowed_name "$value" || { echo "remote: refusing the user $value" >&2; exit 1; }
			if id -u "$value" >/dev/null 2>&1; then userdel "$value" && echo "removed user $value"; fi
			getent group "$value" >/dev/null && groupdel "$value" 2>/dev/null || true
			;;
		group)
			allowed_name "$value" || { echo "remote: refusing the group $value" >&2; exit 1; }
			if getent group "$value" >/dev/null; then groupdel "$value" && echo "removed group $value"; fi
			;;
		esac
	done <"$manifest"
	# Directories, the deepest first. A directory that is not empty stays. The state below $state_root holds the keys
	# of the units: it goes only on SLUIS_PURGE_STATE=1. The manifest goes first, so that /etc/sluis can go too.
	mapfile -t dirs < <(awk -F'\t' '$1 == "dir" { print length($2) "\t" $2 }' "$manifest" | sort -rn | cut -f2-)
	rm -f -- "$manifest"
	for d in "${dirs[@]}"; do
		allowed_dir "$d" || { echo "remote: refusing the directory $d" >&2; exit 1; }
		case "$d" in
		"$state_root" | "$state_root"/*)
			if [ "${SLUIS_PURGE_STATE:-}" = 1 ]; then rm -rf -- "$d" && echo "purged $d"; continue; fi
			;;
		esac
		if rmdir -- "$d" 2>/dev/null; then echo "removed $d"; else echo "kept $d (not empty or gone)"; fi
	done
	echo "undeployed"
	;;

status)
	if [ ! -f "$manifest" ]; then echo "deployed: no (no $manifest)"; else
		echo "deployed: yes ($(grep -c '^file' "$manifest") files, $(grep -c '^unit' "$manifest") units, $(grep -c '^user' "$manifest") users)"
	fi
	rc=0
	if [ -f "$manifest" ]; then
		while IFS=$'\t' read -r kind value; do
			[ "$kind" = unit ] || continue
			st=$(systemctl is-active "$value" || true)
			printf 'unit %-45s %-9s enabled=%s\n' "$value" "$st" "$(systemctl is-enabled "$value" 2>/dev/null || true)"
			[ "$st" = active ] || rc=1
		done <"$manifest"
		while IFS=$'\t' read -r kind value; do
			[ "$kind" = file ] || continue
			[ -e "$value" ] || { echo "missing $value"; rc=1; }
		done <"$manifest"
	fi
	failed=$(systemctl list-units --failed --no-legend 'sluis-*' | awk '{print $1}')
	if [ -n "$failed" ]; then
		echo "failed: $failed"
		rc=1
	fi
	# The lock of the card, from the card driver itself (board_lock_state, remote-lib.sh), one line for boards.sh to read. A locked
	# board is not a failure of status; a card board whose lock cannot be read is: nobody has looked.
	lock_state=none lock_why=""
	if systemctl is-enabled --quiet "sluis-drv-key-yubikey-piv@$boundary.service" 2>/dev/null; then
		board_lock_state
	fi
	case "$lock_state" in
	locked) echo "lock: the card driver is locked: it holds no PIN, so key@ cannot sign or open a key" ;;
	unlocked) echo "lock: the card driver is unlocked" ;;
	none) echo "lock: no card driver on this board, so no PIN" ;;
	*) echo "lock: UNKNOWN: $lock_why"; rc=1 ;;
	esac
	printf '%s%s\n' "$lock_state_prefix" "$lock_state"
	exit "$rc"
	;;

avc)
	# The denials of the SELinux policy since boot: printed, and a failure when one is an enforced denial of ours (avc_check).
	avc_check
	;;

rqlite-install)
	# What rqlite.sh sent: the package (one .deb or .rpm below $stage/rqlite) and, in the environment, the address and ports of this
	# board, its sha256 pin, the size of the cluster and the Raft addresses of all its nodes (empty for a cluster of one). The board
	# checks the package against the pin before it hands it to the package manager as root; the package manager does the install,
	# the drop-in sets the node's flags (no -node-id: rqlite uses the Raft address; every node of a cluster of more than one has
	# -bootstrap-expect and the whole -join list, so that a node without state can never form a cluster of its own), restorecon
	# labels, and the unit is enabled and (re)started when it is not running with this drop-in.
	ip=${RQLITE_NODE_IP:?remote: RQLITE_NODE_IP is not set}
	http_port=${RQLITE_HTTP_PORT:-4001}
	raft_port=${RQLITE_RAFT_PORT:-4002}
	expect=${RQLITE_EXPECT:?remote: RQLITE_EXPECT is not set}
	join=${RQLITE_JOIN:-}
	sha=${RQLITE_SHA256:?remote: RQLITE_SHA256 is not set}
	[[ "$sha" =~ ^[0-9a-f]{64}$ ]] || { echo "remote: RQLITE_SHA256 is not a sha256" >&2; exit 1; }
	shopt -s nullglob
	pkgs=("$stage"/rqlite/*.deb "$stage"/rqlite/*.rpm)
	shopt -u nullglob
	[ "${#pkgs[@]}" -eq 1 ] || { echo "remote: expected one rqlite package in $stage/rqlite, found ${#pkgs[@]}" >&2; exit 1; }
	rqlite_board_has_ip "$ip" || { echo "remote: this board has no address $ip (ip -o -4 addr): rqlite would fail to bind it. SLUIS_BOARDS names the address of the board itself, not one that reaches it through a NAT or an alias." >&2; exit 1; }
	if [ -e "$rqlite_dropin" ] && grep -q -- ' -node-id ' "$rqlite_dropin"; then
		# An earlier shape of this recipe named the node by its host name and started the first node as a cluster of one. Its state
		# holds that id (and, on the first node, a cluster of one), so the node cannot simply change its flags.
		echo "remote: $rqlite_dropin was made by an earlier version of this recipe (-node-id). Its Raft state does not fit the new flags: run boards-undeploy with SLUIS_PURGE_STATE=1 on every board, then boards-rqlite again." >&2
		exit 1
	fi
	rqlite_dropin_text "$ip" "$http_port" "$raft_port" "$expect" "$join" >"$stage/rqlite/10-sluis.conf" || exit 1
	sha256sum -c - <<<"$sha  ${pkgs[0]}" >/dev/null || { echo "remote: ${pkgs[0]##*/} on the board does not have the pinned sha256 $sha: refused" >&2; exit 1; }
	rqlite_install_package "${pkgs[0]}"
	[ -x "$rqlite_bin" ] || { echo "remote: the package left no $rqlite_bin" >&2; exit 1; }
	id -u rqlite >/dev/null 2>&1 || { echo "remote: the package left no user rqlite" >&2; exit 1; }
	changed=0
	if ! cmp -s "$stage/rqlite/10-sluis.conf" "$rqlite_dropin" 2>/dev/null; then
		install -d -m 0755 -o root -g root "$rqlite_dropin_dir"
		install -m 0644 -o root -g root "$stage/rqlite/10-sluis.conf" "$rqlite_dropin"
		changed=1
	fi
	rqlite_relabel
	systemctl daemon-reload
	# A package upgrade runs the prerm (deb) or preun (rpm) of the upstream package, which stops and disables the unit on every
	# removal of the old version, an upgrade included. The enable and the is-active check below start it again, on the new binary.
	# That is how a node comes back after an upgrade here, so do not take these two lines out as redundant.
	systemctl enable "$rqlite_unit" 2>&1 | sed "s|^|enable rqlited: |"
	if [ "$changed" = 1 ] || [ "$(systemctl is-active "$rqlite_unit" || true)" != active ]; then
		systemctl restart "$rqlite_unit"
	fi
	systemctl is-active "$rqlite_unit"
	;;

rqlite-status)
	if ! systemctl cat "$rqlite_unit" >/dev/null 2>&1; then
		echo "rqlite: not installed (run: just boards-rqlite)"
		exit 1
	fi
	st=$(systemctl is-active "$rqlite_unit" || true)
	printf 'rqlite %s %s enabled=%s dropin=%s\n' "$("$rqlite_bin" -version 2>/dev/null | head -1 || echo unknown)" "$st" "$(systemctl is-enabled "$rqlite_unit" 2>/dev/null || true)" "$([ -e "$rqlite_dropin" ] && echo yes || echo no)"
	[ "$st" = active ]
	;;

rqlite-undeploy)
	# Only a board where this tool installed rqlite (its drop-in is there) is touched: another rqlited.service is not ours to stop.
	# Without SLUIS_PURGE_STATE=1 the unit is stopped and disabled; the package, the drop-in and the data stay, because they hold
	# the cluster's copy of the store. With it they are removed as well, the drop-in LAST: it is what says that this tool made the
	# install, so a purge that stops half way (a package manager that fails) is found and finished by the next run. A node that is
	# purged stays in the cluster's configuration of the other nodes until it is removed there.
	# The drop-in is asked first: a purge that stopped half way (the package is removed, the unit file with it, the drop-in and the
	# data are left) has no unit and still has the drop-in, and the next run must finish it, not call the board "not installed" and
	# leave the Raft state behind. Without the drop-in the unit decides.
	if [ ! -e "$rqlite_dropin" ]; then
		if ! systemctl cat "$rqlite_unit" >/dev/null 2>&1; then
			echo "rqlite: not installed"
			exit 0
		fi
		echo "rqlite: no $rqlite_dropin, so this tool did not install it; it is left as it is (running or not), with its package and its data"
		exit 0
	fi
	systemctl disable --now "$rqlite_unit" 2>&1 | sed "s|^|disable rqlited: |" || true
	if [ "${SLUIS_PURGE_STATE:-}" != 1 ]; then
		echo "rqlite: stopped and disabled; the package, the drop-in and $rqlite_var_dir stay (SLUIS_PURGE_STATE=1 removes them)"
		exit 0
	fi
	case "$(os_family)" in
	deb) DEBIAN_FRONTEND=noninteractive apt-get remove -y rqlite ;;
	rpm) dnf remove -y rqlite ;;
	*) echo "remote: the board's package manager is unknown; the rqlite package, its data and the drop-in stay" >&2; exit 1 ;;
	esac
	rm -rf -- "$rqlite_var_dir"
	if id -u rqlite >/dev/null 2>&1; then userdel rqlite && echo "removed user rqlite"; fi
	if getent group rqlite >/dev/null; then groupdel rqlite && echo "removed group rqlite"; fi
	rm -f -- "$rqlite_dropin"
	rmdir -- "$rqlite_dropin_dir" 2>/dev/null || true
	systemctl daemon-reload
	echo "rqlite: removed"
	;;

*)
	echo "remote: unknown mode $mode" >&2
	exit 2
	;;
esac
