#!/usr/bin/env bash
# The part of boards.sh that runs on a board, as root: `remote.sh deploy|undeploy|status STAGE`.
# It is shipped to the board inside the stage and is never installed. It changes only what the manifest lists,
# and it refuses to touch anything outside the paths and names that deploy makes (sluis-rqlite, the user "sluis",
# /opt/sluis/bin/rqlited and /var/lib/sluis are never in that set).
set -euo pipefail

mode=${1:?usage: remote.sh deploy|undeploy|status STAGE}
stage=${2:?usage: remote.sh deploy|undeploy|status STAGE}
boundary=dev
bin_dir=/opt/sluis/bin
manifest=/etc/sluis/deployed-$boundary.manifest
state_root=/var/lib/sluis-state

# The files of a board that runs the card driver (boards.sh, SLUIS_BOARDS_KEY_DRIVER=yubikey-piv), besides its unit and
# the key@ unit that requires it: the first closes the card service to everyone but the card driver's group and root, the
# second does the same through polkit on a board whose pcscd is built with it.
card_serial_env=/etc/sluis/yubikey-piv-$boundary.env
card_pcscd_dropin=/etc/systemd/system/pcscd.socket.d/10-sluis.conf
card_polkit_rules=/etc/polkit-1/rules.d/49-sluis-pcsc.rules
card_polkit_policy=/usr/share/polkit-1/actions/org.debian.pcsc-lite.policy

# What deploy may add, and so what undeploy may remove. Anything else in the manifest is refused.
allowed_path() {
	case "$1" in
	"$bin_dir"/actors/* | "$bin_dir"/drivers/* | "$bin_dir"/cli/*) return 0 ;;
	/etc/systemd/system/sluis-*@.service) return 0 ;;
	/etc/sysusers.d/sluis-*-"$boundary".conf | /etc/tmpfiles.d/sluis-*-"$boundary".conf) return 0 ;;
	/etc/sluis/config/"$boundary"/*.jws | /etc/sluis/bootstrap.d/"$boundary".yaml | /etc/sluis/rqlite-"$boundary".env) return 0 ;;
	/etc/sluis/credentials/"$boundary"/sluis-*/*) return 0 ;;
	"$card_pcscd_dropin" | "$card_polkit_rules" | "$card_serial_env") return 0 ;;
	esac
	return 1
}
allowed_dir() {
	case "$1" in
	"$bin_dir"/actors | "$bin_dir"/drivers | "$bin_dir"/drivers/* | "$bin_dir"/cli) return 0 ;;
	/run/sluis | /run/sluis/*) return 0 ;;
	/etc/sluis | /etc/sysusers.d) return 0 ;;
	/etc/systemd/system/pcscd.socket.d | /etc/polkit-1/rules.d) return 0 ;;
	/etc/sluis/config | /etc/sluis/config/"$boundary" | /etc/sluis/bootstrap.d) return 0 ;;
	/etc/sluis/credentials | /etc/sluis/credentials/"$boundary" | /etc/sluis/credentials/"$boundary"/sluis-*) return 0 ;;
	"$state_root" | "$state_root"/*) return 0 ;;
	esac
	return 1
}
allowed_name() { [[ "$1" =~ ^sluis-[a-z0-9-]+-$boundary$ ]] && [ "$1" != "sluis-rqlite" ]; }

note() { # add "kind<TAB>value" to the manifest before the thing is made, so that a crash leaves it listed
	mkdir -p "$(dirname "$manifest")"
	printf '%s\t%s\n' "$1" "$2" >>"$manifest"
}
sort_manifest() {
	[ -f "$manifest" ] || return 0
	sort -u -o "$manifest" "$manifest"
}

case "$mode" in
deploy)
	[ -d "$stage/files" ] && [ -f "$stage/plan.tsv" ] || { echo "remote: no stage in $stage" >&2; exit 1; }
	[ -s "$stage/plan.tsv" ] || { echo "remote: the plan is empty" >&2; exit 1; }
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
		# The card service and its reader driver: on the Orange Pi image they are there already; if not, apt installs them.
		if ! dpkg -s pcscd libccid >/dev/null 2>&1; then
			echo "remote: installing pcscd and libccid"
			DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends pcscd libccid
		fi
		install_card() { # source dest
			allowed_path "$2" || { echo "remote: refusing $2" >&2; exit 1; }
			d=$(dirname "$2")
			if [ ! -d "$d" ]; then
				note dir "$d"
				install -d -m 0755 -o root -g root "$d"
			fi
			note file "$2"
			install -m 0644 -o root -g root "$1" "$2"
		}
		install_card "$stage/files/card/pcscd-socket.dropin" "$card_pcscd_dropin"
		install_card "$stage/files/card/yubikey-piv.env" "$card_serial_env" # the card the driver is bound to
		# pcsc-lite as Debian and Ubuntu 22.04 build it has no polkit: the socket group above is the control there.
		if [ -e "$card_polkit_policy" ]; then
			install_card "$stage/files/card/pcsc-polkit.rules" "$card_polkit_rules"
		fi
		card_changed=1
	else
		for f in "$card_pcscd_dropin" "$card_polkit_rules" "$card_serial_env"; do
			if [ -e "$f" ]; then
				rm -f -- "$f"
				echo "removed $f"
				card_changed=1
			fi
		done
	fi
	sort_manifest

	# The seed: the signed config and the bootstrap file (root's, public), the credentials (root's, mode 0400, read by
	# systemd's LoadCredential=), and the rqlite address of this board. Every file is listed before it is made.
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
					install -m 0400 -o root -g root "$f" "$dest"
				done
			done
		fi
		sort_manifest
	fi

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
	# The two key drivers serve one socket: the one this deploy does not start is stopped and disabled.
	for other in sluis-drv-key-software@$boundary.service sluis-drv-key-yubikey-piv@$boundary.service; do
		printf '%s\n' "${units[@]}" | grep -qx "$other" && continue
		if systemctl cat "$other" >/dev/null 2>&1; then
			systemctl disable --now "$other" 2>&1 | sed "s|^|disable $other: |" || true
		fi
	done
	for u in "${units[@]}"; do
		if ! out=$(systemd-analyze verify "$u" 2>&1); then
			printf '%s\n' "$out" | sed "s|^|verify $u: |" >&2
			echo "remote: systemd-analyze verify refused $u; nothing was started" >&2
			sort_manifest
			exit 1
		fi
		[ -z "$out" ] || printf '%s\n' "$out" | sed "s|^|verify $u: |"
		echo "verify $u: ok"
		note unit "$u"
	done
	sort_manifest
	for u in "${units[@]}"; do
		systemctl enable "$u" 2>&1 | sed "s|^|enable $u: |"
	done
	# Stop in reverse order and start in the order of the plan, drivers first. A restart of each unit in turn would
	# restart the actors that Requires= it again and again, and the start limit (5 in 10 s) would put them out.
	for ((i = ${#units[@]} - 1; i >= 0; i--)); do
		systemctl stop "${units[$i]}" || true
	done
	systemctl reset-failed "${units[@]}" || true
	for u in "${units[@]}"; do
		systemctl start "$u" || true
	done
	# The actors dial each other when they start and retry every two seconds until the peer is up: give them time.
	for _ in $(seq 1 30); do
		sleep 2
		pending=0
		for u in "${units[@]}"; do
			[ "$(systemctl is-active "$u" || true)" = active ] || pending=1
		done
		[ "$pending" = 1 ] || break
	done
	fail=0
	for u in "${units[@]}"; do
		st=$(systemctl is-active "$u" || true)
		printf 'unit %s %s\n' "$u" "$st"
		[ "$st" = active ] || fail=1
	done
	exit "$fail"
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
	if grep -q "pcscd.socket.d" "$manifest"; then
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
	# Read only: the unit that is not ours.
	printf 'other sluis-rqlite %s\n' "$(systemctl is-active sluis-rqlite 2>/dev/null || true)"
	exit "$rc"
	;;

*)
	echo "remote: unknown mode $mode" >&2
	exit 2
	;;
esac
