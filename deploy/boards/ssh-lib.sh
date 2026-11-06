#!/usr/bin/env bash
# The ssh of the boards scripts (boards.sh, rqlite.sh), kept in one place. Sourced, never run. It reads, from the caller:
#   SLUIS_BOARD_SSH_USER      the SSH user, with passwordless sudo
#   agent                     the agent socket for ssh; it is set for the ssh commands only, never exported
#   SLUIS_BOARD_SSH_OPTIONS   extra ssh arguments, split at white space, for example
#                             "-o UserKnownHostsFile=/path/to/known_hosts -o StrictHostKeyChecking=yes". A board that was
#                             reinstalled has a new host key; this is how a run trusts it without touching ~/.ssh/known_hosts.
#                             The smoke program (deploy/boards/smoke) reads the same variable. A value with a space in it
#                             (a path) is not supported. All of the value is read, newlines included, as Go's strings.Fields does.
# The options come after the defaults below. ssh keeps the first value it sees for an option, so they add to the defaults and
# do not replace BatchMode, ConnectTimeout or the keep-alive: a connection that is dropped without a reset (a firewall that DROPs)
# ends in about 15 s instead of hanging until the TCP timeout.

ssh_options=()
if [ -n "${SLUIS_BOARD_SSH_OPTIONS:-}" ]; then
	# -d '' reads to the end of the value instead of the first line; read then returns non-zero at the end, which is expected.
	read -rd '' -a ssh_options <<<"$SLUIS_BOARD_SSH_OPTIONS" || true
fi

# shell_quote word... prints the words, each in single quotes, for the shell of the board: ssh joins its arguments with spaces into
# one string that the login shell over there parses again, so a word with a (, a *, a ? or a space in it must be quoted by the
# caller (board_ssh board "cmd $(shell_quote "$x")"). Single quotes work in every POSIX shell; a single quote in a word is closed,
# escaped and opened again.
shell_quote() {
	local w out=""
	for w in "$@"; do
		out="$out'${w//\'/\'\\\'\'}' "
	done
	printf '%s' "${out% }"
}

# board_ssh board command...: the standard input of the caller reaches the command on the board. The command is ONE string for the
# shell of the board (see shell_quote); several words are joined with spaces by ssh and parsed again, not passed as they are.
board_ssh() {
	local b=$1
	shift
	SSH_AUTH_SOCK=${agent:-} ssh -o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=5 -o ServerAliveCountMax=3 ${ssh_options[@]+"${ssh_options[@]}"} "$SLUIS_BOARD_SSH_USER@$b" "$@"
}

# board_ssh_n is board_ssh for a command that reads nothing: ssh gets /dev/null, so it cannot swallow the standard input of a loop
# or of the script that calls it.
board_ssh_n() { # board command...
	board_ssh "$@" </dev/null
}

# board_ssh_secret is board_ssh for a command that is given a secret on standard input (boards-unlock). -T and
# -o StrictHostKeyChecking=yes come before the options of the run: ssh keeps the first value it sees, so neither RequestTTY in
# ~/.ssh/config nor "-o RequestTTY=force" can give the session a terminal, where the remote line discipline would echo what is
# piped in back to this terminal, and neither "StrictHostKeyChecking no" (or accept-new) in ~/.ssh/config nor in the options can
# make the connection trust a key it has not been shown. The host key of the board must therefore be known already: the first
# connection to a new board is made without the PIN (SLUIS_BOARDS=<board> just boards-status), which learns it. A -t, a
# StrictHostKeyChecking that is off and a known-hosts file of /dev/null in the options are refused by the caller
# (ssh_secret_options_ok).
board_ssh_secret() { # board command...
	local b=$1
	shift
	SSH_AUTH_SOCK=${agent:-} ssh -T -o StrictHostKeyChecking=yes -o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=5 -o ServerAliveCountMax=3 ${ssh_options[@]+"${ssh_options[@]}"} "$SLUIS_BOARD_SSH_USER@$b" "$@"
}

# ssh_secret_options_ok succeeds when SLUIS_BOARD_SSH_OPTIONS suits an ssh that carries a secret: it asks for no terminal (-t, -tt:
# the last of -T and -t wins, so a -t after our -T would win), it does not turn host-key checking off (StrictHostKeyChecking=no
# or off would hand the secret to whoever answers on the address; a value in quotes is read as without them), and it does not
# point the known-hosts file at /dev/null (every key would be new). accept-new is only warned about: board_ssh_secret puts
# StrictHostKeyChecking=yes first, so it has no effect on the PIN connection. The reason is printed on standard error.
ssh_secret_options_ok() {
	local tok joined=" "
	for tok in ${ssh_options[@]+"${ssh_options[@]}"}; do
		if [[ "$tok" =~ ^-[A-Za-z]*t[A-Za-z]*$ ]]; then
			echo "ssh: SLUIS_BOARD_SSH_OPTIONS asks for a terminal ($tok); a secret is never sent through one" >&2
			return 1
		fi
		joined="$joined${tok,,} "
	done
	# Quotes, and spaces around an =, do not change what ssh reads; -oKey=value and -o Key=value both end up as key=value.
	joined=${joined//[\"\']/}
	joined=${joined// = /=}
	joined=${joined//= /=}
	joined=${joined// =/=}
	joined=${joined//-ostricthostkeychecking/-o stricthostkeychecking}
	joined=${joined//-ouserknownhostsfile/-o userknownhostsfile}
	if [[ "$joined" =~ stricthostkeychecking(=|\ )(no|off|false)\  ]]; then
		echo "ssh: SLUIS_BOARD_SSH_OPTIONS turns off host-key checking (StrictHostKeyChecking=no); a secret is not sent over such a connection" >&2
		return 1
	fi
	if [[ "$joined" =~ userknownhostsfile(=|\ )/dev/null\  ]]; then
		echo "ssh: SLUIS_BOARD_SSH_OPTIONS points UserKnownHostsFile at /dev/null, so no host key is ever known; a secret is not sent over such a connection" >&2
		return 1
	fi
	if [[ "$joined" =~ stricthostkeychecking(=|\ )accept-new\  ]]; then
		echo "ssh: warning: StrictHostKeyChecking=accept-new is ignored for the PIN: the host key of the board must be known already (run boards-status for it first, without the PIN)" >&2
	fi
}
