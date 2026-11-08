package pkgs

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
)

// The lint of the maintainer scripts and of the units in the driver packages. It reads the text, so it is a tripwire for the ways
// a script usually starts or enables a unit or deletes state, and not a proof that none does: the proof is the lifecycle test of
// the install tier, which looks at the units and the state after install, upgrade, removal and reinstall.

// The lint of a planned script is a tripwire. It reads text, so it cannot see everything a shell can do; the guard that does not
// depend on it is that a package has no script the plan does not list (the plan has none today), and the proof is the lifecycle
// test of the install tier, which looks at the units and the state after install, upgrade, removal and reinstall.

// A script starts or enables nothing (REQ-DEPLOY-049): an instance appears when a bootstrap file exists, and `sluis node apply`
// enables the target. `systemctl try-restart` is allowed: it restarts a unit that is running and never starts a stopped one.
var forbiddenVerbs = map[string]bool{
	"start": true, "restart": true, "reload-or-restart": true, "enable": true, "reenable": true, "preset": true, "preset-all": true,
	"link": true, "isolate": true, "add-wants": true, "add-requires": true, "set-default": true,
}

// Commands whose use is refused whatever the arguments, wherever they stand in the command (after timeout, setsid, flock, su -c,
// runuser, env, a pipe): they start or enable by a route the verbs above do not see, or run text the lint cannot read.
var forbiddenCommands = map[string]string{
	"deb-systemd-helper": "enables a unit", "deb-systemd-invoke": "starts a unit", "invoke-rc.d": "starts a unit",
	"service": "starts a unit", "chkconfig": "enables a unit", "update-rc.d": "enables a unit", "systemd-run": "starts a unit",
	"systemd-sysv-install": "enables a unit", "busctl": "talks to systemd by D-Bus", "dbus-send": "talks to systemd by D-Bus",
	"gdbus": "talks to systemd by D-Bus", "machinectl": "starts a unit", "eval": "runs text the lint cannot read",
	"xargs": "runs text the lint cannot read", "source": "runs a file the lint cannot read", ".": "runs a file the lint cannot read",
	"sh": "runs a script the lint cannot read", "bash": "runs a script the lint cannot read", "dash": "runs a script the lint cannot read",
	"zsh": "runs a script the lint cannot read", "ksh": "runs a script the lint cannot read", "busybox": "runs a script the lint cannot read",
	"php": "runs a script the lint cannot read", "tclsh": "runs a script the lint cannot read", "python": "runs a script the lint cannot read", "python3": "runs a script the lint cannot read", "perl": "runs a script the lint cannot read",
	"ruby": "runs a script the lint cannot read", "lua": "runs a script the lint cannot read", "node": "runs a script the lint cannot read",
}

// Commands that delete accounts or state (decision D7: a package never deletes state or users).
var (
	deleteAccounts = map[string]bool{"userdel": true, "deluser": true, "groupdel": true, "delgroup": true}
	deletePaths    = map[string]bool{"rm": true, "rmdir": true, "unlink": true, "find": true, "shred": true, "mv": true, "truncate": true}
	recursiveOwn   = map[string]bool{"chown": true, "chmod": true, "chgrp": true}
)

// writeCmds are the commands that write or replace a file: with an argument that may name state they are refused (cp /dev/null F,
// tee F, dd of=F, install, touch, truncate is among the deleters).
var writeCmds = map[string]bool{"cp": true, "tee": true, "dd": true, "install": true, "touch": true, "mkdir": true}

// redirect finds the target of > and >> in the text of a simple command.
var redirect = regexp.MustCompile(`>>?\s*("[^"]*"|'[^']*'|[^\s;|&<>()]+)`)

// valueOf is the value of key=value (dd of=F), and the argument itself otherwise.
func valueOf(a string) string {
	if k, v, ok := strings.Cut(unquote(a), "="); ok && !strings.ContainsAny(k, "/ ") {
		return v
	}
	return a
}

func anyStateish(a []string) bool {
	for _, x := range a {
		if stateish(x) {
			return true
		}
	}
	return false
}

func anyHasPrefix(a []string, prefix string) bool {
	for _, x := range a {
		if strings.HasPrefix(x, prefix) && !strings.HasPrefix(x, "--") {
			return true
		}
	}
	return false
}

func anyContainsChars(a []string, chars string) bool {
	for _, x := range a {
		if strings.ContainsAny(x, chars) {
			return true
		}
	}
	return false
}

var wrappers = map[string]bool{"sudo": true, "exec": true, "command": true, "env": true, "nohup": true, "time": true, "nice": true,
	"if": true, "then": true, "do": true, "else": true, "elif": true, "while": true, "until": true, "!": true}

var assignment = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

var sysusersPath = regexp.MustCompile(`/usr/lib/(sysusers|tmpfiles)\.d/[A-Za-z0-9_.@-]+`)

func unquote(t string) string { return strings.Trim(t, "\"'\\") }

// stateish says whether an argument names, or may name, the configuration or the state of sluis: a path of them in any form
// (// and ./ are cleaned), a relative name that holds sluis, or a variable or substitution, whose value the lint cannot see.
func stateish(a string) bool {
	a = unquote(a)
	if strings.ContainsAny(a, "$`") {
		return true
	}
	c := path.Clean(a)
	return strings.HasPrefix(c, "/etc/sluis") || strings.HasPrefix(c, "/var/lib/sluis") || strings.Contains(c, "sluis-state") ||
		(strings.Contains(c, "sluis") && !strings.HasPrefix(c, "/usr/"))
}

// lintScript returns what is wrong with one planned maintainer script.
func lintScript(name, text string) []string {
	var problems []string
	bad := func(format string, a ...any) {
		problems = append(problems, fmt.Sprintf("the script %s ", name)+fmt.Sprintf(format, a...))
	}
	text = strings.ReplaceAll(text, "\\\n", " ")
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		for _, cmd := range splitCommands(line) {
			for _, m := range redirect.FindAllStringSubmatch(cmd, -1) {
				if t := unquote(m[1]); !strings.HasPrefix(t, "&") && t != "/dev/null" && stateish(t) {
					bad("redirects to %q: a package writes no file of /etc/sluis or /var/lib/sluis*, and a target from a variable is refused (decision D7)", t)
				}
			}
			toks := strings.Fields(cmd)
			for len(toks) > 0 && (assignment.MatchString(toks[0]) || wrappers[path.Base(toks[0])]) {
				toks = toks[1:]
			}
			if len(toks) == 0 {
				continue
			}
			if w := unquote(toks[0]); strings.HasPrefix(w, "$") || strings.HasPrefix(w, "`") {
				bad("runs %q, a command taken from a variable or a substitution, which the lint cannot read", toks[0])
				continue
			}
			// Every word is looked at, not the first: timeout 5 systemctl start, setsid, flock f, su -c 'systemctl start x'.
			words := make([]string, len(toks))
			for k, t := range toks {
				words[k] = unquote(t)
			}
			for k, w := range words {
				if w == "" {
					continue
				}
				c := path.Base(w)
				args := words[k+1:]
				switch {
				case forbiddenCommands[c] != "" && (c != "." || k == 0):
					bad("uses %s, which %s: a maintainer script starts or enables nothing and runs nothing it cannot be read for (REQ-DEPLOY-049)", c, forbiddenCommands[c])
				case c == "systemctl":
					for _, a := range args {
						if forbiddenVerbs[a] {
							bad("runs systemctl %s: a maintainer script starts or enables nothing; try-restart is the one restart it may ask for (REQ-DEPLOY-049)", a)
						}
						if strings.ContainsAny(a, "$`") {
							bad("runs systemctl with %q, a verb or unit from a variable, which the lint cannot read", a)
						}
					}
				case c == "ln" && (anyContains(args, ".wants") || anyContains(args, ".requires") || anyContains(args, "/etc/systemd/system")):
					bad("links into a .wants or .requires directory, which enables a unit by hand (REQ-DEPLOY-049)")
				case deleteAccounts[c]:
					bad("runs %s: a package never deletes a user or a group, the files of the uid stay owned by it (decision D7)", c)
				case deletePaths[c]:
					for _, a := range args {
						if stateish(a) {
							bad("runs %s on %q: a package never deletes state, and an argument that may name /etc/sluis or /var/lib/sluis* is refused (decision D7)", c, a)
							break
						}
						if strings.ContainsAny(unquote(a), "*?[") {
							bad("runs %s on the glob %q, which may reach /etc/sluis or /var/lib/sluis*: a package never deletes state (decision D7)", c, a)
							break
						}
					}
					if c == "find" && (contains(args, "-delete") || contains(args, "-exec") || contains(args, "-execdir")) {
						bad("runs find with -delete or -exec: a package never deletes state (decision D7)")
					}
				case writeCmds[c] || (c == "sed" && (contains(args, "-i") || anyHasPrefix(args, "-i") || contains(args, "--in-place"))):
					for _, a := range args {
						if stateish(valueOf(a)) {
							bad("runs %s with %q: a package writes no file of /etc/sluis or /var/lib/sluis* (decision D7)", c, a)
							break
						}
					}
					if c == "cp" && (contains(args, "-s") || contains(args, "--symbolic-link")) {
						bad("runs cp -s: a symbolic link is made by hand, as ln -s is (REQ-DEPLOY-049)")
					}
				case c == "ln" && anyContainsChars(args, "$`"):
					bad("runs ln into a path from a variable, which may be a .wants directory or the state (REQ-DEPLOY-049, decision D7)")
				case c == "ln" && anyStateish(args):
					bad("runs ln on a path of /etc/sluis or /var/lib/sluis* (decision D7)")
				case (c == "awk" || c == "gawk" || c == "mawk") && (contains(args, "-f") || contains(args, "--file")):
					bad("runs %s -f, a program from a file the lint cannot read", c)
				case recursiveOwn[c]:
					for _, a := range args {
						if a == "-R" || a == "--recursive" || (strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && strings.Contains(a, "R")) {
							bad("runs %s recursively: a package changes no state, and a recursive change reaches /var/lib/sluis-state (decision D7)", c)
						}
					}
				case c == "systemd-tmpfiles" && (contains(args, "--remove") || contains(args, "--clean")):
					bad("runs systemd-tmpfiles with --remove or --clean: a package never deletes state (decision D7)")
				}
			}
		}
	}
	return problems
}

func contains(a []string, s string) bool {
	for _, x := range a {
		if x == s {
			return true
		}
	}
	return false
}

func anyContains(a []string, sub string) bool {
	for _, x := range a {
		if strings.Contains(x, sub) {
			return true
		}
	}
	return false
}

var separators = regexp.MustCompile(`&&|\|\||[;|&(){}\n]`)

func splitCommands(line string) []string {
	var res []string
	for _, c := range separators.Split(line, -1) {
		if c = strings.TrimSpace(c); c != "" {
			res = append(res, c)
		}
	}
	return res
}

// checkScripts lints the maintainer scripts of a package: only the four of dpkg and the rpm scriptlets that match them, nothing
// that starts, enables or deletes, and every sysusers or tmpfiles file a script names is a file of the package (a script that
// skipped a missing file silently left the driver's user uncreated in the spike, and the unit then failed with status 217/USER).
func checkScripts(pk *Pkg, s Spec) []string {
	var problems []string
	// The plan says which scripts a package has: none today. A script that is not planned is a failure whatever it says, and the
	// text of a planned one is the planned text; only planned text is linted, so the lint is not the only guard.
	for n, body := range s.Scripts {
		if got, ok := pk.Scripts[n]; !ok {
			problems = append(problems, fmt.Sprintf("lacks the planned script %s", n))
		} else if strings.TrimSpace(got) != strings.TrimSpace(body) {
			problems = append(problems, fmt.Sprintf("the script %s is not the planned one", n))
		}
	}
	for n := range pk.Scripts {
		if _, ok := s.Scripts[n]; !ok {
			problems = append(problems, fmt.Sprintf("has the script %s, which the plan does not have: a package has no script that is not planned", n))
		}
	}
	names := make([]string, 0, len(pk.Scripts))
	for n := range pk.Scripts {
		names = append(names, n)
	}
	sort.Strings(names)
	have := map[string]bool{}
	for _, f := range pk.Files {
		have[f.Path] = true
	}
	for _, n := range names {
		switch n {
		case "preinst", "postinst", "prerm", "postrm":
		default:
			problems = append(problems, fmt.Sprintf("has the scriptlet %s, which is none of preinst, postinst, prerm and postrm", n))
		}
		problems = append(problems, lintScript(n, pk.Scripts[n])...)
		for _, p := range sysusersPath.FindAllString(pk.Scripts[n], -1) {
			if !have[p] {
				problems = append(problems, fmt.Sprintf("the script %s names %s, which the package does not hold", n, p))
			}
		}
	}
	return problems
}

var installSection = regexp.MustCompile(`(?m)^\s*\[Install\]`)

// checkDriverUnits is REQ-SUPPLY-028: a driver package installs no service for an operator to start. A unit file in it is allowed
// only as a template service (`name@.service`) with no [Install] section, which `systemctl enable` cannot enable and which only
// the owner's unit can start with Requires=; no socket, timer, path or target, no .wants or .requires link, and no preset.
func checkDriverUnits(pk *Pkg) []string {
	var problems []string
	for _, f := range pk.Files {
		switch {
		case strings.Contains(f.Path, ".wants/") || strings.Contains(f.Path, ".requires/") || strings.Contains(f.Path, "/system-preset/") || strings.Contains(f.Path, "/system-generators/"):
			problems = append(problems, fmt.Sprintf("a driver package holds %s, which enables or starts a unit by itself (REQ-SUPPLY-028)", f.Path))
		case f.Kind == 'f' && strings.HasPrefix(f.Path, "/usr/lib/systemd/system/"):
			base := path.Base(f.Path)
			if !strings.HasSuffix(base, "@.service") {
				problems = append(problems, fmt.Sprintf("a driver package holds the unit %s, which is not a template service (REQ-SUPPLY-028)", f.Path))
			} else if installSection.Match(f.Body) {
				problems = append(problems, fmt.Sprintf("the unit %s of a driver package has an [Install] section, so an operator can enable it (REQ-SUPPLY-028)", f.Path))
			}
		}
	}
	return problems
}
