package main

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

// A script starts or enables nothing (REQ-DEPLOY-049): an instance appears when a bootstrap file exists, and `sluis node apply`
// enables the target. `systemctl try-restart` is allowed: it restarts a unit that is running and never starts a stopped one.
var forbiddenVerbs = map[string]bool{
	"start": true, "restart": true, "reload-or-restart": true, "enable": true, "reenable": true, "preset": true, "preset-all": true,
	"link": true, "isolate": true, "add-wants": true, "add-requires": true, "set-default": true,
}

// Commands whose use is refused whatever the arguments: they start or enable by a route the verbs above do not see.
var forbiddenCommands = map[string]string{
	"deb-systemd-helper": "enables a unit", "deb-systemd-invoke": "starts a unit", "invoke-rc.d": "starts a unit",
	"service": "starts a unit", "chkconfig": "enables a unit", "update-rc.d": "enables a unit", "systemd-run": "starts a unit",
	"systemd-sysv-install": "enables a unit",
}

// Commands that run another command from a string or a variable, which the lint cannot read.
var indirect = map[string]bool{"eval": true, "xargs": true, "source": true, ".": true}

// Commands that delete accounts or state (decision D7: a package never deletes state or users).
var (
	deleteAccounts = map[string]bool{"userdel": true, "deluser": true, "groupdel": true, "delgroup": true}
	deletePaths    = map[string]bool{"rm": true, "rmdir": true, "unlink": true, "find": true, "shred": true, "mv": true, "truncate": true}
)

var statePath = regexp.MustCompile(`(^|[^A-Za-z0-9_-])/(etc/sluis|var/lib/sluis)`)

var wrappers = map[string]bool{"sudo": true, "exec": true, "command": true, "env": true, "nohup": true, "time": true, "nice": true,
	"if": true, "then": true, "do": true, "else": true, "elif": true, "while": true, "until": true, "!": true}

var assignment = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

var sysusersPath = regexp.MustCompile(`/usr/lib/(sysusers|tmpfiles)\.d/[A-Za-z0-9_.@-]+`)

// lintScript returns what is wrong with one maintainer script.
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
			toks := strings.Fields(cmd)
			// Leading assignments and wrappers are not the command.
			for len(toks) > 0 && (assignment.MatchString(toks[0]) || wrappers[path.Base(toks[0])]) {
				switch path.Base(toks[0]) {
				case "env", "sudo", "nice":
					for len(toks) > 1 && strings.HasPrefix(toks[1], "-") {
						toks = toks[1:]
					}
				}
				toks = toks[1:]
			}
			if len(toks) == 0 {
				continue
			}
			word := strings.Trim(toks[0], "\"'")
			if word == "" {
				continue
			}
			c := path.Base(word)
			args := toks[1:]
			switch {
			case strings.HasPrefix(toks[0], "$") || strings.HasPrefix(toks[0], "`"):
				bad("runs %q, a command taken from a variable or a substitution, which the lint cannot read", toks[0])
			case indirect[c]:
				bad("uses %s, which runs a command the lint cannot read", c)
			case (c == "sh" || c == "bash" || c == "dash") && contains(args, "-c"):
				bad("uses %s -c, which runs a command the lint cannot read", c)
			case forbiddenCommands[c] != "":
				bad("uses %s, which %s: a maintainer script starts or enables nothing (REQ-DEPLOY-049)", c, forbiddenCommands[c])
			case c == "systemctl":
				for _, a := range args {
					if strings.HasPrefix(a, "-") {
						continue
					}
					if forbiddenVerbs[a] {
						bad("runs systemctl %s: a maintainer script starts or enables nothing; try-restart is the one restart it may ask for (REQ-DEPLOY-049)", a)
					}
					break
				}
			case c == "ln" && (anyContains(args, ".wants") || anyContains(args, ".requires") || anyContains(args, "/etc/systemd/system")):
				bad("links into a .wants or .requires directory, which enables a unit by hand (REQ-DEPLOY-049)")
			case deleteAccounts[c]:
				bad("runs %s: a package never deletes a user or a group, the files of the uid stay owned by it (decision D7)", c)
			case deletePaths[c] && statePath.MatchString(" "+strings.Join(args, " ")):
				bad("runs %s on /etc/sluis or /var/lib/sluis*: a package never deletes state (decision D7)", c)
			case c == "systemd-tmpfiles" && (contains(args, "--remove") || contains(args, "--clean")):
				bad("runs systemd-tmpfiles with --remove or --clean: a package never deletes state (decision D7)")
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
func checkScripts(pk *Pkg) []string {
	var problems []string
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
