package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"strings"
	"text/tabwriter"
	"unicode"

	"github.com/truvity/sluis/v2/kits/go/cli"
)

// configField is one setting of `sluis config explain`: the `fields` member of cli.md "JSON output". Value is the
// effective value, or `sha384:` and the digest of one that is long or holds a control character; for a credential it
// is the reference (the name of the credential in the secret source) and Secret is true. Class is `-` for a setting of
// the bootstrap file, which is not a kind; Version is empty for it, which has none. Checks names the checks of
// `config check` that cover the setting.
type configField struct {
	Path    string `json:"path"`
	Value   string `json:"value"`
	Class   string `json:"class"`
	Layer   string `json:"layer"`
	Version string `json:"version"`
	Source  string `json:"source"`
	Secret  bool   `json:"secret,omitempty"`
	// Digest says that Value is `sha384:` and the digest of what the file holds, not the value.
	Digest bool     `json:"digest,omitempty"`
	Checks []string `json:"checks,omitempty"`
}

// explainGroup is what the helper prints: settings that share one provenance, so that the class, layer, version,
// source and checks are written once for a document and not on each of its settings. The CLI writes one field for each
// setting (cli.md "JSON output").
type explainGroup struct {
	Class    string   `json:"class"`
	Layer    string   `json:"layer"`
	Version  string   `json:"version"`
	Source   string   `json:"source"`
	Checks   []string `json:"checks"`
	Settings []struct {
		Path   string `json:"path"`
		Value  string `json:"value"`
		Secret bool   `json:"secret"`
		Digest bool   `json:"digest"`
	} `json:"settings"`
}

func (g explainGroup) fields() []configField {
	out := make([]configField, 0, len(g.Settings))
	for _, s := range g.Settings {
		out = append(out, configField{
			Path: s.Path, Value: s.Value, Class: g.Class, Layer: g.Layer, Version: g.Version, Source: g.Source,
			Secret: s.Secret, Digest: s.Digest, Checks: g.Checks,
		})
	}
	return out
}

// sourceDigestShown is how many hex digits of a document's digest the text output shows; the JSON output has all.
const sourceDigestShown = 12

// configExplainCommand is `sluis config explain DIR` (cli.md "sluis config check and explain"; REQ-OPS-023). It runs
// the same store helper as `config check`, with `--explain`: the helper loads the bootstrap file and the signed
// documents with store@'s own code and describes the set it accepts, so that the CLI never reads a document and the
// values are those store@ would run with. A set that is refused is not explained: the failed checks are printed, as
// `config check` prints them, and the command exits 3.
func (a *app) configExplainCommand() command {
	var bootstrap, helper string
	var field optionalString
	var live bool
	return command{
		name: "config explain",
		flags: func(fs *flag.FlagSet) {
			fs.BoolVar(&live, "live", false, liveHelp)
			fs.StringVar(&bootstrap, "bootstrap", "", "the bootstrap file; by default /etc/sluis/bootstrap.d/<boundary>.yaml")
			fs.Var(&field, "field", "print only the settings under this path, such as durable or Upstream.workforce.issuer")
			fs.StringVar(&helper, "helper", "", "the store executable that reads the files; by default $"+helperEnv+
				", then store beside this executable, then ../libexec/sluis/actors/store beside it")
		},
		run: func(ctx context.Context, positional []string, res *result) error {
			if len(positional) != 1 {
				return cli.Usage(errors.New("config explain takes one argument, the directory of the signed config documents"))
			}
			if live {
				return errLive
			}
			// A flag that is given and empty is an unset variable in `--field "$FIELD"`: it must not explain everything.
			if field.set && strings.TrimSpace(field.value) == "" {
				return cli.Usage(errors.New("--field names a path, such as durable or Upstream.workforce.issuer"))
			}
			bootstrap, err := a.bootstrapFile(bootstrap)
			if err != nil {
				return err
			}
			return a.configExplain(ctx, positional[0], bootstrap, helper, field.value, res)
		},
	}
}

func (a *app) configExplain(ctx context.Context, dir, bootstrap, helper, field string, res *result) error {
	more := []string{"--explain"}
	if field != "" {
		more = append(more, "--field", field)
	}
	stdout, code, path, err := a.runStore(ctx, "config explain", dir, bootstrap, helper, explainOutputMax,
		"; name fewer settings with --field PATH", more...)
	if err != nil {
		return err
	}
	var out struct {
		Checks []configCheck  `json:"checks"`
		Groups []explainGroup `json:"groups"`
	}
	if err := json.Unmarshal(stdout, &out); err != nil || len(out.Checks) == 0 {
		return fmt.Errorf("the store helper %s printed no checks: is it the store executable of this release?", path)
	}
	// A set that fails a check has no effective values: the failed lines are the answer, as for `config check`.
	if err := a.finishChecks(out.Checks, code, res); err != nil {
		return err
	}
	res.Text = ""
	var fields []configField
	for _, g := range out.Groups {
		fields = append(fields, g.fields()...)
	}
	if len(fields) == 0 {
		if field != "" {
			return cli.Usage(fmt.Errorf("--field %s: no setting is at that path (a setting that a file leaves out has no entry: "+
				"the built-in layer of the documents is not built yet)", field))
		}
		return fmt.Errorf("the store helper %s printed no settings: is it the store executable of this release?", path)
	}
	res.Fields = fields
	res.Text = explainText(fields)
	return nil
}

// explainText is the table a person reads. It is one line for each setting, with the columns of the JSON members. A
// unsafe character in a field (see clean) is shown as ?, so that no document can write an escape sequence to a terminal; the
// helper already replaces such a value by its digest, and this holds if a helper does not.
func explainText(fields []configField) string {
	var b bytes.Buffer
	w := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "PATH\tVALUE\tCLASS\tLAYER\tVERSION\tSOURCE")
	for _, f := range fields {
		value := clean(f.Value)
		if f.Secret {
			value += " (secret reference, not resolved)"
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", clean(f.Path), value, dash(clean(f.Class)),
			dash(clean(f.Layer)), dash(clean(f.Version)), dash(shortSource(clean(f.Source))))
	}
	_ = w.Flush()
	return strings.TrimRight(b.String(), "\n")
}

// shortSource shortens `Kind:seq:sha384` to the first digits of the digest. The JSON output has the whole of it.
func shortSource(s string) string {
	parts := strings.Split(s, ":")
	if len(parts) == 3 && len(parts[2]) > sourceDigestShown {
		parts[2] = parts[2][:sourceDigestShown]
	}
	return strings.Join(parts, ":")
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// clean replaces each control character (Cc), invisible format character (Cf: bidirectional controls, zero-width
// characters, tags) and line or paragraph separator (Zl, Zp) by ?.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.In(r, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp) {
			return '?'
		}
		return r
	}, s)
}
