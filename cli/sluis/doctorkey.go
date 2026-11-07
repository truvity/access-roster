package main

import (
	"context"
	"errors"
	"fmt"
)

// The checks of `doctor` that ask key@ (cli.md, "sluis doctor"): where its keys are held, and how long the certificates
// of its keys last (ADR 0024, "Lifetimes and the warning"). They use the status call of `key status`, so they need
// `--boundary` (or `--socket`) and root, and they only read.
//
// A warning is exit 10 whatever it is about (finishDoctor), so only a level above a notice raises the code here.
//
// A key@ with no admin socket on this host is not a failure: `doctor` is also run before key@ exists, and then the
// checks say `not-run`. A key@ that has a socket and cannot answer is a failure (exit 1): a caller that cannot ask does
// not know.

// doctorKey runs the checks of key@. It returns the checks, the exit code of the highest expiry level among them (0, 10, 11
// or 12), and the error of a key@ that could not be asked, if any.
func (a *app) doctorKey(ctx context.Context, socketFlag string) ([]configCheck, int, error) {
	c := configCheck{Name: "key-store", Path: "key.store"}
	if socketFlag == "" && a.boundary == "" {
		c.Result, c.Note = resultNotRun, "key@ was not asked: name the boundary with --boundary (or --socket) to check its store and the expiry of its certificates"
		return []configCheck{c}, 0, nil
	}
	sock, err := a.keyStatusSocket(socketFlag)
	if err != nil {
		return nil, 0, err
	}
	st, err := a.askKeyStatus(ctx, sock)
	switch {
	case errors.Is(err, errNoKeySocket):
		c.Result, c.Note = resultNotRun, "key@ has no admin socket on this host, so its store and certificates are not checked"
		return []configCheck{c}, 0, nil
	case err != nil:
		c.Result, c.Note = resultNotRun, err.Error()
		return []configCheck{c}, 0, err
	}

	checks := []configCheck{checkKeyStore(st)}
	exit := 0
	for _, k := range st.keys {
		if k.NotAfter == "" {
			if needsCertificate(k.Purpose) {
				checks = append(checks, configCheck{Name: "certificate", Path: k.Purpose, Result: resultWarn,
					Note: k.Purpose + " has no certificate installed; run sluis key request and sluis key install"})
			}
			continue
		}
		e := configCheck{Name: "expiry", Path: k.Purpose, Result: resultOK}
		switch k.Level {
		case levelNotice, levelAlert, levelCritical:
			e.Result, e.Note = resultWarn, k.Level+": "+expiryPhrase(k) // names the purpose
			exit = max(exit, k.code)
		default:
			e.Note = fmt.Sprintf("the certificate of %s ends on %s, in %d days", k.Purpose, k.NotAfter[:10], *k.DaysLeft)
		}
		checks = append(checks, e)
	}
	return checks, exit, nil
}

// checkKeyStore says where key@ keeps its keys, and holds the floor of the software store: ok in development, a warning in
// staging, and a failure in production, which key@ refuses at its start (ADR 0006, "Floors in code").
func checkKeyStore(st *keyStatus) configCheck {
	c := configCheck{Name: "key-store", Path: "key.store"}
	switch {
	case st.store == "software" && st.environment == "production":
		c.Result, c.Note = resultFail, "key@ holds its keys in software in a production boundary, which its floor refuses"
	case st.store == "software" && st.environment == "staging":
		c.Result, c.Note = resultWarn, "key@ holds its keys in software in a staging boundary: they are not hardware-held"
	case st.store == "software":
		c.Result, c.Note = resultOK, "key@ holds its keys in software, in a development boundary: they guard development data only"
	default:
		c.Result, c.Note = resultOK, "key@ holds its keys in the store "+quoteShort(st.store)
	}
	return c
}
