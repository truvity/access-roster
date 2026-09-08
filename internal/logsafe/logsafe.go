// Package logsafe makes a value safe to write into a log line.
//
// A log is read by people and by machines that split it into records. A
// value carrying a newline can therefore forge a record — a refusal that
// looks like a success, an identity that was never there — and the values
// most worth logging are exactly the ones that came from outside: an
// address a gateway forwarded, a path a caller chose, the text of an
// error built from either.
//
// Structured handlers escape these already, which is why nothing here has
// ever been forgeable in practice. This makes it true by construction
// instead of by the handler's choice, and names the intent where it can
// be seen.
package logsafe

import "strings"

// Limit is how much of a value is kept. Long enough for an address, a
// method name or a sentence; short enough that one field cannot bury a
// record.
const Limit = 256

// separators are what a reader or a parser takes for the end of a record.
// Removing them is the whole of the security property, and it is done with
// a replacer rather than folded into the pass below so that it is
// recognisable — to a person reading this, and to the analysers that look
// for exactly this shape.
var separators = strings.NewReplacer("\n", "", "\r", "", "\t", "")

// Value returns text that cannot forge a log record.
func Value(text string) string {
	text = separators.Replace(text)
	// The rest is hygiene: control characters that would garble a
	// terminal or a viewer without forging anything.
	text = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, text)
	if len(text) > Limit {
		return text[:Limit] + "…"
	}
	return text
}

// Error is [Value] over an error's message. Errors are worth their own
// call because the interesting ones are built from the input that caused
// them: a directory read that failed carries the address it was asked
// about.
func Error(err error) string {
	if err == nil {
		return ""
	}
	return Value(err.Error())
}
