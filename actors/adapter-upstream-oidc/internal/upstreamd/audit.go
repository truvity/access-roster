package upstreamd

import "github.com/truvity/sluis/v2/kits/go/audit"

// OCSF class 3002 is Authentication (0030 "The class mapping": a sign-in through an upstream is 3002 / 1 Logon).
// Begin is not a logon: it is activity 99, which names itself. The table is code (0030 "The action table is code").
const classAuthentication = 3002

// The actions of the adapter: metadata.event_code.
const (
	ActionBegin    = "upstream.begin"
	ActionComplete = "upstream.complete"
)

var (
	actionBegin    = audit.Action{Name: ActionBegin, ClassUID: classAuthentication, ActivityID: 99, ActivityName: "Upstream Begin"}
	actionComplete = audit.Action{Name: ActionComplete, ClassUID: classAuthentication, ActivityID: 1}
)

// subjectKind is the Kind of the pseudonym of a person who signed in at an upstream. The adapter does not know the
// sluis subject, which session assigns, so the identifier is the upstream's issuer and subject (0029 "Pseudonyms").
const subjectKind = "person"
