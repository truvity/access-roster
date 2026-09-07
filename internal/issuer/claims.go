package issuer

import (
	"github.com/truvity/access-roster/policy"
)

// Claims are what a token carries beyond the fixed identity fields: the
// deep merge of every held group's fragment, with the group names under
// `groups` because that is the claim relying parties already read.
//
// The merge and the group names are the policy package's work, shared
// with the hub, so that what an operator sees on a group's page and what
// lands in a token cannot drift apart: one implementation, two readers.
// What is left here is the wire: yaml.v3 leaves its own named map type
// behind on nested mappings, and a JWT library marshalling that will
// either refuse it or emit something a relying party cannot read, so the
// fragments are flattened to plain Go maps on the way out.
func Claims(result policy.Result) map[string]any {
	plain, ok := policy.Plain(result.Claims).(map[string]any)
	if !ok {
		return map[string]any{}
	}
	return plain
}
