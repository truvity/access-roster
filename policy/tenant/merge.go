package tenant

import (
	"maps"
	"slices"

	"github.com/truvity/sluis/policy/compile"
)

// merged is the base with the fragments added. It builds new maps and
// never writes to the base, but it shares the slices and rows of its inputs
// and the result must not be written to either. A rung gets the fragment's
// people appended to the base's and keeps the base's session duration; a
// rung the base does not declare is created with none. Any other key
// already in the model keeps its row: the checks refuse such a fragment
// before it gets here, so the rule only makes the function total.
func merged(base compile.Model, fragments ...Fragment) compile.Model {
	out := base

	out.Rungs = maps.Clone(base.Rungs)
	out.Projects = maps.Clone(base.Projects)
	out.Applications = maps.Clone(base.Applications)
	out.GitHub = maps.Clone(base.GitHub)
	out.Slack = maps.Clone(base.Slack)
	out.Jobs = maps.Clone(base.Jobs)
	out.Workloads = maps.Clone(base.Workloads)

	for _, f := range fragments {
		if len(f.Rungs) > 0 && out.Rungs == nil {
			out.Rungs = map[string]compile.Rung{}
		}

		for name, people := range f.Rungs {
			rung := out.Rungs[name]
			rung.Groups = slices.Concat(rung.Groups, people.Groups)
			rung.Users = slices.Concat(rung.Users, people.Users)
			out.Rungs[name] = rung
		}

		out.Projects = addRows(out.Projects, f.Projects)
		out.Applications = addRows(out.Applications, f.Applications)
		out.GitHub = addRows(out.GitHub, f.GitHub)
		out.Slack = addRows(out.Slack, f.Slack)
		out.Jobs = addRows(out.Jobs, f.Jobs)
		out.Workloads = addRows(out.Workloads, f.Workloads)
	}

	return out
}

// addRows puts the rows whose key is not yet in the map into it, creating
// the map when there is something to add.
func addRows[V any](into, rows map[string]V) map[string]V {
	if len(rows) > 0 && into == nil {
		into = map[string]V{}
	}

	for k, v := range rows {
		if _, ok := into[k]; !ok {
			into[k] = v
		}
	}

	return into
}
