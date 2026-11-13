package tenant

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"go.yaml.in/yaml/v3"

	"github.com/truvity/sluis/policy"
	"github.com/truvity/sluis/policy/compile"
)

// The wire shapes. They exist for the keys: [compile.Population] and
// [compile.Project] carry no tags, and a company writes snake_case.
type (
	populationWire struct {
		Groups []string `yaml:"groups"`
		Users  []string `yaml:"users"`
	}

	projectWire struct {
		Scopes       []string `yaml:"scopes"`
		SecretScopes []string `yaml:"secret_scopes"`
		ViewerScopes []string `yaml:"viewer_scopes"`
		Deployers    []string `yaml:"deployers"`
		Approvers    []string `yaml:"approvers"`
		Viewers      []string `yaml:"viewers"`
		ViewerUsers  []string `yaml:"viewer_users"`
	}

	fragmentWire struct {
		Rungs        map[string]populationWire         `yaml:"rungs"`
		Projects     map[string]projectWire            `yaml:"projects"`
		Applications map[string]populationWire         `yaml:"applications"`
		GitHub       map[string]compile.GitHubOrg      `yaml:"github"`
		Slack        map[string]compile.SlackWorkspace `yaml:"slack"`
		Jobs         map[string]compile.GitHubJob      `yaml:"jobs"`
		Workloads    map[string]workloadWire           `yaml:"workloads"`
		AppGrants    map[string][]AppGrant             `yaml:"app_grants"`
		Gates        map[string]gateWire               `yaml:"gates"`
	}

	// gateWire is a [Gate] as a company writes it.
	gateWire struct {
		DisplayName string          `yaml:"display_name"`
		Description string          `yaml:"description"`
		Redirects   []string        `yaml:"redirects"`
		SignedOut   []string        `yaml:"signed_out"`
		Requires    []string        `yaml:"requires"`
		TTLCap      policy.Duration `yaml:"ttl_cap"`
	}

	// workloadWire reads `aws` as a node so that its keys are checked as
	// strictly as every other: the decoder's strictness does not reach a
	// type that decodes a node itself.
	workloadWire struct {
		Cluster   string    `yaml:"cluster"`
		Namespace string    `yaml:"namespace"`
		Name      string    `yaml:"name"`
		Why       string    `yaml:"why"`
		AWS       yaml.Node `yaml:"aws"`
	}
)

// DecodeFragment reads a fragment from YAML or JSON. An unknown key is an
// error, which is how a key the fragment has no field for (the scopes
// matrix, the vocabulary, a lifetime, a rung's session length) is refused
// instead of ignored. An empty document is an empty fragment, and a second
// document is an error.
func DecodeFragment(data []byte) (Fragment, error) {
	var w fragmentWire

	if err := decodeStrict(data, &w); err != nil {
		return Fragment{}, fmt.Errorf("fragment: %w", err)
	}

	f := Fragment{
		Rungs:        populations(w.Rungs),
		Applications: populations(w.Applications),
		GitHub:       w.GitHub,
		Slack:        w.Slack,
		Jobs:         w.Jobs,
	}

	if len(w.AppGrants) > 0 {
		f.AppGrants = w.AppGrants
	}

	if len(w.Gates) > 0 {
		f.Gates = make(map[string]Gate, len(w.Gates))

		for id := range w.Gates {
			f.Gates[id] = Gate(w.Gates[id])
		}
	}

	if len(w.Projects) > 0 {
		f.Projects = make(map[string]compile.Project, len(w.Projects))

		for name := range w.Projects {
			f.Projects[name] = compile.Project(w.Projects[name])
		}
	}

	if len(w.Workloads) > 0 {
		f.Workloads = make(map[string]compile.Workload, len(w.Workloads))

		for key := range w.Workloads {
			wl := w.Workloads[key]
			workload := compile.Workload{Cluster: wl.Cluster, Namespace: wl.Namespace, Name: wl.Name, Why: wl.Why}

			if !wl.AWS.IsZero() {
				roles, err := decodeAWS(&wl.AWS)
				if err != nil {
					return Fragment{}, fmt.Errorf("fragment: workloads[%s].aws: %w", key, err)
				}

				workload.AWS = roles
			}

			f.Workloads[key] = workload
		}
	}

	return f, nil
}

// DecodeCeiling reads a ceiling from YAML or JSON and validates it. An empty
// document is the zero ceiling, which allows nothing.
func DecodeCeiling(data []byte) (Ceiling, error) {
	var c Ceiling

	if err := decodeStrict(data, &c); err != nil {
		return Ceiling{}, fmt.Errorf("ceiling: %w", err)
	}

	if err := c.Validate(); err != nil {
		return Ceiling{}, fmt.Errorf("ceiling: %w", err)
	}

	return c, nil
}

// decodeStrict decodes exactly one document and refuses an unknown key.
func decodeStrict(data []byte, into any) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)

	if err := dec.Decode(into); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}

		return err //nolint:wrapcheck // the decoder's message carries the line
	}

	var rest yaml.Node
	if err := dec.Decode(&rest); err == nil {
		return errors.New("more than one document")
	} else if !errors.Is(err, io.EOF) {
		return err //nolint:wrapcheck // the decoder's message carries the line
	}

	return nil
}

// decodeAWS reads `aws` as one mapping or a list of mappings, strictly.
func decodeAWS(node *yaml.Node) (compile.WorkloadAWSRoles, error) {
	nodes := []*yaml.Node{node}
	if node.Kind == yaml.SequenceNode {
		nodes = node.Content
	}

	roles := make(compile.WorkloadAWSRoles, 0, len(nodes))

	for _, n := range nodes {
		var role compile.WorkloadAWS

		if err := strictNode(n, &role); err != nil {
			return nil, err
		}

		roles = append(roles, role)
	}

	return roles, nil
}

// strictNode decodes a node into a value and refuses an unknown key. A
// node is re-encoded because [yaml.Node.Decode] has no strict mode.
func strictNode(n *yaml.Node, into any) error {
	raw, err := yaml.Marshal(n)
	if err != nil {
		return fmt.Errorf("re-encode: %w", err)
	}

	return decodeStrict(raw, into)
}

func populations(in map[string]populationWire) map[string]compile.Population {
	if len(in) == 0 {
		return nil
	}

	out := make(map[string]compile.Population, len(in))

	for name, p := range in {
		out[name] = compile.Population(p)
	}

	return out
}
