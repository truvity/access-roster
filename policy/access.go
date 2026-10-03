package policy

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"slices"

	"go.yaml.in/yaml/v3"
)

// An access document is the list-shaped form an installation's own
// tooling derives from its access matrix: who holds which group, the
// directories' channel and team bindings, the declared clients. This file
// turns it into the layer [Parse] reads, so that an installation passes
// the document through and does not hand-write the reshaping (lists to
// tables, camelCase to snake_case, the estate's own rows appended to the
// groups they belong to) in a template of its own. See ADR 0032: one
// configuration file, validated as a whole.
//
// It adds no concept to the policy. Every key below maps to a key of
// [Policy] one for one; [Access.Policy] is a reshaping and nothing else,
// and the result goes through the same Parse, merge and Validate as a
// layer written by hand.

// AccessDocument is one file: the access sections and the estate overlay.
//
//	version: 1
//	access:
//	  lifetimes: {default: 4h}
//	  groups:
//	    - name: env:ssh:admin
//	      emails: [ada@example.com]
//	overlay:
//	  groups:
//	    all:access-roster:operator:
//	      matchers: [...]
type AccessDocument struct {
	// Version is the policy schema's, as in [Policy.Version].
	Version int `yaml:"version"`
	// Access is the derived part, the same for every installation of an
	// estate.
	Access Access `yaml:"access"`
	// Overlay is the part that is this installation's own: how it is
	// reached before a directory can vouch for anybody, and the clients
	// that are not relying parties of the access matrix.
	Overlay AccessOverlay `yaml:"overlay,omitempty"`
}

// Access is the derived part of an [AccessDocument].
type Access struct {
	Lifetimes       map[string]Duration    `yaml:"lifetimes,omitempty"`
	Groups          []AccessGroup          `yaml:"groups,omitempty"`
	People          []AccessPerson         `yaml:"people,omitempty"`
	Slack           []AccessWorkspace      `yaml:"slack,omitempty"`
	GitHub          []AccessOrg            `yaml:"github,omitempty"`
	Vocabulary      *AccessVocabulary      `yaml:"vocabulary,omitempty"`
	Clients         []AccessClient         `yaml:"clients,omitempty"`
	ClientDocuments *AccessClientDocuments `yaml:"clientDocuments,omitempty"`
	Resources       []AccessResource       `yaml:"resources,omitempty"`
}

// AccessGroup is one internal group and everything that admits a caller
// to it, in the order [Access.Policy] writes the matchers.
type AccessGroup struct {
	Name string `yaml:"name"`
	// Members are directory groups.
	Members []string `yaml:"members,omitempty"`
	// Emails admit one signed-in address each.
	Emails []string `yaml:"emails,omitempty"`
	// GitHub admits a CI job by what its verified token says. Only the
	// fields below are carried; a derivation that needs another asks for
	// it here, in the open.
	GitHub []AccessGitHubJob `yaml:"github,omitempty"`
	// ServiceAccounts admit one ServiceAccount on one named cluster.
	ServiceAccounts []ServiceAccountMatcher `yaml:"service_accounts,omitempty"`
	// AWS admits one IAM role in one registered account.
	AWS []AccessAWSRole `yaml:"aws,omitempty"`
}

// AccessGitHubJob is the part of a [GitHubMatcher] a derived group
// carries.
type AccessGitHubJob struct {
	Repository     string `yaml:"repository,omitempty"`
	Owner          string `yaml:"owner,omitempty"`
	Visibility     string `yaml:"visibility,omitempty"`
	Ref            string `yaml:"ref,omitempty"`
	RefType        string `yaml:"ref_type,omitempty"`
	EventName      string `yaml:"event_name,omitempty"`
	WorkflowRef    string `yaml:"workflow_ref,omitempty"`
	JobWorkflowRef string `yaml:"job_workflow_ref,omitempty"`
}

// AccessAWSRole is the part of an [AWSMatcher] a derived group carries.
type AccessAWSRole struct {
	Account string `yaml:"account,omitempty"`
	Role    string `yaml:"role,omitempty"`
	Path    string `yaml:"path,omitempty"`
}

// AccessPerson is one person and the addresses they are known by.
type AccessPerson struct {
	Name      string   `yaml:"name"`
	Addresses []string `yaml:"addresses,omitempty"`
}

// AccessWorkspace is one Slack workspace.
type AccessWorkspace struct {
	Workspace string               `yaml:"workspace"`
	Channels  []AccessSlackChannel `yaml:"channels,omitempty"`
}

// AccessSlackChannel is one channel's binding.
type AccessSlackChannel struct {
	Name    string   `yaml:"name"`
	Private bool     `yaml:"private,omitempty"`
	Mode    string   `yaml:"mode,omitempty"`
	Adopt   string   `yaml:"adopt,omitempty"`
	Ignore  []string `yaml:"ignore,omitempty"`
	From    []string `yaml:"from,omitempty"`
}

// AccessOrg is one GitHub organisation's bindings.
type AccessOrg struct {
	Org     string             `yaml:"org"`
	Members []string           `yaml:"members,omitempty"`
	Teams   []AccessGitHubTeam `yaml:"teams,omitempty"`
	Ignore  []string           `yaml:"ignore,omitempty"`
}

// AccessGitHubTeam is one team's bindings.
type AccessGitHubTeam struct {
	Slug        string   `yaml:"slug"`
	Members     []string `yaml:"members,omitempty"`
	Maintainers []string `yaml:"maintainers,omitempty"`
}

// AccessVocabulary is [Vocabulary] as lists.
type AccessVocabulary struct {
	Scopes []AccessScope `yaml:"scopes,omitempty"`
	Things []AccessThing `yaml:"things,omitempty"`
}

// AccessScope is one declared scope.
type AccessScope struct {
	Name      string `yaml:"name"`
	Sensitive bool   `yaml:"sensitive,omitempty"`
}

// AccessThing is one declared thing and its role ladder.
type AccessThing struct {
	Name   string       `yaml:"name"`
	Scopes []string     `yaml:"scopes,omitempty"`
	Roles  []AccessRole `yaml:"roles,omitempty"`
}

// AccessRole is one role of a thing.
type AccessRole struct {
	Name    string   `yaml:"name"`
	Scopes  []string `yaml:"scopes,omitempty"`
	Implies []string `yaml:"implies,omitempty"`
}

// AccessClient is one declared client. `secretKey` and the last six fields
// describe the relying party's own deployment (the key its secret is
// projected under, where it is served, how it is reached) and are read by
// whatever deploys it; they take no part in the policy
// and are accepted so that one row serves both.
type AccessClient struct {
	Name              string         `yaml:"name"`
	Kind              string         `yaml:"kind"`
	DisplayName       string         `yaml:"displayName,omitempty"`
	Description       string         `yaml:"description,omitempty"`
	Secret            string         `yaml:"secret,omitempty"`
	SecretKey         string         `yaml:"secretKey,omitempty"`
	Redirects         []string       `yaml:"redirects,omitempty"`
	SignedOut         []string       `yaml:"signedOut,omitempty"`
	BackchannelLogout string         `yaml:"backchannelLogout,omitempty"`
	TTLCap            Duration       `yaml:"ttlCap,omitempty"`
	SigningAlg        string         `yaml:"signingAlg,omitempty"`
	GroupsDelimiter   string         `yaml:"groupsDelimiter,omitempty"`
	SignInExchange    bool           `yaml:"signInExchange,omitempty"`
	Requires          []string       `yaml:"requires,omitempty"`
	Groups            GroupsOverride `yaml:"groups,omitempty"`

	Hostname string `yaml:"hostname,omitempty"`
	Prefix   string `yaml:"prefix,omitempty"`
	Mount    string `yaml:"mount,omitempty"`
	Cluster  string `yaml:"cluster,omitempty"`
	Proxy    any    `yaml:"proxy,omitempty"`
	Deliver  any    `yaml:"deliver,omitempty"`
}

// AccessClientDocuments is [ClientDocuments] in the document's spelling.
type AccessClientDocuments struct {
	Origins  []string       `yaml:"origins,omitempty"`
	Requires []string       `yaml:"requires,omitempty"`
	TTLCap   Duration       `yaml:"ttlCap,omitempty"`
	Groups   GroupsOverride `yaml:"groups,omitempty"`
}

// AccessResource is one resource (RFC 8707).
type AccessResource struct {
	ID              string         `yaml:"id"`
	DisplayName     string         `yaml:"displayName,omitempty"`
	Description     string         `yaml:"description,omitempty"`
	Requires        []string       `yaml:"requires,omitempty"`
	TTLCap          Duration       `yaml:"ttlCap,omitempty"`
	SigningAlg      string         `yaml:"signingAlg,omitempty"`
	GroupsDelimiter string         `yaml:"groupsDelimiter,omitempty"`
	Groups          GroupsOverride `yaml:"groups,omitempty"`
}

// AccessOverlay is what an installation adds to the derived part.
type AccessOverlay struct {
	// Groups add matchers to a group, appended after what the access
	// matrix derived. A group the matrix never produced is created with
	// only these: the matrix describes people, so a workload rule has
	// nothing there to attach to.
	Groups map[string]OverlayGroup `yaml:"groups,omitempty"`
	// Clients are declared in full. An id the access part also declares
	// is refused, not merged.
	Clients map[string]Client `yaml:"clients,omitempty"`
}

// OverlayGroup is the matchers an overlay adds to one group.
type OverlayGroup struct {
	Matchers []Matcher `yaml:"matchers,omitempty"`
}

// IsAccessDocument reports whether a YAML file is an [AccessDocument]
// rather than a [Policy] layer: it carries an `access` key, which a
// policy layer never has.
func IsAccessDocument(data []byte) bool {
	var top map[string]yaml.Node
	if err := yaml.Unmarshal(data, &top); err != nil {
		return false
	}
	_, ok := top["access"]
	return ok
}

// ParseAccess reads one access document and returns the layer it
// stands for. Unknown keys are an error, as in [Parse].
func ParseAccess(data []byte) (Policy, error) {
	var doc AccessDocument
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&doc); err != nil {
		return Policy{}, fmt.Errorf("parse access document: %w", err)
	}
	if doc.Version == 0 {
		doc.Version = 1
	}
	return doc.Policy()
}

// Policy reshapes the document into the layer [Parse] would have read had
// it been written out by hand.
func (d AccessDocument) Policy() (Policy, error) {
	out, err := d.Access.policy()
	if err != nil {
		return Policy{}, err
	}
	out.Version = d.Version
	for _, name := range slices.Sorted(maps.Keys(d.Overlay.Groups)) {
		group := out.Groups[name]
		group.Matchers = append(group.Matchers, d.Overlay.Groups[name].Matchers...)
		if out.Groups == nil {
			out.Groups = map[string]Group{}
		}
		out.Groups[name] = group
	}
	for _, id := range slices.Sorted(maps.Keys(d.Overlay.Clients)) {
		if _, dup := out.Clients[id]; dup {
			return Policy{}, fmt.Errorf("overlay declares client %q, which access declares too", id)
		}
		if out.Clients == nil {
			out.Clients = map[string]Client{}
		}
		out.Clients[id] = d.Overlay.Clients[id]
	}
	return out, nil
}

func (a Access) policy() (Policy, error) {
	var out Policy
	out.Lifetimes = a.Lifetimes
	var err error
	if out.Groups, err = a.groups(); err != nil {
		return Policy{}, err
	}
	if len(a.People) > 0 {
		out.People = make(map[string][]string, len(a.People))
		for _, person := range a.People {
			if _, dup := out.People[person.Name]; dup {
				return Policy{}, fmt.Errorf("person %q is declared twice", person.Name)
			}
			out.People[person.Name] = person.Addresses
		}
	}
	if out.Slack, err = a.slack(); err != nil {
		return Policy{}, err
	}
	if out.GitHub, err = a.github(); err != nil {
		return Policy{}, err
	}
	if out.Vocabulary, err = a.Vocabulary.vocabulary(); err != nil {
		return Policy{}, err
	}
	if out.Clients, err = a.clients(); err != nil {
		return Policy{}, err
	}
	if cd := a.ClientDocuments; cd != nil {
		out.ClientDocuments = ClientDocuments{Origins: cd.Origins, Requires: cd.Requires, TTLCap: cd.TTLCap, Groups: cd.Groups}
	}
	if len(a.Resources) > 0 {
		out.Resources = make(map[string]Resource, len(a.Resources))
		for i := range a.Resources {
			r := &a.Resources[i]
			if _, dup := out.Resources[r.ID]; dup {
				return Policy{}, fmt.Errorf("resource %q is declared twice", r.ID)
			}
			out.Resources[r.ID] = Resource{
				DisplayName: r.DisplayName, Description: r.Description, Requires: r.Requires,
				TTLCap: r.TTLCap, SigningAlg: r.SigningAlg, Groups: r.Groups, GroupsDelimiter: r.GroupsDelimiter,
			}
		}
	}
	return out, nil
}

func (a Access) groups() (map[string]Group, error) {
	if len(a.Groups) == 0 {
		return nil, nil
	}
	out := make(map[string]Group, len(a.Groups))
	for i := range a.Groups {
		g := &a.Groups[i]
		if _, dup := out[g.Name]; dup {
			return nil, fmt.Errorf("group %q is declared twice", g.Name)
		}
		var matchers []Matcher
		for _, email := range g.Emails {
			matchers = append(matchers, Matcher{Email: email})
		}
		for k := range g.GitHub {
			j := &g.GitHub[k]
			matchers = append(matchers, Matcher{GitHub: &GitHubMatcher{
				Repository: j.Repository, Owner: j.Owner, Visibility: j.Visibility, Ref: j.Ref, RefType: j.RefType,
				EventName: j.EventName, WorkflowRef: j.WorkflowRef, JobWorkflowRef: j.JobWorkflowRef,
			}})
		}
		for _, sa := range g.ServiceAccounts {
			matchers = append(matchers, Matcher{ServiceAccount: &ServiceAccountMatcher{
				Cluster: sa.Cluster, Namespace: sa.Namespace, Name: sa.Name,
			}})
		}
		for _, r := range g.AWS {
			matchers = append(matchers, Matcher{AWS: &AWSMatcher{Account: r.Account, Role: r.Role, Path: r.Path}})
		}
		out[g.Name] = Group{Members: g.Members, Matchers: matchers}
	}
	return out, nil
}

func (a Access) slack() (Slack, error) {
	if len(a.Slack) == 0 {
		return Slack{}, nil
	}
	out := Slack{Workspaces: make(map[string]SlackWorkspace, len(a.Slack))}
	for _, w := range a.Slack {
		if _, dup := out.Workspaces[w.Workspace]; dup {
			return Slack{}, fmt.Errorf("slack workspace %q is declared twice", w.Workspace)
		}
		var channels map[string]SlackChannel
		if len(w.Channels) > 0 {
			channels = make(map[string]SlackChannel, len(w.Channels))
		}
		for _, c := range w.Channels {
			if _, dup := channels[c.Name]; dup {
				return Slack{}, fmt.Errorf("slack channel %s/%s is declared twice", w.Workspace, c.Name)
			}
			channels[c.Name] = SlackChannel{Private: c.Private, Mode: c.Mode, Ignore: c.Ignore, From: c.From, Adopt: c.Adopt}
		}
		out.Workspaces[w.Workspace] = SlackWorkspace{Channels: channels}
	}
	return out, nil
}

func (a Access) github() (map[string]GitHubOrg, error) {
	if len(a.GitHub) == 0 {
		return nil, nil
	}
	out := make(map[string]GitHubOrg, len(a.GitHub))
	for _, o := range a.GitHub {
		if _, dup := out[o.Org]; dup {
			return nil, fmt.Errorf("github organisation %q is declared twice", o.Org)
		}
		var teams map[string]GitHubTeam
		if len(o.Teams) > 0 {
			teams = make(map[string]GitHubTeam, len(o.Teams))
		}
		for _, t := range o.Teams {
			if _, dup := teams[t.Slug]; dup {
				return nil, fmt.Errorf("github team %s/%s is declared twice", o.Org, t.Slug)
			}
			teams[t.Slug] = GitHubTeam{Members: t.Members, Maintainers: t.Maintainers}
		}
		out[o.Org] = GitHubOrg{Members: o.Members, Teams: teams, Ignore: o.Ignore}
	}
	return out, nil
}

func (v *AccessVocabulary) vocabulary() (*Vocabulary, error) {
	if v == nil {
		return nil, nil
	}
	out := &Vocabulary{Scopes: make(map[string]ScopeSpec, len(v.Scopes)), Things: make(map[string]ThingSpec, len(v.Things))}
	for _, s := range v.Scopes {
		if _, dup := out.Scopes[s.Name]; dup {
			return nil, fmt.Errorf("vocabulary scope %q is declared twice", s.Name)
		}
		out.Scopes[s.Name] = ScopeSpec{Sensitive: s.Sensitive}
	}
	for _, t := range v.Things {
		if _, dup := out.Things[t.Name]; dup {
			return nil, fmt.Errorf("vocabulary thing %q is declared twice", t.Name)
		}
		roles := make(map[string]RoleSpec, len(t.Roles))
		for _, r := range t.Roles {
			if _, dup := roles[r.Name]; dup {
				return nil, fmt.Errorf("vocabulary role %s:%s is declared twice", t.Name, r.Name)
			}
			roles[r.Name] = RoleSpec{Implies: r.Implies, Scopes: r.Scopes}
		}
		out.Things[t.Name] = ThingSpec{Scopes: t.Scopes, Roles: roles}
	}
	return out, nil
}

func (a Access) clients() (map[string]Client, error) {
	if len(a.Clients) == 0 {
		return nil, nil
	}
	out := make(map[string]Client, len(a.Clients))
	for i := range a.Clients {
		c := &a.Clients[i]
		if c.Name == "" {
			return nil, errors.New("a client has no name")
		}
		if _, dup := out[c.Name]; dup {
			return nil, fmt.Errorf("client %q is declared twice", c.Name)
		}
		out[c.Name] = Client{
			Kind: c.Kind, DisplayName: c.DisplayName, Description: c.Description, Secret: c.Secret,
			Redirects: c.Redirects, SignedOut: c.SignedOut, Requires: c.Requires, TTLCap: c.TTLCap,
			SignInExchange: c.SignInExchange, BackChannelLogout: c.BackchannelLogout, SigningAlg: c.SigningAlg,
			Groups: c.Groups, GroupsDelimiter: c.GroupsDelimiter,
		}
	}
	return out, nil
}
