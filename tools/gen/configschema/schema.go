package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"

	"github.com/truvity/sluis/v2/gen/go/buf/validate"
	"google.golang.org/protobuf/proto"
)

// draft is the dialect of every schema (ADR 0004, "Schemas are Protobuf").
const draft = "https://json-schema.org/draft/2020-12/schema"

// durationPattern is the form of a duration in a configuration file: one whole number and one unit (ADR 0004, REQ-DATA-044).
const durationPattern = "^[0-9]+(s|m|h|d)$"

// durationDescription is the sentence an editor shows for a duration.
const durationDescription = "A duration: one whole number and one unit of s, m, h or d, such as 900s, 15m, 12h or 30d."

// A root is a message whose schema is published: the message, and where the schema lives. The path is the identifier:
// https://sluis.id/schema/<name>/<version>/<name>.schema.json (ADR 0004: a stable $id with its version in the path).
type root struct {
	Message string // the full name of the Protobuf message
	Name    string // the name in the path
	Version string // v1, v2, ...: a new version is a new identifier beside the old one
	Title   string
	// Shape is "" for a file that is the message itself (the bootstrap file). A signed config document is a mapping from item
	// id to item (signed-config.md "The payload"): "single" for a kind with one item, `default`, and "keyed" for a kind whose
	// items are named by their id. The message is the item.
	Shape string
	// Nullable lets every field that is not required, and is a string, bytes or a list, be null in the file: the loaders of the
	// signed documents read a null as absent, as proto3 JSON does. The bootstrap file's loaders do not, so its schema does not.
	Nullable bool
}

// payload is the root of one kind of signed config document.
func payload(message, name, title, shape string) root {
	return root{Message: "sluis.config.v2alpha1." + message, Name: name, Version: "v1", Title: title, Shape: shape, Nullable: true}
}

// storeIDPattern is the id of an item: a store part (store-api.md "Address encoding"). The schema does not exclude "." and
// "..", which the loaders do: a schema is never stricter than its loaders.
const storeIDPattern = "^[a-z0-9._-]{1,128}$"

// roots lists every published schema. A configuration joins it with the message that reads it ([principle 8]).
var roots = []root{
	{Message: "sluis.config.v2alpha1.Bootstrap", Name: "bootstrap", Version: "v1", Title: "The bootstrap file of store@"},
	payload("Boundary", "boundary", "The payload of a signed Boundary document", "single"),
	payload("KeyPlan", "key-plan", "The payload of a signed KeyPlan document", "single"),
	payload("TokenLifetime", "token-lifetime", "The payload of a signed TokenLifetime document", "single"),
	payload("AuditLog", "audit-log", "The payload of a signed AuditLog document", "single"),
	payload("AuditCatalogue", "audit-catalogue", "The payload of a signed AuditCatalogue document", "single"),
	payload("ExchangeTrust", "exchange-trust", "The payload of a signed ExchangeTrust document", "single"),
	payload("Upstream", "upstream", "The payload of a signed Upstream document", "keyed"),
	payload("InstallationClient", "installation-client", "The payload of a signed InstallationClient document", "keyed"),
}

const idBase = "https://sluis.id/schema/"

// Path is the file of the schema below the schema directory, which is also the tail of its identifier.
func (r root) Path() string { return r.Name + "/" + r.Version + "/" + r.Name + ".schema.json" }

// ID is the identifier of the schema.
func (r root) ID() string { return idBase + r.Path() }

// An obj is a JSON object that keeps the order its keys were added in, so that the golden file reads like the message.
type obj []kv
type kv struct {
	k string
	v any
}

func (o *obj) set(k string, v any) { *o = append(*o, kv{k, v}) }

func (o obj) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, e := range o {
		if i > 0 {
			b.WriteByte(',')
		}
		k, err := encode(e.k)
		if err != nil {
			return nil, err
		}
		v, err := encode(e.v)
		if err != nil {
			return nil, err
		}
		b.Write(k)
		b.WriteByte(':')
		b.Write(v)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

// encode writes a JSON value without the escaping of <, > and & that a pattern or a description may hold.
func encode(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(b.Bytes(), "\n"), nil
}

// A generator makes the schema of one root.
type generator struct {
	defs     map[string]obj // by message name, for $defs
	order    []string
	nullable bool // a field that is not required may be null (root.Nullable)
}

// schemaOf returns the JSON Schema of a root message as indented JSON ending in a newline.
func schemaOf(r root, md protoreflect.MessageDescriptor) ([]byte, error) {
	g := &generator{defs: map[string]obj{}, nullable: r.Nullable}
	if r.Shape != "" {
		return g.payloadSchema(r, md)
	}
	body, err := g.message(md, true)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", r.Message, err)
	}
	doc := obj{}
	doc.set("$schema", draft)
	doc.set("$id", r.ID())
	doc.set("title", r.Title)
	if d := description(md); d != "" {
		doc.set("description", d)
	}
	// The properties of the root come with `$schema`, which a file may set to name the schema for editors, and
	// which only this identifier may be (the loader refuses another).
	for _, e := range body {
		if e.k == "description" {
			continue
		}
		if e.k == "properties" {
			props := obj{{"$schema", obj{{"const", r.ID()}, {"description", "The identifier of this schema, for editors."}}}}
			props = append(props, e.v.(obj)...)
			doc.set("properties", props)
			continue
		}
		doc.set(e.k, e.v)
	}
	return g.finish(doc)
}

// finish adds the definitions to a document and writes it as indented JSON ending in a newline.
func (g *generator) finish(doc obj) ([]byte, error) {
	if len(g.defs) > 0 {
		defs := obj{}
		names := append([]string(nil), g.order...)
		sort.Strings(names)
		for _, n := range names {
			defs.set(n, g.defs[n])
		}
		doc.set("$defs", defs)
	}
	var out bytes.Buffer
	raw, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	if err := json.Indent(&out, raw, "", "  "); err != nil {
		return nil, err
	}
	out.WriteByte('\n')
	return out.Bytes(), nil
}

// payloadSchema is the schema of a signed config document: a mapping from item id to item, where the item is the message.
// There is no `$schema` key: a key of the mapping is an item id.
func (g *generator) payloadSchema(r root, md protoreflect.MessageDescriptor) ([]byte, error) {
	name := string(md.Name())
	g.defs[name] = nil
	g.order = append(g.order, name)
	item, err := g.message(md, false)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", r.Message, err)
	}
	g.defs[name] = item
	ref := obj{{"$ref", "#/$defs/" + name}}
	doc := obj{}
	doc.set("$schema", draft)
	doc.set("$id", r.ID())
	doc.set("title", r.Title)
	doc.set("type", "object")
	switch r.Shape {
	case "single":
		// One item, with the id `default`.
		doc.set("properties", obj{{"default", ref}})
		doc.set("required", []string{"default"})
		doc.set("unevaluatedProperties", false)
	case "keyed":
		// One item or more, each named by its id.
		doc.set("minProperties", 1)
		doc.set("propertyNames", obj{{"pattern", storeIDPattern}})
		doc.set("additionalProperties", ref)
	default:
		return nil, fmt.Errorf("%s: the shape %q is neither single nor keyed", r.Message, r.Shape)
	}
	return g.finish(doc)
}

// message is the object schema of a message: every key it does not name is an error (unevaluatedProperties).
func (g *generator) message(md protoreflect.MessageDescriptor, top bool) (obj, error) {
	for i := 0; i < md.Oneofs().Len(); i++ {
		if !md.Oneofs().Get(i).IsSynthetic() {
			return nil, fmt.Errorf("%s: a oneof has no JSON Schema form here", md.FullName())
		}
	}
	o := obj{}
	o.set("type", "object")
	if d := description(md); d != "" && !top {
		o.set("description", d)
	}
	props := obj{}
	var required []string
	fields := md.Fields()
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		s, req, err := g.field(fd)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", fd.Name(), err)
		}
		props.set(string(fd.Name()), s)
		if req {
			required = append(required, string(fd.Name()))
		}
	}
	// A name the message retired is refused as itself, not as an unknown key: the schema says it was once a key.
	reserved := md.ReservedNames()
	for i := 0; i < reserved.Len(); i++ {
		props.set(string(reserved.Get(i)), false)
	}
	o.set("properties", props)
	if len(required) > 0 {
		o.set("required", required)
	}
	o.set("unevaluatedProperties", false)
	return o, nil
}

// field returns the schema of a field, and whether the field is required.
func (g *generator) field(fd protoreflect.FieldDescriptor) (obj, bool, error) {
	rules, err := rulesOf(fd)
	if err != nil {
		return nil, false, err
	}
	if fd.IsMap() {
		return nil, false, fmt.Errorf("a map has no JSON Schema form here")
	}
	var s obj
	if fd.IsList() {
		s = obj{}
		s.set("type", "array")
		listRules(&s, rules)
		items, err := g.single(fd, rules.items)
		if err != nil {
			return nil, false, err
		}
		s.set("items", items)
	} else if s, err = g.single(fd, rules); err != nil {
		return nil, false, err
	}
	// Required bytes are not empty.
	if rules.required && !fd.IsList() && fd.Kind() == protoreflect.BytesKind {
		for i, e := range s {
			if e.k == "pattern" {
				s[i].v = "^[A-Za-z0-9_-]+$"
			}
		}
	}
	// A required string says something: the loaders refuse an empty one, as protovalidate does.
	if rules.required && !fd.IsList() && (fd.Kind() == protoreflect.StringKind || fd.Kind() == protoreflect.BytesKind) && !has(s, "pattern", "minLength", "enum", "const") {
		s = insertAfterType(s, "minLength", uint64(1))
	}
	// A string, bytes or list that is not required may be null where the loaders read null as absent.
	if g.nullable && !rules.required && (fd.IsList() || fd.Kind() == protoreflect.StringKind || fd.Kind() == protoreflect.BytesKind) {
		s = nullable(s)
	}
	if d := description(fd); d != "" {
		s = withDescription(s, d)
	}
	return s, rules.required, nil
}

func has(s obj, keys ...string) bool {
	for _, e := range s {
		for _, k := range keys {
			if e.k == k {
				return true
			}
		}
	}
	return false
}

// insertAfterType puts a keyword right after "type", so that the golden file reads type first.
func insertAfterType(s obj, k string, v any) obj {
	for i, e := range s {
		if e.k == "type" {
			out := append(obj{}, s[:i+1]...)
			out = append(out, kv{k, v})
			return append(out, s[i+1:]...)
		}
	}
	return append(s, kv{k, v})
}

// nullable makes the type of a schema "the type or null".
func nullable(s obj) obj {
	out := append(obj{}, s...)
	for i, e := range out {
		if e.k == "type" {
			out[i].v = []string{e.v.(string), "null"}
		}
	}
	return out
}

// withDescription puts the field's own comment in the schema (beside a $ref, which draft 2020-12 allows), in place of
// the general sentence of its type.
func withDescription(s obj, d string) obj {
	for i, e := range s {
		if e.k == "description" {
			s[i].v = d
			return s
		}
	}
	return append(s, kv{"description", d})
}

// single is the schema of one value of a field: the field itself, or an element of a list.
func (g *generator) single(fd protoreflect.FieldDescriptor, rules *fieldRules) (obj, error) {
	s := obj{}
	switch fd.Kind() {
	case protoreflect.StringKind:
		s.set("type", "string")
		stringRules(&s, rules)
	case protoreflect.BytesKind:
		// Bytes in a file are base64url without padding (RFC 4648 section 5). The loaders also refuse stray bits in the last
		// character, which a pattern cannot state.
		s.set("type", "string")
		s.set("pattern", "^[A-Za-z0-9_-]*$")
	case protoreflect.Uint32Kind:
		s.set("type", "integer")
		s.set("minimum", 0)
		s.set("maximum", 4294967295)
	case protoreflect.MessageKind:
		if fd.Message().FullName() == "google.protobuf.Duration" {
			// A duration range is a protovalidate rule: the pattern states the form only (ADR 0004).
			s.set("type", "string")
			s.set("pattern", durationPattern)
			s.set("description", durationDescription)
			break
		}
		name := string(fd.Message().Name())
		if _, done := g.defs[name]; !done {
			g.defs[name] = nil
			g.order = append(g.order, name)
			body, err := g.message(fd.Message(), false)
			if err != nil {
				return nil, err
			}
			g.defs[name] = body
		}
		s.set("$ref", "#/$defs/"+name)
	default:
		return nil, fmt.Errorf("a field of kind %s has no JSON Schema form here", fd.Kind())
	}
	return s, nil
}

// fieldRules are the protovalidate rules of a field, in the parts the generator expresses.
type fieldRules struct {
	required bool
	// The string rules, by name; a list's size rules, by name.
	strings, list map[protoreflect.Name]protoreflect.Value
	// The rules of each element of a list.
	items *fieldRules
}

// protovalidateOnly are the rules that JSON Schema cannot state and that protovalidate alone enforces (ADR 0004:
// cross-field rules, duration ranges). The generator skips these and stops on every other rule it does not express,
// so that no rule is lost without notice.
var protovalidateOnly = map[protoreflect.Name]bool{"cel": true, "duration": true}

func rulesOf(fd protoreflect.FieldDescriptor) (*fieldRules, error) {
	opts, _ := fd.Options().(*descriptorpb.FieldOptions)
	if opts == nil || !proto.HasExtension(opts, validate.E_Field) {
		return &fieldRules{}, nil
	}
	return parseRules(proto.GetExtension(opts, validate.E_Field).(*validate.FieldRules).ProtoReflect())
}

func parseRules(fr protoreflect.Message) (*fieldRules, error) {
	r := &fieldRules{}
	var err error
	fr.Range(func(f protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		switch name := f.Name(); name {
		case "required":
			r.required = v.Bool()
		case "string":
			r.strings, err = named(v.Message(), "string", map[protoreflect.Name]bool{
				"pattern": true, "min_len": true, "max_len": true, "len": true, "const": true, "in": true,
			})
		case "repeated":
			r.list, err = named(v.Message(), "repeated", map[protoreflect.Name]bool{
				"min_items": true, "max_items": true, "unique": true, "items": true,
			})
			if err == nil {
				if items := v.Message().Descriptor().Fields().ByName("items"); v.Message().Has(items) {
					r.items, err = parseRules(v.Message().Get(items).Message())
					delete(r.list, "items")
				}
			}
		default:
			if !protovalidateOnly[name] {
				err = fmt.Errorf("the rule %q is neither expressed in JSON Schema nor listed as protovalidate only", name)
			}
		}
		return err == nil
	})
	return r, err
}

// named collects the set fields of a rules message and stops on one that is not in the allowed set.
func named(m protoreflect.Message, kind string, allowed map[protoreflect.Name]bool) (map[protoreflect.Name]protoreflect.Value, error) {
	out := map[protoreflect.Name]protoreflect.Value{}
	var err error
	m.Range(func(f protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		if !allowed[f.Name()] {
			err = fmt.Errorf("the %s rule %q is neither expressed in JSON Schema nor listed as protovalidate only", kind, f.Name())
			return false
		}
		out[f.Name()] = v
		return true
	})
	return out, err
}

// stringRules writes the string rules the generator expresses: a pattern, a length, an exact value, a set of values.
func stringRules(s *obj, r *fieldRules) {
	if r == nil {
		return
	}
	for _, k := range []protoreflect.Name{"pattern", "min_len", "max_len", "len", "const", "in"} {
		v, ok := r.strings[k]
		if !ok {
			continue
		}
		switch k {
		case "pattern":
			s.set("pattern", v.String())
		case "min_len":
			s.set("minLength", v.Uint())
		case "max_len":
			s.set("maxLength", v.Uint())
		case "len":
			s.set("minLength", v.Uint())
			s.set("maxLength", v.Uint())
		case "const":
			s.set("const", v.String())
		case "in":
			var vals []string
			for i := 0; i < v.List().Len(); i++ {
				vals = append(vals, v.List().Get(i).String())
			}
			s.set("enum", vals)
		}
	}
}

// listRules writes the size rules of a list.
func listRules(s *obj, r *fieldRules) {
	if v, ok := r.list["min_items"]; ok {
		s.set("minItems", v.Uint())
	}
	if v, ok := r.list["max_items"]; ok {
		s.set("maxItems", v.Uint())
	}
	if v, ok := r.list["unique"]; ok && v.Bool() {
		s.set("uniqueItems", true)
	}
}

// description is the comment above a declaration, in one line. It is empty when the descriptors carry no source.
func description(d protoreflect.Descriptor) string {
	loc := d.ParentFile().SourceLocations().ByDescriptor(d)
	text := strings.TrimSpace(loc.LeadingComments)
	if text == "" {
		return ""
	}
	return strings.Join(strings.Fields(text), " ")
}
