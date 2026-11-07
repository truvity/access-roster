package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	"github.com/truvity/sluis/v2/gen/go/buf/validate"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/known/durationpb"
)

const repoRoot = "../../.."

// verifies: REQ-DATA-037
//
// The committed schemas are what the Protobuf messages make: a schema that differs, or a schema that no message makes,
// fails. `just config-schema-gen` writes them. The test needs buf, as `just proto-check` does, and fails without it.
func TestTheCommittedSchemasAreWhatTheMessagesMake(t *testing.T) {
	if _, err := exec.LookPath("buf"); err != nil {
		t.Fatal("buf is not on PATH: run the test in devbox (a skipped golden check is not a pass)")
	}
	files, err := load(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	made, err := generate(files)
	if err != nil {
		t.Fatal(err)
	}
	if len(made) != len(roots) || len(made) == 0 {
		t.Fatalf("%d schemas for %d roots", len(made), len(roots))
	}
	if err := compare(repoRoot, made); err != nil {
		t.Fatal(err)
	}
}

// field helpers for a synthetic message: each case below is a mutation of one field of it.
func str(name string, num int32, rules *validate.FieldRules) *descriptorpb.FieldDescriptorProto {
	return field(name, num, descriptorpb.FieldDescriptorProto_TYPE_STRING, "", false, rules)
}

func field(name string, num int32, typ descriptorpb.FieldDescriptorProto_Type, typeName string, repeated bool, rules *validate.FieldRules) *descriptorpb.FieldDescriptorProto {
	f := &descriptorpb.FieldDescriptorProto{
		Name: proto.String(name), JsonName: proto.String(name), Number: proto.Int32(num), Type: typ.Enum(),
		Label: descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
	}
	if repeated {
		f.Label = descriptorpb.FieldDescriptorProto_LABEL_REPEATED.Enum()
	}
	if typeName != "" {
		f.TypeName = proto.String(typeName)
	}
	if rules != nil {
		f.Options = &descriptorpb.FieldOptions{}
		proto.SetExtension(f.Options, validate.E_Field, rules)
	}
	return f
}

// schemaFor builds a file with a message M (and the given nested messages) and returns the schema of M.
func schemaFor(t *testing.T, m *descriptorpb.DescriptorProto, others ...*descriptorpb.DescriptorProto) (map[string]any, error) {
	t.Helper()
	return schemaForRoot(t, root{Message: "t.M", Name: "m", Version: "v1", Title: "M"}, m, others...)
}

// schemaForRoot is schemaFor with the root given, for the shapes of a signed document.
func schemaForRoot(t *testing.T, r root, m *descriptorpb.DescriptorProto, others ...*descriptorpb.DescriptorProto) (map[string]any, error) {
	t.Helper()
	dur := protodesc.ToFileDescriptorProto(durationpb.File_google_protobuf_duration_proto)
	fdp := &descriptorpb.FileDescriptorProto{
		Name: proto.String("t.proto"), Package: proto.String("t"), Syntax: proto.String("proto3"),
		Dependency:  []string{dur.GetName()},
		MessageType: append([]*descriptorpb.DescriptorProto{m}, others...),
	}
	file, err := protodesc.NewFile(fdp, fileResolver(t, dur))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := schemaOf(r, file.Messages().ByName("M"))
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(doc, &out); err != nil {
		t.Fatal(err)
	}
	return out, nil
}

func fileResolver(t *testing.T, dur *descriptorpb.FileDescriptorProto) protodesc.Resolver {
	t.Helper()
	files, err := protodesc.NewFiles(&descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{dur}})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func get(t *testing.T, v any, path ...string) any {
	t.Helper()
	for _, p := range path {
		m, ok := v.(map[string]any)
		if !ok {
			t.Fatalf("%v: not an object at %q", path, p)
		}
		v = m[p]
	}
	return v
}

func rulesString(r *validate.StringRules) *validate.FieldRules {
	return &validate.FieldRules{Type: &validate.FieldRules_String_{String_: r}}
}

// The rules the schema states are the ones the messages hold, one keyword each: each field below is changed on its own
// in the mutation cases that follow.
func TestEachRuleBecomesItsKeyword(t *testing.T) {
	n := uint64(3)
	required := &validate.FieldRules{Required: proto.Bool(true)}
	required.Type = &validate.FieldRules_String_{String_: &validate.StringRules{
		Pattern: proto.String("^x$"), MinLen: &n, MaxLen: proto.Uint64(9), In: []string{"a", "b"},
	}}
	dur := &validate.FieldRules{Type: &validate.FieldRules_Duration{Duration: &validate.DurationRules{}}}
	list := &validate.FieldRules{Type: &validate.FieldRules_Repeated{Repeated: &validate.RepeatedRules{MinItems: proto.Uint64(1), MaxItems: proto.Uint64(4), Unique: proto.Bool(true)}}}
	s, err := schemaFor(t, &descriptorpb.DescriptorProto{
		Name: proto.String("M"),
		Field: []*descriptorpb.FieldDescriptorProto{
			str("a", 1, required),
			field("d", 2, descriptorpb.FieldDescriptorProto_TYPE_MESSAGE, ".google.protobuf.Duration", false, dur),
			field("l", 3, descriptorpb.FieldDescriptorProto_TYPE_STRING, "", true, list),
			field("n", 4, descriptorpb.FieldDescriptorProto_TYPE_MESSAGE, ".t.N", false, nil),
		},
		ReservedName: []string{"old"},
	}, &descriptorpb.DescriptorProto{Name: proto.String("N"), Field: []*descriptorpb.FieldDescriptorProto{str("x", 1, nil)}})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		path []string
		want any
	}{
		{[]string{"properties", "a", "pattern"}, "^x$"},
		{[]string{"properties", "a", "minLength"}, 3.0},
		{[]string{"properties", "a", "maxLength"}, 9.0},
		{[]string{"properties", "d", "pattern"}, "^[0-9]+(s|m|h|d)$"},
		{[]string{"properties", "l", "minItems"}, 1.0},
		{[]string{"properties", "l", "maxItems"}, 4.0},
		{[]string{"properties", "l", "uniqueItems"}, true},
		{[]string{"properties", "n", "$ref"}, "#/$defs/N"},
		{[]string{"properties", "old"}, false},
		{[]string{"unevaluatedProperties"}, false},
		{[]string{"$defs", "N", "unevaluatedProperties"}, false},
	} {
		if got := get(t, s, c.path...); got != c.want {
			t.Errorf("%s: got %v, want %v", strings.Join(c.path, "."), got, c.want)
		}
	}
	if req := get(t, s, "required").([]any); len(req) != 1 || req[0] != "a" {
		t.Errorf("required: %v", req)
	}
	if enum := get(t, s, "properties", "a", "enum").([]any); len(enum) != 2 {
		t.Errorf("enum: %v", enum)
	}
}

// A rule the generator neither states nor lists as protovalidate-only stops the generator, so no rule is dropped without notice.
func TestARuleThatCannotBeStatedStopsTheGenerator(t *testing.T) {
	for name, f := range map[string]*descriptorpb.FieldDescriptorProto{
		"a string well-known rule": str("a", 1, rulesString(&validate.StringRules{WellKnown: &validate.StringRules_Email{Email: true}})),
		"a string prefix":          str("a", 1, rulesString(&validate.StringRules{Prefix: proto.String("x")})),
		"an int64 field":           field("a", 1, descriptorpb.FieldDescriptorProto_TYPE_INT64, "", false, nil),
		"a bytes rule":             field("a", 1, descriptorpb.FieldDescriptorProto_TYPE_BYTES, "", false, &validate.FieldRules{Type: &validate.FieldRules_Bytes{Bytes: &validate.BytesRules{}}}),
		"a bool rule":              field("a", 1, descriptorpb.FieldDescriptorProto_TYPE_BOOL, "", false, &validate.FieldRules{Type: &validate.FieldRules_Bool{Bool: &validate.BoolRules{}}}),
	} {
		if _, err := schemaFor(t, &descriptorpb.DescriptorProto{Name: proto.String("M"), Field: []*descriptorpb.FieldDescriptorProto{f}}); err == nil {
			t.Errorf("%s: the generator made a schema", name)
		}
	}
}

// What protovalidate alone enforces is skipped on purpose: a CEL rule and the range of a duration.
func TestWhatProtovalidateAloneEnforcesIsSkipped(t *testing.T) {
	cel := &validate.FieldRules{Cel: []*validate.Rule{{Id: proto.String("x"), Expression: proto.String("true")}}}
	cel.Type = &validate.FieldRules_String_{String_: &validate.StringRules{MinLen: proto.Uint64(1)}}
	dur := &validate.FieldRules{Type: &validate.FieldRules_Duration{Duration: &validate.DurationRules{GreaterThan: &validate.DurationRules_Gt{Gt: durationpb.New(0)}}}}
	s, err := schemaFor(t, &descriptorpb.DescriptorProto{Name: proto.String("M"), Field: []*descriptorpb.FieldDescriptorProto{
		str("a", 1, cel),
		field("d", 2, descriptorpb.FieldDescriptorProto_TYPE_MESSAGE, ".google.protobuf.Duration", false, dur),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if get(t, s, "properties", "a", "minLength") != 1.0 || get(t, s, "properties", "d", "pattern") == nil {
		t.Errorf("the rules beside the skipped ones were lost: %v", s)
	}
}

func TestTheBootstrapSchemaNamesItself(t *testing.T) {
	raw, err := os.ReadFile(repoRoot + "/schema/bootstrap/v1/bootstrap.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var s map[string]any
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	if s["$id"] != "https://sluis.id/schema/bootstrap/v1/bootstrap.schema.json" || s["$schema"] != draft {
		t.Errorf("$id %v, $schema %v", s["$id"], s["$schema"])
	}
}

// A signed document is a mapping from item id to item: one item `default`, or one or more items by id. A field that is not
// required may be null where the loaders read null as absent, bytes are base64url, and a number is a 32-bit unsigned integer.
func TestThePayloadShapes(t *testing.T) {
	m := &descriptorpb.DescriptorProto{Name: proto.String("M"), Field: []*descriptorpb.FieldDescriptorProto{
		str("s", 1, nil),
		str("r", 2, &validate.FieldRules{Required: proto.Bool(true)}),
		field("b", 3, descriptorpb.FieldDescriptorProto_TYPE_BYTES, "", false, nil),
		field("c", 4, descriptorpb.FieldDescriptorProto_TYPE_BYTES, "", false, &validate.FieldRules{Required: proto.Bool(true)}),
		field("n", 5, descriptorpb.FieldDescriptorProto_TYPE_UINT32, "", false, nil),
		field("l", 6, descriptorpb.FieldDescriptorProto_TYPE_STRING, "", true, nil),
		field("d", 7, descriptorpb.FieldDescriptorProto_TYPE_MESSAGE, ".google.protobuf.Duration", false, nil),
	}}
	single, err := schemaForRoot(t, payload("M", "m", "M", "single"), m)
	if err != nil {
		t.Fatal(err)
	}
	keyed, err := schemaForRoot(t, payload("M", "m", "M", "keyed"), m)
	if err != nil {
		t.Fatal(err)
	}
	got := func(v any) string { b, _ := json.Marshal(v); return string(b) }
	for _, c := range []struct {
		name string
		v    any
		want string
	}{
		{"single: the item is default", get(t, single, "properties", "default", "$ref"), `"#/$defs/M"`},
		{"single: no other id", get(t, single, "unevaluatedProperties"), `false`},
		{"single: default is required", get(t, single, "required"), `["default"]`},
		{"single: no $schema key, a key is an item id", get(t, single, "properties", "$schema"), `null`},
		{"keyed: one or more items", get(t, keyed, "minProperties"), `1`},
		{"keyed: every item is the message", get(t, keyed, "additionalProperties", "$ref"), `"#/$defs/M"`},
		{"keyed: ids are store parts", get(t, keyed, "propertyNames", "pattern"), `"` + storeIDPattern + `"`},
		{"a string that is not required may be null", get(t, single, "$defs", "M", "properties", "s", "type"), `["string","null"]`},
		{"a required string is not null and not empty", get(t, single, "$defs", "M", "properties", "r"), `{"minLength":1,"type":"string"}`},
		{"bytes that are not required may be empty or null", get(t, single, "$defs", "M", "properties", "b"), `{"pattern":"^[A-Za-z0-9_-]*$","type":["string","null"]}`},
		{"required bytes are not empty", get(t, single, "$defs", "M", "properties", "c"), `{"pattern":"^[A-Za-z0-9_-]+$","type":"string"}`},
		{"a number is a 32-bit unsigned integer and is not null", get(t, single, "$defs", "M", "properties", "n"), `{"maximum":4294967295,"minimum":0,"type":"integer"}`},
		{"a list that is not required may be null", get(t, single, "$defs", "M", "properties", "l", "type"), `["array","null"]`},
		{"a duration is not null", get(t, single, "$defs", "M", "properties", "d", "type"), `"string"`},
	} {
		if g := got(c.v); g != c.want && !sameJSON(g, c.want) {
			t.Errorf("%s: got %s, want %s", c.name, g, c.want)
		}
	}
}

// sameJSON compares two JSON texts as values, so that the order of keys does not matter.
func sameJSON(a, b string) bool {
	var x, y any
	if json.Unmarshal([]byte(a), &x) != nil || json.Unmarshal([]byte(b), &y) != nil {
		return false
	}
	return reflect.DeepEqual(x, y)
}
