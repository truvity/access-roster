package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

const (
	// userUnknown is the user.uid of an Authentication record with no known subject (kits/go/audit).
	userUnknown = "unknown"
	// classApplicationLifecycle and classAuthentication are the classes whose required attributes the record fills
	// from the emitting actor's name (kits/go/audit buildRecord).
	classApplicationLifecycle = 6002
	classAuthentication       = 3002
	classEntityManagement     = 3004
	entityTypeOther           = 99

	defsFile = "defs.schema.json"
	draft    = "https://json-schema.org/draft/2020-12/schema"
	maxSafe  = 9007199254740991
)

type obj = map[string]any

func ref(name string) obj { return obj{"$ref": defsFile + "#/$defs/" + name} }

func marshal(v any, pretty bool) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if pretty {
		enc.SetIndent("", " ")
	}
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	out := buf.Bytes()
	if strings.Contains(string(out), "`") {
		return nil, fmt.Errorf("a schema holds a back quote")
	}
	return out, nil
}

// buildSchemas returns the schema documents by file name: defs.schema.json and <action>.schema.json.
func buildSchemas(t *tableFile) (map[string]obj, error) {
	out := map[string]obj{defsFile: buildDefs(t)}
	for _, a := range t.Actions {
		out[a.Name+".schema.json"] = buildAction(t, a)
	}
	return out, nil
}

func scalar(d typeDef) obj {
	o := obj{"type": d.Type}
	if d.Pattern != "" {
		o["pattern"] = d.Pattern
	}
	if d.MaxLength != nil {
		o["maxLength"] = *d.MaxLength
	}
	if d.Minimum != nil {
		o["minimum"] = *d.Minimum
	}
	if d.Maximum != nil {
		o["maximum"] = *d.Maximum
	}
	return o
}

func buildDefs(t *tableFile) obj {
	defs := obj{}
	for name, d := range t.Types {
		o := scalar(d)
		if d.Doc != "" {
			o["description"] = d.Doc
		}
		defs[name] = o
	}
	// The members the record layout fixes, whatever the action (ADR 0030, "The record format").
	defs["uuid7"] = obj{"type": "string", "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
		"description": "metadata.uid: a UUIDv7 in the form of RFC 9562."}
	defs["pseudonym"] = obj{"type": "string", "pattern": "^p1\\.[0-9]{6}\\.[A-Za-z0-9_-]{22}$",
		"description": "user.uid: a keyed pseudonym of a person, never the person (ADR 0029, Pseudonyms)."}
	defs["user_known"] = obj{
		"type": "object", "additionalProperties": false, "required": []string{"type_id", "uid"},
		"description": "user of a record whose subject is known: the pseudonym, and what kind of identity it is (1 a person, 3 a client or a workload, 99 another kind), so a pseudonym of a client never passes for a person's.",
		"properties":  obj{"uid": ref("pseudonym"), "type_id": obj{"type": "integer", "enum": []int{1, 3, 99}}},
	}
	defs["user_unknown"] = obj{
		"type": "object", "additionalProperties": false, "required": []string{"type_id", "uid"},
		"description": "user of an Authentication record that established no subject: OCSF requires the user, and this says there is none (ADR 0030, The OCSF attributes a class requires).",
		"properties":  obj{"uid": obj{"const": userUnknown}, "type_id": obj{"const": 0}},
	}
	defs["user_either"] = obj{"anyOf": []obj{ref("user_known"), ref("user_unknown")}}
	defs["correlation"] = obj{"type": "string", "pattern": "^[A-Za-z0-9_-]{1,64}$",
		"description": "metadata.correlation_uid: the id of the call being served."}
	defs["lost"] = obj{
		"type": "object", "additionalProperties": false, "required": []string{"process", "since", "total"},
		"description": "unmapped.sluis.lost: the running total of best-effort facts one process failed to deliver for the tenant of this record (ADR 0029). The emitter writes it; a caller cannot.",
		"properties": obj{
			"process": obj{"type": "string", "pattern": "^[0-9a-f]{16}$"},
			"total":   obj{"type": "integer", "minimum": 1, "maximum": maxSafe},
			"since":   obj{"type": "integer", "minimum": 0, "maximum": maxSafe},
		},
	}
	defs["policy"] = obj{
		"type": "object", "additionalProperties": false, "required": []string{"uid"},
		"description": "The policy decision that gated the action (security_control profile): its id and the digest of the bundle.",
		"properties":  obj{"uid": ref("ident"), "version": ref("text")},
	}
	defs["authorization"] = obj{
		"type": "object", "additionalProperties": false,
		// A decision no policy determined (a default denial) is its verdict alone; an entry says one or the other.
		"anyOf": []obj{{"required": []string{"policy"}}, {"required": []string{"decision"}}},
		"properties": obj{
			"policy":   obj{"type": "object", "additionalProperties": false, "required": []string{"uid"}, "properties": obj{"uid": ref("ident")}},
			"decision": obj{"enum": []string{"Allowed", "Denied"}},
		},
	}
	return obj{
		"$schema": draft, "title": "Shared definitions of the sluis audit record schemas",
		"$comment": "Generated from docs/architecture/audit-actions.yaml by tools/gen/audit. Do not edit.",
		"$defs":    defs,
	}
}

func fieldSchema(f fieldSpec) obj {
	switch {
	case f.Type != "":
		return ref(f.Type)
	case f.Items != "":
		return obj{"type": "array", "maxItems": f.Max, "items": ref(f.Items)}
	case f.Map != nil:
		return obj{"type": "object", "maxProperties": f.Max, "propertyNames": ref(f.Key.Type), "additionalProperties": objectSchema(f.Map.Fields)}
	}
	return objectSchema(f.Fields)
}

func objectSchema(fs map[string]fieldSpec) obj {
	props := obj{}
	req := []string{}
	for _, n := range sortedNames(fs) {
		props[n] = fieldSchema(fs[n])
		if fs[n].Required {
			req = append(req, n)
		}
	}
	o := obj{"type": "object", "additionalProperties": false, "properties": props}
	if len(req) > 0 {
		o["required"] = req
	}
	return o
}

func intConst(vals []int) obj {
	if len(vals) == 1 {
		return obj{"type": "integer", "const": vals[0]}
	}
	return obj{"type": "integer", "enum": vals}
}

func buildAction(t *tableFile, a action) obj {
	acts := a.activities()
	var ids, typeUIDs []int
	var names []string
	for _, ac := range acts {
		ids = append(ids, ac.ID)
		typeUIDs = append(typeUIDs, a.Class*100+ac.ID)
		if ac.Name != "" {
			names = append(names, ac.Name)
		}
	}
	var statuses []int
	for _, o := range []string{"success", "failure"} {
		for _, have := range a.Outcomes {
			if have == o {
				statuses = append(statuses, map[string]int{"success": 1, "failure": 2}[o])
			}
		}
	}
	tenantOK := a.Tenant == "optional"
	policyOK := a.Policy == "optional" || a.Policy == "required"

	md := obj{
		"event_code": obj{"const": a.Name},
		"log_name":   ref("ident"),
		"product": obj{
			"type": "object", "additionalProperties": false, "required": []string{"name", "version"},
			"properties": obj{"name": obj{"const": t.Product}, "version": ref("text")},
		},
		"uid":             ref("uuid7"),
		"version":         obj{"const": t.OCSF},
		"correlation_uid": ref("correlation"),
	}
	if tenantOK {
		md["tenant_uid"] = ref("ident")
	}
	var profile string
	switch {
	case a.Class == classApplicationLifecycle:
		profile = "host" // `actor` is an attribute of the host profile in this class
	case policyOK:
		profile = "security_control"
	}
	if profile != "" {
		md["profiles"] = obj{"type": "array", "minItems": 1, "maxItems": 1, "items": obj{"const": profile}}
	}
	mdRequired := []string{"event_code", "log_name", "product", "uid", "version"}
	if a.Class == classApplicationLifecycle {
		mdRequired = append(mdRequired, "profiles") // the host profile is not optional here: `actor` needs it
	}
	sortStrings(mdRequired)
	props := obj{
		"activity_id": intConst(ids),
		"actor": obj{
			"type": "object", "additionalProperties": false, "required": []string{"user"},
			"properties": obj{"user": obj{
				"type": "object", "additionalProperties": false, "required": []string{"type_id", "uid"},
				"properties": obj{
					"type_id": obj{"const": 3},
					"uid":     obj{"type": "string", "pattern": "^" + a.Actor + "@[A-Za-z0-9._-]{1,128}$"},
				},
			}},
		},
		"category_uid": obj{"type": "integer", "const": a.Class / 1000},
		"class_uid":    obj{"type": "integer", "const": a.Class},
		"metadata": obj{
			"type": "object", "additionalProperties": false,
			"required":   mdRequired,
			"properties": md,
		},
		"severity_id": obj{"type": "integer", "const": 1},
		"status_id":   intConst(statuses),
		"status_code": ref("reason"),
		"time":        ref("uint"),
		"type_uid":    intConst(typeUIDs),
	}
	required := []string{"activity_id", "actor", "category_uid", "class_uid", "metadata", "severity_id", "status_id", "time", "type_uid"}
	if len(names) > 0 {
		if len(names) == 1 && len(acts) == 1 {
			props["activity_name"] = obj{"type": "string", "const": names[0]}
			required = append(required, "activity_name")
		} else {
			props["activity_name"] = obj{"type": "string", "enum": names}
		}
	}
	switch {
	case a.Class == classAuthentication:
		// OCSF requires the subject of an authentication. A row that may name nobody says `unknown` then.
		user := ref("user_unknown")
		switch a.Subject {
		case "required":
			user = ref("user_known")
		case "optional":
			user = ref("user_either")
		}
		props["user"] = user
		required = append(required, "user")
	case a.Subject == "optional" || a.Subject == "required":
		props["user"] = ref("user_known")
		if a.Subject == "required" {
			required = append(required, "user")
		}
	}
	// The attributes of the class that the emitting actor's own name fills (kits/go/audit buildRecord).
	named := func(name string) {
		props[name] = obj{"type": "object", "additionalProperties": false, "required": []string{"name"}, "properties": obj{"name": obj{"const": a.Actor}}}
		required = append(required, name)
	}
	switch a.Class {
	case classApplicationLifecycle:
		named("application")
	case classAuthentication:
		named("service")
	case classEntityManagement:
		e := a.Entity
		eprops := obj{"type": obj{"const": e.Type}, "type_id": obj{"const": entityTypeOther}}
		ereq := []string{"type", "type_id"}
		for _, m := range []struct {
			on   bool
			name string
			typ  string
		}{{e.Name, "name", "ident"}, {e.UID, "uid", "ident"}, {e.Version, "version", "decimal"}} {
			if m.on {
				eprops[m.name] = ref(m.typ)
				ereq = append(ereq, m.name)
			}
		}
		sortStrings(ereq)
		props["entity"] = obj{"type": "object", "additionalProperties": false, "required": ereq, "properties": eprops}
		required = append(required, "entity")
	}
	if policyOK {
		props["policy"] = ref("policy")
		props["action_id"] = obj{"type": "integer", "enum": []int{1, 2}}
		props["authorizations"] = obj{"type": "array", "maxItems": 128, "items": ref("authorization")}
		if a.Policy == "required" {
			required = append(required, "policy")
		}
	}
	// unmapped.sluis: the members of the row, and lost, which the emitter adds to a record of any action.
	sluisProps := obj{"lost": ref("lost")}
	var sluisReq []string
	for _, n := range sortedNames(a.Fields) {
		sluisProps[n] = fieldSchema(a.Fields[n])
		if a.Fields[n].Required {
			sluisReq = append(sluisReq, n)
		}
	}
	sluis := obj{"type": "object", "additionalProperties": false, "properties": sluisProps}
	unmapped := obj{"type": "object", "additionalProperties": false, "required": []string{"sluis"}, "properties": obj{"sluis": sluis}}
	if len(sluisReq) > 0 {
		sluis["required"] = sluisReq
		required = append(required, "unmapped")
	}
	props["unmapped"] = unmapped

	var all []obj
	if len(acts) > 1 {
		var branches []obj
		for _, ac := range acts {
			b := obj{"properties": obj{"activity_id": obj{"const": ac.ID}, "type_uid": obj{"const": a.Class*100 + ac.ID}}}
			if ac.Name != "" {
				b["properties"].(obj)["activity_name"] = obj{"const": ac.Name}
				b["required"] = []string{"activity_name"}
			}
			branches = append(branches, b)
		}
		all = append(all, obj{"anyOf": branches})
	}
	if policyOK {
		// REQ-AUDIT-120: a record that carries the attributes of a profile declares it.
		all = append(all, obj{
			"if":   obj{"required": []string{"policy"}},
			"then": obj{"properties": obj{"metadata": obj{"required": []string{"profiles"}}}},
		})
	}
	sortStrings(required)
	doc := obj{
		"$schema": draft, "title": a.Name,
		"$comment": "Generated from docs/architecture/audit-actions.yaml by tools/gen/audit. Do not edit.",
		"type":     "object", "additionalProperties": false, "required": required, "properties": props,
	}
	if len(all) > 0 {
		doc["allOf"] = all
	}
	return doc
}
