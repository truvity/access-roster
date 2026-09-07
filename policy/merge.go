package policy

import (
	"fmt"
	"maps"
	"slices"
)

// mergeFragment merges src into dst under the rules the reference states:
// lists union, maps recurse, scalars may not conflict. Conflicts are
// already refused at load, so a conflict here is a bug rather than a
// configuration error; it is still reported rather than resolved.
func mergeFragment(dst map[string]any, src map[string]any, at string) error {
	for _, key := range slices.Sorted(maps.Keys(src)) {
		where := key
		if at != "" {
			where = at + "." + key
		}
		incoming := src[key]
		existing, present := dst[key]
		if !present {
			dst[key] = cloneValue(incoming)
			continue
		}
		merged, err := mergeValue(existing, incoming, where)
		if err != nil {
			return err
		}
		dst[key] = merged
	}
	return nil
}

// asMap accepts any map with string keys and dynamic values. yaml.v3
// reuses the named type it is decoding into for nested mappings, so a
// fragment's inner maps arrive as Fragment rather than map[string]any; a
// type switch on the unnamed type alone silently misses them, which cost
// one merged claim before this existed.
func asMap(v any) (map[string]any, bool) {
	switch typed := v.(type) {
	case map[string]any:
		return typed, true
	case Fragment:
		return typed, true
	default:
		return nil, false
	}
}

func mergeValue(existing, incoming any, where string) (any, error) {
	if left, ok := asMap(existing); ok {
		right, ok := asMap(incoming)
		if !ok {
			return nil, fmt.Errorf("%s is a map in one group and a %T in another", where, incoming)
		}
		out := maps.Clone(left)
		if err := mergeFragment(out, right, where); err != nil {
			return nil, err
		}
		return out, nil
	}

	switch left := existing.(type) {
	case []any:
		right, ok := incoming.([]any)
		if !ok {
			return nil, fmt.Errorf("%s is a list in one group and a %T in another", where, incoming)
		}
		return union(left, right), nil

	default:
		if fmt.Sprint(existing) != fmt.Sprint(incoming) {
			return nil, fmt.Errorf("%s is set to %v and to %v by different groups", where, existing, incoming)
		}
		return existing, nil
	}
}

// union de-duplicates and sorts, so that a token's claims do not depend on
// the order the groups happened to be evaluated in.
func union(left, right []any) []any {
	seen := make(map[string]any, len(left)+len(right))
	for _, v := range append(slices.Clone(left), right...) {
		seen[fmt.Sprint(v)] = v
	}
	out := make([]any, 0, len(seen))
	for _, key := range slices.Sorted(maps.Keys(seen)) {
		out = append(out, seen[key])
	}
	return out
}

// Plain returns a value with every named map type replaced by
// map[string]any, so that an encoder which type-switches on the unnamed
// type sees what it expects.
func Plain(v any) any { return cloneValue(v) }

func cloneValue(v any) any {
	if typed, ok := asMap(v); ok {
		out := make(map[string]any, len(typed))
		for k, inner := range typed {
			out[k] = cloneValue(inner)
		}
		return out
	}
	switch typed := v.(type) {
	case []any:
		out := make([]any, 0, len(typed))
		for _, inner := range typed {
			out = append(out, cloneValue(inner))
		}
		return out
	default:
		return v
	}
}

// walkScalars visits every scalar leaf with its dotted path.
func walkScalars(value any, at string, visit func(where string, got any) error) error {
	if typed, ok := asMap(value); ok {
		for _, key := range slices.Sorted(maps.Keys(typed)) {
			where := key
			if at != "" {
				where = at + "." + key
			}
			if err := walkScalars(typed[key], where, visit); err != nil {
				return err
			}
		}
		return nil
	}
	switch value.(type) {
	case []any:
		// A list is unioned, never conflicting: its members are not
		// scalars for this purpose.
		return nil
	default:
		return visit(at, value)
	}
}
