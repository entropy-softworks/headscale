package scim

import (
	"encoding/json"
	"slices"
	"strings"
	"time"
)

// Match reports whether resource satisfies the filter e. resource is a
// map[string]any as produced by decoding JSON, or any value that marshals to
// a JSON object (*User, *Group, ...). A nil filter matches everything.
//
// Semantics (RFC 7644 section 3.4.2.2):
//   - attribute names are case-insensitive;
//   - string comparison is case-insensitive unless the attribute is
//     caseExact: id, externalId, meta.location, $ref (RFC 7643). userName,
//     displayName and emails.value are caseExact=false, so Okta's
//     random-case userName lookups and Entra ID's email lookups match;
//   - a multi-valued attribute matches if any of its values matches; for a
//     multi-valued complex attribute without sub-attribute the "value"
//     sub-attribute is compared;
//   - ordering operators compare RFC 3339 timestamps as times, other strings
//     lexically and numbers numerically;
//   - "ne" is the negation of "eq", so an absent attribute is "ne" to every
//     non-null value, and "x eq null" matches an absent attribute.
func Match(e Expr, resource any) (bool, error) {
	if e == nil {
		return true, nil
	}

	obj, ok := resource.(map[string]any)
	if !ok {
		data, err := json.Marshal(resource)
		if err != nil {
			return false, Internal(err)
		}

		err = json.Unmarshal(data, &obj)
		if err != nil {
			return false, Internal(err)
		}
	}

	return eval(e, obj), nil
}

func eval(e Expr, obj map[string]any) bool {
	switch x := e.(type) {
	case *LogicalExpr:
		if x.Op == OpAnd {
			return eval(x.Left, obj) && eval(x.Right, obj)
		}

		return eval(x.Left, obj) || eval(x.Right, obj)
	case *NotExpr:
		return !eval(x.X, obj)
	case *PresentExpr:
		return slices.ContainsFunc(lookup(obj, x.Path), present)
	case *CompareExpr:
		values := lookup(obj, x.Path)
		caseExact := isCaseExact(x.Path.Attr, x.Path.Sub)

		if x.Op == OpNe {
			return !anyMatch(values, OpEq, x.Value, caseExact)
		}

		return anyMatch(values, x.Op, x.Value, caseExact)
	case *ValuePathExpr:
		raw, ok := getFold(scope(obj, x.Path), x.Path.Attr)
		if !ok {
			return false
		}

		for _, el := range asList(raw) {
			m, ok := el.(map[string]any)
			if !ok {
				continue
			}

			if evalElement(x.Filter, m, x.Path.Attr) {
				return true
			}
		}

		return false
	}

	return false
}

// evalElement evaluates a value-path filter against one element of the
// multi-valued attribute parent. Paths inside are sub-attributes of parent,
// which matters for caseExact lookups.
func evalElement(e Expr, el map[string]any, parent string) bool {
	switch x := e.(type) {
	case *LogicalExpr:
		if x.Op == OpAnd {
			return evalElement(x.Left, el, parent) && evalElement(x.Right, el, parent)
		}

		return evalElement(x.Left, el, parent) || evalElement(x.Right, el, parent)
	case *NotExpr:
		return !evalElement(x.X, el, parent)
	case *PresentExpr:
		v, _ := getFold(el, x.Path.Attr)

		return present(v)
	case *CompareExpr:
		var values []any
		if v, ok := getFold(el, x.Path.Attr); ok {
			values = []any{v}
		}

		caseExact := isCaseExact(parent, x.Path.Attr)
		if x.Op == OpNe {
			return !anyMatch(values, OpEq, x.Value, caseExact)
		}

		return anyMatch(values, x.Op, x.Value, caseExact)
	case *ValuePathExpr:
		// Rejected by the parser.
		return false
	}

	return false
}

// scope returns the object holding path's attribute: the extension block
// for extension-qualified paths, obj otherwise.
func scope(obj map[string]any, p AttrPath) map[string]any {
	if !p.IsExtension() {
		return obj
	}

	ext, _ := getFold(obj, p.URI)
	m, _ := ext.(map[string]any)

	return m
}

// lookup returns the values of p in obj, flattening multi-valued attributes.
func lookup(obj map[string]any, p AttrPath) []any {
	raw, ok := getFold(scope(obj, p), p.Attr)
	if !ok {
		return nil
	}

	var out []any

	for _, el := range asList(raw) {
		m, isObj := el.(map[string]any)

		switch {
		case p.Sub != "" && isObj:
			if v, ok := getFold(m, p.Sub); ok {
				out = append(out, v)
			}
		case p.Sub != "":
			// Sub-attribute of a non-complex value: nothing to compare.
		case isObj:
			if v, ok := getFold(m, "value"); ok {
				out = append(out, v)
			}
		default:
			out = append(out, el)
		}
	}

	return out
}

func asList(v any) []any {
	if l, ok := v.([]any); ok {
		return l
	}

	return []any{v}
}

func getFold(m map[string]any, key string) (any, bool) {
	if m == nil {
		return nil, false
	}

	if v, ok := m[key]; ok {
		return v, true
	}

	for k, v := range m {
		if strings.EqualFold(k, key) {
			return v, true
		}
	}

	return nil, false
}

func present(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case string:
		return x != ""
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	default:
		return true
	}
}

func anyMatch(values []any, op CompareOp, lit any, caseExact bool) bool {
	if len(values) == 0 {
		// Absent attribute: only "eq null" matches.
		return op == OpEq && lit == nil
	}

	for _, v := range values {
		if compare(v, op, lit, caseExact) {
			return true
		}
	}

	return false
}

func compare(v any, op CompareOp, lit any, caseExact bool) bool {
	switch l := lit.(type) {
	case nil:
		return op == OpEq && v == nil
	case bool:
		b, ok := v.(bool)

		return ok && op == OpEq && b == l
	case float64:
		n, ok := v.(float64)
		if !ok {
			return false
		}

		return ordered(op, cmpFloat(n, l))
	case string:
		s, ok := v.(string)
		if !ok {
			return false
		}

		return compareString(s, op, l, caseExact)
	}

	return false
}

func compareString(s string, op CompareOp, l string, caseExact bool) bool {
	if !caseExact {
		s = strings.ToLower(s)
		l = strings.ToLower(l)
	}

	switch op {
	case OpEq:
		return s == l
	case OpCo:
		return strings.Contains(s, l)
	case OpSw:
		return strings.HasPrefix(s, l)
	case OpEw:
		return strings.HasSuffix(s, l)
	case OpGt, OpGe, OpLt, OpLe:
		ts, errS := time.Parse(time.RFC3339Nano, s)
		tl, errL := time.Parse(time.RFC3339Nano, l)

		if errS == nil && errL == nil {
			return ordered(op, ts.Compare(tl))
		}

		return ordered(op, strings.Compare(s, l))
	case OpNe:
		return s != l
	}

	return false
}

func cmpFloat(a, b float64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

// ordered applies an eq or ordering operator to a three-way comparison.
func ordered(op CompareOp, c int) bool {
	switch op {
	case OpEq:
		return c == 0
	case OpNe:
		return c != 0
	case OpGt:
		return c > 0
	case OpGe:
		return c >= 0
	case OpLt:
		return c < 0
	case OpLe:
		return c <= 0
	case OpCo, OpSw, OpEw:
	}

	return false
}

// Equality is a `attr eq "value"` condition extracted from a filter for an
// indexed lookup.
type Equality struct {
	// Attr is the canonical attribute path, e.g. "userName", "externalId",
	// "displayName" or "emails.value" (value paths are flattened).
	Attr string
	// Value is the compared string. Unless [IsCaseExact] reports true for
	// Attr, the lookup must be case-insensitive.
	Value string
	// Exact is true when the filter consists of this comparison alone, so
	// the lookup result needs no further filtering with [Match]. This
	// assumes the database compares like [Match] does: case-insensitive
	// attributes are folded with Unicode strings.ToLower. SQLite's NOCASE
	// collation folds ASCII only, so a lookup relying on it can miss
	// non-ASCII matches; fold the value (and the stored column) in Go, or
	// post-filter with Match, when that matters.
	Exact bool
}

// ExtractEquality finds a string equality that every resource matching e
// must satisfy, restricted to the attributes in attrs (canonical names,
// matched case-insensitively; none means any attribute). Only top-level
// "and" conjuncts are considered, including the conjuncts inside a value
// path, which are flattened to "attr.sub". For
//
//	userName eq "alice" and active eq true
//	emails[type eq "work"].value eq "a@b.c"
//	emails eq "a@b.c"
//
// ExtractEquality(e, "userName") returns userName/"alice";
// ExtractEquality(e, "emails.value") returns emails.value/"a@b.c" for the
// second (whose conjuncts are type eq "work" and value eq "a@b.c", so
// ExtractEquality(e, "emails.type") would return emails.type/"work") and
// for the third (a multi-valued attribute without sub-attribute compares
// its "value"). Exact is false for the first two. A handler can use the
// result to narrow a database query and must then apply [Match] to the
// candidates unless Exact is set. It returns false for filters with no such
// condition (e.g. any "or" at the top).
func ExtractEquality(e Expr, attrs ...string) (Equality, bool) {
	var found []Equality

	collectEqualities(e, "", &found)

	for _, eq := range found {
		if len(attrs) > 0 && !containsFold(attrs, eq.Attr) {
			continue
		}

		_, single := e.(*CompareExpr)
		eq.Exact = single

		return eq, true
	}

	return Equality{}, false
}

func collectEqualities(e Expr, parent string, out *[]Equality) {
	switch x := e.(type) {
	case *LogicalExpr:
		if x.Op == OpAnd {
			collectEqualities(x.Left, parent, out)
			collectEqualities(x.Right, parent, out)
		}
	case *ValuePathExpr:
		if parent == "" && !x.Path.IsExtension() {
			collectEqualities(x.Filter, x.Path.Attr, out)
		}
	case *CompareExpr:
		s, ok := x.Value.(string)
		if !ok || x.Op != OpEq || x.Path.IsExtension() {
			return
		}

		attr := x.Path.String()

		switch {
		case parent != "":
			attr = parent + "." + x.Path.Attr
		case x.Path.Sub == "" && hasValueSub(x.Path.Attr):
			// emails eq "x" compares emails.value (RFC 7644 3.4.2.2).
			attr += ".value"
		}

		*out = append(*out, Equality{Attr: attr, Value: s})
	case *NotExpr, *PresentExpr:
	}
}

// hasValueSub reports whether attr is a known complex attribute with a
// "value" sub-attribute (emails, groups, members).
func hasValueSub(attr string) bool {
	_, ok := knownAttrs[strings.ToLower(attr)].subs["value"]

	return ok
}
