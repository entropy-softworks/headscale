package scim

import (
	"encoding/json"
	"maps"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

// ListRequest is a parsed list/query request (RFC 7644 section 3.4.2).
type ListRequest struct {
	// StartIndex is the 1-based index of the first result. Values below 1
	// are raised to 1 (RFC 7644 section 3.4.2.4).
	StartIndex int
	// Count is the maximum number of results, in [0, MaxPageSize]. Negative
	// values become 0 (return only totalResults); absent or larger values
	// become MaxPageSize.
	Count int
	// Filter is the parsed filter, or nil when absent.
	Filter Expr
	// Attributes and ExcludedAttributes are the requested projection, as
	// written (URN prefixes allowed). See [Project].
	Attributes         []string
	ExcludedAttributes []string
}

// Offset returns the zero-based offset of the first result.
func (r *ListRequest) Offset() int {
	return r.StartIndex - 1
}

// ParseListRequest parses startIndex, count, filter, attributes and
// excludedAttributes from a query string. Parameter names are
// case-insensitive. Non-integer startIndex/count yield invalidValue, a bad
// filter invalidFilter. sortBy/sortOrder are ignored (sort is advertised as
// unsupported).
func ParseListRequest(q url.Values) (*ListRequest, error) {
	req := &ListRequest{StartIndex: 1, Count: MaxPageSize}

	get := func(name string) (string, bool) { return queryParam(q, name) }

	if s, ok := get("startIndex"); ok && s != "" {
		n, err := strconv.Atoi(s)
		if err != nil {
			return nil, InvalidValue("startIndex must be an integer, got %q", s)
		}

		req.StartIndex = max(n, 1)
	}

	if s, ok := get("count"); ok && s != "" {
		n, err := strconv.Atoi(s)
		if err != nil {
			return nil, InvalidValue("count must be an integer, got %q", s)
		}

		req.Count = min(max(n, 0), MaxPageSize)
	}

	if s, ok := get("filter"); ok && s != "" {
		f, err := ParseFilter(s)
		if err != nil {
			return nil, err
		}

		req.Filter = f
	}

	attrs, excluded, err := ParseProjection(q)
	if err != nil {
		return nil, err
	}

	req.Attributes = attrs
	req.ExcludedAttributes = excluded

	return req, nil
}

// ParseProjection parses the attributes and excludedAttributes query
// parameters, for single-resource GET, POST, PUT and PATCH responses (RFC
// 7644 section 3.9); pass the results to [Project]. Invalid attribute names
// yield invalidValue.
func ParseProjection(q url.Values) ([]string, []string, error) {
	var attrs, excluded []string

	if s, ok := queryParam(q, "attributes"); ok {
		attrs = splitAttrList(s)
	}

	if s, ok := queryParam(q, "excludedAttributes"); ok {
		excluded = splitAttrList(s)
	}

	for _, a := range slices.Concat(attrs, excluded) {
		_, err := ParseAttrPath(a)
		if err != nil {
			return nil, nil, InvalidValue("invalid attribute %q", a)
		}
	}

	return attrs, excluded, nil
}

// queryParam returns the first value of the parameter name, matched
// case-insensitively. If the query holds several spellings (count and
// COUNT), the exact spelling wins, then the lexically smallest, so the
// result never depends on map iteration order.
func queryParam(q url.Values, name string) (string, bool) {
	if v := q[name]; len(v) > 0 {
		return strings.TrimSpace(v[0]), true
	}

	keys := slices.Sorted(maps.Keys(q))
	for _, k := range keys {
		if v := q[k]; strings.EqualFold(k, name) && len(v) > 0 {
			return strings.TrimSpace(v[0]), true
		}
	}

	return "", false
}

func splitAttrList(s string) []string {
	var out []string

	for part := range strings.SplitSeq(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}

	return out
}

// ListResponse is the RFC 7644 section 3.4.2 list response. startIndex,
// itemsPerPage and totalResults are JSON integers (Okta requires this) and
// Resources is always an array, never null.
type ListResponse struct {
	Schemas      []string `json:"schemas"`
	TotalResults int      `json:"totalResults"`
	ItemsPerPage int      `json:"itemsPerPage"`
	StartIndex   int      `json:"startIndex"`
	Resources    []any    `json:"Resources"`
}

// NewListResponse builds a list response for one page. total is the number
// of resources matching the query across all pages; page holds the
// resources of this page (already projected if needed).
func NewListResponse(req *ListRequest, total int, page []any) *ListResponse {
	if page == nil {
		page = []any{}
	}

	start := 1
	if req != nil {
		start = req.StartIndex
	}

	return &ListResponse{
		Schemas:      []string{SchemaListResponse},
		TotalResults: total,
		ItemsPerPage: len(page),
		StartIndex:   start,
		Resources:    page,
	}
}

// Paginate returns the slice of items selected by req's startIndex and
// count. Callers must pass items in a stable order (e.g. by id) so that
// consecutive pages neither repeat nor skip resources.
func Paginate[T any](req *ListRequest, items []T) []T {
	off := req.Offset()
	if off >= len(items) {
		return nil
	}

	end := min(off+req.Count, len(items))

	return items[off:end]
}

// alwaysReturned are attributes projection never removes
// (RFC 7643 section 7, returned "always").
var alwaysReturned = []string{"id", "schemas"}

// Project applies an attributes/excludedAttributes projection (RFC 7644
// section 3.9) to resource and returns the result as a JSON object. With
// neither list it returns the resource unchanged. attributes selects
// top-level attributes or single sub-attributes ("name.givenName");
// excludedAttributes removes them (e.g. Entra ID's excludedAttributes=members
// on group lookups). id and schemas are always kept. Names match
// case-insensitively and may carry a core schema URN prefix.
func Project(resource any, attributes, excluded []string) (any, error) {
	if len(attributes) == 0 && len(excluded) == 0 {
		return resource, nil
	}

	data, err := json.Marshal(resource)
	if err != nil {
		return nil, Internal(err)
	}

	var obj map[string]any

	err = json.Unmarshal(data, &obj)
	if err != nil {
		return nil, Internal(err)
	}

	if len(attributes) > 0 {
		obj = include(obj, attributes)
	}

	for _, a := range excluded {
		p, err := ParseAttrPath(a)
		if err != nil || p.IsExtension() || containsFold(alwaysReturned, p.Attr) {
			continue
		}

		key, ok := findKey(obj, p.Attr)
		if !ok {
			continue
		}

		if p.Sub == "" {
			delete(obj, key)

			continue
		}

		excludeSub(obj, key, p.Sub)
	}

	return obj, nil
}

func include(obj map[string]any, attributes []string) map[string]any {
	out := map[string]any{}

	for _, a := range alwaysReturned {
		if k, ok := findKey(obj, a); ok {
			out[k] = obj[k]
		}
	}

	for _, a := range attributes {
		p, err := ParseAttrPath(a)
		if err != nil || p.IsExtension() {
			continue
		}

		key, ok := findKey(obj, p.Attr)
		if !ok {
			continue
		}

		if p.Sub == "" {
			out[key] = obj[key]

			continue
		}

		if list, isList := obj[key].([]any); isList {
			out[key] = includeSubList(list, out[key], p.Sub)

			continue
		}

		if src, ok := obj[key].(map[string]any); ok {
			dst, _ := out[key].(map[string]any)
			if merged := includeSub(src, dst, p.Sub); merged != nil {
				out[key] = merged
			}
		}
	}

	return out
}

// includeSub copies sub from src into dst (allocated if nil) and returns
// dst, or returns dst unchanged when src lacks sub.
func includeSub(src, dst map[string]any, sub string) map[string]any {
	sk, ok := findKey(src, sub)
	if !ok {
		return dst
	}

	if dst == nil {
		dst = map[string]any{}
	}

	dst[sk] = src[sk]

	return dst
}

// includeSubList projects sub out of every element of a multi-valued
// complex attribute, merging with an earlier projection prev of the same
// attribute (e.g. attributes=emails.value,emails.type).
func includeSubList(list []any, prev any, sub string) []any {
	prevList, _ := prev.([]any)
	out := make([]any, len(list))

	for i, el := range list {
		var dst map[string]any
		if i < len(prevList) {
			dst, _ = prevList[i].(map[string]any)
		}

		src, _ := el.(map[string]any)
		if merged := includeSub(src, dst, sub); merged != nil {
			out[i] = merged
		} else {
			out[i] = map[string]any{}
		}
	}

	return out
}

func findKey(m map[string]any, name string) (string, bool) {
	if _, ok := m[name]; ok {
		return name, true
	}

	for k := range m {
		if strings.EqualFold(k, name) {
			return k, true
		}
	}

	return "", false
}

// excludeSub removes sub from the complex attribute obj[key] (or from every
// element of a multi-valued one) and drops whatever becomes empty, so the
// response never carries "name":{} or "emails":[{}].
func excludeSub(obj map[string]any, key, sub string) {
	switch v := obj[key].(type) {
	case map[string]any:
		if sk, ok := findKey(v, sub); ok {
			delete(v, sk)
		}

		if len(v) == 0 {
			delete(obj, key)
		}
	case []any:
		kept := v[:0]

		for _, el := range v {
			m, ok := el.(map[string]any)
			if !ok {
				kept = append(kept, el)

				continue
			}

			if sk, ok := findKey(m, sub); ok {
				delete(m, sk)
			}

			if len(m) > 0 {
				kept = append(kept, m)
			}
		}

		if len(kept) == 0 {
			delete(obj, key)
		} else {
			obj[key] = kept
		}
	}
}
