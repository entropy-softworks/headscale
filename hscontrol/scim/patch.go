package scim

import (
	"bytes"
	"encoding/json"
	"io"
	"strconv"
	"strings"
)

// PatchRequest is a decoded PATCH body (RFC 7644 section 3.5.2).
type PatchRequest struct {
	Schemas    []string         `json:"schemas"`
	Operations []PatchOperation `json:"Operations"`
}

// PatchOperation is one raw operation as sent by the client. Use
// [NormalizeUserPatch] or [NormalizeGroupPatch] to turn it into canonical
// [Operation] values.
type PatchOperation struct {
	Op    string          `json:"op"`
	Path  string          `json:"path,omitempty"`
	Value json.RawMessage `json:"value,omitempty"`
}

// Limits for a single PATCH request, on top of [MaxBodySize],
// [MaxMembersPerRequest] and [MaxEmails]. Real clients send one to a few
// dozen operations with paths well under 200 bytes.
const (
	// MaxOperations is the most operations one PATCH may carry (413 beyond).
	MaxOperations = 1000
	// MaxPathLength is the longest PATCH path accepted (invalidPath beyond).
	MaxPathLength = 1024
)

// DecodePatch decodes a PATCH request body. Malformed JSON, a schemas list
// without the PatchOp URN or an empty Operations list yield invalidSyntax;
// more than [MaxOperations] operations yield 413.
func DecodePatch(r io.Reader) (*PatchRequest, error) {
	var req PatchRequest

	err := decodeBody(r, &req)
	if err != nil {
		return nil, err
	}

	if len(req.Schemas) > 0 && !containsFold(req.Schemas, SchemaPatchOp) {
		return nil, InvalidSyntax("schemas must include %s", SchemaPatchOp)
	}

	if len(req.Operations) == 0 {
		return nil, InvalidSyntax("Operations must contain at least one operation")
	}

	if len(req.Operations) > MaxOperations {
		return nil, PayloadTooLarge("at most %d operations per request", MaxOperations)
	}

	return &req, nil
}

// Path is a canonical PATCH target (RFC 7644 section 3.5.2 PATH):
// Attr, Attr.Sub, Attr[Filter] or Attr[Filter].Sub, optionally qualified
// with a schema URN. Filter paths are relative to the elements of Attr.
// Attr and Sub use the canonical schema spelling for known attributes.
type Path struct {
	URI    string
	Attr   string
	Filter Expr
	Sub    string
}

// IsExtension reports whether the path addresses a schema other than core
// User or Group (such as the enterprise extension).
func (p Path) IsExtension() bool {
	return AttrPath{URI: p.URI}.IsExtension()
}

// String renders the path without URI, e.g. `emails[type eq "work"].value`.
func (p Path) String() string {
	s := p.Attr
	if p.Filter != nil {
		s += "[" + p.Filter.String() + "]"
	}

	if p.Sub != "" {
		s += "." + p.Sub
	}

	return s
}

// Operation is a canonical PATCH operation. The concrete types are
// SetAttribute, RemoveAttribute, AddMembers, RemoveMembers, ReplaceMembers
// and IgnoredAttribute.
type Operation interface {
	// String renders the operation for logs and golden tests.
	String() string
	isOperation()
}

// SetAttribute assigns Value to Path. Value is a string, a bool (active,
// emails[...].primary), []Email (emails) or [EmailPatch] (a filtered emails
// path without sub-attribute, such as emails[type eq "work"] with an object
// value). Append is set for "add" to the multi-valued emails attribute: the
// values are added rather than replacing the list.
//
// A filtered emails path that matches no element is an upsert: a new email
// is created, seeded from the filter's equality conditions (so
// emails[type eq "work"].value creates a work email). Entra ID relies on
// this when a user gains an email after creation.
type SetAttribute struct {
	Path   Path
	Value  any
	Append bool
}

// RemoveAttribute unassigns Path. Removing filtered emails that match
// nothing is a no-op.
type RemoveAttribute struct {
	Path Path
}

// EmailPatch is the value of a SetAttribute on a filtered emails path
// without sub-attribute. All fields are applied to the same elements, which
// are selected once, so the result does not depend on the order of the keys
// in the request (replacing "type" must not change which email "value"
// lands on). Nil fields are left unchanged.
type EmailPatch struct {
	Value   *string `json:"value,omitempty"`
	Type    *string `json:"type,omitempty"`
	Primary *bool   `json:"primary,omitempty"`
}

// IgnoredAttribute records a path that was accepted but has no effect:
// extension schema attributes, RFC core attributes headscale does not store
// (title, phoneNumbers, ...) and unknown attributes, which custom Entra ID
// and Okta attribute mappings produce. Apply functions skip it; a handler
// may log it.
type IgnoredAttribute struct {
	Path   Path
	Reason string
}

// AddMembers adds users to a group; existing members are kept.
type AddMembers struct {
	IDs []string
}

// RemoveMembers removes users from a group; unknown IDs are ignored.
type RemoveMembers struct {
	IDs []string
}

// ReplaceMembers sets the group membership to exactly IDs (possibly none).
type ReplaceMembers struct {
	IDs []string
}

func (SetAttribute) isOperation()     {}
func (RemoveAttribute) isOperation()  {}
func (AddMembers) isOperation()       {}
func (RemoveMembers) isOperation()    {}
func (ReplaceMembers) isOperation()   {}
func (IgnoredAttribute) isOperation() {}

func (o IgnoredAttribute) String() string {
	s := "ignore " + o.Path.String()
	if o.Path.IsExtension() {
		s = "ignore " + o.Path.URI + ":" + o.Path.String()
	}

	return s + " (" + o.Reason + ")"
}

func (o SetAttribute) String() string {
	v, err := json.Marshal(o.Value)
	if err != nil {
		v = []byte("?")
	}

	if o.Append {
		return "append " + o.Path.String() + " " + string(v)
	}

	return "set " + o.Path.String() + " " + string(v)
}

func (o RemoveAttribute) String() string { return "remove " + o.Path.String() }

func (o AddMembers) String() string { return "add-members " + jsonList(o.IDs) }

func (o RemoveMembers) String() string { return "remove-members " + jsonList(o.IDs) }

func (o ReplaceMembers) String() string { return "replace-members " + jsonList(o.IDs) }

func jsonList(ids []string) string {
	if len(ids) == 0 {
		return "[]"
	}

	quoted := make([]string, len(ids))
	for i, id := range ids {
		quoted[i] = strconv.Quote(id)
	}

	return "[" + strings.Join(quoted, ",") + "]"
}

const (
	opAdd     = "add"
	opReplace = "replace"
	opRemove  = "remove"
)

// Attribute names used in dispatch.
const (
	attrUserName    = "userName"
	attrDisplayName = "displayName"
	attrExternalID  = "externalId"
	attrActive      = "active"
	attrName        = "name"
	attrEmails      = "emails"
	attrMembers     = "members"
	attrValue       = "value"
	attrType        = "type"
	attrPrimary     = "primary"
)

// readOnlyAttrs cannot be changed by PATCH (mutability error). A path-less
// value object may still carry "id" and "schemas" (Okta sends id when
// renaming groups); those keys are skipped instead.
var readOnlyAttrs = []string{"id", "meta", "groups", "schemas"}

// ignoredUserAttrs are RFC 7643 core User attributes headscale does not
// store. Entra ID's default attribute mappings send several of them
// (title, phoneNumbers, addresses, preferredLanguage, nickName), so they are
// accepted and dropped rather than rejected. password is in the list
// because Okta may send it; it is never stored.
var ignoredUserAttrs = []string{
	"nickName", "profileUrl", "title", "userType", "preferredLanguage",
	"locale", "timezone", "password", "phoneNumbers", "ims", "photos",
	"addresses", "entitlements", "roles", "x509Certificates",
}

var ignoredNameSubs = []string{"middleName", "honorificPrefix", "honorificSuffix"}

type resourceKind int

const (
	kindUser resourceKind = iota
	kindGroup
)

// NormalizeUserPatch validates req against the User schema and returns the
// canonical operations in request order. It handles the forms sent by Entra
// ID (with and without aadOptscim062020), Okta and Authentik; see the
// package documentation for the full table.
func NormalizeUserPatch(req *PatchRequest) ([]Operation, error) {
	return normalize(req, kindUser)
}

// NormalizeGroupPatch validates req against the Group schema and returns the
// canonical operations in request order.
func NormalizeGroupPatch(req *PatchRequest) ([]Operation, error) {
	return normalize(req, kindGroup)
}

func normalize(req *PatchRequest, kind resourceKind) ([]Operation, error) {
	if len(req.Operations) > MaxOperations {
		return nil, PayloadTooLarge("at most %d operations per request", MaxOperations)
	}

	var (
		out     []Operation
		members int
	)

	for i, raw := range req.Operations {
		ops, err := normalizeOne(raw, kind)
		if err == nil {
			members += countMembers(ops)
			if members > MaxMembersPerRequest {
				err = PayloadTooLarge("at most %d member references per request", MaxMembersPerRequest)
			}
		}

		if err != nil {
			se := AsError(err)
			detail := *se
			detail.Detail = "Operations[" + strconv.Itoa(i) + "]: " + se.Detail

			return nil, &detail
		}

		out = append(out, ops...)
	}

	return out, nil
}

func countMembers(ops []Operation) int {
	n := 0

	for _, op := range ops {
		switch o := op.(type) {
		case AddMembers:
			n += len(o.IDs)
		case RemoveMembers:
			n += len(o.IDs)
		case ReplaceMembers:
			n += len(o.IDs)
		case SetAttribute, RemoveAttribute, IgnoredAttribute:
		}
	}

	return n
}

func normalizeOne(raw PatchOperation, kind resourceKind) ([]Operation, error) {
	op := strings.ToLower(strings.TrimSpace(raw.Op))
	switch op {
	case opAdd, opReplace, opRemove:
	default:
		return nil, InvalidSyntax("unsupported op %q", raw.Op)
	}

	if strings.TrimSpace(raw.Path) != "" {
		path, err := ParsePath(raw.Path)
		if err != nil {
			return nil, err
		}

		return normalizePath(op, path, raw.Value, kind)
	}

	if op == opRemove {
		return nil, NoTarget("remove requires a path")
	}

	return normalizePathless(op, raw.Value, kind, false)
}

// normalizePathless expands {"op":"replace","value":{...}} into one
// operation per key. Keys may be dotted ("name.givenName", Entra ID with
// aadOptscim062020) or schema-qualified; nested objects ({"name":{...}})
// are expanded by the per-attribute handlers. id, schemas and meta are
// skipped (Okta sends id on group rename). A core schema block
// ({"urn:...:core:2.0:User": {...}}) is unwrapped once; nested blocks are
// rejected so a request cannot drive unbounded recursion.
func normalizePathless(op string, value json.RawMessage, kind resourceKind, nested bool) ([]Operation, error) {
	kvs, ok := decodeObject(value)
	if !ok {
		return nil, InvalidSyntax("%s without path requires an object value", op)
	}

	var out []Operation

	for _, kv := range kvs {
		key := strings.TrimSpace(kv.key)

		// {"urn:...:core:2.0:User": {...}} carries core attributes. Any
		// other schema URN key (the enterprise extension block, or an
		// extension-qualified attribute) parses as an extension path and is
		// dropped by normalizePath.
		if strings.EqualFold(key, SchemaUser) || strings.EqualFold(key, SchemaGroup) {
			if nested {
				return nil, InvalidSyntax("nested schema block %q", key)
			}

			ops, err := normalizePathless(op, kv.value, kind, true)
			if err != nil {
				return nil, err
			}

			out = append(out, ops...)

			continue
		}

		path, err := ParsePath(key)
		if err != nil {
			return nil, err
		}

		if path.Filter == nil && path.Sub == "" && containsFold([]string{"id", "schemas", "meta"}, path.Attr) {
			continue
		}

		ops, err := normalizePath(op, path, kv.value, kind)
		if err != nil {
			return nil, err
		}

		out = append(out, ops...)
	}

	return out, nil
}

func normalizePath(op string, p Path, value json.RawMessage, kind resourceKind) ([]Operation, error) {
	if p.IsExtension() {
		return ignored(p, "extension schema"), nil
	}

	if containsFold(readOnlyAttrs, p.Attr) {
		return nil, Mutability("attribute %q is read-only", p.Attr)
	}

	if kind == kindGroup {
		return normalizeGroupPath(op, p, value)
	}

	return normalizeUserPath(op, p, value)
}

func normalizeUserPath(op string, p Path, value json.RawMessage) ([]Operation, error) {
	switch p.Attr {
	case attrUserName, attrDisplayName, attrExternalID:
		return scalarOp(op, p, value, decodeString)
	case attrActive:
		return scalarOp(op, p, value, decodeBool)
	case attrName:
		return nameOp(op, p, value)
	case attrEmails:
		return emailsOp(op, p, value)
	}

	if containsFold(ignoredUserAttrs, p.Attr) {
		return ignored(p, "not stored"), nil
	}

	return ignored(p, "unknown attribute"), nil
}

// ignored reports p as accepted without effect. Unknown attributes are
// ignored rather than rejected with invalidPath: custom attribute mappings in
// Entra ID and Okta would otherwise make every update of a user fail.
func ignored(p Path, reason string) []Operation {
	return []Operation{IgnoredAttribute{Path: p, Reason: reason}}
}

func normalizeGroupPath(op string, p Path, value json.RawMessage) ([]Operation, error) {
	switch p.Attr {
	case attrDisplayName, attrExternalID:
		return scalarOp(op, p, value, decodeString)
	case attrMembers:
		return membersOp(op, p, value)
	}

	return ignored(p, "unknown attribute"), nil
}

type decoder func(json.RawMessage) (any, error)

func isNull(value json.RawMessage) bool {
	v := bytes.TrimSpace(value)

	return len(v) == 0 || bytes.Equal(v, []byte("null"))
}

// scalarOp handles single-valued attributes without sub-attributes. A null
// value for add/replace unassigns the attribute (RFC 7644 section 3.5.2.3
// leaves this to the provider; Okta and Entra ID never rely on it).
func scalarOp(op string, p Path, value json.RawMessage, dec decoder) ([]Operation, error) {
	if p.Filter != nil || p.Sub != "" {
		return nil, InvalidPath("attribute %q has no sub-attributes", p.Attr)
	}

	if op == opRemove || isNull(value) {
		return []Operation{RemoveAttribute{Path: p}}, nil
	}

	v, err := dec(value)
	if err != nil {
		return nil, err
	}

	return []Operation{SetAttribute{Path: p, Value: v}}, nil
}

func decodeString(value json.RawMessage) (any, error) {
	var s string

	err := json.Unmarshal(value, &s)
	if err == nil {
		return s, nil
	}

	// Numbers are accepted as their literal text (externalId = 12345).
	var n json.Number

	err = json.Unmarshal(value, &n)
	if err == nil {
		return n.String(), nil
	}

	return nil, InvalidValue("expected a string, got %s", value)
}

func decodeBool(value json.RawMessage) (any, error) {
	return parseFlexBool(value)
}

func nameOp(op string, p Path, value json.RawMessage) ([]Operation, error) {
	if p.Filter != nil {
		return nil, InvalidPath("name is not multi-valued")
	}

	if p.Sub != "" {
		if containsFold(ignoredNameSubs, p.Sub) {
			return ignored(p, "not stored"), nil
		}

		if _, ok := knownAttrs["name"].subs[strings.ToLower(p.Sub)]; !ok {
			return nil, InvalidPath("unsupported attribute %q", p)
		}

		return subOp(op, Path{Attr: attrName, Sub: p.Sub}, value, decodeString)
	}

	if op == opRemove || isNull(value) {
		return []Operation{RemoveAttribute{Path: p}}, nil
	}

	// Replacing a complex attribute updates the given sub-attributes only
	// (RFC 7644 section 3.5.2.3), so expand the object.
	kvs, ok := decodeObject(value)
	if !ok {
		return nil, InvalidValue("name requires an object value")
	}

	var out []Operation

	for _, kv := range kvs {
		ops, err := nameOp(op, Path{Attr: attrName, Sub: canonicalSub(attrName, kv.key)}, kv.value)
		if err != nil {
			return nil, err
		}

		out = append(out, ops...)
	}

	return out, nil
}

func emailsOp(op string, p Path, value json.RawMessage) ([]Operation, error) {
	if p.Filter == nil && p.Sub != "" {
		return nil, InvalidPath("use a value filter to address an email, e.g. emails[type eq \"work\"].%s", p.Sub)
	}

	if p.Filter == nil {
		if op == opRemove && !isNull(value) {
			return removeEmailValues(p, value)
		}

		if op == opRemove || isNull(value) {
			return []Operation{RemoveAttribute{Path: p}}, nil
		}

		emails, err := decodeEmails(value)
		if err != nil {
			return nil, err
		}

		return []Operation{SetAttribute{Path: p, Value: emails, Append: op == opAdd}}, nil
	}

	if p.Sub == "" {
		if op == opRemove {
			return []Operation{RemoveAttribute{Path: p}}, nil
		}

		patch, err := decodeEmailPatch(p, value)
		if err != nil {
			return nil, err
		}

		return []Operation{SetAttribute{Path: p, Value: patch}}, nil
	}

	switch p.Sub {
	case attrValue, attrType:
		return subOp(op, p, value, decodeString)
	case attrPrimary:
		return subOp(op, p, value, decodeBool)
	case "display":
		return ignored(p, "not stored"), nil
	}

	return nil, InvalidPath("unsupported attribute %q", p)
}

// decodeEmailPatch decodes the object value of emails[filter]. Null
// members and display are ignored.
func decodeEmailPatch(p Path, value json.RawMessage) (EmailPatch, error) {
	var patch EmailPatch

	kvs, ok := decodeObject(value)
	if !ok {
		return patch, InvalidValue("%s requires an object value", p)
	}

	for _, kv := range kvs {
		sub := canonicalSub(attrEmails, kv.key)
		if isNull(kv.value) || sub == "display" {
			continue
		}

		switch sub {
		case attrValue, attrType:
			v, err := decodeString(kv.value)
			if err != nil {
				return patch, err
			}

			s, _ := v.(string)
			if sub == attrValue {
				patch.Value = &s
			} else {
				patch.Type = &s
			}
		case attrPrimary:
			b, err := parseFlexBool(kv.value)
			if err != nil {
				return patch, err
			}

			patch.Primary = &b
		default:
			return patch, InvalidPath("unsupported attribute %q", Path{Attr: p.Attr, Filter: p.Filter, Sub: sub})
		}
	}

	return patch, nil
}

// removeEmailValues handles {"op":"remove","path":"emails","value":[...]}:
// like the members form, the array lists the emails to remove (by value,
// case-insensitively) rather than all of them.
func removeEmailValues(p Path, value json.RawMessage) ([]Operation, error) {
	emails, err := decodeEmails(value)
	if err != nil {
		return nil, err
	}

	var filter Expr

	for _, e := range emails {
		c := &CompareExpr{Path: AttrPath{Attr: attrValue}, Op: OpEq, Value: e.Value}
		if filter == nil {
			filter = c
		} else {
			filter = &LogicalExpr{Op: OpOr, Left: filter, Right: c}
		}
	}

	if filter == nil {
		return nil, nil
	}

	return []Operation{RemoveAttribute{Path: Path{URI: p.URI, Attr: p.Attr, Filter: filter}}}, nil
}

func subOp(op string, p Path, value json.RawMessage, dec decoder) ([]Operation, error) {
	if op == opRemove || isNull(value) {
		return []Operation{RemoveAttribute{Path: p}}, nil
	}

	v, err := dec(value)
	if err != nil {
		return nil, err
	}

	return []Operation{SetAttribute{Path: p, Value: v}}, nil
}

func decodeEmails(value json.RawMessage) ([]Email, error) {
	var list []Email

	v := bytes.TrimSpace(value)
	if len(v) > 0 && v[0] == '{' {
		var e Email

		err := json.Unmarshal(v, &e)
		if err != nil {
			return nil, InvalidValue("invalid email: %v", err)
		}

		list = []Email{e}
	} else {
		err := json.Unmarshal(v, &list)
		if err != nil {
			return nil, InvalidValue("emails requires an array of emails: %v", err)
		}
	}

	if len(list) > MaxEmails {
		return nil, InvalidValue("at most %d emails are supported", MaxEmails)
	}

	for i, e := range list {
		if strings.TrimSpace(e.Value) == "" {
			return nil, InvalidValue("emails[%d].value is required", i)
		}
	}

	return list, nil
}

// membersOp handles every membership form real clients send:
//
//	add     members            [{"value":"id"}]  (all clients)
//	remove  members            [{"value":"id"}]  (Entra ID without aadOptscim062020, Authentik)
//	remove  members[value eq "id"]               (Okta, Entra ID with aadOptscim062020)
//	remove  members                              (remove all)
//	replace members            [{"value":"id"}]  (Okta)
func membersOp(op string, p Path, value json.RawMessage) ([]Operation, error) {
	if p.Sub != "" {
		return nil, InvalidPath("unsupported attribute %q", p)
	}

	if p.Filter != nil {
		if op != opRemove {
			return nil, InvalidPath("%s with a members filter is not supported", op)
		}

		ids, ok := memberFilterIDs(p.Filter)
		if !ok {
			return nil, InvalidPath("members filter must be `value eq \"id\"` (optionally joined with or), got %s", p.Filter)
		}

		return []Operation{RemoveMembers{IDs: ids}}, nil
	}

	if isNull(value) {
		switch op {
		case opRemove, opReplace:
			return []Operation{ReplaceMembers{IDs: []string{}}}, nil
		default:
			return nil, InvalidValue("add members requires a value")
		}
	}

	ids, err := decodeMemberIDs(value)
	if err != nil {
		return nil, err
	}

	switch op {
	case opAdd:
		return []Operation{AddMembers{IDs: ids}}, nil
	case opRemove:
		return []Operation{RemoveMembers{IDs: ids}}, nil
	default:
		return []Operation{ReplaceMembers{IDs: ids}}, nil
	}
}

// memberFilterIDs extracts the IDs of `value eq "a" [or value eq "b" ...]`.
func memberFilterIDs(e Expr) ([]string, bool) {
	var ids []string

	if !collectMemberIDs(e, &ids) {
		return nil, false
	}

	return dedupe(ids), true
}

func collectMemberIDs(e Expr, ids *[]string) bool {
	switch x := e.(type) {
	case *LogicalExpr:
		return x.Op == OpOr && collectMemberIDs(x.Left, ids) && collectMemberIDs(x.Right, ids)
	case *CompareExpr:
		s, ok := x.Value.(string)
		if !ok || x.Op != OpEq || x.Path.Attr != attrValue || x.Path.Sub != "" || s == "" {
			return false
		}

		*ids = append(*ids, s)

		return true
	case *NotExpr, *PresentExpr, *ValuePathExpr:
	}

	return false
}

// decodeMemberIDs accepts an array of member objects (the RFC form), a
// single member object, or an array of plain id strings.
func decodeMemberIDs(value json.RawMessage) ([]string, error) {
	v := bytes.TrimSpace(value)
	if len(v) > 0 && v[0] == '{' {
		v = append(append([]byte{'['}, v...), ']')
	}

	var raw []json.RawMessage

	err := json.Unmarshal(v, &raw)
	if err != nil {
		return nil, InvalidValue("members requires an array of members")
	}

	if len(raw) > MaxMembersPerRequest {
		return nil, PayloadTooLarge("at most %d member references per request", MaxMembersPerRequest)
	}

	ids := make([]string, 0, len(raw))

	for i, r := range raw {
		var id string

		var m Member

		if json.Unmarshal(r, &id) != nil {
			err := json.Unmarshal(r, &m)
			if err != nil {
				return nil, InvalidValue("members[%d] is not a member object", i)
			}

			id = m.Value
		}

		id = strings.TrimSpace(id)
		if id == "" {
			return nil, InvalidValue("members[%d].value is required", i)
		}

		ids = append(ids, id)
	}

	return dedupe(ids), nil
}

// dedupe removes repeated ids, keeping the first occurrence, in O(n).
func dedupe(ids []string) []string {
	seen := make(map[string]struct{}, len(ids))
	out := make([]string, 0, len(ids))

	for _, id := range ids {
		if _, dup := seen[id]; !dup {
			seen[id] = struct{}{}
			out = append(out, id)
		}
	}

	return out
}

type objectEntry struct {
	key   string
	value json.RawMessage
}

// decodeObject decodes a JSON object preserving key order, so that
// normalisation is deterministic and follows the client's intent when keys
// overlap (e.g. "name" then "name.givenName").
func decodeObject(value json.RawMessage) ([]objectEntry, bool) {
	dec := json.NewDecoder(bytes.NewReader(value))

	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, false
	}

	var out []objectEntry

	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, false
		}

		key, ok := tok.(string)
		if !ok {
			return nil, false
		}

		var v json.RawMessage

		err = dec.Decode(&v)
		if err != nil {
			return nil, false
		}

		out = append(out, objectEntry{key: key, value: v})
	}

	return out, true
}

// ParsePath parses a PATCH path. Errors are invalidPath; paths longer than
// [MaxPathLength] are rejected before parsing.
func ParsePath(s string) (Path, error) {
	if len(s) > MaxPathLength {
		return Path{}, InvalidPath("path longer than %d bytes", MaxPathLength)
	}

	toks, err := lexFilter(strings.TrimSpace(s))
	if err != nil {
		return Path{}, InvalidPath("invalid path %q: %s", s, AsError(err).Detail)
	}

	p := &parser{toks: toks}

	t := p.next()
	if t.kind != tokWord {
		return Path{}, InvalidPath("invalid path %q", s)
	}

	ap, err := parseAttrPath(t.text)
	if err != nil {
		return Path{}, InvalidPath("invalid path %q", s)
	}

	out := Path{URI: ap.URI, Attr: ap.Attr, Sub: ap.Sub}

	if p.at(tokLBracket) {
		if ap.Sub != "" {
			return Path{}, InvalidPath("invalid path %q: filter on sub-attribute", s)
		}

		p.next()

		f, err := p.parseOr(true)
		if err != nil {
			return Path{}, InvalidPath("invalid path %q: %s", s, AsError(err).Detail)
		}

		if !p.at(tokRBracket) {
			return Path{}, InvalidPath("invalid path %q: expected \"]\"", s)
		}

		closing := p.next()

		out.Filter = f

		if st, ok := p.subAfter(closing); ok {
			sub := st.text[1:]
			if !validAttrName(sub) {
				return Path{}, InvalidPath("invalid path %q", s)
			}

			out.Sub = canonicalSub(ap.Attr, sub)
		}
	}

	if !p.at(tokEOF) {
		return Path{}, InvalidPath("invalid path %q: unexpected %s", s, p.peek().desc())
	}

	return out, nil
}
