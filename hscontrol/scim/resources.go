package scim

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"time"
)

// Schema and message URNs (RFC 7643 section 8.7, RFC 7644 section 3).
const (
	SchemaUser                  = "urn:ietf:params:scim:schemas:core:2.0:User"
	SchemaGroup                 = "urn:ietf:params:scim:schemas:core:2.0:Group"
	SchemaEnterpriseUser        = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
	SchemaServiceProviderConfig = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
	SchemaResourceType          = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
	SchemaSchema                = "urn:ietf:params:scim:schemas:core:2.0:Schema"
	SchemaListResponse          = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	SchemaPatchOp               = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	SchemaError                 = "urn:ietf:params:scim:api:messages:2.0:Error"
)

// ContentType is the SCIM media type (RFC 7644 section 8.1).
const ContentType = "application/scim+json"

// Resource type names used in meta.resourceType and /ResourceTypes.
const (
	ResourceTypeUser  = "User"
	ResourceTypeGroup = "Group"
)

// MaxBodySize is the largest request body DecodeUser, DecodeGroup and
// DecodePatch accept. Group PATCH requests from Entra ID carry at most a few
// hundred member references; 1 MiB leaves ample headroom.
const MaxBodySize = 1 << 20

// Limits on the size of a single request, so that one authenticated request
// cannot make the server do unbounded work. Real clients stay far below
// them: Entra ID and Okta send one to a few emails per user and batch group
// membership changes in the hundreds.
const (
	// MaxEmails is the most emails a user may have (invalidValue beyond).
	MaxEmails = 32
	// MaxMembersPerRequest is the most member references one POST, PUT or
	// PATCH request may carry (413 beyond).
	MaxMembersPerRequest = 10000
)

// Meta is the common "meta" attribute (RFC 7643 section 3.1). It is
// read-only: request decoders discard it.
type Meta struct {
	ResourceType string    `json:"resourceType,omitempty"`
	Created      time.Time `json:"created,omitzero"`
	LastModified time.Time `json:"lastModified,omitzero"`
	Location     string    `json:"location,omitempty"`
	Version      string    `json:"version,omitempty"`
}

// Name is the User "name" complex attribute. Only the sub-attributes
// headscale stores are modelled; others (middleName, honorificPrefix, ...)
// are dropped on decode.
type Name struct {
	Formatted  string `json:"formatted,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
	GivenName  string `json:"givenName,omitempty"`
}

// IsZero reports whether no sub-attribute is set.
func (n *Name) IsZero() bool {
	return n == nil || *n == Name{}
}

// Email is one element of the User "emails" attribute.
type Email struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

// UnmarshalJSON accepts "primary" as a JSON boolean or as the strings
// "True"/"False" (Entra ID without the aadOptscim062020 flag).
func (e *Email) UnmarshalJSON(data []byte) error {
	var aux struct {
		Value   string    `json:"value"`
		Type    string    `json:"type"`
		Primary *flexBool `json:"primary"`
	}

	err := json.Unmarshal(data, &aux)
	if err != nil {
		return err
	}

	*e = Email{Value: aux.Value, Type: aux.Type}
	if aux.Primary != nil {
		e.Primary = bool(*aux.Primary)
	}

	return nil
}

// GroupRef is one element of the read-only User "groups" attribute.
type GroupRef struct {
	Value   string `json:"value"`
	Ref     string `json:"$ref,omitempty"`
	Display string `json:"display,omitempty"`
}

// Member is one element of the Group "members" attribute. Entra ID sends
// "$ref": null when adding members; that decodes to an empty Ref.
type Member struct {
	Value   string `json:"value"`
	Ref     string `json:"$ref,omitempty"`
	Display string `json:"display,omitempty"`
	Type    string `json:"type,omitempty"`
}

// User is the SCIM core User resource (RFC 7643 section 4.1) restricted to
// the attributes headscale supports.
//
// Decoding is lenient: unknown attributes, extension blocks (the enterprise
// extension Entra ID always sends), "roles" and "password" (Okta sends it on
// create) are silently dropped, and "active" may be a boolean or a
// case-insensitive "True"/"False" string. Encoding always emits schemas and
// userName and omits empty optional attributes, so a response never contains
// null.
//
//nolint:recvcheck // value-receiver MarshalJSON so values and pointers encode alike
type User struct {
	Schemas     []string   `json:"schemas"`
	ID          string     `json:"id,omitempty"`
	ExternalID  string     `json:"externalId,omitempty"`
	UserName    string     `json:"userName"`
	Name        *Name      `json:"name,omitempty"`
	DisplayName string     `json:"displayName,omitempty"`
	Active      *bool      `json:"active,omitempty"`
	Emails      []Email    `json:"emails,omitempty"`
	Groups      []GroupRef `json:"groups,omitempty"`
	Meta        *Meta      `json:"meta,omitempty"`
}

// IsActive reports the effective value of active. An unset active means
// true: RFC 7643 leaves the default to the service provider and every
// provisioning client treats a created user as active unless told otherwise.
func (u *User) IsActive() bool {
	return u.Active == nil || *u.Active
}

// PrimaryEmail returns the primary email value, or the first email if none
// is marked primary, or "" if there are none.
func (u *User) PrimaryEmail() string {
	for _, e := range u.Emails {
		if e.Primary {
			return e.Value
		}
	}

	if len(u.Emails) > 0 {
		return u.Emails[0].Value
	}

	return ""
}

type userAlias User

// MarshalJSON always emits the core User schema URN and active (an unset
// active is rendered as true, see [User.IsActive]) and drops an empty name.
// Because [Match] evaluates a *User through this encoding, "active eq true"
// also matches a user whose Active is nil.
func (u User) MarshalJSON() ([]byte, error) {
	a := userAlias(u)
	a.Schemas = []string{SchemaUser}
	a.Active = new(u.IsActive())

	if a.Name.IsZero() {
		a.Name = nil
	}

	return json.Marshal(a)
}

// UnmarshalJSON decodes a User leniently (see [User]).
func (u *User) UnmarshalJSON(data []byte) error {
	var aux struct {
		userAlias

		Active *flexBool `json:"active"`
	}

	err := json.Unmarshal(data, &aux)
	if err != nil {
		return err
	}

	*u = User(aux.userAlias)
	if aux.Active != nil {
		u.Active = new(bool(*aux.Active))
	}

	return nil
}

// Group is the SCIM core Group resource (RFC 7643 section 4.2).
//
//nolint:recvcheck // value-receiver MarshalJSON so values and pointers encode alike
type Group struct {
	Schemas     []string `json:"schemas"`
	ID          string   `json:"id,omitempty"`
	ExternalID  string   `json:"externalId,omitempty"`
	DisplayName string   `json:"displayName"`
	Members     []Member `json:"members,omitempty"`
	Meta        *Meta    `json:"meta,omitempty"`
}

type groupAlias Group

// MarshalJSON always emits the core Group schema URN.
func (g Group) MarshalJSON() ([]byte, error) {
	a := groupAlias(g)
	a.Schemas = []string{SchemaGroup}

	return json.Marshal(a)
}

// MemberIDs returns the member values in order.
func (g *Group) MemberIDs() []string {
	ids := make([]string, 0, len(g.Members))
	for _, m := range g.Members {
		ids = append(ids, m.Value)
	}

	return ids
}

// flexBool decodes a JSON boolean or a case-insensitive "true"/"false"
// string. Entra ID sends "True"/"False" strings unless the application uses
// the aadOptscim062020 feature flag
// (https://learn.microsoft.com/entra/identity/app-provisioning/application-provisioning-config-problem-scim-compatibility).
type flexBool bool

func (b *flexBool) UnmarshalJSON(data []byte) error {
	v, err := parseFlexBool(data)
	if err != nil {
		return err
	}

	*b = flexBool(v)

	return nil
}

func parseFlexBool(data []byte) (bool, error) {
	data = bytes.TrimSpace(data)

	switch {
	case bytes.Equal(data, []byte("true")):
		return true, nil
	case bytes.Equal(data, []byte("false")):
		return false, nil
	}

	var s string

	err := json.Unmarshal(data, &s)
	if err == nil {
		switch strings.ToLower(strings.TrimSpace(s)) {
		case "true":
			return true, nil
		case "false":
			return false, nil
		}
	}

	return false, InvalidValue("expected a boolean, got %s", data)
}

// DecodeUser decodes a User from a POST or PUT request body. Read-only
// attributes (id, groups, meta) are discarded as RFC 7643 section 2.2
// requires; the handler sets id from the URL. Malformed JSON yields
// invalidSyntax; a wrongly typed attribute (such as a non-boolean active)
// yields invalidValue. If several emails claim primary, only the last one
// keeps it, as for PATCH (RFC 7643 section 2.4 allows one primary value).
func DecodeUser(r io.Reader) (*User, error) {
	var u User

	err := decodeBody(r, &u)
	if err != nil {
		return nil, err
	}

	u.ID = ""
	u.Groups = nil
	u.Meta = nil

	if len(u.Emails) > MaxEmails {
		return nil, InvalidValue("at most %d emails are supported", MaxEmails)
	}

	normalisePrimary(u.Emails, -1)

	return &u, nil
}

// normalisePrimary enforces RFC 7643 section 2.4: at most one primary value.
// keep is the index that must stay primary, or -1 to keep the last one
// marked primary.
func normalisePrimary(emails []Email, keep int) {
	if keep < 0 {
		for i, e := range slices.Backward(emails) {
			if e.Primary {
				keep = i

				break
			}
		}
	}

	for i := range emails {
		emails[i].Primary = i == keep && keep >= 0
	}
}

// DecodeGroup decodes a Group from a POST or PUT request body, discarding
// read-only attributes (id, meta) and member display names (display is
// read-only in RFC 7643 section 8.7.1; the server fills it on output).
func DecodeGroup(r io.Reader) (*Group, error) {
	var g Group

	err := decodeBody(r, &g)
	if err != nil {
		return nil, err
	}

	g.ID = ""
	g.Meta = nil

	if len(g.Members) > MaxMembersPerRequest {
		return nil, PayloadTooLarge("at most %d members per request", MaxMembersPerRequest)
	}

	for i := range g.Members {
		g.Members[i].Display = ""
	}

	return &g, nil
}

func decodeBody(r io.Reader, v any) error {
	data, err := io.ReadAll(io.LimitReader(r, MaxBodySize+1))
	if err != nil {
		return InvalidSyntax("reading request body: %v", err)
	}

	if len(data) > MaxBodySize {
		return PayloadTooLarge("request body exceeds %d bytes", MaxBodySize)
	}

	err = json.Unmarshal(data, v)
	if err != nil {
		return jsonError(err)
	}

	return nil
}

// jsonError maps a decoding error to a SCIM error whose detail names at most
// the offending attribute, never Go types or struct fields.
func jsonError(err error) *Error {
	if se, ok := errors.AsType[*Error](err); ok {
		return se
	}

	if te, ok := errors.AsType[*json.UnmarshalTypeError](err); ok {
		if te.Field != "" {
			return InvalidValue("attribute %q has the wrong type", te.Field)
		}

		return InvalidSyntax("request body must be a JSON object")
	}

	if se, ok := errors.AsType[*json.SyntaxError](err); ok {
		return InvalidSyntax("malformed JSON at offset %d", se.Offset)
	}

	return InvalidSyntax("malformed JSON")
}

// Validate checks a User decoded for create or replace: userName must be
// non-blank (invalidValue), schemas, when given, must include the core User
// URN (invalidSyntax), and every email must have a value (invalidValue).
// Extension schema URNs are accepted and ignored.
func (u *User) Validate() error {
	if len(u.Schemas) > 0 && !containsFold(u.Schemas, SchemaUser) {
		return InvalidSyntax("schemas must include %s", SchemaUser)
	}

	if strings.TrimSpace(u.UserName) == "" {
		return InvalidValue("userName is required")
	}

	if len(u.Emails) > MaxEmails {
		return InvalidValue("at most %d emails are supported", MaxEmails)
	}

	for i, e := range u.Emails {
		if strings.TrimSpace(e.Value) == "" {
			return InvalidValue("emails[%d].value is required", i)
		}
	}

	return nil
}

// Validate checks a Group decoded for create or replace: displayName must be
// non-blank (invalidValue), schemas, when given, must include the core Group
// URN (invalidSyntax), and every member must have a value (invalidValue).
func (g *Group) Validate() error {
	if len(g.Schemas) > 0 && !containsFold(g.Schemas, SchemaGroup) {
		return InvalidSyntax("schemas must include %s", SchemaGroup)
	}

	if strings.TrimSpace(g.DisplayName) == "" {
		return InvalidValue("displayName is required")
	}

	for i, m := range g.Members {
		if strings.TrimSpace(m.Value) == "" {
			return InvalidValue("members[%d].value is required", i)
		}
	}

	return nil
}

func containsFold(list []string, s string) bool {
	return slices.ContainsFunc(list, func(e string) bool {
		return strings.EqualFold(e, s)
	})
}

// UserLocation returns the meta.location of a user: baseURL/Users/id.
func UserLocation(baseURL, id string) string {
	return strings.TrimRight(baseURL, "/") + "/Users/" + id
}

// GroupLocation returns the meta.location of a group: baseURL/Groups/id.
func GroupLocation(baseURL, id string) string {
	return strings.TrimRight(baseURL, "/") + "/Groups/" + id
}
