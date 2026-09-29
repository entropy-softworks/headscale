package scim

import (
	"strings"
)

// MaxPageSize is the largest page a list request returns and the value
// advertised as filter.maxResults in the ServiceProviderConfig. Larger
// "count" values are clamped (RFC 7644 section 3.4.2.4 lets the service
// provider return fewer results than requested).
const MaxPageSize = 1000

// Attribute characteristic values (RFC 7643 section 2.2 and 7).
const (
	MutabilityReadOnly  = "readOnly"
	MutabilityReadWrite = "readWrite"
	MutabilityImmutable = "immutable"

	ReturnedAlways  = "always"
	ReturnedDefault = "default"
	ReturnedNever   = "never"

	UniquenessNone   = "none"
	UniquenessServer = "server"
)

// ServiceProviderConfig is the /ServiceProviderConfig document (RFC 7643
// section 5). Authentik only falls back to a userName filter after a 409 if
// this advertises filter support, so it must stay accurate.
type ServiceProviderConfig struct {
	Schemas               []string     `json:"schemas"`
	DocumentationURI      string       `json:"documentationUri,omitempty"`
	Patch                 Supported    `json:"patch"`
	Bulk                  BulkConfig   `json:"bulk"`
	Filter                FilterConfig `json:"filter"`
	ChangePassword        Supported    `json:"changePassword"`
	Sort                  Supported    `json:"sort"`
	ETag                  Supported    `json:"etag"`
	AuthenticationSchemes []AuthScheme `json:"authenticationSchemes"`
	Meta                  *Meta        `json:"meta,omitempty"`
}

// Supported is a {"supported": bool} feature block.
type Supported struct {
	Supported bool `json:"supported"`
}

// BulkConfig is the "bulk" feature block.
type BulkConfig struct {
	Supported      bool `json:"supported"`
	MaxOperations  int  `json:"maxOperations"`
	MaxPayloadSize int  `json:"maxPayloadSize"`
}

// FilterConfig is the "filter" feature block.
type FilterConfig struct {
	Supported  bool `json:"supported"`
	MaxResults int  `json:"maxResults"`
}

// AuthScheme is one authenticationSchemes entry.
type AuthScheme struct {
	Type             string `json:"type"`
	Name             string `json:"name"`
	Description      string `json:"description"`
	SpecURI          string `json:"specUri,omitempty"`
	DocumentationURI string `json:"documentationUri,omitempty"`
	Primary          bool   `json:"primary,omitempty"`
}

// NewServiceProviderConfig returns the ServiceProviderConfig for a SCIM
// endpoint rooted at baseURL (e.g. "https://hs.example.com/scim/v2").
func NewServiceProviderConfig(baseURL string) *ServiceProviderConfig {
	return &ServiceProviderConfig{
		Schemas: []string{SchemaServiceProviderConfig},
		Patch:   Supported{Supported: true},
		Bulk:    BulkConfig{Supported: false},
		Filter:  FilterConfig{Supported: true, MaxResults: MaxPageSize},
		// changePassword: passwords are dropped; headscale has none.
		ChangePassword: Supported{Supported: false},
		Sort:           Supported{Supported: false},
		ETag:           Supported{Supported: false},
		AuthenticationSchemes: []AuthScheme{{
			Type: "oauthbearertoken",
			Name: "OAuth Bearer Token",
			Description: "Authentication with a bearer token issued by headscale, " +
				"sent as \"Authorization: Bearer <token>\".",
			SpecURI: "https://www.rfc-editor.org/info/rfc6750",
			Primary: true,
		}},
		Meta: &Meta{
			ResourceType: "ServiceProviderConfig",
			Location:     trimBase(baseURL) + "/ServiceProviderConfig",
		},
	}
}

// ResourceType is a /ResourceTypes entry (RFC 7643 section 6).
type ResourceType struct {
	Schemas          []string          `json:"schemas"`
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	Endpoint         string            `json:"endpoint"`
	Description      string            `json:"description,omitempty"`
	Schema           string            `json:"schema"`
	SchemaExtensions []SchemaExtension `json:"schemaExtensions,omitempty"`
	Meta             *Meta             `json:"meta,omitempty"`
}

// SchemaExtension is a ResourceType schemaExtensions entry.
type SchemaExtension struct {
	Schema   string `json:"schema"`
	Required bool   `json:"required"`
}

// NewResourceTypes returns the User and Group resource types, in that order.
// No schema extension is advertised: the enterprise extension is accepted on
// input and ignored.
func NewResourceTypes(baseURL string) []ResourceType {
	base := trimBase(baseURL)

	return []ResourceType{
		{
			Schemas:     []string{SchemaResourceType},
			ID:          ResourceTypeUser,
			Name:        ResourceTypeUser,
			Endpoint:    "/Users",
			Description: "User Account",
			Schema:      SchemaUser,
			Meta: &Meta{
				ResourceType: "ResourceType",
				Location:     base + "/ResourceTypes/" + ResourceTypeUser,
			},
		},
		{
			Schemas:     []string{SchemaResourceType},
			ID:          ResourceTypeGroup,
			Name:        ResourceTypeGroup,
			Endpoint:    "/Groups",
			Description: "Group",
			Schema:      SchemaGroup,
			Meta: &Meta{
				ResourceType: "ResourceType",
				Location:     base + "/ResourceTypes/" + ResourceTypeGroup,
			},
		},
	}
}

// Schema is a /Schemas entry (RFC 7643 section 7).
type Schema struct {
	Schemas     []string    `json:"schemas"`
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Description string      `json:"description,omitempty"`
	Attributes  []Attribute `json:"attributes"`
	Meta        *Meta       `json:"meta,omitempty"`
}

// Attribute is an attribute definition (RFC 7643 section 7). The boolean
// characteristics are always emitted.
type Attribute struct {
	Name            string      `json:"name"`
	Type            string      `json:"type"`
	SubAttributes   []Attribute `json:"subAttributes,omitempty"`
	MultiValued     bool        `json:"multiValued"`
	Description     string      `json:"description,omitempty"`
	Required        bool        `json:"required"`
	CanonicalValues []string    `json:"canonicalValues,omitempty"`
	CaseExact       bool        `json:"caseExact"`
	Mutability      string      `json:"mutability"`
	Returned        string      `json:"returned"`
	Uniqueness      string      `json:"uniqueness"`
	ReferenceTypes  []string    `json:"referenceTypes,omitempty"`
}

func strAttr(name, desc string) Attribute {
	return Attribute{
		Name:        name,
		Type:        "string",
		Description: desc,
		Mutability:  MutabilityReadWrite,
		Returned:    ReturnedDefault,
		Uniqueness:  UniquenessNone,
	}
}

func userAttributes() []Attribute {
	userName := strAttr("userName", "Unique identifier for the User, used as "+
		"the headscale user name. Compared case-insensitively.")
	userName.Required = true
	userName.Uniqueness = UniquenessServer

	emailType := strAttr("type", "A label indicating the e-mail's function.")
	emailType.CanonicalValues = []string{"work", "home", "other"}

	primary := Attribute{
		Name:        "primary",
		Type:        "boolean",
		Description: "Indicates the primary e-mail address.",
		Mutability:  MutabilityReadWrite,
		Returned:    ReturnedDefault,
		Uniqueness:  UniquenessNone,
	}

	emails := Attribute{
		Name:        "emails",
		Type:        "complex",
		MultiValued: true,
		Description: "E-mail addresses for the User.",
		Mutability:  MutabilityReadWrite,
		Returned:    ReturnedDefault,
		Uniqueness:  UniquenessNone,
		SubAttributes: []Attribute{
			strAttr("value", "E-mail address."),
			emailType,
			primary,
		},
	}

	name := Attribute{
		Name:        "name",
		Type:        "complex",
		Description: "The components of the user's name.",
		Mutability:  MutabilityReadWrite,
		Returned:    ReturnedDefault,
		Uniqueness:  UniquenessNone,
		SubAttributes: []Attribute{
			strAttr("formatted", "The full name."),
			strAttr("familyName", "The family name."),
			strAttr("givenName", "The given name."),
		},
	}

	active := Attribute{
		Name:        "active",
		Type:        "boolean",
		Description: "The User's administrative status. Inactive users are suspended.",
		Mutability:  MutabilityReadWrite,
		Returned:    ReturnedDefault,
		Uniqueness:  UniquenessNone,
	}

	groups := Attribute{
		Name:        "groups",
		Type:        "complex",
		MultiValued: true,
		Description: "Groups the user belongs to. Managed through the Group resource.",
		Mutability:  MutabilityReadOnly,
		Returned:    ReturnedDefault,
		Uniqueness:  UniquenessNone,
		SubAttributes: []Attribute{
			readOnly(strAttr("value", "The id of the Group.")),
			refAttr("Group"),
			readOnly(strAttr("display", "The displayName of the Group.")),
		},
	}

	return []Attribute{
		userName,
		name,
		strAttr("displayName", "The name of the User, suitable for display."),
		active,
		emails,
		groups,
	}
}

func groupAttributes() []Attribute {
	displayName := strAttr("displayName", "A human-readable name for the Group, "+
		"referenced in the policy as group:<displayName>@<domain>. Unique "+
		"case-insensitively among groups.")
	displayName.Required = true
	displayName.Uniqueness = UniquenessServer

	memberType := immutable(strAttr("type", "The type of the member."))
	memberType.CanonicalValues = []string{ResourceTypeUser}

	members := Attribute{
		Name:        "members",
		Type:        "complex",
		MultiValued: true,
		Description: "The members of the Group. Only Users are supported.",
		Mutability:  MutabilityReadWrite,
		Returned:    ReturnedDefault,
		Uniqueness:  UniquenessNone,
		SubAttributes: []Attribute{
			immutable(strAttr("value", "The id of the member.")),
			immutable(refAttr(ResourceTypeUser)),
			readOnly(strAttr("display", "The displayName of the member, or its userName.")),
			memberType,
		},
	}

	return []Attribute{displayName, members}
}

func readOnly(a Attribute) Attribute {
	a.Mutability = MutabilityReadOnly

	return a
}

func immutable(a Attribute) Attribute {
	a.Mutability = MutabilityImmutable

	return a
}

func refAttr(refType string) Attribute {
	a := readOnly(strAttr("$ref", "The URI of the referenced resource."))
	a.Type = "reference"
	a.CaseExact = true
	a.ReferenceTypes = []string{refType}

	return a
}

// NewSchemas returns the core User and Group schema definitions, in that
// order, restricted to the attributes headscale supports. The common
// attributes id, externalId and meta are not listed, following RFC 7643
// section 8.7.1.
func NewSchemas(baseURL string) []Schema {
	base := trimBase(baseURL)

	return []Schema{
		{
			Schemas:     []string{SchemaSchema},
			ID:          SchemaUser,
			Name:        ResourceTypeUser,
			Description: "User Account",
			Attributes:  userAttributes(),
			Meta: &Meta{
				ResourceType: "Schema",
				Location:     base + "/Schemas/" + SchemaUser,
			},
		},
		{
			Schemas:     []string{SchemaSchema},
			ID:          SchemaGroup,
			Name:        ResourceTypeGroup,
			Description: "Group",
			Attributes:  groupAttributes(),
			Meta: &Meta{
				ResourceType: "Schema",
				Location:     base + "/Schemas/" + SchemaGroup,
			},
		},
	}
}

func trimBase(baseURL string) string {
	return strings.TrimRight(baseURL, "/")
}

// attrInfo is what the filter evaluator and path canonicaliser need to know
// about an attribute.
type attrInfo struct {
	name      string // canonical spelling
	caseExact bool
	subs      map[string]attrInfo
}

// knownAttrs indexes, by lower-case name, every attribute of the User and
// Group schemas plus the common attributes id, externalId and meta
// (RFC 7643 section 3.1). id and externalId are caseExact per the RFC; so
// the evaluator compares them byte-for-byte while userName, displayName and
// emails.value compare case-insensitively.
var knownAttrs = buildKnownAttrs()

func buildKnownAttrs() map[string]attrInfo {
	out := map[string]attrInfo{}

	add := func(a Attribute) {
		key := strings.ToLower(a.Name)

		info, ok := out[key]
		if !ok {
			info = attrInfo{name: a.Name, caseExact: a.CaseExact, subs: map[string]attrInfo{}}
		}

		for _, s := range a.SubAttributes {
			info.subs[strings.ToLower(s.Name)] = attrInfo{name: s.Name, caseExact: s.CaseExact}
		}

		out[key] = info
	}

	for _, a := range userAttributes() {
		add(a)
	}

	for _, a := range groupAttributes() {
		add(a)
	}

	add(Attribute{Name: "id", CaseExact: true})
	add(Attribute{Name: "externalId", CaseExact: true})
	add(Attribute{Name: "schemas", CaseExact: true})
	add(Attribute{Name: "meta", SubAttributes: []Attribute{
		{Name: "resourceType", CaseExact: true},
		{Name: "created"},
		{Name: "lastModified"},
		{Name: "location", CaseExact: true},
		{Name: "version", CaseExact: true},
	}})

	return out
}

func canonicalAttr(name string) string {
	if info, ok := knownAttrs[strings.ToLower(name)]; ok {
		return info.name
	}

	return name
}

func canonicalSub(attr, sub string) string {
	if info, ok := knownAttrs[strings.ToLower(attr)]; ok {
		if s, ok := info.subs[strings.ToLower(sub)]; ok {
			return s.name
		}
	}

	return sub
}

// isCaseExact reports whether values of attr (or attr.sub) are compared
// case-sensitively. Unknown attributes default to caseExact=false (RFC 7643
// section 2.2).
func isCaseExact(attr, sub string) bool {
	info, ok := knownAttrs[strings.ToLower(attr)]
	if !ok {
		return false
	}

	if sub == "" {
		return info.caseExact
	}

	return info.subs[strings.ToLower(sub)].caseExact
}

// IsCaseExact reports whether the attribute path (e.g. "externalId",
// "emails.value") compares case-sensitively per the schema.
func IsCaseExact(path string) bool {
	attr, sub, _ := strings.Cut(path, ".")

	return isCaseExact(attr, sub)
}
