package types

import (
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// GroupSource records which system asserted a [UserGroup] membership. Each
// source owns its own rows: syncing one source replaces only that source's
// memberships, so a login can never clobber memberships provisioned by
// another system (e.g. a future SCIM endpoint).
type GroupSource string

const (
	// GroupSourceOIDC marks memberships taken from the OIDC groups claim at
	// login, and groups created by them.
	GroupSourceOIDC GroupSource = "oidc"

	// GroupSourceSCIM marks memberships, and groups, provisioned through the
	// SCIM endpoint.
	GroupSourceSCIM GroupSource = "scim"
)

var (
	ErrGroupNameEmpty        = errors.New("group name is empty")
	ErrGroupNameContainsAt   = errors.New("group name must not contain '@'")
	ErrGroupNameTooLong      = errors.New("group name is too long")
	ErrGroupDomainMissing    = errors.New("group domain is empty")
	ErrGroupDomainContainsAt = errors.New("group domain must not contain '@'")
)

// maxGroupNameLength bounds a group name taken from an identity provider.
const maxGroupNameLength = 255

// Group is a group of users asserted by an identity provider. Policies refer
// to it as `group:<Name>`, where Name is the qualified, lowercased
// `<name>@<domain>` identifier (see [QualifyGroupName]), or as
// `group:<ExternalName>` when it has one. Groups defined in the policy file
// are not stored here.
type Group struct {
	ID   uint `gorm:"primaryKey"`
	Name string

	// DisplayName is the name as the provisioning client sent it, before
	// qualification and case folding. Empty for groups created by OIDC
	// logins, which only know the qualified name.
	DisplayName string

	// ExternalID is the provisioning client's identifier for the group (the
	// SCIM externalId, e.g. an Entra object id). Unique when set.
	ExternalID sql.NullString

	// ExternalName is ExternalID qualified like Name (see
	// [QualifyGroupName]); unique when set. It is an alias the policy
	// matches as well as Name, so a policy can reference a group by the
	// stable id that identity providers such as Entra also send in the
	// OIDC groups claim, and keep working when the group is renamed.
	ExternalName sql.NullString

	// Source is the system that created and owns the group row: OIDC
	// logins create groups on demand, the SCIM endpoint manages its own.
	// Memberships carry their own source (see [UserGroup]).
	Source GroupSource

	CreatedAt time.Time
	UpdatedAt time.Time
}

// UserGroup is a user's membership of a [Group], as asserted by Source.
type UserGroup struct {
	UserID  uint        `gorm:"primaryKey"`
	GroupID uint        `gorm:"primaryKey"`
	Source  GroupSource `gorm:"primaryKey"`

	// Group is preloaded for reads only; memberships are written exclusively
	// through the db package's sync functions.
	Group Group `gorm:"->"`

	CreatedAt time.Time
}

// QualifyGroupName normalises a group name asserted by an identity provider
// and qualifies it with domain, producing the identifier that policies
// reference as `group:<name>@<domain>`. Names are lowercased (policy group
// references are matched case-insensitively, as in Tailscale). A name that is
// already qualified with domain, as providers that name groups by email
// address send it, is accepted as is; any other '@' is rejected, since it
// separates the name from the domain.
func QualifyGroupName(name, domain string) (string, error) {
	name = FoldGroupName(strings.TrimSpace(name))
	domain = FoldGroupName(strings.TrimSpace(domain))

	if local, ok := strings.CutSuffix(name, "@"+domain); ok && domain != "" {
		name = local
	}

	switch {
	case name == "":
		return "", ErrGroupNameEmpty
	case strings.Contains(name, "@"):
		return "", fmt.Errorf("%w: %q", ErrGroupNameContainsAt, name)
	case domain == "":
		return "", ErrGroupDomainMissing
	case strings.Contains(domain, "@"):
		return "", fmt.Errorf("%w: %q", ErrGroupDomainContainsAt, domain)
	}

	qualified := name + "@" + domain
	if len(qualified) > maxGroupNameLength {
		return "", fmt.Errorf("%w: %d > %d bytes", ErrGroupNameTooLong, len(qualified), maxGroupNameLength)
	}

	return qualified, nil
}

// FoldGroupName lowercases the ASCII letters of a group name, the case folding
// used both for names from an identity provider and for policy references to
// them. Other characters are kept as is: full Unicode case folding would merge
// distinct names, such as the Kelvin sign 'K' (U+212A) with 'k', letting
// whoever can name a group at the identity provider join another group.
func FoldGroupName(name string) string {
	return strings.Map(func(r rune) rune {
		if 'A' <= r && r <= 'Z' {
			return r + ('a' - 'A')
		}

		return r
	}, name)
}

// IsSCIM reports whether the group is managed by the SCIM endpoint.
func (g *Group) IsSCIM() bool {
	return g != nil && g.Source == GroupSourceSCIM
}

// Matches reports whether a policy reference to the qualified name selects
// the group: name is either its Name or its ExternalName.
func (g *Group) Matches(name string) bool {
	return g.Name == name || (g.ExternalName.Valid && g.ExternalName.String == name)
}

// groupNames returns the sorted, de-duplicated names of the groups in
// memberships. A user can hold the same group from several sources. With
// withExternal, the groups' external names are included too.
func groupNames(memberships []UserGroup, withExternal bool) []string {
	if len(memberships) == 0 {
		return nil
	}

	names := make([]string, 0, len(memberships))
	for _, m := range memberships {
		names = append(names, m.Group.Name)

		if withExternal && m.Group.ExternalName.Valid {
			names = append(names, m.Group.ExternalName.String)
		}
	}

	slices.Sort(names)

	return slices.Compact(names)
}

// GroupsFromClaims returns the group names in claims under claim, and whether
// the claim is present. claim is first looked up as a literal name, so names
// containing dots (such as Auth0's https://example.com/groups) work; if absent,
// a dotted path reaches into nested objects (Keycloak's realm_access.roles).
// The value may be a single string or an array; non-string entries are
// ignored.
func GroupsFromClaims(claims map[string]any, claim string) ([]string, bool) {
	val, ok := claims[claim]
	if !ok {
		val, ok = nestedClaim(claims, claim)
	}

	if !ok || val == nil {
		return nil, ok
	}

	switch v := val.(type) {
	case string:
		return []string{v}, true
	case []any:
		groups := make([]string, 0, len(v))

		for _, item := range v {
			if s, ok := item.(string); ok {
				groups = append(groups, s)
			}
		}

		return groups, true
	default:
		return nil, true
	}
}

func nestedClaim(claims map[string]any, path string) (any, bool) {
	parts := strings.Split(path, ".")
	if len(parts) < 2 {
		return nil, false
	}

	var cur any = claims

	for _, part := range parts {
		obj, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}

		cur, ok = obj[part]
		if !ok {
			return nil, false
		}
	}

	return cur, true
}
