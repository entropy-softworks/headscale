package apiv1

import (
	"context"
	"math"
	"net/http"
	"strconv"

	"github.com/danielgtaylor/huma/v2"
	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/types"
)

func init() {
	registrations = append(registrations, registerSCIM)
}

// ScimUser is a user provisioned through SCIM, as the admin sees it: the
// SCIM attributes the identity provider sent, and the login and suspension
// state Headscale derives from them.
type ScimUser struct {
	// ID is both the Headscale user id and the SCIM id.
	ID          string `format:"uint64"    json:"id"`
	UserName    string `json:"userName"`
	ExternalID  string `json:"externalId"`
	Email       string `json:"email"`
	DisplayName string `json:"displayName"`
	// Name is the Headscale user name: the case-folded userName until the
	// user is linked, then the one their login asserts.
	Name string `json:"name"`
	// Linked reports that an OIDC login has been linked to the user.
	Linked bool `json:"linked"`
	// Suspended reports that the user is suspended (SCIM active=false, or
	// an admin's suspension).
	Suspended bool `json:"suspended"`
}

// ScimGroup is a group provisioned through SCIM.
type ScimGroup struct {
	ID          string `format:"uint64"    json:"id"`
	DisplayName string `json:"displayName"`
	// Name is the qualified name (<displayName>@<domain>, lowercased).
	Name string `json:"name"`
	// PolicyReference is how a policy refers to the group: group:<name>.
	PolicyReference string `json:"policyReference"`
	ExternalID      string `json:"externalId"`
	// ExternalName is the externalId qualified like Name, empty when the
	// group has none, and PolicyAlias the policy reference it provides.
	ExternalName string `json:"externalName"`
	PolicyAlias  string `json:"policyAlias"`
	// MemberCount is the number of SCIM members.
	MemberCount int    `json:"memberCount"`
	Source      string `json:"source"`
}

type (
	listScimUsersOutput struct {
		Body struct {
			ScimUsers []ScimUser `json:"scimUsers" nullable:"false"`
		}
	}
	listScimGroupsOutput struct {
		Body struct {
			ScimGroups []ScimGroup `json:"scimGroups" nullable:"false"`
		}
	}
	scimGroupIDInput struct {
		ID string `format:"uint64" path:"id"`
	}
	releaseScimGroupOutput struct {
		Body struct{}
	}
)

func registerSCIM(api huma.API, b Backend) {
	huma.Register(api, huma.Operation{
		OperationID: "listScimUsers",
		Method:      http.MethodGet,
		Path:        "/api/v1/scim/user",
		Summary:     "List SCIM users",
		Description: "Lists the users provisioned through SCIM, with whether an OIDC login " +
			"has been linked to each and whether it is suspended.",
		Tags:     []string{"Scim"},
		Security: bearerAuth,
	}, func(ctx context.Context, _ *struct{}) (*listScimUsersOutput, error) {
		users, _, err := b.State.ListSCIMUsers(db.SCIMUserFilter{}, 1, math.MaxInt32)
		if err != nil {
			return nil, mapError("listing scim users", err)
		}

		out := &listScimUsersOutput{}

		out.Body.ScimUsers = make([]ScimUser, len(users))
		for i := range users {
			out.Body.ScimUsers[i] = scimUserFromView(users[i].View())
		}

		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "listScimGroups",
		Method:      http.MethodGet,
		Path:        "/api/v1/scim/group",
		Summary:     "List SCIM groups",
		Description: "Lists the groups provisioned through SCIM, with the policy references " +
			"that select them and their number of members.",
		Tags:     []string{"Scim"},
		Security: bearerAuth,
	}, func(ctx context.Context, _ *struct{}) (*listScimGroupsOutput, error) {
		groups, _, err := b.State.ListSCIMGroups(b.scimGroupsDomain(), db.SCIMGroupFilter{}, 1, math.MaxInt32)
		if err != nil {
			return nil, mapError("listing scim groups", err)
		}

		ids := make([]uint, len(groups))
		for i := range groups {
			ids[i] = groups[i].ID
		}

		members, err := b.State.SCIMGroupMembers(ids...)
		if err != nil {
			return nil, mapError("listing scim group members", err)
		}

		out := &listScimGroupsOutput{}

		out.Body.ScimGroups = make([]ScimGroup, len(groups))
		for i := range groups {
			out.Body.ScimGroups[i] = scimGroupFromState(&groups[i], len(members[groups[i].ID]))
		}

		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "releaseScimGroup",
		Method:      http.MethodPost,
		Path:        "/api/v1/scim/group/{id}/release",
		Summary:     "Release SCIM group",
		Description: "Hands a SCIM group back to OIDC logins, for when SCIM provisioning is " +
			"turned off: its SCIM memberships and external id are removed, and logins " +
			"asserting the group in their groups claim grant it again from their next " +
			"login. The group keeps its id and name, so policies referencing group:<name> " +
			"keep working; references to its external id alias stop matching.",
		Tags:     []string{"Scim"},
		Security: bearerAuth,
	}, func(ctx context.Context, in *scimGroupIDInput) (*releaseScimGroupOutput, error) {
		id, err := strconv.ParseUint(in.ID, 10, strconv.IntSize)
		if err != nil {
			return nil, huma.Error400BadRequest("invalid scim group id", err)
		}

		// While SCIM runs, the identity provider still owns the group and
		// would provision it again.
		if b.Cfg != nil && b.Cfg.SCIM.Enabled {
			return nil, huma.Error409Conflict(
				"scim group release requires scim.enabled=false; the identity provider would re-provision it")
		}

		c, err := b.State.ReleaseSCIMGroup(uint(id))
		if err != nil {
			return nil, mapError("releasing scim group", err)
		}

		b.Change(c)

		return &releaseScimGroupOutput{}, nil
	})
}

// scimGroupsDomain is the domain SCIM group names are qualified with; nil
// only during spec emission, when no handler runs.
func (b Backend) scimGroupsDomain() string {
	if b.Cfg == nil {
		return ""
	}

	return b.Cfg.SCIM.GroupsDomain
}

func scimUserFromView(u types.UserView) ScimUser {
	return ScimUser{
		ID:          formatID(u.ID()),
		UserName:    u.SCIMUserName().String,
		ExternalID:  u.ExternalID().String,
		Email:       u.SCIMEmail(),
		DisplayName: u.SCIMDisplayName(),
		Name:        u.Name(),
		Linked:      u.ProviderIdentifier().Valid,
		Suspended:   u.IsSuspended(),
	}
}

func scimGroupFromState(g *types.Group, members int) ScimGroup {
	out := ScimGroup{
		ID:              formatID(g.ID),
		DisplayName:     g.DisplayName,
		Name:            g.Name,
		PolicyReference: "group:" + g.Name,
		ExternalID:      g.ExternalID.String,
		ExternalName:    g.ExternalName.String,
		MemberCount:     members,
		Source:          string(g.Source),
	}
	if g.ExternalName.Valid {
		out.PolicyAlias = "group:" + g.ExternalName.String
	}

	return out
}
