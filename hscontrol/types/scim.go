package types

// ProvisionedBySCIM is the [User.ProvisionedBy] value of users created, or
// adopted, by the SCIM endpoint.
const ProvisionedBySCIM = "scim"

// SCIMUserAttributes are the attributes of a user that the SCIM endpoint
// manages. Empty strings mean "not set".
//
// UserName is stored verbatim in [User.SCIMUserName] and is the key a SCIM
// user is linked to an OIDC login by. The SCIM values are kept in their own
// columns and read back from them. While the user has not logged in, they
// are also written to the core columns, so the account is usable before the
// first login: [User.Name] is the case-folded UserName, [User.Email] the
// Email (or an email-shaped UserName), [User.DisplayName] the DisplayName.
// Once linked to a login, the login's claims own the core columns and SCIM
// never writes them.
type SCIMUserAttributes struct {
	UserName    string
	ExternalID  string
	DisplayName string
	GivenName   string
	FamilyName  string
	// Email is the primary email.
	Email string

	// Active is the inverse of suspension. The db package's SCIM user
	// functions neither read nor write it: State applies it with
	// SetUserSuspended in the same transaction. SCIM owns suspension of the
	// users it manages: active=true lifts a suspension an admin set.
	Active bool
}

// IsSCIMProvisioned reports whether the SCIM endpoint manages the user.
func (u *User) IsSCIMProvisioned() bool {
	return u != nil && u.ProvisionedBy.Valid && u.ProvisionedBy.String == ProvisionedBySCIM
}

// IsSCIMProvisioned reports whether SCIM manages the user; see
// [User.IsSCIMProvisioned].
func (v UserView) IsSCIMProvisioned() bool {
	return v.Valid() && v.ж.IsSCIMProvisioned()
}

// SCIMAttributes returns the user's SCIM-managed attributes, the starting
// point for applying a SCIM PATCH.
func (u *User) SCIMAttributes() SCIMUserAttributes {
	return SCIMUserAttributes{
		UserName:    u.SCIMUserName.String,
		ExternalID:  u.ExternalID.String,
		DisplayName: u.SCIMDisplayName,
		GivenName:   u.GivenName,
		FamilyName:  u.FamilyName,
		Email:       u.SCIMEmail,
		Active:      !u.IsSuspended(),
	}
}

// SCIMGroupOpKind is the kind of a [SCIMGroupOp].
type SCIMGroupOpKind int

const (
	// SCIMGroupRename sets the group's display name (and so its qualified
	// name) to Value.
	SCIMGroupRename SCIMGroupOpKind = iota + 1
	// SCIMGroupSetExternalID sets the group's external id to Value; an empty
	// Value clears it.
	SCIMGroupSetExternalID
	// SCIMGroupAddMembers adds Members to the group's SCIM memberships.
	SCIMGroupAddMembers
	// SCIMGroupRemoveMembers removes Members from the group's SCIM
	// memberships.
	SCIMGroupRemoveMembers
	// SCIMGroupReplaceMembers makes Members the group's complete set of SCIM
	// memberships.
	SCIMGroupReplaceMembers
)

// SCIMGroupOp is one change to a SCIM group. A SCIM PATCH maps to a list of
// them, applied in order in one transaction; a PUT to a rename, an external
// id change and a member replacement.
type SCIMGroupOp struct {
	Kind    SCIMGroupOpKind
	Value   string
	Members []UserID
}
