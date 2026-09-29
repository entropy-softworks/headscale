package state

import (
	"fmt"
	"time"

	hsdb "github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/juanfont/headscale/hscontrol/util/zlog/zf"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

// SCIM provisioning. These methods wrap the db package's SCIM functions (see
// hscontrol/db/scim.go for the storage model and error sentinels) in a
// transaction and bring the NodeStore and policy manager up to date
// afterwards. Each returns the change to broadcast; an empty change means
// nothing any node sees changed. domain is the domain SCIM group names are
// qualified with (see [types.QualifyGroupName]).

// GetSCIMUser returns the SCIM user uid, or [hsdb.ErrUserNotFound].
func (s *State) GetSCIMUser(uid types.UserID) (*types.User, error) {
	return hsdb.GetSCIMUserByID(s.db.DB, uid)
}

// GetSCIMUserByUserName returns the SCIM user with the userName (compared
// case-insensitively), or [hsdb.ErrUserNotFound].
func (s *State) GetSCIMUserByUserName(userName string) (*types.User, error) {
	return hsdb.GetSCIMUserByUserName(s.db.DB, userName)
}

// GetSCIMUserByExternalID returns the SCIM user with the externalId, or
// [hsdb.ErrUserNotFound].
func (s *State) GetSCIMUserByExternalID(externalID string) (*types.User, error) {
	return hsdb.GetSCIMUserByExternalID(s.db.DB, externalID)
}

// ListSCIMUsers returns a page of SCIM users and the total number of
// matches; see [hsdb.ListSCIMUsers].
func (s *State) ListSCIMUsers(filter hsdb.SCIMUserFilter, startIndex, count int) ([]types.User, int64, error) {
	var total int64

	users, err := hsdb.Read(s.db.DB, func(rx *gorm.DB) ([]types.User, error) {
		u, n, err := hsdb.ListSCIMUsers(rx, filter, startIndex, count)
		total = n

		return u, err
	})

	return users, total, err
}

// CreateSCIMUser provisions a user from attrs, suspended unless attrs.Active,
// in one transaction. adopt lets it adopt the one existing OIDC user whose
// stored email is the userName; it follows scim.adopt_existing_users, off by
// default (see [hsdb.CreateSCIMUser], which also lists the errors).
func (s *State) CreateSCIMUser(attrs types.SCIMUserAttributes, adopt bool) (*types.User, change.Change, error) {
	var adopted, suspensionChanged bool

	user, err := hsdb.Write(s.db.DB, func(tx *gorm.DB) (*types.User, error) {
		u, a, err := hsdb.CreateSCIMUser(tx, attrs, adopt)
		if err != nil {
			return nil, err
		}

		adopted = a
		suspensionChanged, err = hsdb.SetUserSuspended(tx, types.UserID(u.ID), suspensionTime(attrs.Active))

		return u, err
	})
	if err != nil {
		return nil, change.Change{}, err
	}

	uid := types.UserID(user.ID)

	if adopted {
		// Adoption hands an existing account and its nodes to the
		// directory: make it visible in the logs.
		log.Warn().Uint64(zf.UserID, uint64(uid)).Str(zf.UserName, attrs.UserName).
			Msg("scim create adopted an existing OIDC user")
	}

	c, err := s.afterSCIMUserWrite(uid, adopted, suspensionChanged, attrs.Active)
	if err != nil {
		return nil, change.Change{}, err
	}

	// As in CreateUser: a new user can make SSH policies resolvable that
	// were not, which the policy manager does not detect.
	if !adopted && c.IsEmpty() {
		c = change.PolicyChange()
	}

	user, err = s.GetUserByID(uid)

	return user, c, err
}

// ReplaceSCIMUser replaces the SCIM user's attributes (PUT) and applies
// attrs.Active, in one transaction; see [hsdb.ReplaceSCIMUser]. SCIM owns
// the suspension of the users it manages: active=true lifts a suspension
// an admin set.
func (s *State) ReplaceSCIMUser(uid types.UserID, attrs types.SCIMUserAttributes) (*types.User, change.Change, error) {
	return s.PatchSCIMUser(uid, func(a *types.SCIMUserAttributes) error {
		*a = attrs

		return nil
	})
}

// PatchSCIMUser applies fn to the SCIM user's current attributes (PATCH),
// then stores them and applies Active as [State.ReplaceSCIMUser] does. An
// error from fn is returned as is and changes nothing.
func (s *State) PatchSCIMUser(uid types.UserID, fn func(*types.SCIMUserAttributes) error) (*types.User, change.Change, error) {
	var active, suspensionChanged bool

	_, err := hsdb.Write(s.db.DB, func(tx *gorm.DB) (*types.User, error) {
		u, err := hsdb.PatchSCIMUser(tx, uid, func(a *types.SCIMUserAttributes) error {
			err := fn(a)
			active = a.Active

			return err
		})
		if err != nil {
			return nil, err
		}

		suspensionChanged, err = hsdb.SetUserSuspended(tx, uid, suspensionTime(active))

		return u, err
	})
	if err != nil {
		return nil, change.Change{}, err
	}

	c, err := s.afterSCIMUserWrite(uid, true, suspensionChanged, active)
	if err != nil {
		return nil, change.Change{}, err
	}

	user, err := s.GetUserByID(uid)

	return user, c, err
}

// suspensionTime is the suspended_at a SCIM active flag asks for.
func suspensionTime(active bool) time.Time {
	if active {
		return time.Time{}
	}

	return time.Now()
}

// afterSCIMUserWrite brings the NodeStore and policy manager up to date
// after a committed SCIM user write, and returns the change to broadcast.
func (s *State) afterSCIMUserWrite(uid types.UserID, mayHaveNodes, suspensionChanged, active bool) (change.Change, error) {
	if suspensionChanged {
		// Refreshes the user's nodes and the policy manager too.
		return s.applySuspensionChange(uid, !active)
	}

	return s.refreshSCIMUser(uid, mayHaveNodes)
}

// DeleteSCIMUser deprovisions the SCIM user: it is suspended at once, so it
// can register no new node meanwhile, then its nodes are deleted (as the API
// deletes nodes, updating the NodeStore and policy), then the user with its
// pre-auth keys and memberships. It returns the changes to broadcast, which
// may be non-empty alongside an error: they describe what was already
// deleted and must still be sent. It returns [hsdb.ErrUserNotFound] when uid
// is not a SCIM user.
func (s *State) DeleteSCIMUser(uid types.UserID) ([]change.Change, error) {
	_, err := s.GetSCIMUser(uid)
	if err != nil {
		return nil, err
	}

	var changes []change.Change

	appendChange := func(c change.Change) {
		if !c.IsEmpty() {
			changes = append(changes, c)
		}
	}

	c, err := s.SuspendUser(uid)
	appendChange(c)

	if err != nil {
		return changes, fmt.Errorf("suspending SCIM user %d before deletion: %w", uid, err)
	}

	for _, node := range s.nodeStore.ListNodesByUser(uid).All() {
		cs, err := s.DeleteNode(node)
		for _, c := range cs {
			appendChange(c)
		}

		if err != nil {
			return changes, fmt.Errorf("deleting node %d of SCIM user %d: %w", node.ID(), uid, err)
		}
	}

	c, err = s.DeleteUser(uid)
	appendChange(c)

	if err != nil {
		return changes, fmt.Errorf("deleting SCIM user %d: %w", uid, err)
	}

	// The user is gone: forget their suspension too.
	err = s.syncSuspendedUsers()

	return changes, err
}

// FindUnlinkedSCIMUserByUserName returns the SCIM user, not yet linked to a
// login, whose userName is userName (the login's verified email), or
// [hsdb.ErrUserNotFound]. See [hsdb.FindUnlinkedSCIMUserByUserName].
func (s *State) FindUnlinkedSCIMUserByUserName(userName string) (*types.User, error) {
	return hsdb.FindUnlinkedSCIMUserByUserName(s.db.DB, userName)
}

// FindUnlinkedSCIMUsersByEmail returns up to limit SCIM users, not yet
// linked to a login, whose SCIM email is email; see
// [hsdb.FindUnlinkedSCIMUsersByEmail].
func (s *State) FindUnlinkedSCIMUsersByEmail(email string, limit int) ([]types.User, error) {
	return hsdb.FindUnlinkedSCIMUsersByEmail(s.db.DB, email, limit)
}

// FindUnlinkedSCIMUserByExternalID returns the SCIM user, not yet linked to a
// login, whose externalId is externalID, or [hsdb.ErrUserNotFound].
func (s *State) FindUnlinkedSCIMUserByExternalID(externalID string) (*types.User, error) {
	return hsdb.FindUnlinkedSCIMUserByExternalID(s.db.DB, externalID)
}

// LinkSCIMUser links the unlinked SCIM user to the OIDC identity
// providerIdentifier; see [hsdb.LinkSCIMUser] for the errors. The OIDC
// callback then updates the user from the login's claims as usual.
func (s *State) LinkSCIMUser(uid types.UserID, providerIdentifier string) (*types.User, change.Change, error) {
	user, err := hsdb.Write(s.db.DB, func(tx *gorm.DB) (*types.User, error) {
		return hsdb.LinkSCIMUser(tx, uid, providerIdentifier)
	})
	if err != nil {
		return nil, change.Change{}, err
	}

	c, err := s.refreshSCIMUser(uid, true)
	if err != nil {
		return nil, change.Change{}, err
	}

	return user, c, nil
}

// refreshSCIMUser pushes a changed user to the policy manager and, when the
// user may have nodes, to their nodes' copies in the NodeStore.
func (s *State) refreshSCIMUser(uid types.UserID, mayHaveNodes bool) (change.Change, error) {
	if mayHaveNodes {
		err := s.refreshNodeStoreUser(uid)
		if err != nil {
			return change.Change{}, err
		}
	}

	c, err := s.updatePolicyManagerUsers()
	if err != nil {
		return change.Change{}, fmt.Errorf("updating policy manager after SCIM user change: %w", err)
	}

	return c, nil
}

// GetSCIMGroup returns the SCIM group id, or [hsdb.ErrGroupNotFound].
func (s *State) GetSCIMGroup(id uint) (*types.Group, error) {
	return hsdb.GetSCIMGroupByID(s.db.DB, id)
}

// GetSCIMGroupByExternalID returns the SCIM group with the externalId, or
// [hsdb.ErrGroupNotFound].
func (s *State) GetSCIMGroupByExternalID(externalID string) (*types.Group, error) {
	return hsdb.GetSCIMGroupByExternalID(s.db.DB, externalID)
}

// GetSCIMGroupByDisplayName returns the SCIM group named displayName in
// domain, or [hsdb.ErrGroupNotFound].
func (s *State) GetSCIMGroupByDisplayName(domain, displayName string) (*types.Group, error) {
	return hsdb.GetSCIMGroupByDisplayName(s.db.DB, domain, displayName)
}

// ListSCIMGroups returns a page of SCIM groups and the total number of
// matches; see [hsdb.ListSCIMGroups].
func (s *State) ListSCIMGroups(domain string, filter hsdb.SCIMGroupFilter, startIndex, count int) ([]types.Group, int64, error) {
	var total int64

	groups, err := hsdb.Read(s.db.DB, func(rx *gorm.DB) ([]types.Group, error) {
		g, n, err := hsdb.ListSCIMGroups(rx, domain, filter, startIndex, count)
		total = n

		return g, err
	})

	return groups, total, err
}

// SCIMGroupMembers returns the SCIM members of each group; see
// [hsdb.SCIMGroupMembers].
func (s *State) SCIMGroupMembers(groupIDs ...uint) (map[uint][]types.UserID, error) {
	return hsdb.SCIMGroupMembers(s.db.DB, groupIDs...)
}

// CreateSCIMGroup provisions a group with the given SCIM members, in one
// transaction, adopting a group of that name created by OIDC logins and
// revoking the OIDC memberships SCIM's authority excludes (see
// [hsdb.CreateSCIMGroup] and [hsdb.ApplySCIMGroupOps] for the errors).
func (s *State) CreateSCIMGroup(
	domain, displayName, externalID string,
	members []types.UserID,
) (*types.Group, change.Change, error) {
	var affected []types.UserID

	group, err := hsdb.Write(s.db.DB, func(tx *gorm.DB) (*types.Group, error) {
		g, revoked, err := hsdb.CreateSCIMGroup(tx, domain, displayName, externalID)
		if err != nil {
			return nil, err
		}

		affected = revoked

		added, err := hsdb.ApplySCIMGroupOps(tx, domain, g.ID, types.SCIMGroupOp{
			Kind:    types.SCIMGroupAddMembers,
			Members: members,
		})
		affected = append(affected, added...)

		return g, err
	})
	if err != nil {
		return nil, change.Change{}, err
	}

	c, err := s.applyGroupMembershipChanges(affected)

	return group, c, err
}

// UpdateSCIMGroup applies ops to the SCIM group in one transaction (a PATCH,
// or for a PUT a rename, an external id change and a member replacement);
// see [hsdb.ApplySCIMGroupOps] for their semantics and errors.
func (s *State) UpdateSCIMGroup(domain string, id uint, ops ...types.SCIMGroupOp) (*types.Group, change.Change, error) {
	var affected []types.UserID

	group, err := hsdb.Write(s.db.DB, func(tx *gorm.DB) (*types.Group, error) {
		var err error

		affected, err = hsdb.ApplySCIMGroupOps(tx, domain, id, ops...)
		if err != nil {
			return nil, err
		}

		return hsdb.GetSCIMGroupByID(tx, id)
	})
	if err != nil {
		return nil, change.Change{}, err
	}

	c, err := s.applyGroupMembershipChanges(affected)

	return group, c, err
}

// DeleteSCIMGroup deletes the SCIM group and all its memberships, and the
// OIDC memberships of groups named like its external name; see
// [hsdb.DeleteSCIMGroup].
func (s *State) DeleteSCIMGroup(id uint) (change.Change, error) {
	members, err := hsdb.Write(s.db.DB, func(tx *gorm.DB) ([]types.UserID, error) {
		return hsdb.DeleteSCIMGroup(tx, id)
	})
	if err != nil {
		return change.Change{}, err
	}

	return s.applyGroupMembershipChanges(members)
}

// ReleaseSCIMGroup hands the SCIM group back to OIDC logins, for when SCIM
// provisioning is turned off; see [hsdb.ReleaseSCIMGroup].
func (s *State) ReleaseSCIMGroup(id uint) (change.Change, error) {
	members, err := hsdb.Write(s.db.DB, func(tx *gorm.DB) ([]types.UserID, error) {
		return hsdb.ReleaseSCIMGroup(tx, id)
	})
	if err != nil {
		return change.Change{}, err
	}

	return s.applyGroupMembershipChanges(members)
}

// applyGroupMembershipChanges refreshes the NodeStore copies of users whose
// groups changed and the policy manager, as [State.SetUserGroups] does.
func (s *State) applyGroupMembershipChanges(users []types.UserID) (change.Change, error) {
	if len(users) == 0 {
		return change.Change{}, nil
	}

	// Read before the NodeStore write below; see updatePolicyManagerNodes.
	genBefore := s.polMan.NodesGeneration()

	// Display only, as in [State.SetUserGroups]: it must not keep the policy
	// update below from running.
	err := s.refreshNodeStoreUsers(users...)
	if err != nil {
		log.Error().Err(err).Int(zf.UserCount, len(users)).
			Msg("refreshing users' nodes after a SCIM group change")
	}

	c, err := s.updatePolicyManagerUsers()
	if err != nil {
		return s.policyChangeSince(genBefore), fmt.Errorf("updating policy manager after SCIM group change: %w", err)
	}

	return c.Merge(s.policyChangeSince(genBefore)), nil
}
