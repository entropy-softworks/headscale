package state

import (
	"database/sql"
	"slices"
	"testing"

	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const scimTestDomain = "example.com"

type scimFixture struct {
	s        *State
	dave     *types.User
	daveNode *types.Node
	louNode  *types.Node
}

// scimTestState returns a State whose database holds an OIDC user, dave,
// with one registered node and a pre-auth key, and a local user, lou, with
// one node.
func scimTestState(t *testing.T) scimFixture {
	t.Helper()

	cfg := persistTestConfig(t.TempDir() + "/headscale.db")

	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(t, err)

	dave, err := database.CreateUser(types.User{
		Name:               "dave",
		Email:              "dave@example.com",
		ProviderIdentifier: sql.NullString{String: "https://idp.example.com/dave", Valid: true},
		Provider:           util.RegisterMethodOIDC,
	})
	require.NoError(t, err)

	daveNode := database.CreateRegisteredNodeForTest(dave, "dave-node")

	uid := types.UserID(dave.ID)
	_, err = database.CreatePreAuthKey(&uid, true, false, nil, nil)
	require.NoError(t, err)

	lou := database.CreateUserForTest("lou")
	louNode := database.CreateRegisteredNodeForTest(lou, "lou-node")

	require.NoError(t, database.Close())

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	return scimFixture{s: s, dave: dave, daveNode: daveNode, louNode: louNode}
}

// keysOf returns the ids of uid's pre-auth keys.
func keysOf(t *testing.T, s *State, uid uint) []uint64 {
	t.Helper()

	keys, err := s.ListPreAuthKeys()
	require.NoError(t, err)

	var ids []uint64

	for _, k := range keys {
		if k.UserID != nil && *k.UserID == uid {
			ids = append(ids, k.ID)
		}
	}

	return ids
}

// filterSrcIPs returns the source addresses of the compiled global filter.
func filterSrcIPs(s *State) []string {
	rules, _ := s.Filter()

	var srcs []string
	for _, r := range rules {
		srcs = append(srcs, r.SrcIPs...)
	}

	return srcs
}

func TestCreateSCIMUserSuspendsInactive(t *testing.T) {
	s := scimTestState(t).s

	user, c, err := s.CreateSCIMUser(types.SCIMUserAttributes{UserName: "new@example.com", Active: false}, true)
	require.NoError(t, err)
	assert.False(t, c.IsEmpty(), "a new user is a policy change")
	assert.True(t, user.IsSuspended(), "an inactive SCIM user is suspended")
	assert.True(t, user.IsSCIMProvisioned())

	user, c, err = s.PatchSCIMUser(types.UserID(user.ID), func(a *types.SCIMUserAttributes) error {
		a.Active = true

		return nil
	})
	require.NoError(t, err)
	assert.False(t, c.IsEmpty(), "reactivating is a change")
	assert.False(t, user.IsSuspended())

	user, _, err = s.ReplaceSCIMUser(types.UserID(user.ID), types.SCIMUserAttributes{UserName: "new@example.com"})
	require.NoError(t, err)
	assert.True(t, user.IsSuspended(), "PUT without active=true deactivates")

	_, _, err = s.CreateSCIMUser(types.SCIMUserAttributes{UserName: "NEW@example.com", Active: true}, true)
	require.ErrorIs(t, err, db.ErrSCIMConflict)
}

func TestCreateSCIMUserAdoptsAndSuspends(t *testing.T) {
	f := scimTestState(t)
	s, dave, daveNode := f.s, f.dave, f.daveNode

	user, _, err := s.CreateSCIMUser(types.SCIMUserAttributes{
		UserName: "Dave@Example.com", GivenName: "Dave", Active: false,
	}, true)
	require.NoError(t, err)
	assert.Equal(t, dave.ID, user.ID, "the existing OIDC user is adopted")
	assert.True(t, user.IsSuspended())

	node, ok := s.GetNodeByID(daveNode.ID)
	require.True(t, ok)
	assert.True(t, s.IsNodeSuspended(node), "deactivating an adopted user cuts off their nodes")
	assert.Equal(t, "Dave", node.User().AsStruct().GivenName, "the node's copy of its user is refreshed")

	_, c, err := s.ReplaceSCIMUser(types.UserID(user.ID), types.SCIMUserAttributes{UserName: "dave@example.com", Active: true})
	require.NoError(t, err)
	assert.False(t, c.IsEmpty())

	node, _ = s.GetNodeByID(daveNode.ID)
	assert.False(t, s.IsNodeSuspended(node))
}

func TestLinkSCIMUser(t *testing.T) {
	s := scimTestState(t).s

	user, _, err := s.CreateSCIMUser(types.SCIMUserAttributes{UserName: "erin@example.com", ExternalID: "00u-erin", Active: true}, true)
	require.NoError(t, err)

	found, err := s.FindUnlinkedSCIMUserByUserName("ERIN@example.com")
	require.NoError(t, err)
	assert.Equal(t, user.ID, found.ID)

	found, err = s.FindUnlinkedSCIMUserByExternalID("00u-erin")
	require.NoError(t, err)
	assert.Equal(t, user.ID, found.ID)

	linked, _, err := s.LinkSCIMUser(types.UserID(user.ID), "https://idp.example.com/erin")
	require.NoError(t, err)
	assert.Equal(t, util.RegisterMethodOIDC, linked.Provider)

	byLogin, err := s.GetUserByOIDCIdentifier("https://idp.example.com/erin")
	require.NoError(t, err)
	assert.Equal(t, user.ID, byLogin.ID)

	_, err = s.FindUnlinkedSCIMUserByUserName("erin@example.com")
	require.ErrorIs(t, err, db.ErrUserNotFound)

	_, _, err = s.LinkSCIMUser(types.UserID(user.ID), "https://idp.example.com/erin2")
	require.ErrorIs(t, err, db.ErrSCIMUserLinked)
}

func TestDeleteSCIMUserDeletesNodesAndKeys(t *testing.T) {
	f := scimTestState(t)
	s, dave, daveNode, louNode := f.s, f.dave, f.daveNode, f.louNode

	_, err := s.DeleteSCIMUser(types.UserID(dave.ID))
	require.ErrorIs(t, err, db.ErrUserNotFound, "a user SCIM does not manage cannot be deleted through SCIM")

	_, err = s.DeleteSCIMUser(types.UserID(*louNode.UserID))
	require.ErrorIs(t, err, db.ErrUserNotFound)

	_, _, err = s.CreateSCIMUser(types.SCIMUserAttributes{UserName: "dave@example.com", Active: true}, true)
	require.NoError(t, err)

	require.NotEmpty(t, keysOf(t, s, dave.ID))

	changes, err := s.DeleteSCIMUser(types.UserID(dave.ID))
	require.NoError(t, err)

	removed := false

	for _, c := range changes {
		if slices.Contains(c.PeersRemoved, daveNode.ID) {
			removed = true
		}
	}

	assert.True(t, removed, "peers must be told the node is gone: %v", changes)

	_, ok := s.GetNodeByID(daveNode.ID)
	assert.False(t, ok, "the node is removed from the NodeStore")

	_, err = s.DB().GetNodeByID(daveNode.ID)
	require.Error(t, err, "the node is removed from the database")

	_, err = s.GetUserByID(types.UserID(dave.ID))
	require.ErrorIs(t, err, db.ErrUserNotFound)

	keysBefore := len(keysOf(t, s, *louNode.UserID))
	assert.Empty(t, keysOf(t, s, dave.ID), "the user's pre-auth keys are deleted")
	assert.NotZero(t, keysBefore, "other users' keys are kept")

	_, ok = s.GetNodeByID(louNode.ID)
	assert.True(t, ok, "other users' nodes are untouched")

	_, err = s.DeleteSCIMUser(types.UserID(dave.ID))
	require.ErrorIs(t, err, db.ErrUserNotFound)
}

// TestSCIMGroupResolvesByExternalID follows a group through its SCIM
// lifecycle with a policy that references it by externalId, checking that
// each step that changes who the group selects reports a change and
// recompiles the filter.
func TestSCIMGroupResolvesByExternalID(t *testing.T) {
	f := scimTestState(t)
	s, dave, daveNode := f.s, f.dave, f.daveNode

	_, err := s.SetPolicy([]byte(`{
		"acls": [{"action": "accept", "src": ["group:6f1e-guid@example.com"], "dst": ["*:22"]}]
	}`))
	require.NoError(t, err)
	require.Empty(t, filterSrcIPs(s))

	daveIP := daveNode.IPv4.String()
	uid := types.UserID(dave.ID)

	_, _, err = s.CreateSCIMUser(types.SCIMUserAttributes{UserName: "dave@example.com", Active: true}, true)
	require.NoError(t, err)

	group, c, err := s.CreateSCIMGroup(scimTestDomain, "Engineering", "6F1E-GUID", []types.UserID{uid})
	require.NoError(t, err)
	assert.False(t, c.IsEmpty(), "gaining a referenced group must broadcast")
	assert.Contains(t, filterSrcIPs(s), daveIP)
	assert.Equal(t, "engineering@example.com", group.Name)

	node, _ := s.GetNodeByID(daveNode.ID)
	assert.Equal(t, []string{"engineering@example.com"}, node.User().GroupNames(),
		"the node's copy of its user shows the group")

	members, err := s.SCIMGroupMembers(group.ID)
	require.NoError(t, err)
	assert.Equal(t, []types.UserID{uid}, members[group.ID])

	// A rename keeps the external name, so the policy still selects dave.
	group, _, err = s.UpdateSCIMGroup(scimTestDomain, group.ID, types.SCIMGroupOp{Kind: types.SCIMGroupRename, Value: "Platform"})
	require.NoError(t, err)
	assert.Equal(t, "platform@example.com", group.Name)
	assert.Contains(t, filterSrcIPs(s), daveIP)

	// Changing the external id moves the alias away.
	_, c, err = s.UpdateSCIMGroup(scimTestDomain, group.ID, types.SCIMGroupOp{Kind: types.SCIMGroupSetExternalID, Value: "other"})
	require.NoError(t, err)
	assert.False(t, c.IsEmpty(), "losing the referenced external name must broadcast")
	assert.Empty(t, filterSrcIPs(s))

	_, _, err = s.UpdateSCIMGroup(scimTestDomain, group.ID, types.SCIMGroupOp{Kind: types.SCIMGroupSetExternalID, Value: "6f1e-guid"})
	require.NoError(t, err)
	assert.Contains(t, filterSrcIPs(s), daveIP)

	// Unchanged membership is no change.
	_, c, err = s.UpdateSCIMGroup(scimTestDomain, group.ID, types.SCIMGroupOp{Kind: types.SCIMGroupAddMembers, Members: []types.UserID{uid}})
	require.NoError(t, err)
	assert.True(t, c.IsEmpty(), "re-adding a member must not broadcast")

	_, c, err = s.UpdateSCIMGroup(scimTestDomain, group.ID, types.SCIMGroupOp{Kind: types.SCIMGroupRemoveMembers, Members: []types.UserID{uid}})
	require.NoError(t, err)
	assert.False(t, c.IsEmpty(), "losing membership must broadcast")
	assert.Empty(t, filterSrcIPs(s), "a removed member no longer matches")

	_, _, err = s.UpdateSCIMGroup(scimTestDomain, group.ID, types.SCIMGroupOp{Kind: types.SCIMGroupReplaceMembers, Members: []types.UserID{uid}})
	require.NoError(t, err)
	assert.Contains(t, filterSrcIPs(s), daveIP)

	c, err = s.DeleteSCIMGroup(group.ID)
	require.NoError(t, err)
	assert.False(t, c.IsEmpty(), "deleting a referenced group must broadcast")
	assert.Empty(t, filterSrcIPs(s))

	node, _ = s.GetNodeByID(daveNode.ID)
	assert.Empty(t, node.User().GroupNames())

	_, err = s.GetSCIMGroup(group.ID)
	require.ErrorIs(t, err, db.ErrGroupNotFound)
}

// TestSCIMGroupRevokesOIDCMemberships checks that SCIM is authoritative
// for the groups it manages, both when it adopts a group created by logins
// and in the Entra case, where logins assert the group's object id, which is
// the SCIM externalId: the OIDC membership is revoked at once (a change is
// broadcast and the filter no longer admits the node), and a later login
// asserting the group does not grant it again.
func TestSCIMGroupRevokesOIDCMemberships(t *testing.T) {
	tests := []struct {
		name        string
		ref         string
		oidcGroup   string
		displayName string
		externalID  string
	}{
		{"adopted name", "group:eng@example.com", "eng@example.com", "eng", ""},
		{"entra externalId", "group:6f1e-guid@example.com", "6f1e-guid@example.com", "Engineering", "6F1E-GUID"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := scimTestState(t)
			s, dave, daveNode := f.s, f.dave, f.daveNode
			daveIP := daveNode.IPv4.String()
			uid := types.UserID(dave.ID)

			_, err := s.SetPolicy([]byte(`{
				"acls": [{"action": "accept", "src": ["` + tt.ref + `"], "dst": ["*:22"]}]
			}`))
			require.NoError(t, err)

			_, err = s.SetUserGroups(uid, types.GroupSourceOIDC, []string{tt.oidcGroup})
			require.NoError(t, err)
			require.Contains(t, filterSrcIPs(s), daveIP, "the login grants the group before SCIM manages it")

			_, c, err := s.CreateSCIMGroup(scimTestDomain, tt.displayName, tt.externalID, nil)
			require.NoError(t, err)
			assert.False(t, c.IsEmpty(), "revoking must broadcast")
			assert.NotContains(t, filterSrcIPs(s), daveIP, "revoked at once")

			node, _ := s.GetNodeByID(daveNode.ID)
			assert.Empty(t, node.User().GroupNames(), "the node's copy of its user is refreshed")

			c, err = s.SetUserGroups(uid, types.GroupSourceOIDC, []string{tt.oidcGroup})
			require.NoError(t, err)
			assert.True(t, c.IsEmpty())
			assert.NotContains(t, filterSrcIPs(s), daveIP, "a later login does not grant it again")
		})
	}
}

// TestNewStatePurgesNonSCIMMemberships checks the startup purge of OIDC
// memberships of SCIM-managed groups, written before they were managed.
func TestNewStatePurgesNonSCIMMemberships(t *testing.T) {
	cfg := persistTestConfig(t.TempDir() + "/headscale.db")
	cfg.OIDC.Groups = types.OIDCGroupsConfig{Enabled: true, Claim: "groups", Domain: scimTestDomain}

	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(t, err)

	uid := types.UserID(database.CreateUserForTest("alice").ID)
	g, _, err := db.CreateSCIMGroup(database.DB, scimTestDomain, "Eng", "")
	require.NoError(t, err)
	require.NoError(t, database.DB.Create(&types.UserGroup{UserID: uint(uid), GroupID: g.ID, Source: types.GroupSourceOIDC}).Error)
	require.NoError(t, database.Close())

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	user, err := s.GetUserByID(uid)
	require.NoError(t, err)
	assert.Empty(t, user.GroupNames())
}

// TestReplaceSCIMUserOwnsSuspension checks that SCIM's active flag is
// authoritative: active=true lifts a suspension an admin set.
func TestReplaceSCIMUserOwnsSuspension(t *testing.T) {
	s := scimTestState(t).s

	user, _, err := s.CreateSCIMUser(types.SCIMUserAttributes{UserName: "kim@example.com", Active: true}, true)
	require.NoError(t, err)

	uid := types.UserID(user.ID)
	_, err = s.SuspendUser(uid)
	require.NoError(t, err)

	user, c, err := s.ReplaceSCIMUser(uid, types.SCIMUserAttributes{UserName: "kim@example.com", Active: true})
	require.NoError(t, err)
	assert.False(t, user.IsSuspended())
	assert.False(t, c.IsEmpty())
}

// TestDeleteSCIMUserSuspendsFirst checks that deprovisioning suspends the
// user before deleting anything: when the delete fails part way (here, a
// node the NodeStore does not know about blocks it), the user is left
// suspended rather than active.
func TestDeleteSCIMUserSuspendsFirst(t *testing.T) {
	f := scimTestState(t)
	s := f.s

	user, _, err := s.CreateSCIMUser(types.SCIMUserAttributes{UserName: "dave@example.com", Active: true}, true)
	require.NoError(t, err)

	s.DB().CreateRegisteredNodeForTest(user, "db-only-node")

	_, err = s.DeleteSCIMUser(types.UserID(user.ID))
	require.ErrorIs(t, err, db.ErrUserStillHasNodes)

	got, err := s.GetUserByID(types.UserID(user.ID))
	require.NoError(t, err)
	assert.True(t, got.IsSuspended())
}

// TestNewStateDeletesOrphanedOIDCGroups checks the startup cleanup: an OIDC
// group whose memberships were pruned is deleted, a SCIM group is kept.
func TestNewStateDeletesOrphanedOIDCGroups(t *testing.T) {
	cfg := persistTestConfig(t.TempDir() + "/headscale.db")

	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(t, err)

	uid := types.UserID(database.CreateUserForTest("alice").ID)
	_, err = db.SetUserGroups(database.DB, uid, types.GroupSourceOIDC, []string{"eng@example.com"})
	require.NoError(t, err)
	_, _, err = db.CreateSCIMGroup(database.DB, scimTestDomain, "Empty", "")
	require.NoError(t, err)
	require.NoError(t, database.Close())

	// Group sync is disabled: the OIDC membership is pruned at startup.
	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	var names []string
	require.NoError(t, s.DB().DB.Model(&types.Group{}).Order("name").Pluck("name", &names).Error)
	assert.Equal(t, []string{"empty@example.com"}, names)
}

// TestReleaseSCIMGroup checks that releasing a referenced SCIM group revokes
// its SCIM members' access and broadcasts, and that logins can grant it
// again afterwards.
func TestReleaseSCIMGroup(t *testing.T) {
	f := scimTestState(t)
	s, dave, daveNode := f.s, f.dave, f.daveNode
	daveIP := daveNode.IPv4.String()
	uid := types.UserID(dave.ID)

	_, err := s.SetPolicy([]byte(`{
		"acls": [{"action": "accept", "src": ["group:eng@example.com"], "dst": ["*:22"]}]
	}`))
	require.NoError(t, err)

	_, _, err = s.CreateSCIMUser(types.SCIMUserAttributes{UserName: "dave@example.com", Active: true}, true)
	require.NoError(t, err)

	g, _, err := s.CreateSCIMGroup(scimTestDomain, "Eng", "", []types.UserID{uid})
	require.NoError(t, err)
	require.Contains(t, filterSrcIPs(s), daveIP)

	c, err := s.ReleaseSCIMGroup(g.ID)
	require.NoError(t, err)
	assert.False(t, c.IsEmpty())
	assert.NotContains(t, filterSrcIPs(s), daveIP)

	_, err = s.SetUserGroups(uid, types.GroupSourceOIDC, []string{"eng@example.com"})
	require.NoError(t, err)
	assert.Contains(t, filterSrcIPs(s), daveIP, "logins grant a released group again")
}
