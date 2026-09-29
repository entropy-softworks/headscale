package hscontrol

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"

	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// seedSCIMDirectory provisions, as an identity provider would, an active
// user linked to a login, an unlinked suspended user, and a group with an
// external id holding both, next to a local user SCIM does not manage.
func seedSCIMDirectory(t *testing.T, app *Headscale) (*types.User, *types.User, *types.Group) {
	t.Helper()

	app.cfg.SCIM = types.SCIMConfig{Enabled: true, GroupsDomain: "example.com", LinkBy: types.SCIMLinkByEmail}
	s := app.state

	app.state.CreateUserForTest("local")

	alice, _, err := s.CreateSCIMUser(types.SCIMUserAttributes{
		UserName: "alice@example.com", ExternalID: "00u-alice", DisplayName: "Alice", Active: true,
	}, true)
	require.NoError(t, err)

	alice, _, err = s.LinkSCIMUser(types.UserID(alice.ID), "https://idp.example.com/alice")
	require.NoError(t, err)

	bob, _, err := s.CreateSCIMUser(types.SCIMUserAttributes{UserName: "bob", Email: "bob@example.com"}, true)
	require.NoError(t, err)

	group, _, err := s.CreateSCIMGroup("example.com", "Eng", "0a1b-eng",
		[]types.UserID{types.UserID(alice.ID), types.UserID(bob.ID)})
	require.NoError(t, err)

	return alice, bob, group
}

func TestAPIV1ListScimUsers(t *testing.T) {
	h := newAPIV1Harness(t)
	alice, bob, _ := seedSCIMDirectory(t, h.app)

	res := h.callHuma(http.MethodGet, "/api/v1/scim/user", nil)
	require.Equalf(t, http.StatusOK, res.status, "%s", res.body)

	assert.JSONEq(t, `{"scimUsers": [
		{"id": "`+strconv.FormatUint(uint64(alice.ID), 10)+`", "userName": "alice@example.com",
		 "externalId": "00u-alice", "email": "", "displayName": "Alice", "name": "alice@example.com",
		 "linked": true, "suspended": false},
		{"id": "`+strconv.FormatUint(uint64(bob.ID), 10)+`", "userName": "bob",
		 "externalId": "", "email": "bob@example.com", "displayName": "", "name": "bob",
		 "linked": false, "suspended": true}
	]}`, string(res.body), "only SCIM users are listed")
}

func TestAPIV1ListScimGroups(t *testing.T) {
	h := newAPIV1Harness(t)

	empty := h.callHuma(http.MethodGet, "/api/v1/scim/group", nil)
	require.Equal(t, http.StatusOK, empty.status)
	assert.JSONEq(t, `{"scimGroups": []}`, string(empty.body))

	_, _, group := seedSCIMDirectory(t, h.app)

	res := h.callHuma(http.MethodGet, "/api/v1/scim/group", nil)
	require.Equalf(t, http.StatusOK, res.status, "%s", res.body)

	assert.JSONEq(t, `{"scimGroups": [{
		"id": "`+strconv.FormatUint(uint64(group.ID), 10)+`", "displayName": "Eng", "name": "eng@example.com",
		"policyReference": "group:eng@example.com", "externalId": "0a1b-eng",
		"externalName": "0a1b-eng@example.com", "policyAlias": "group:0a1b-eng@example.com",
		"memberCount": 2, "source": "scim"
	}]}`, string(res.body))
}

func TestAPIV1ReleaseScimGroup(t *testing.T) {
	h := newAPIV1Harness(t)
	alice, _, group := seedSCIMDirectory(t, h.app)

	path := "/api/v1/scim/group/" + strconv.FormatUint(uint64(group.ID), 10) + "/release"

	// While SCIM is enabled the identity provider owns the group.
	res := h.callHuma(http.MethodPost, path, nil)
	assertStatus(t, res, http.StatusConflict)
	assert.Contains(t, string(res.body), "scim.enabled=false")

	_, err := h.app.state.GetSCIMGroup(group.ID)
	require.NoError(t, err, "the refused release kept the group")

	h.app.cfg.SCIM.Enabled = false

	res = h.callHuma(http.MethodPost, path, nil)
	require.Equalf(t, http.StatusOK, res.status, "%s", res.body)

	_, err = h.app.state.GetSCIMGroup(group.ID)
	require.ErrorIs(t, err, db.ErrGroupNotFound, "a released group is no longer managed by SCIM")

	user, err := h.app.state.GetUserByID(types.UserID(alice.ID))
	require.NoError(t, err)
	assert.Empty(t, user.GroupNames(), "releasing removes the SCIM memberships")

	list := h.callHuma(http.MethodGet, "/api/v1/scim/group", nil)
	assert.JSONEq(t, `{"scimGroups": []}`, string(list.body))

	// Logins may grant the group again.
	_, err = h.app.state.SetUserGroups(types.UserID(alice.ID), types.GroupSourceOIDC, []string{"eng@example.com"})
	require.NoError(t, err)

	user, err = h.app.state.GetUserByID(types.UserID(alice.ID))
	require.NoError(t, err)
	assert.Equal(t, []string{"eng@example.com"}, user.GroupNames())

	assertStatus(t, h.callHuma(http.MethodPost, path, nil), http.StatusNotFound)
	assertStatus(t, h.callHuma(http.MethodPost, "/api/v1/scim/group/abc/release", nil), http.StatusBadRequest)
}

// TestAPIV1ScimManagedUserProtections checks that while SCIM is enabled the
// admin API neither renames nor deletes users the identity provider
// manages, and that it does once SCIM is disabled.
func TestAPIV1ScimManagedUserProtections(t *testing.T) {
	h := newAPIV1Harness(t)
	alice, bob, _ := seedSCIMDirectory(t, h.app)

	aliceID := strconv.FormatUint(uint64(alice.ID), 10)
	bobID := strconv.FormatUint(uint64(bob.ID), 10)

	res := h.callHuma(http.MethodPost, "/api/v1/user/"+aliceID+"/rename/renamed", nil)
	assertStatus(t, res, http.StatusConflict)
	assert.Contains(t, string(res.body), "managed by SCIM")

	res = h.callHuma(http.MethodDelete, "/api/v1/user/"+bobID, nil)
	assertStatus(t, res, http.StatusConflict)
	assert.Contains(t, string(res.body), "identity provider")

	_, err := h.app.state.GetUserByID(types.UserID(bob.ID))
	require.NoError(t, err, "the refused delete kept the user")

	// Users SCIM does not manage are unaffected.
	local, err := h.app.state.GetUserByName("local")
	require.NoError(t, err)

	res = h.callHuma(http.MethodPost, "/api/v1/user/"+strconv.FormatUint(uint64(local.ID), 10)+"/rename/local2", nil)
	assertStatus(t, res, http.StatusOK)

	// The listing marks SCIM-managed and suspended users.
	list := h.callHuma(http.MethodGet, "/api/v1/user", nil)
	require.Equal(t, http.StatusOK, list.status)

	var got struct {
		Users []struct {
			ID          string `json:"id"`
			ScimManaged bool   `json:"scimManaged"`
			Suspended   bool   `json:"suspended"`
		} `json:"users"`
	}
	require.NoError(t, json.Unmarshal(list.body, &got))
	require.Len(t, got.Users, 3)

	flags := map[string][2]bool{}
	for _, u := range got.Users {
		flags[u.ID] = [2]bool{u.ScimManaged, u.Suspended}
	}

	assert.Equal(t, [2]bool{true, false}, flags[aliceID])
	assert.Equal(t, [2]bool{true, true}, flags[bobID])
	assert.Equal(t, [2]bool{false, false}, flags[strconv.FormatUint(uint64(local.ID), 10)])

	// With SCIM disabled, nothing competes with the admin.
	h.app.cfg.SCIM.Enabled = false

	res = h.callHuma(http.MethodDelete, "/api/v1/user/"+bobID, nil)
	assertStatus(t, res, http.StatusOK)
}
