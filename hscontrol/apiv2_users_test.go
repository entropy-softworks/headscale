package hscontrol

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"

	"github.com/danielgtaylor/huma/v2/humatest"
	"github.com/google/go-cmp/cmp"
	apiv2 "github.com/juanfont/headscale/hscontrol/api/v2"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// userID stringifies a test user's id the way the API emits it.
func userID(u *types.User) string {
	return strconv.FormatUint(uint64(u.ID), 10)
}

// getUserByID GETs a user by id and decodes it.
func getUserByID(t *testing.T, api humatest.TestAPI, id string) apiv2.User {
	t.Helper()

	resp := api.Get("/api/v2/users/" + id)
	require.Equalf(t, http.StatusOK, resp.Code, "body: %s", resp.Body)

	var user apiv2.User
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &user))

	return user
}

// listUsers GETs the user list (with an optional raw query string) and returns
// the decoded slice plus the raw body, so tests can pin the envelope shape.
func listUsers(t *testing.T, api humatest.TestAPI, query string) ([]apiv2.User, string) {
	t.Helper()

	resp := api.Get("/api/v2/tailnet/-/users" + query)
	require.Equalf(t, http.StatusOK, resp.Code, "body: %s", resp.Body)

	var env struct {
		Users []apiv2.User `json:"users"`
	}
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &env))

	return env.Users, resp.Body.String()
}

func containsUserID(users []apiv2.User, id string) bool {
	for _, u := range users {
		if u.ID == id {
			return true
		}
	}

	return false
}

func TestAPIv2User_Get(t *testing.T) {
	app := createTestApp(t)
	api := registerAPIV2(t, app)

	user := app.state.CreateUserForTest("golden")

	got := getUserByID(t, api, userID(user))

	// Shape for a user with no devices: identity mapped, unmodelled fields fixed.
	want := apiv2.User{
		ID:          userID(user),
		DisplayName: "golden",
		LoginName:   "golden",
		TailnetID:   "1",
		Created:     user.CreatedAt,
		Type:        "member",
		Role:        "member",
		Status:      "active",
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("user mismatch (-want +got):\n%s", diff)
	}
}

func TestAPIv2User_Get_DeviceCount(t *testing.T) {
	app := createTestApp(t)
	api := registerAPIV2(t, app)

	user := app.state.CreateUserForTest("owner")

	const wantDevices = 3
	for i := range wantDevices {
		node := app.state.CreateRegisteredNodeForTest(user, "dut-"+strconv.Itoa(i))
		app.state.PutNodeInStoreForTest(*node)
	}

	got := getUserByID(t, api, userID(user))
	assert.Equal(t, wantDevices, got.DeviceCount, "deviceCount aggregates the user's nodes")
}

func TestAPIv2User_Get_NotFound(t *testing.T) {
	app := createTestApp(t)
	api := registerAPIV2(t, app)

	tests := []struct {
		name string
		id   string
	}{
		{name: "unknown numeric id", id: "999999"},
		{name: "non-numeric id", id: "not-a-number"},
		// The tagged-devices pseudo-user is never a real DB row.
		{name: "tagged-devices pseudo-user", id: strconv.Itoa(types.TaggedDevicesUserID)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := api.Get("/api/v2/users/" + tt.id)
			assert.Equal(t, http.StatusNotFound, resp.Code)
			assert.Contains(t, resp.Body.String(), `"message"`, "Tailscale error shape")
		})
	}
}

func TestAPIv2User_List(t *testing.T) {
	app := createTestApp(t)
	api := registerAPIV2(t, app)

	u1 := app.state.CreateUserForTest("alice")
	u2 := app.state.CreateUserForTest("bob")

	users, body := listUsers(t, api, "")
	assert.Contains(t, body, `"users"`, "list is enveloped under users")
	assert.True(t, containsUserID(users, userID(u1)))
	assert.True(t, containsUserID(users, userID(u2)))
	assert.False(t, containsUserID(users, strconv.Itoa(types.TaggedDevicesUserID)),
		"tagged-devices pseudo-user is not listed")

	for _, u := range users {
		assert.NotEmpty(t, u.ID, "every user has an id")
		assert.NotEmpty(t, u.LoginName, "every user has a login name")
		assert.Equal(t, "member", u.Type)
		assert.Equal(t, "active", u.Status)
	}
}

func TestAPIv2User_List_Filters(t *testing.T) {
	app := createTestApp(t)
	api := registerAPIV2(t, app)

	app.state.CreateUserForTest("alice")
	app.state.CreateUserForTest("bob")

	tests := []struct {
		name      string
		query     string
		wantEmpty bool
	}{
		{name: "no filter", query: "", wantEmpty: false},
		{name: "type member", query: "?type=member", wantEmpty: false},
		{name: "role member", query: "?role=member", wantEmpty: false},
		{name: "member and member", query: "?type=member&role=member", wantEmpty: false},
		{name: "type shared", query: "?type=shared", wantEmpty: true},
		{name: "role admin", query: "?role=admin", wantEmpty: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			users, body := listUsers(t, api, tt.query)
			assert.Contains(t, body, `"users"`)
			assert.NotContains(t, body, "null", "empty list marshals as [] not null")

			if tt.wantEmpty {
				assert.Empty(t, users)
			} else {
				assert.NotEmpty(t, users)
			}
		})
	}
}

func TestAPIv2User_List_BadTailnet(t *testing.T) {
	app := createTestApp(t)
	api := registerAPIV2(t, app)

	resp := api.Get("/api/v2/tailnet/example.com/users")
	assert.Equal(t, http.StatusNotFound, resp.Code)
	assert.Contains(t, resp.Body.String(), `"message"`)
}

// TestAPIv2User_SuspendRestore checks Tailscale's suspend and restore
// endpoints: they return 200, are idempotent, report the state as the user's
// status, and cut off and reconnect the user's nodes.
func TestAPIv2User_SuspendRestore(t *testing.T) {
	app := createTestApp(t)
	api := registerAPIV2(t, app)

	user := app.state.CreateUserForTest("suspendee")
	node := app.state.CreateRegisteredNodeForTest(user, "suspendee-node")
	app.state.PutNodeInStoreForTest(*node)

	nodeView := func() types.NodeView {
		nv, ok := app.state.GetNodeByID(node.ID)
		require.True(t, ok)

		return nv
	}

	for range 2 {
		resp := api.Post("/api/v2/users/"+userID(user)+"/suspend", struct{}{})
		require.Equalf(t, http.StatusOK, resp.Code, "body: %s", resp.Body)
	}

	assert.Equal(t, "suspended", getUserByID(t, api, userID(user)).Status)
	assert.True(t, app.state.IsNodeSuspended(nodeView()))

	for range 2 {
		resp := api.Post("/api/v2/users/"+userID(user)+"/restore", struct{}{})
		require.Equalf(t, http.StatusOK, resp.Code, "body: %s", resp.Body)
	}

	assert.Equal(t, "active", getUserByID(t, api, userID(user)).Status)
	assert.False(t, app.state.IsNodeSuspended(nodeView()))

	for _, path := range []string{"/api/v2/users/999999/suspend", "/api/v2/users/nope/restore"} {
		resp := api.Post(path, struct{}{})
		assert.Equalf(t, http.StatusNotFound, resp.Code, "%s: %s", path, resp.Body)
	}
}
