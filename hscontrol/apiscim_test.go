package hscontrol

import (
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	apiscim "github.com/juanfont/headscale/hscontrol/api/scim"
	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/scim"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// scimEnv is a headscale app with SCIM enabled, served over a real
// httptest server through the production router, and a SCIM token.
type scimEnv struct {
	t     *testing.T
	app   *Headscale
	url   string
	token string
}

const scimTestDomain = "example.com"

func newSCIMEnv(t *testing.T) *scimEnv {
	t.Helper()

	app := createTestApp(t)
	app.cfg.SCIM = types.SCIMConfig{
		Enabled:            true,
		GroupsDomain:       scimTestDomain,
		LinkBy:             types.SCIMLinkByEmail,
		AdoptExistingUsers: true,
	}

	srv := httptest.NewServer(app.HTTPHandler())
	t.Cleanup(srv.Close)

	app.cfg.ServerURL = srv.URL

	token, _, err := app.state.CreateSCIMToken("scim test", nil)
	require.NoError(t, err)

	return &scimEnv{t: t, app: app, url: srv.URL, token: token}
}

type scimResponse struct {
	status int
	header http.Header
	body   []byte
}

// object decodes the body as a JSON object.
func (r scimResponse) object(t *testing.T) map[string]any {
	t.Helper()

	var m map[string]any
	require.NoError(t, json.Unmarshal(r.body, &m), "body: %s", r.body)

	return m
}

// list decodes a list response; the typed fields fail to decode unless
// totalResults, itemsPerPage and startIndex are JSON integers.
func (r scimResponse) list(t *testing.T) scimList {
	t.Helper()

	require.Equal(t, http.StatusOK, r.status, "body: %s", r.body)

	var l scimList
	require.NoError(t, json.Unmarshal(r.body, &l), "body: %s", r.body)
	assert.Equal(t, []string{scim.SchemaListResponse}, l.Schemas)
	require.NotNil(t, l.Resources, "Resources is an array, never null")

	return l
}

// scimError decodes an RFC 7644 error body and checks its shape.
func (r scimResponse) scimError(t *testing.T, status int, scimType scim.ScimType) scim.Error {
	t.Helper()

	require.Equal(t, status, r.status, "body: %s", r.body)
	assert.Equal(t, scim.ContentType, r.header.Get("Content-Type"))

	raw := r.object(t)
	assert.Equal(t, []any{scim.SchemaError}, raw["schemas"])
	assert.Equal(t, strconv.Itoa(status), raw["status"], "status is a JSON string")

	var e scim.Error
	require.NoError(t, json.Unmarshal(r.body, &e))
	assert.Equal(t, scimType, e.ScimType)

	return e
}

type scimList struct {
	Schemas      []string         `json:"schemas"`
	TotalResults int              `json:"totalResults"`
	ItemsPerPage int              `json:"itemsPerPage"`
	StartIndex   int              `json:"startIndex"`
	Resources    []map[string]any `json:"Resources"`
}

// send sends a request with exactly the given headers.
func (e *scimEnv) send(method, path, body string, headers map[string]string) scimResponse {
	e.t.Helper()

	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}

	req, err := http.NewRequestWithContext(e.t.Context(), method, e.url+path, rd)
	require.NoError(e.t, err)

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := http.DefaultClient.Do(req)
	require.NoError(e.t, err)

	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	require.NoError(e.t, err)

	return scimResponse{status: resp.StatusCode, header: resp.Header, body: data}
}

// do sends an authenticated request with an application/scim+json body.
func (e *scimEnv) do(method, path, body string) scimResponse {
	e.t.Helper()

	h := map[string]string{"Authorization": "Bearer " + e.token}
	if body != "" {
		h["Content-Type"] = scim.ContentType
	}

	return e.send(method, path, body, h)
}

// create POSTs body to /scim/v2/<resource> and returns the new id.
func (e *scimEnv) create(resource, body string) string {
	e.t.Helper()

	res := e.do(http.MethodPost, "/scim/v2/"+resource, body)
	require.Equal(e.t, http.StatusCreated, res.status, "body: %s", res.body)

	obj := res.object(e.t)
	id, _ := obj["id"].(string)
	require.NotEmpty(e.t, id)
	assert.Equal(e.t, e.url+"/scim/v2/"+resource+"/"+id, res.header.Get("Location"))

	return id
}

func (e *scimEnv) get(path string) map[string]any {
	e.t.Helper()

	res := e.do(http.MethodGet, path, "")
	require.Equal(e.t, http.StatusOK, res.status, "body: %s", res.body)
	assert.Equal(e.t, scim.ContentType, res.header.Get("Content-Type"))

	return res.object(e.t)
}

func (e *scimEnv) user(id string) *types.User {
	e.t.Helper()

	n, err := strconv.ParseUint(id, 10, 64)
	require.NoError(e.t, err)

	u, err := e.app.state.GetUserByID(types.UserID(n))
	require.NoError(e.t, err)

	return u
}

// fixture reads a request body from the scim package's testdata, applying
// old, new replacement pairs (the fixtures carry the client's ids).
func fixture(t *testing.T, name string, oldnew ...string) string {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("scim", "testdata", name))
	require.NoError(t, err)

	return strings.NewReplacer(oldnew...).Replace(string(data))
}

// dig walks a decoded JSON value by object keys and array indices.
func dig(t *testing.T, v any, path ...any) any {
	t.Helper()

	for _, p := range path {
		switch k := p.(type) {
		case string:
			m, ok := v.(map[string]any)
			require.True(t, ok, "%v is not an object", v)

			v = m[k]
		case int:
			l, ok := v.([]any)
			require.True(t, ok, "%v is not an array", v)
			require.Less(t, k, len(l))

			v = l[k]
		}
	}

	return v
}

func filterQuery(f string) string {
	return "filter=" + url.QueryEscape(f)
}

func memberValues(t *testing.T, group map[string]any) []string {
	t.Helper()

	raw, _ := group["members"].([]any)
	out := make([]string, 0, len(raw))

	for _, m := range raw {
		obj, ok := m.(map[string]any)
		require.True(t, ok)

		v, _ := obj["value"].(string)
		out = append(out, v)
	}

	return out
}

func TestSCIMDisabled(t *testing.T) {
	app := createTestApp(t)
	srv := httptest.NewServer(app.HTTPHandler())
	t.Cleanup(srv.Close)

	token, _, err := app.state.CreateSCIMToken("unused", nil)
	require.NoError(t, err)

	e := &scimEnv{t: t, app: app, url: srv.URL, token: token}

	for _, path := range []string{"/scim/v2/ServiceProviderConfig", "/scim/v2/Users"} {
		res := e.do(http.MethodGet, path, "")
		assert.Equal(t, http.StatusNotFound, res.status, path)
	}
}

func TestSCIMAuthentication(t *testing.T) {
	e := newSCIMEnv(t)

	apiKey, _, err := e.app.state.CreateAPIKey(nil)
	require.NoError(t, err)

	mint := func(scopes ...string) string {
		_, client, err := e.app.state.CreateOAuthClient(scopes, []string{"tag:ci"}, "scim test", nil)
		require.NoError(t, err)

		exp := time.Now().Add(time.Hour)
		tok, _, err := e.app.state.MintAccessToken(client.ClientID, scopes, nil, &exp)
		require.NoError(t, err)

		return tok
	}

	revoked, revokedTok, err := e.app.state.CreateSCIMToken("revoked", nil)
	require.NoError(t, err)
	require.NoError(t, e.app.state.RevokeSCIMToken(revokedTok.ID))

	unauthenticated := map[string]map[string]string{
		"no header":     {},
		"basic":         {"Authorization": "Basic " + e.token},
		"empty bearer":  {"Authorization": "Bearer "},
		"admin api key": {"Authorization": "Bearer " + apiKey},
		"garbage":       {"Authorization": "Bearer hskey-scim-nope-nope"},
		"revoked":       {"Authorization": "Bearer " + revoked},
	}

	// Discovery, resources and unknown paths alike require a credential.
	paths := []string{"/scim/v2/ServiceProviderConfig", "/scim/v2/Users", "/scim/v2/nope"}

	for name, h := range unauthenticated {
		t.Run(name, func(t *testing.T) {
			for _, path := range paths {
				res := e.send(http.MethodGet, path, "", h)
				se := res.scimError(t, http.StatusUnauthorized, "")
				assert.True(t, strings.HasPrefix(res.header.Get("WWW-Authenticate"), "Bearer"),
					"401 carries a Bearer challenge, got %q", res.header.Get("WWW-Authenticate"))
				assert.NotContains(t, se.Detail, "revoked", "the cause is not echoed")
			}
		})
	}

	// Writes are refused before they reach the state layer.
	for _, req := range []struct{ method, path, body string }{
		{http.MethodPost, "/scim/v2/Users", `{"userName":"mallory@example.com"}`},
		{http.MethodPut, "/scim/v2/Users/1", `{"userName":"mallory@example.com"}`},
		{http.MethodPatch, "/scim/v2/Users/1", fixture(t, "patch/user/entra_disable_legacy.json")},
		{http.MethodDelete, "/scim/v2/Users/1", ""},
		{http.MethodPost, "/scim/v2/Groups", `{"displayName":"mallory"}`},
		{http.MethodPatch, "/scim/v2/Groups/1", fixture(t, "patch/group/entra_rename.json")},
		{http.MethodDelete, "/scim/v2/Groups/1", ""},
	} {
		for name, h := range map[string]map[string]string{
			"no header": {"Content-Type": scim.ContentType},
			"api key":   {"Content-Type": scim.ContentType, "Authorization": "Bearer " + apiKey},
		} {
			res := e.send(req.method, req.path, req.body, h)
			res.scimError(t, http.StatusUnauthorized, "")
			assert.NotEmpty(t, res.header.Get("WWW-Authenticate"), "%s %s %s", name, req.method, req.path)
		}
	}

	users, _, err := e.app.state.ListSCIMUsers(db.SCIMUserFilter{}, 1, 10)
	require.NoError(t, err)
	assert.Empty(t, users, "no unauthenticated write landed")

	for name, tok := range map[string]string{"oauth all": mint("all"), "oauth users": mint("users")} {
		t.Run(name, func(t *testing.T) {
			res := e.send(http.MethodGet, "/scim/v2/Users", "", map[string]string{"Authorization": "Bearer " + tok})
			res.scimError(t, http.StatusForbidden, "")
			assert.Contains(t, res.header.Get("WWW-Authenticate"), "insufficient_scope")
		})
	}

	ok := map[string]string{
		"scim token":       "Bearer " + e.token,
		"lowercase scheme": "bearer " + e.token,
		"oauth scim":       "Bearer " + mint("scim"),
		"oauth with scim":  "Bearer " + mint("users", "scim"),
	}
	for name, auth := range ok {
		t.Run(name, func(t *testing.T) {
			res := e.send(http.MethodGet, "/scim/v2/Users", "", map[string]string{"Authorization": auth})
			res.list(t)
		})
	}
}

func TestSCIMDiscovery(t *testing.T) {
	e := newSCIMEnv(t)
	base := e.url + "/scim/v2"

	spc := e.get("/scim/v2/ServiceProviderConfig")
	assert.Equal(t, map[string]any{"supported": true}, spc["patch"])
	assert.Equal(t, map[string]any{"supported": false}, spc["sort"])
	assert.Equal(t, map[string]any{"supported": false}, spc["etag"])
	assert.Equal(t, map[string]any{"supported": false}, spc["changePassword"])
	assert.Equal(t, false, dig(t, spc, "bulk", "supported"))
	assert.Equal(t, map[string]any{"supported": true, "maxResults": float64(scim.MaxPageSize)}, spc["filter"])
	assert.Equal(t, base+"/ServiceProviderConfig", dig(t, spc, "meta", "location"))

	rts := e.do(http.MethodGet, "/scim/v2/ResourceTypes", "").list(t)
	assert.Equal(t, 2, rts.TotalResults)
	assert.Equal(t, "User", rts.Resources[0]["id"])
	assert.Equal(t, "/Users", rts.Resources[0]["endpoint"])

	rt := e.get("/scim/v2/ResourceTypes/Group")
	assert.Equal(t, scim.SchemaGroup, rt["schema"])
	assert.Equal(t, base+"/ResourceTypes/Group", dig(t, rt, "meta", "location"))

	schemas := e.do(http.MethodGet, "/scim/v2/Schemas", "").list(t)
	assert.Equal(t, 2, schemas.TotalResults)

	group := e.get("/scim/v2/Schemas/" + scim.SchemaGroup)
	attrs, _ := group["attributes"].([]any)
	require.NotEmpty(t, attrs)

	displayName, _ := attrs[0].(map[string]any)
	assert.Equal(t, "displayName", displayName["name"])
	assert.Equal(t, "server", displayName["uniqueness"], "group names are unique")

	user := e.get("/scim/v2/Schemas/" + scim.SchemaUser)
	userName, _ := dig(t, user, "attributes", 0).(map[string]any)
	assert.Equal(t, "userName", userName["name"])
	assert.Equal(t, "server", userName["uniqueness"])

	e.do(http.MethodGet, "/scim/v2/Schemas/urn:nope", "").scimError(t, http.StatusNotFound, "")
	e.do(http.MethodGet, "/scim/v2/ResourceTypes/Nope", "").scimError(t, http.StatusNotFound, "")
}

// TestSCIMEntraUserLifecycle replays Entra ID's user provisioning: create,
// look up by userName, disable and re-enable (the pre-aadOptscim062020
// "False"/"True" strings), attribute updates in both PATCH dialects, and
// deprovisioning.
func TestSCIMEntraUserLifecycle(t *testing.T) {
	e := newSCIMEnv(t)

	const userName = "Test_User_ab6490ee-1e48-479e-a20b-2d77186b5dd1"

	id := e.create("Users", fixture(t, "users/entra_create.json"))

	u := e.get("/scim/v2/Users/" + id)
	assert.Equal(t, userName, u["userName"])
	assert.Equal(t, "0a21f0f2-8d2a-4f8e-bf98-7363c4aed4ef", u["externalId"])
	assert.Equal(t, true, u["active"])
	assert.Equal(t, map[string]any{"givenName": "givenName", "familyName": "familyName"}, u["name"])
	assert.Equal(t, []any{map[string]any{
		"value": "Test_User_fd0ea19b-0777-472c-9f96-4f70d2226f2e@testuser.com", "type": "work", "primary": true,
	}}, u["emails"])
	assert.NotContains(t, u, "roles")

	meta, _ := u["meta"].(map[string]any)
	assert.Equal(t, "User", meta["resourceType"])
	assert.Equal(t, e.url+"/scim/v2/Users/"+id, meta["location"])
	assert.NotEmpty(t, meta["created"])
	assert.NotEmpty(t, meta["lastModified"])

	// Entra ID looks the user up before creating it, and after a 409.
	l := e.do(http.MethodGet, "/scim/v2/Users?"+filterQuery(`userName eq "`+strings.ToUpper(userName)+`"`), "").list(t)
	require.Equal(t, 1, l.TotalResults)
	assert.Equal(t, id, l.Resources[0]["id"])

	l = e.do(http.MethodGet, "/scim/v2/Users?"+filterQuery(`externalId eq "0a21f0f2-8d2a-4f8e-bf98-7363c4aed4ef"`), "").list(t)
	assert.Equal(t, 1, l.TotalResults)

	l = e.do(http.MethodGet, "/scim/v2/Users?"+filterQuery(`externalId eq "0A21F0F2-8D2A-4F8E-BF98-7363C4AED4EF"`), "").list(t)
	assert.Equal(t, 0, l.TotalResults, "externalId is caseExact")
	assert.Empty(t, l.Resources)

	e.do(http.MethodPost, "/scim/v2/Users", fixture(t, "users/entra_create.json")).
		scimError(t, http.StatusConflict, scim.ScimTypeUniqueness)

	res := e.do(http.MethodPatch, "/scim/v2/Users/"+id, fixture(t, "patch/user/entra_disable_legacy.json"))
	require.Equal(t, http.StatusOK, res.status, "body: %s", res.body)
	assert.Equal(t, false, res.object(t)["active"])
	assert.Equal(t, false, e.get("/scim/v2/Users/" + id)["active"])
	assert.True(t, e.user(id).IsSuspended(), "active=false suspends the user")

	res = e.do(http.MethodPatch, "/scim/v2/Users/"+id,
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"Replace","path":"active","value":"True"}]}`)
	require.Equal(t, http.StatusOK, res.status, "body: %s", res.body)
	assert.Equal(t, true, res.object(t)["active"])
	assert.False(t, e.user(id).IsSuspended(), "active=true restores the user")

	res = e.do(http.MethodPatch, "/scim/v2/Users/"+id, fixture(t, "patch/user/entra_update.json"))
	require.Equal(t, http.StatusOK, res.status, "body: %s", res.body)
	u = res.object(t)
	assert.Equal(t, []any{map[string]any{
		"value": "updatedEmail@microsoft.com", "type": "work", "primary": true,
	}}, u["emails"], "the work email is replaced in place")
	assert.Equal(t, "updatedFamilyName", dig(t, u, "name", "familyName"))

	// Unsupported and extension attributes are accepted and ignored.
	res = e.do(http.MethodPatch, "/scim/v2/Users/"+id, fixture(t, "patch/user/entra_add_attr_legacy.json"))
	require.Equal(t, http.StatusOK, res.status, "body: %s", res.body)
	u = res.object(t)
	assert.Equal(t, "Babs Jensen", u["displayName"])
	assert.Equal(t, "e5b0c0d4", u["externalId"])
	assert.NotContains(t, u, "nickName")

	// With aadOptscim062020: path-less, dotted keys, real booleans.
	res = e.do(http.MethodPatch, "/scim/v2/Users/"+id, fixture(t, "patch/user/entra_flag_pathless.json"))
	require.Equal(t, http.StatusOK, res.status, "body: %s", res.body)
	u = res.object(t)
	assert.Equal(t, false, u["active"])
	assert.Equal(t, "Test User", u["displayName"])
	assert.Equal(t, map[string]any{"givenName": "Test", "familyName": "User"}, u["name"])
	assert.Equal(t, "test.user@contoso.com", dig(t, u, "emails", 0, "value"))
	assert.True(t, e.user(id).IsSuspended())

	res = e.do(http.MethodDelete, "/scim/v2/Users/"+id, "")
	require.Equal(t, http.StatusNoContent, res.status, "body: %s", res.body)
	assert.Empty(t, res.body)

	e.do(http.MethodGet, "/scim/v2/Users/"+id, "").scimError(t, http.StatusNotFound, "")
	e.do(http.MethodDelete, "/scim/v2/Users/"+id, "").scimError(t, http.StatusNotFound, "")

	n, err := strconv.ParseUint(id, 10, 64)
	require.NoError(t, err)

	_, err = e.app.state.GetUserByID(types.UserID(n))
	require.Error(t, err, "the user is deleted")
}

// TestSCIMEntraGroupLifecycle replays Entra ID's group provisioning:
// create, look up with excludedAttributes=members, membership changes in
// both dialects, the membership check filter, rename and delete.
func TestSCIMEntraGroupLifecycle(t *testing.T) {
	e := newSCIMEnv(t)

	alice := e.create("Users", `{"userName":"alice@example.com","displayName":"Alice"}`)
	bob := e.create("Users", `{"userName":"bob@example.com"}`)

	gid := e.create("Groups", fixture(t, "groups/entra_create.json"))

	g := e.get("/scim/v2/Groups/" + gid)
	assert.Equal(t, "displayName", g["displayName"])
	assert.Equal(t, "8aa1a0c0-c4c3-4bc0-b4a5-2ef676900159", g["externalId"])
	assert.NotContains(t, g, "members")

	l := e.do(http.MethodGet, "/scim/v2/Groups?"+filterQuery(`displayName eq "DISPLAYNAME"`)+"&excludedAttributes=members", "").list(t)
	require.Equal(t, 1, l.TotalResults)
	assert.Equal(t, gid, l.Resources[0]["id"])

	patch := func(body string) {
		t.Helper()

		res := e.do(http.MethodPatch, "/scim/v2/Groups/"+gid, body)
		require.Equal(t, http.StatusNoContent, res.status, "body: %s", res.body)
		assert.Empty(t, res.body)
	}

	patch(fixture(t, "patch/group/entra_add_members_legacy.json", "f648f8d5ea4e4cd38e9c", alice))
	patch(fixture(t, "patch/group/entra_add_members_legacy.json", "f648f8d5ea4e4cd38e9c", bob))

	g = e.get("/scim/v2/Groups/" + gid)
	assert.Equal(t, []string{alice, bob}, memberValues(t, g))
	assert.Equal(t, map[string]any{
		"value":   alice,
		"display": "Alice",
		"$ref":    e.url + "/scim/v2/Users/" + alice,
		"type":    "User",
	}, dig(t, g, "members", 0))
	assert.Equal(t, "bob@example.com", dig(t, g, "members", 1, "display"),
		"display falls back to the userName")

	// excludedAttributes=members omits them on single reads and lists.
	g = e.get("/scim/v2/Groups/" + gid + "?excludedAttributes=members")
	assert.NotContains(t, g, "members")
	assert.Equal(t, "displayName", g["displayName"])

	l = e.do(http.MethodGet, "/scim/v2/Groups?excludedAttributes=members", "").list(t)
	require.Len(t, l.Resources, 1)
	assert.NotContains(t, l.Resources[0], "members")

	// The user shows the group, read-only.
	u := e.get("/scim/v2/Users/" + alice)
	assert.Equal(t, []any{map[string]any{
		"value": gid, "display": "displayName", "$ref": e.url + "/scim/v2/Groups/" + gid,
	}}, u["groups"])

	// Entra ID checks membership with a filter.
	member := func(uid string) int {
		t.Helper()

		f := `id eq "` + gid + `" and members eq "` + uid + `"`

		return e.do(http.MethodGet, "/scim/v2/Groups?"+filterQuery(f)+"&excludedAttributes=members", "").list(t).TotalResults
	}
	assert.Equal(t, 1, member(alice))

	patch(fixture(t, "patch/group/entra_remove_members_legacy.json", "a71aac5b-f8b0-4c4e-8f2e-5f4c1d1e1b2a", alice))
	assert.Equal(t, 0, member(alice))
	assert.Equal(t, 1, member(bob))

	patch(fixture(t, "patch/group/entra_remove_member_flag.json", "a71aac5b-f8b0-4c4e-8f2e-5f4c1d1e1b2a", bob))
	assert.Equal(t, 0, member(bob))
	assert.NotContains(t, e.get("/scim/v2/Groups/"+gid), "members")

	// Removing a non-member, or something that cannot be a user id, is a no-op.
	patch(fixture(t, "patch/group/entra_remove_members_legacy.json"))

	patch(fixture(t, "patch/group/entra_rename.json"))
	assert.Equal(t, "1879db59-3bdf-4490-ad68-ab880a269474updatedDisplayName", e.get("/scim/v2/Groups/" + gid)["displayName"])

	// Asking for attributes turns the 204 into a 200 with the group.
	res := e.do(http.MethodPatch, "/scim/v2/Groups/"+gid+"?attributes=displayName",
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"Eng"}]}`)
	require.Equal(t, http.StatusOK, res.status, "body: %s", res.body)
	assert.Equal(t, map[string]any{"id": gid, "schemas": []any{scim.SchemaGroup}, "displayName": "Eng"}, res.object(t))

	res = e.do(http.MethodDelete, "/scim/v2/Groups/"+gid, "")
	require.Equal(t, http.StatusNoContent, res.status, "body: %s", res.body)
	e.do(http.MethodGet, "/scim/v2/Groups/"+gid, "").scimError(t, http.StatusNotFound, "")
	assert.NotContains(t, e.get("/scim/v2/Users/"+alice), "groups")
}

// TestSCIMOktaFlows replays Okta: a create carrying a password, the
// random-case userName lookup, a PUT deactivation, and group push.
func TestSCIMOktaFlows(t *testing.T) {
	e := newSCIMEnv(t)

	res := e.do(http.MethodPost, "/scim/v2/Users", fixture(t, "users/okta_create.json"))
	require.Equal(t, http.StatusCreated, res.status, "body: %s", res.body)
	assert.NotContains(t, string(res.body), "1mz050nq", "the password is never echoed")
	id, _ := res.object(t)["id"].(string)

	l := e.do(http.MethodGet, "/scim/v2/Users?"+filterQuery(`userName eq "TeSt.UsEr@OkTa.LoCaL"`)+"&startIndex=1&count=100", "").list(t)
	require.Equal(t, 1, l.TotalResults)
	assert.Equal(t, 1, l.StartIndex)
	assert.Equal(t, 1, l.ItemsPerPage)

	put := fixture(t, "users/okta_put_deactivate.json", "23a35c27-23d3-4c03-b4c5-6443c09e7173", id)
	res = e.do(http.MethodPut, "/scim/v2/Users/"+id, put)
	require.Equal(t, http.StatusOK, res.status, "body: %s", res.body)
	u := res.object(t)
	assert.Equal(t, false, u["active"])
	assert.Equal(t, "Another User", u["displayName"])
	assert.Equal(t, map[string]any{"givenName": "Another", "familyName": "User"}, u["name"])
	assert.NotContains(t, string(res.body), "t1meMa$heen")
	assert.True(t, e.user(id).IsSuspended())

	// A PUT without active keeps the user suspended; it does not reactivate.
	res = e.do(http.MethodPut, "/scim/v2/Users/"+id, `{"userName":"test.user@okta.local","displayName":"No Active"}`)
	require.Equal(t, http.StatusOK, res.status, "body: %s", res.body)
	u = res.object(t)
	assert.Equal(t, false, u["active"])
	assert.NotContains(t, u, "name", "PUT clears what it omits")
	assert.NotContains(t, u, "externalId")
	assert.True(t, e.user(id).IsSuspended())

	res = e.do(http.MethodPut, "/scim/v2/Users/"+id, strings.Replace(put, `"active": false`, `"active": true`, 1))
	require.Equal(t, http.StatusOK, res.status, "body: %s", res.body)
	assert.False(t, e.user(id).IsSuspended())

	res = e.do(http.MethodPatch, "/scim/v2/Users/"+id, fixture(t, "patch/user/okta_oin_deactivate.json"))
	require.Equal(t, http.StatusOK, res.status, "body: %s", res.body)
	assert.True(t, e.user(id).IsSuspended())

	res = e.do(http.MethodPatch, "/scim/v2/Users/"+id,
		fixture(t, "patch/user/okta_oin_profile.json", "23a35c27-23d3-4c03-b4c5-6443c09e7173", id))
	require.Equal(t, http.StatusOK, res.status, "body: %s", res.body)
	assert.Equal(t, "another.user@okta.local", dig(t, res.object(t), "emails", 0, "value"))
	assert.False(t, e.user(id).IsSuspended())

	other := e.create("Users", `{"userName":"test.user2@okta.local","active":true}`)

	gid := e.create("Groups", fixture(t, "groups/okta_create.json"))
	res = e.do(http.MethodPatch, "/scim/v2/Groups/"+gid,
		strings.Replace(fixture(t, "patch/group/okta_rename.json"), `"Test SCIMv2"`, `"Renamed"`, 1))
	require.Equal(t, http.StatusNoContent, res.status, "body: %s", res.body)
	assert.Equal(t, "Renamed", e.get("/scim/v2/Groups/" + gid)["displayName"])

	res = e.do(http.MethodPatch, "/scim/v2/Groups/"+gid,
		fixture(t, "patch/group/okta_add_members.json", "23a35c27-23d3-4c03-b4c5-6443c09e7173", id))
	require.Equal(t, http.StatusNoContent, res.status, "body: %s", res.body)
	assert.Equal(t, []string{id}, memberValues(t, e.get("/scim/v2/Groups/"+gid)))

	res = e.do(http.MethodPatch, "/scim/v2/Groups/"+gid, fixture(t, "patch/group/okta_replace_members.json",
		"23a35c27-23d3-4c03-b4c5-6443c09e7173", id, "89bb1940-b905-4575-9e7f-6f887cfb368e", other))
	require.Equal(t, http.StatusNoContent, res.status, "body: %s", res.body)
	assert.Equal(t, []string{id, other}, memberValues(t, e.get("/scim/v2/Groups/"+gid)))

	res = e.do(http.MethodPatch, "/scim/v2/Groups/"+gid,
		fixture(t, "patch/group/okta_remove_member.json", "89bb1940-b905-4575-9e7f-6f887cfb368e", other))
	require.Equal(t, http.StatusNoContent, res.status, "body: %s", res.body)
	assert.Equal(t, []string{id}, memberValues(t, e.get("/scim/v2/Groups/"+gid)))

	// Group push looks the group up by displayName.
	l = e.do(http.MethodGet, "/scim/v2/Groups?"+filterQuery(`displayName eq "renamed"`), "").list(t)
	require.Equal(t, 1, l.TotalResults)
	assert.Equal(t, []string{id}, memberValues(t, l.Resources[0]))
}

// TestSCIMAuthentikFlows replays Authentik: create, PUT updates, a group
// created with members and a PATCH adding and removing members.
func TestSCIMAuthentikFlows(t *testing.T) {
	e := newSCIMEnv(t)

	first := e.create("Users", fixture(t, "users/authentik_create.json"))
	second := e.create("Users", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"bob","active":true}`)
	third := e.create("Users", `{"userName":"carol","active":true}`)

	put := strings.Replace(fixture(t, "users/authentik_create.json"), `"displayName": "authentik Default Admin"`, `"displayName": "Admin Renamed"`, 1)
	res := e.send(http.MethodPut, "/scim/v2/Users/"+first, put,
		map[string]string{"Authorization": "Bearer " + e.token, "Content-Type": "application/json; charset=utf-8"})
	require.Equal(t, http.StatusOK, res.status, "body: %s", res.body)
	assert.Equal(t, scim.ContentType, res.header.Get("Content-Type"), "responses are always scim+json")
	u := res.object(t)
	assert.Equal(t, "Admin Renamed", u["displayName"])
	assert.Equal(t, "admin@example.com", dig(t, u, "emails", 0, "value"))

	gid := e.create("Groups", fixture(t, "groups/authentik_create.json", `"1"`, `"`+first+`"`, `"2"`, `"`+second+`"`))
	assert.Equal(t, []string{first, second}, memberValues(t, e.get("/scim/v2/Groups/"+gid)))

	res = e.do(http.MethodPatch, "/scim/v2/Groups/"+gid, fixture(t, "patch/group/authentik_members.json",
		`"1"`, `"`+third+`"`, `"2"`, `"`+second+`"`, `"3"`, `"`+first+`"`))
	require.Equal(t, http.StatusNoContent, res.status, "body: %s", res.body)
	assert.Equal(t, []string{second, third}, memberValues(t, e.get("/scim/v2/Groups/"+gid)))

	res = e.do(http.MethodPut, "/scim/v2/Groups/"+gid, `{"displayName":"superadmins","members":[{"value":"`+third+`"}]}`)
	require.Equal(t, http.StatusOK, res.status, "body: %s", res.body)
	g := res.object(t)
	assert.Equal(t, "superadmins", g["displayName"])
	assert.NotContains(t, g, "externalId", "PUT clears an omitted externalId")
	assert.Equal(t, []string{third}, memberValues(t, g))
}

func TestSCIMPagination(t *testing.T) {
	e := newSCIMEnv(t)

	ids := make([]string, 0, 5)
	for i := range 5 {
		ids = append(ids, e.create("Users", `{"userName":"user`+strconv.Itoa(i)+`@example.com",`+
			`"emails":[{"value":"mail`+strconv.Itoa(i)+`@example.com"}]}`))
	}

	resourceIDs := func(l scimList) []string {
		out := make([]string, 0, len(l.Resources))
		for _, r := range l.Resources {
			id, _ := r["id"].(string)
			out = append(out, id)
		}

		return out
	}

	// Paged in the database, and in memory for a filter it cannot index.
	for _, q := range []string{"", "&" + filterQuery(`active eq true`)} {
		l := e.do(http.MethodGet, "/scim/v2/Users?startIndex=2&count=2"+q, "").list(t)
		assert.Equal(t, 5, l.TotalResults, q)
		assert.Equal(t, 2, l.ItemsPerPage, q)
		assert.Equal(t, 2, l.StartIndex, q)
		assert.Equal(t, ids[1:3], resourceIDs(l), q)

		l = e.do(http.MethodGet, "/scim/v2/Users?count=0"+q, "").list(t)
		assert.Equal(t, 5, l.TotalResults, q)
		assert.Equal(t, 0, l.ItemsPerPage, q)
		assert.Empty(t, l.Resources, q)

		l = e.do(http.MethodGet, "/scim/v2/Users?startIndex=10"+q, "").list(t)
		assert.Equal(t, 5, l.TotalResults, q)
		assert.Empty(t, l.Resources, q)

		l = e.do(http.MethodGet, "/scim/v2/Users?startIndex=0&count=5000"+q, "").list(t)
		assert.Equal(t, ids, resourceIDs(l), q)
	}

	l := e.do(http.MethodGet, "/scim/v2/Users?"+filterQuery(`userName sw "user1" or userName ew "3@example.com"`), "").list(t)
	assert.Equal(t, []string{ids[1], ids[3]}, resourceIDs(l))

	l = e.do(http.MethodGet, "/scim/v2/Users?"+filterQuery(`emails.value eq "MAIL4@example.com"`), "").list(t)
	assert.Equal(t, []string{ids[4]}, resourceIDs(l), "emails compare case-insensitively")

	l = e.do(http.MethodGet, "/scim/v2/Users?"+filterQuery(`emails[type eq "work"].value eq "mail2@example.com"`), "").list(t)
	assert.Equal(t, []string{ids[2]}, resourceIDs(l))

	l = e.do(http.MethodGet, "/scim/v2/Users?attributes=userName&count=1", "").list(t)
	assert.Equal(t, []map[string]any{{
		"id": ids[0], "schemas": []any{scim.SchemaUser}, "userName": "user0@example.com",
	}}, l.Resources)
}

func TestSCIMErrors(t *testing.T) {
	e := newSCIMEnv(t)

	uid := e.create("Users", `{"userName":"alice@example.com"}`)
	e.create("Groups", `{"displayName":"Eng"}`)

	for _, f := range []string{`userName eq`, `userName xx "a"`, `(userName eq "a"`} {
		e.do(http.MethodGet, "/scim/v2/Users?"+filterQuery(f), "").scimError(t, http.StatusBadRequest, scim.ScimTypeInvalidFilter)
		e.do(http.MethodGet, "/scim/v2/Groups?"+filterQuery(f), "").scimError(t, http.StatusBadRequest, scim.ScimTypeInvalidFilter)
	}

	e.do(http.MethodGet, "/scim/v2/Users?count=abc", "").scimError(t, http.StatusBadRequest, scim.ScimTypeInvalidValue)

	for _, path := range []string{"/scim/v2/Users/999", "/scim/v2/Users/abc", "/scim/v2/Users/-1", "/scim/v2/Groups/999", "/scim/v2/Groups/x", "/scim/v2/Nope"} {
		e.do(http.MethodGet, path, "").scimError(t, http.StatusNotFound, "")
	}

	e.do(http.MethodPatch, "/scim/v2/Users/999", fixture(t, "patch/user/entra_disable_legacy.json")).
		scimError(t, http.StatusNotFound, "")
	e.do(http.MethodPut, "/scim/v2/Users/999", `{"userName":"x"}`).scimError(t, http.StatusNotFound, "")
	e.do(http.MethodPatch, "/scim/v2/Groups/999", fixture(t, "patch/group/entra_rename.json")).
		scimError(t, http.StatusNotFound, "")
	e.do(http.MethodDelete, "/scim/v2/Groups/999", "").scimError(t, http.StatusNotFound, "")
	res405 := e.do(http.MethodDelete, "/scim/v2/Users", "")
	res405.scimError(t, http.StatusMethodNotAllowed, "")
	assert.ElementsMatch(t, []string{http.MethodGet, http.MethodPost}, res405.header.Values("Allow"))

	res405 = e.do(http.MethodPost, "/scim/v2/Groups/1", "{}")
	res405.scimError(t, http.StatusMethodNotAllowed, "")
	assert.ElementsMatch(t,
		[]string{http.MethodGet, http.MethodPut, http.MethodPatch, http.MethodDelete},
		res405.header.Values("Allow"))

	// An invalid projection fails a write before anything is stored.
	e.do(http.MethodPost, "/scim/v2/Users?attributes=a[b", `{"userName":"projected@example.com"}`).
		scimError(t, http.StatusBadRequest, scim.ScimTypeInvalidValue)

	l0 := e.do(http.MethodGet, "/scim/v2/Users?"+filterQuery(`userName eq "projected@example.com"`), "").list(t)
	assert.Equal(t, 0, l0.TotalResults)

	e.do(http.MethodPost, "/scim/v2/Users", `{"userName":"ALICE@example.com"}`).
		scimError(t, http.StatusConflict, scim.ScimTypeUniqueness)
	e.do(http.MethodPost, "/scim/v2/Groups", `{"displayName":"eng"}`).
		scimError(t, http.StatusConflict, scim.ScimTypeUniqueness)
	e.do(http.MethodPost, "/scim/v2/Groups", `{"displayName":"a@b"}`).
		scimError(t, http.StatusBadRequest, scim.ScimTypeInvalidValue)
	e.do(http.MethodPost, "/scim/v2/Users", `{"displayName":"no userName"}`).
		scimError(t, http.StatusBadRequest, scim.ScimTypeInvalidValue)
	e.do(http.MethodPost, "/scim/v2/Users", `{"userName":`).
		scimError(t, http.StatusBadRequest, scim.ScimTypeInvalidSyntax)
	e.do(http.MethodPost, "/scim/v2/Users", `{"userName":"x","emails":[{"value":"not an email"}]}`).
		scimError(t, http.StatusBadRequest, scim.ScimTypeInvalidValue)

	// Unknown members are a bad value, not a missing resource.
	for _, body := range []string{
		`{"displayName":"ops","members":[{"value":"999"}]}`,
		`{"displayName":"ops","members":[{"value":"not-an-id"}]}`,
	} {
		e.do(http.MethodPost, "/scim/v2/Groups", body).scimError(t, http.StatusBadRequest, scim.ScimTypeInvalidValue)
	}

	l := e.do(http.MethodGet, "/scim/v2/Groups?"+filterQuery(`displayName eq "ops"`), "").list(t)
	assert.Equal(t, 0, l.TotalResults, "a failed create leaves nothing behind")

	gid := e.create("Groups", `{"displayName":"ops","members":[{"value":"`+uid+`"}]}`)
	e.do(http.MethodPatch, "/scim/v2/Groups/"+gid,
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"add","path":"members","value":[{"value":"999"}]}]}`).
		scimError(t, http.StatusBadRequest, scim.ScimTypeInvalidValue)
	e.do(http.MethodPatch, "/scim/v2/Groups/"+gid,
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"remove","path":"displayName"}]}`).
		scimError(t, http.StatusBadRequest, scim.ScimTypeInvalidValue)
	e.do(http.MethodPatch, "/scim/v2/Users/"+uid,
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"id","value":"5"}]}`).
		scimError(t, http.StatusBadRequest, scim.ScimTypeMutability)
	e.do(http.MethodPatch, "/scim/v2/Users/"+uid, `{"Operations":[]}`).
		scimError(t, http.StatusBadRequest, scim.ScimTypeInvalidSyntax)
	assert.Equal(t, []string{uid}, memberValues(t, e.get("/scim/v2/Groups/"+gid)), "a failed PATCH changes nothing")

	// Content types: scim+json and json are accepted, others refused.
	auth := "Bearer " + e.token
	res := e.send(http.MethodPost, "/scim/v2/Users", `{"userName":"x@example.com"}`,
		map[string]string{"Authorization": auth, "Content-Type": "text/plain"})
	res.scimError(t, http.StatusUnsupportedMediaType, "")

	res = e.send(http.MethodPost, "/scim/v2/Users", `{"userName":"x@example.com"}`,
		map[string]string{"Authorization": auth, "Content-Type": "application/json"})
	require.Equal(t, http.StatusCreated, res.status, "body: %s", res.body)

	res = e.send(http.MethodPost, "/scim/v2/Users", `{"userName":"y@example.com"}`,
		map[string]string{"Authorization": auth, "Content-Type": "application/scim+json; charset=utf-8"})
	require.Equal(t, http.StatusCreated, res.status, "body: %s", res.body)

	e.do(http.MethodPost, "/scim/v2/Users", `{"userName":"`+strings.Repeat("a", scim.MaxBodySize)+`"}`).
		scimError(t, http.StatusRequestEntityTooLarge, "")
}

// TestSCIMGroupGrantsPolicy checks the point of SCIM groups: a policy
// referencing group:<name>@<domain> applies to the members the identity
// provider pushes, and stops applying when it removes them.
func TestSCIMGroupGrantsPolicy(t *testing.T) {
	e := newSCIMEnv(t)

	_, err := e.app.state.SetPolicy([]byte(`{
		"tagOwners": {"tag:eng": ["group:engineering@example.com"]},
		"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]
	}`))
	require.NoError(t, err)

	uid := e.create("Users", `{"userName":"dave@example.com","active":true}`)
	user := e.user(uid)

	node := e.app.state.CreateRegisteredNodeForTest(user, "dave-laptop")
	node.User = user
	nodeID := e.app.state.PutNodeInStoreForTest(*node).ID()

	canTag := func() bool {
		t.Helper()

		n, ok := e.app.state.GetNodeByID(nodeID)
		require.True(t, ok)

		return e.app.state.NodeCanHaveTag(n, "tag:eng")
	}

	require.False(t, canTag())

	gid := e.create("Groups", `{"displayName":"Engineering","externalId":"eng-guid"}`)

	assert.False(t, canTag(), "an empty group grants nothing")

	patch := func(op string) {
		t.Helper()

		res := e.do(http.MethodPatch, "/scim/v2/Groups/"+gid,
			`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"`+op+`","path":"members","value":[{"value":"`+uid+`"}]}]}`)
		require.Equal(t, http.StatusNoContent, res.status, "body: %s", res.body)
	}

	patch("add")
	assert.True(t, canTag(), "a member of group:engineering@example.com owns tag:eng")

	patch("remove")
	assert.False(t, canTag(), "removing the member revokes it")

	patch("add")
	require.True(t, canTag())

	res := e.do(http.MethodDelete, "/scim/v2/Groups/"+gid, "")
	require.Equal(t, http.StatusNoContent, res.status)
	assert.False(t, canTag(), "deleting the group revokes it")
}

// TestSCIMLeavesOtherResourcesAlone checks that the endpoint reaches only
// what SCIM manages: a local user, an OIDC user and an OIDC group are "not
// found" to every method and are left as they were, with their nodes, and
// neither user can be made a member of a SCIM group.
func TestSCIMLeavesOtherResourcesAlone(t *testing.T) {
	e := newSCIMEnv(t)

	local := e.app.state.CreateUserForTest("lou")
	oidc, err := e.app.state.DB().CreateUser(types.User{
		Name:               "olga",
		Email:              "olga@example.com",
		ProviderIdentifier: sql.NullString{String: "https://idp.example.com/olga", Valid: true},
		Provider:           util.RegisterMethodOIDC,
	})
	require.NoError(t, err)

	nodes := map[uint]types.NodeID{}

	for _, u := range []*types.User{local, oidc} {
		node := e.app.state.CreateRegisteredNodeForTest(u, u.Name+"-laptop")
		node.User = u
		nodes[u.ID] = e.app.state.PutNodeInStoreForTest(*node).ID()
	}

	_, err = e.app.state.SetUserGroups(types.UserID(oidc.ID), types.GroupSourceOIDC, []string{"ops@" + scimTestDomain})
	require.NoError(t, err)

	var oidcGroup types.Group
	require.NoError(t, e.app.state.DB().DB.Where("name = ?", "ops@"+scimTestDomain).First(&oidcGroup).Error)

	for _, u := range []*types.User{local, oidc} {
		id := strconv.FormatUint(uint64(u.ID), 10)
		path := "/scim/v2/Users/" + id

		e.do(http.MethodGet, path, "").scimError(t, http.StatusNotFound, "")
		e.do(http.MethodPut, path, `{"userName":"taken@example.com","active":false}`).scimError(t, http.StatusNotFound, "")
		e.do(http.MethodPatch, path, fixture(t, "patch/user/entra_disable_legacy.json")).scimError(t, http.StatusNotFound, "")
		e.do(http.MethodDelete, path, "").scimError(t, http.StatusNotFound, "")

		l := e.do(http.MethodGet, "/scim/v2/Users", "").list(t)
		assert.Equal(t, 0, l.TotalResults, "only SCIM users are listed")

		e.do(http.MethodPost, "/scim/v2/Groups", `{"displayName":"with-`+u.Name+`","members":[{"value":"`+id+`"}]}`).
			scimError(t, http.StatusBadRequest, scim.ScimTypeInvalidValue)

		after := e.user(id)
		assert.Equal(t, u.Name, after.Name)
		assert.False(t, after.IsSuspended(), "%s is not suspended", u.Name)
		assert.False(t, after.IsSCIMProvisioned())

		_, ok := e.app.state.GetNodeByID(nodes[u.ID])
		assert.True(t, ok, "%s keeps its node", u.Name)
	}

	sid := e.create("Users", `{"userName":"sam@example.com"}`)
	gid := e.create("Groups", `{"displayName":"eng","members":[{"value":"`+sid+`"}]}`)
	e.do(http.MethodPatch, "/scim/v2/Groups/"+gid,
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[`+
			`{"op":"add","path":"members","value":[{"value":"`+strconv.FormatUint(uint64(oidc.ID), 10)+`"}]}]}`).
		scimError(t, http.StatusBadRequest, scim.ScimTypeInvalidValue)
	assert.Equal(t, []string{sid}, memberValues(t, e.get("/scim/v2/Groups/"+gid)))

	opsPath := "/scim/v2/Groups/" + strconv.FormatUint(uint64(oidcGroup.ID), 10)
	e.do(http.MethodGet, opsPath, "").scimError(t, http.StatusNotFound, "")
	e.do(http.MethodPatch, opsPath, fixture(t, "patch/group/entra_rename.json")).scimError(t, http.StatusNotFound, "")
	e.do(http.MethodDelete, opsPath, "").scimError(t, http.StatusNotFound, "")

	l := e.do(http.MethodGet, "/scim/v2/Groups", "").list(t)
	assert.Equal(t, 1, l.TotalResults, "only SCIM groups are listed")
	assert.Equal(t, []string{"ops@" + scimTestDomain}, e.user(strconv.FormatUint(uint64(oidc.ID), 10)).GroupNames(),
		"the OIDC group and its membership are kept")
}

// TestSCIMBroadcastsChanges checks that writes whose effect nodes can see
// are broadcast: the endpoint is mounted as in production, with a spy in
// place of the batcher.
func TestSCIMBroadcastsChanges(t *testing.T) {
	e := newSCIMEnv(t)

	var (
		mu   sync.Mutex
		sent []change.Change
	)

	spy := func(cs ...change.Change) {
		mu.Lock()
		defer mu.Unlock()

		sent = append(sent, cs...)
	}

	r := chi.NewRouter()
	r.Mount(apiscim.BasePath, apiscim.Handler(apiscim.Backend{State: e.app.state, Change: spy, Cfg: e.app.cfg}))
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)

	e.url = srv.URL
	e.app.cfg.ServerURL = srv.URL

	_, err := e.app.state.SetPolicy([]byte(`{
		"tagOwners": {"tag:eng": ["group:eng@example.com"]},
		"acls": [{"action": "accept", "src": ["group:eng@example.com"], "dst": ["*:*"]}]
	}`))
	require.NoError(t, err)

	broadcasts := func(name string, fn func()) {
		t.Helper()

		mu.Lock()
		sent = nil
		mu.Unlock()

		fn()

		mu.Lock()
		defer mu.Unlock()

		require.NotEmpty(t, sent, "%s must broadcast", name)

		for _, c := range sent {
			assert.False(t, c.IsEmpty(), "%s: only non-empty changes are sent", name)
		}
	}

	var uid, gid string

	broadcasts("create user", func() { uid = e.create("Users", `{"userName":"una@example.com"}`) })

	user := e.user(uid)
	node := e.app.state.CreateRegisteredNodeForTest(user, "una-laptop")
	node.User = user
	nodeID := e.app.state.PutNodeInStoreForTest(*node).ID()

	// A node write hands the NodeStore's nodes to the policy manager, so
	// the group's filter rules have an address to change.
	expiry := time.Now().Add(time.Hour)
	_, _, err = e.app.state.SetNodeExpiry(nodeID, &expiry)
	require.NoError(t, err)

	broadcasts("create group with member", func() {
		gid = e.create("Groups", `{"displayName":"eng","members":[{"value":"`+uid+`"}]}`)
	})
	broadcasts("remove member", func() {
		res := e.do(http.MethodPatch, "/scim/v2/Groups/"+gid,
			`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"remove","path":"members"}]}`)
		require.Equal(t, http.StatusNoContent, res.status, "body: %s", res.body)
	})
	broadcasts("deactivate user", func() {
		res := e.do(http.MethodPatch, "/scim/v2/Users/"+uid, fixture(t, "patch/user/entra_disable_legacy.json"))
		require.Equal(t, http.StatusOK, res.status, "body: %s", res.body)
	})
	broadcasts("delete user", func() {
		res := e.do(http.MethodDelete, "/scim/v2/Users/"+uid, "")
		require.Equal(t, http.StatusNoContent, res.status, "body: %s", res.body)
	})
}
