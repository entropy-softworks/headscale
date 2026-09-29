package hscontrol

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// seedSCIMToken creates a SCIM token and returns its id as the API renders it
// and the plaintext secret.
func seedSCIMToken(t *testing.T, app *Headscale, description string) (string, string) {
	t.Helper()

	secret, tok, err := app.state.CreateSCIMToken(description, nil)
	require.NoError(t, err)

	return strconv.FormatUint(tok.ID, 10), secret
}

func TestAPIV1ScimTokenCreate(t *testing.T) {
	h := newAPIV1Harness(t)

	expiry := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)

	body, err := json.Marshal(map[string]any{"description": "entra", "expiration": expiry})
	require.NoError(t, err)

	res := h.callHuma(http.MethodPost, "/api/v1/scim/token", body)
	require.Equalf(t, http.StatusOK, res.status, "%s", res.body)

	var got struct {
		Token     string         `json:"token"`
		ScimToken map[string]any `json:"scimToken"`
	}
	require.NoError(t, json.Unmarshal(res.body, &got))

	// The plaintext is returned once, here; the listing only has the mask.
	require.True(t, strings.HasPrefix(got.Token, types.SCIMTokenPrefix), got.Token)
	assert.Equal(t, "1", got.ScimToken["id"])
	assert.Equal(t, "entra", got.ScimToken["description"])
	assert.Nil(t, got.ScimToken["revoked"])
	assert.Nil(t, got.ScimToken["lastSeen"])

	prefix, _ := got.ScimToken["prefix"].(string)
	identifier := strings.TrimPrefix(got.Token, types.SCIMTokenPrefix)[:12]
	assert.Equal(t, types.SCIMTokenPrefix+identifier+"-***", prefix)

	expStr, ok := got.ScimToken["expiration"].(string)
	require.True(t, ok, "expiration is set")

	exp, err := time.Parse(time.RFC3339, expStr)
	require.NoError(t, err)
	assert.True(t, expiry.Equal(exp))

	// The created token authenticates for SCIM.
	p, err := h.app.state.AuthenticateSCIM(got.Token)
	require.NoError(t, err)
	assert.Equal(t, types.CredentialSCIMToken, p.Kind)

	list := h.callHuma(http.MethodGet, "/api/v1/scim/token", nil)
	require.Equal(t, http.StatusOK, list.status)
	assert.NotContains(t, string(list.body), got.Token[len(got.Token)-64:], "the secret is never listed")

	t.Run("past expiration is rejected", func(t *testing.T) {
		for _, when := range []time.Time{time.Now().Add(-time.Hour), {}} {
			body, err := json.Marshal(map[string]any{"expiration": when})
			require.NoError(t, err)

			res := h.callHuma(http.MethodPost, "/api/v1/scim/token", body)
			assertStatus(t, res, http.StatusBadRequest)
		}
	})

	t.Run("empty body never expires", func(t *testing.T) {
		res := h.callHuma(http.MethodPost, "/api/v1/scim/token", []byte(`{}`))
		require.Equalf(t, http.StatusOK, res.status, "%s", res.body)

		var got struct {
			ScimToken map[string]any `json:"scimToken"`
		}
		require.NoError(t, json.Unmarshal(res.body, &got))
		assert.Nil(t, got.ScimToken["expiration"])
		assert.Empty(t, got.ScimToken["description"])
	})
}

func TestAPIV1ScimTokenList(t *testing.T) {
	t.Run("empty returns empty array", func(t *testing.T) {
		h := newAPIV1Harness(t)

		res := h.callHuma(http.MethodGet, "/api/v1/scim/token", nil)
		require.Equal(t, http.StatusOK, res.status)
		assert.JSONEq(t, `{"scimTokens":[]}`, string(res.body))
	})

	t.Run("empty parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		h.assertParity(t, http.MethodGet, "/api/v1/scim/token", nil)
	})

	t.Run("populated parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		seedSCIMToken(t, h.app, "okta")
		id, _ := seedSCIMToken(t, h.app, "entra")

		n, err := strconv.ParseUint(id, 10, 64)
		require.NoError(t, err)
		require.NoError(t, h.app.state.RevokeSCIMToken(n))

		// Other credential kinds are not listed.
		_, _, err = h.app.state.CreateAPIKey(nil)
		require.NoError(t, err)

		res := h.assertParity(t, http.MethodGet, "/api/v1/scim/token", nil)

		var got struct {
			ScimTokens []map[string]any `json:"scimTokens"`
		}
		require.NoError(t, json.Unmarshal(res.body, &got))
		require.Len(t, got.ScimTokens, 2)
		assert.Nil(t, got.ScimTokens[0]["revoked"])
		assert.NotNil(t, got.ScimTokens[1]["revoked"])
	})
}

func TestAPIV1ScimTokenRevoke(t *testing.T) {
	t.Run("parity", func(t *testing.T) {
		res := assertParityIsolated(t, func(t *testing.T, app *Headscale) {
			t.Helper()
			seedSCIMToken(t, app, "")
		}, http.MethodPost, "/api/v1/scim/token/1/revoke", nil)
		assertStatus(t, res, http.StatusOK)
	})

	t.Run("revoked token stops authenticating", func(t *testing.T) {
		h := newAPIV1Harness(t)
		id, secret := seedSCIMToken(t, h.app, "")

		res := h.callHuma(http.MethodPost, "/api/v1/scim/token/"+id+"/revoke", nil)
		assertStatus(t, res, http.StatusOK)

		_, err := h.app.state.AuthenticateSCIM(secret)
		require.ErrorIs(t, err, state.ErrSCIMUnauthenticated)
	})

	t.Run("not found parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		res := h.assertParity(t, http.MethodPost, "/api/v1/scim/token/999/revoke", nil)
		assertStatus(t, res, http.StatusNotFound)
	})

	t.Run("api key id is not a scim token parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		id, _ := seedAPIKey(t, h.app)
		res := h.assertParity(t, http.MethodPost,
			"/api/v1/scim/token/"+strconv.FormatUint(id, 10)+"/revoke", nil)
		assertStatus(t, res, http.StatusNotFound)
	})

	t.Run("invalid id parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		res := h.assertParity(t, http.MethodPost, "/api/v1/scim/token/abc/revoke", nil)
		assertStatus(t, res, http.StatusBadRequest)
	})
}

func TestAPIV1ScimTokenDelete(t *testing.T) {
	t.Run("parity", func(t *testing.T) {
		res := assertParityIsolated(t, func(t *testing.T, app *Headscale) {
			t.Helper()
			seedSCIMToken(t, app, "")
		}, http.MethodDelete, "/api/v1/scim/token/1", nil)
		assertStatus(t, res, http.StatusOK)
	})

	t.Run("deleted token is gone", func(t *testing.T) {
		h := newAPIV1Harness(t)
		id, secret := seedSCIMToken(t, h.app, "")

		res := h.callHuma(http.MethodDelete, "/api/v1/scim/token/"+id, nil)
		assertStatus(t, res, http.StatusOK)

		_, err := h.app.state.AuthenticateSCIM(secret)
		require.ErrorIs(t, err, state.ErrSCIMUnauthenticated)

		list := h.callHuma(http.MethodGet, "/api/v1/scim/token", nil)
		assert.JSONEq(t, `{"scimTokens":[]}`, string(list.body))

		again := h.callHuma(http.MethodDelete, "/api/v1/scim/token/"+id, nil)
		assertStatus(t, again, http.StatusNotFound)
	})

	t.Run("not found parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		res := h.assertParity(t, http.MethodDelete, "/api/v1/scim/token/999", nil)
		assertStatus(t, res, http.StatusNotFound)
	})

	t.Run("invalid id parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		res := h.assertParity(t, http.MethodDelete, "/api/v1/scim/token/abc", nil)
		assertStatus(t, res, http.StatusBadRequest)
	})
}
