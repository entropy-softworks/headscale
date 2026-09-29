package hscontrol

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAPIV1AuthMiddleware proves the v1 API, mounted on the real router, is
// guarded by the Huma security middleware: missing or bad Bearer tokens are
// rejected with 401 before reaching a handler; a valid key passes to 200. The
// per-endpoint harness bypasses auth via WithLocalTrust, so this is the one
// place the middleware itself is exercised.
func TestAPIV1AuthMiddleware(t *testing.T) {
	app := createTestApp(t)
	handler := app.HTTPHandler()

	expiry := time.Now().Add(time.Hour)
	valid, _, err := app.state.CreateAPIKey(&expiry)
	require.NoError(t, err)

	scimToken, _, err := app.state.CreateSCIMToken("idp", nil)
	require.NoError(t, err)

	tests := []struct {
		name       string
		authHeader string
		wantStatus int
	}{
		{name: "missing bearer", authHeader: "", wantStatus: http.StatusUnauthorized},
		{name: "no bearer prefix", authHeader: "tskey-invalid", wantStatus: http.StatusUnauthorized},
		{name: "invalid bearer token", authHeader: "Bearer tskey-invalid", wantStatus: http.StatusUnauthorized},
		{name: "valid api key", authHeader: "Bearer " + valid, wantStatus: http.StatusOK},
		{name: "scim token is not an api key", authHeader: "Bearer " + scimToken, wantStatus: http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(
				context.Background(), http.MethodGet, "/api/v1/node", nil,
			)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			assert.Equalf(t, tt.wantStatus, rec.Code, "body: %s", rec.Body.String())
		})
	}
}

// TestAPIV1DocsArePublic proves the OpenAPI document and docs UI live under
// /api/v1 and are reachable without an API key, while the operations beside them
// stay key-gated. The docs page points at the versioned spec so a future
// /api/v2 can carry its own.
func TestAPIV1DocsArePublic(t *testing.T) {
	app := createTestApp(t)
	handler := app.HTTPHandler()

	tests := []struct {
		path     string
		contains string
	}{
		{path: "/api/v1/openapi.yaml", contains: "openapi:"},
		{path: "/api/v1/docs", contains: "/api/v1/openapi.yaml"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			// No Authorization header: these must be public.
			req := httptest.NewRequestWithContext(
				context.Background(), http.MethodGet, tt.path, nil,
			)

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			require.Equalf(t, http.StatusOK, rec.Code, "%s should be public; body: %s", tt.path, rec.Body.String())
			assert.Containsf(t, rec.Body.String(), tt.contains, "%s body", tt.path)
		})
	}
}

// TestAPIV1Unauthorized401 pins the 401 body: RFC 7807 JSON containing
// "Unauthorized", under 100 bytes and leaking no data, as the integration
// auth-bypass tests require.
func TestAPIV1Unauthorized401(t *testing.T) {
	app := createTestApp(t)
	handler := app.HTTPHandler()

	req := httptest.NewRequestWithContext(
		context.Background(), http.MethodGet, "/api/v1/node", nil,
	)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusUnauthorized, rec.Code)

	body := rec.Body.Bytes()
	assert.Contains(t, string(body), "Unauthorized")
	assert.Lessf(t, len(body), 100, "401 body must stay small (no data leak): %s", body)

	var problem map[string]any
	require.NoError(t, json.Unmarshal(body, &problem), "401 body must be JSON: %s", body)
	assert.NotContains(t, problem, "users")
}

// TestAPIV1ScimTokenRoutesRequireAuth proves every SCIM token route, mounted on
// the real router, rejects a request without an API key before it reaches the
// handler, and that a SCIM token does not stand in for one.
func TestAPIV1ScimTokenRoutesRequireAuth(t *testing.T) {
	app := createTestApp(t)
	handler := app.HTTPHandler()

	scimToken, tok, err := app.state.CreateSCIMToken("idp", nil)
	require.NoError(t, err)

	id := strconv.FormatUint(tok.ID, 10)

	routes := []struct {
		method, path string
	}{
		{http.MethodPost, "/api/v1/scim/token"},
		{http.MethodGet, "/api/v1/scim/token"},
		{http.MethodPost, "/api/v1/scim/token/" + id + "/revoke"},
		{http.MethodDelete, "/api/v1/scim/token/" + id},
	}

	for _, route := range routes {
		for name, header := range map[string]string{
			"no credentials": "",
			"scim token":     "Bearer " + scimToken,
		} {
			t.Run(route.method+" "+route.path+" "+name, func(t *testing.T) {
				req := httptest.NewRequestWithContext(
					context.Background(), route.method, route.path, strings.NewReader(`{}`),
				)
				req.Header.Set("Content-Type", "application/json")

				if header != "" {
					req.Header.Set("Authorization", header)
				}

				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)

				assert.Equalf(t, http.StatusUnauthorized, rec.Code, "body: %s", rec.Body.String())
			})
		}
	}

	// Nothing was revoked or deleted.
	got, err := app.state.GetSCIMTokenByID(tok.ID)
	require.NoError(t, err)
	assert.Nil(t, got.Revoked)
}
