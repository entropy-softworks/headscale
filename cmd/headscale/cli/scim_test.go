package cli

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	clientv1 "github.com/juanfont/headscale/gen/client/v1"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSCIMTokenCommandsRegistered(t *testing.T) {
	for _, path := range [][]string{
		{"scim", "tokens", "create"},
		{"scim", "tokens", "list"},
		{"scim", "tokens", "revoke"},
		{"scim", "tokens", "delete"},
	} {
		cmd, _, err := rootCmd.Find(path)
		require.NoError(t, err, path)
		assert.Equal(t, path[len(path)-1], cmd.Name())
	}
}

func TestSCIMTokenExpiration(t *testing.T) {
	newCmd := func(t *testing.T, value string) *cobra.Command {
		t.Helper()

		cmd := &cobra.Command{}
		cmd.Flags().String("expiration", DefaultSCIMTokenExpiry, "")

		if value != "" {
			require.NoError(t, cmd.Flags().Set("expiration", value))
		}

		return cmd
	}

	for _, v := range []string{scimTokenNoExpiry, "Never", "NEVER"} {
		never, err := scimTokenExpiration(newCmd(t, v))
		require.NoError(t, err, v)
		assert.Nil(t, never, v)
	}

	def, err := scimTokenExpiration(newCmd(t, ""))
	require.NoError(t, err)
	require.NotNil(t, def)
	assert.WithinDuration(t, time.Now().Add(90*24*time.Hour), *def, time.Minute)

	day, err := scimTokenExpiration(newCmd(t, "1d"))
	require.NoError(t, err)
	require.NotNil(t, day)
	assert.WithinDuration(t, time.Now().Add(24*time.Hour), *day, time.Minute)

	_, err = scimTokenExpiration(newCmd(t, "soon"))
	require.Error(t, err)

	for _, v := range []string{"0", "0s", "-1h"} {
		_, err = scimTokenExpiration(newCmd(t, v))
		require.Error(t, err, v)
	}
}

func TestSCIMTokenIDArg(t *testing.T) {
	id, err := scimTokenIDArg([]string{"42"})
	require.NoError(t, err)
	assert.Equal(t, "42", id)

	for _, bad := range []string{"", "abc", "-1", "../1"} {
		_, err := scimTokenIDArg([]string{bad})
		require.ErrorIs(t, err, errMissingParameter, bad)
	}
}

func TestSCIMAdminCommandsRegistered(t *testing.T) {
	for _, path := range [][]string{
		{"scim", "users", "list"},
		{"scim", "groups", "list"},
		{"scim", "groups", "release"},
	} {
		cmd, _, err := rootCmd.Find(path)
		require.NoError(t, err, path)
		assert.Equal(t, path[len(path)-1], cmd.Name())
	}
}

// scimAdminServer serves canned SCIM admin responses and records the
// requests it receives.
func scimAdminServer(t *testing.T, requests *[]string) *clientv1.ClientWithResponses {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*requests = append(*requests, r.Method+" "+r.URL.Path)

		w.Header().Set("Content-Type", "application/json")

		switch r.Method + " " + r.URL.Path {
		case "GET /api/v1/scim/user":
			_, _ = w.Write([]byte(`{"scimUsers":[{"id":"1","userName":"alice@example.com","linked":true}]}`))
		case "GET /api/v1/scim/group":
			_, _ = w.Write([]byte(`{"scimGroups":[{"id":"2","name":"eng@example.com","memberCount":3}]}`))
		case "POST /api/v1/scim/group/2/release":
			_, _ = w.Write([]byte(`{}`))
		default:
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"status":404,"title":"Not Found","detail":"releasing scim group"}`))
		}
	}))
	t.Cleanup(srv.Close)

	client, err := clientv1.NewClientWithResponses(srv.URL)
	require.NoError(t, err)

	return client
}

func scimAdminCmd(t *testing.T) *cobra.Command {
	t.Helper()

	cmd := &cobra.Command{}
	cmd.Flags().String("output", "json", "")
	cmd.Flags().Bool("force", true, "")

	return cmd
}

func TestSCIMAdminCommands(t *testing.T) {
	var requests []string

	client := scimAdminServer(t, &requests)
	ctx := t.Context()

	require.NoError(t, listSCIMUsers(ctx, client, scimAdminCmd(t), nil))
	require.NoError(t, listSCIMGroups(ctx, client, scimAdminCmd(t), nil))
	require.NoError(t, releaseSCIMGroup(ctx, client, scimAdminCmd(t), []string{"2"}))

	err := releaseSCIMGroup(ctx, client, scimAdminCmd(t), []string{"9"})
	require.ErrorContains(t, err, "releasing scim group", "the API's error is reported")

	err = releaseSCIMGroup(ctx, client, scimAdminCmd(t), []string{"abc"})
	require.ErrorIs(t, err, errMissingParameter, "an invalid id is rejected before any request")

	assert.Equal(t, []string{
		"GET /api/v1/scim/user",
		"GET /api/v1/scim/group",
		"POST /api/v1/scim/group/2/release",
		"POST /api/v1/scim/group/9/release",
	}, requests)
}

func TestSCIMTableCells(t *testing.T) {
	assert.Equal(t, "yes", yesNo(true))
	assert.Equal(t, "no", yesNo(false))
	assert.Contains(t, activeOrSuspended(true), "suspended")
	assert.Contains(t, activeOrSuspended(false), "active")
}
