package state

import (
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newSCIMTestState(t *testing.T) *State {
	t.Helper()

	s, err := NewState(persistTestConfig(t.TempDir() + "/headscale.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	return s
}

// mintTestAccessToken creates an OAuth client with scopes and returns a token
// minted for it with the same scopes.
func mintTestAccessToken(t *testing.T, s *State, scopes []string, expiration time.Time) string {
	t.Helper()

	_, client, err := s.CreateOAuthClient(scopes, []string{"tag:ci"}, "scim test", nil)
	require.NoError(t, err)

	tok, _, err := s.MintAccessToken(client.ClientID, scopes, nil, &expiration)
	require.NoError(t, err)

	return tok
}

func TestAuthenticateSCIM(t *testing.T) {
	s := newSCIMTestState(t)

	hour := time.Now().Add(time.Hour)

	scimSecret, scimTok, err := s.CreateSCIMToken("entra", nil)
	require.NoError(t, err)

	revokedSecret, revokedTok, err := s.CreateSCIMToken("revoked", nil)
	require.NoError(t, err)
	require.NoError(t, s.RevokeSCIMToken(revokedTok.ID))

	past := time.Now().Add(-time.Minute)
	expiredSecret, _, err := s.CreateSCIMToken("expired", &past)
	require.NoError(t, err)

	deletedSecret, deletedTok, err := s.CreateSCIMToken("deleted", nil)
	require.NoError(t, err)
	require.NoError(t, s.DeleteSCIMToken(deletedTok.ID))

	apiKey, _, err := s.CreateAPIKey(nil)
	require.NoError(t, err)

	pak, err := s.CreatePreAuthKey(nil, false, false, nil, []string{"tag:ci"})
	require.NoError(t, err)

	clientSecret, _, err := s.CreateOAuthClient([]string{"scim"}, nil, "client", nil)
	require.NoError(t, err)

	scimAccess := mintTestAccessToken(t, s, []string{"scim"}, hour)
	mixedAccess := mintTestAccessToken(t, s, []string{"users", "scim"}, hour)
	allAccess := mintTestAccessToken(t, s, []string{"all"}, hour)
	usersAccess := mintTestAccessToken(t, s, []string{"users"}, hour)
	expiredAccess := mintTestAccessToken(t, s, []string{"scim"}, past)

	t.Run("scim token", func(t *testing.T) {
		p, err := s.AuthenticateSCIM(scimSecret)
		require.NoError(t, err)
		assert.Equal(t, types.SCIMPrincipal{
			Kind:         types.CredentialSCIMToken,
			CredentialID: scimTok.ID,
			Identifier:   scimTok.Prefix,
		}, p)

		got, err := s.GetSCIMTokenByID(scimTok.ID)
		require.NoError(t, err)
		assert.NotNil(t, got.LastSeen, "authentication records last use")
	})

	for name, tok := range map[string]string{"scim only": scimAccess, "scim among others": mixedAccess} {
		t.Run("oauth token "+name, func(t *testing.T) {
			p, err := s.AuthenticateSCIM(tok)
			require.NoError(t, err)
			assert.Equal(t, types.CredentialOAuthToken, p.Kind)
			assert.NotZero(t, p.CredentialID)
			assert.NotEmpty(t, p.ClientID)
		})
	}

	forbidden := map[string]string{
		"oauth token with all":     allAccess,
		"oauth token without scim": usersAccess,
	}
	for name, tok := range forbidden {
		t.Run(name, func(t *testing.T) {
			_, err := s.AuthenticateSCIM(tok)
			require.ErrorIs(t, err, ErrSCIMForbidden)
			require.NotErrorIs(t, err, ErrSCIMUnauthenticated)
		})
	}

	unauthenticated := map[string]string{
		"empty":                  "",
		"garbage":                "not-a-token",
		"revoked scim token":     revokedSecret,
		"expired scim token":     expiredSecret,
		"deleted scim token":     deletedSecret,
		"wrong secret":           scimSecret[:len(scimSecret)-4] + "zzzz",
		"admin api key":          apiKey,
		"pre-auth key":           pak.Key,
		"oauth client secret":    clientSecret,
		"expired oauth token":    expiredAccess,
		"bearer header verbatim": "Bearer " + scimSecret,
	}
	for name, tok := range unauthenticated {
		t.Run(name, func(t *testing.T) {
			_, err := s.AuthenticateSCIM(tok)
			require.ErrorIs(t, err, ErrSCIMUnauthenticated)
			require.NotErrorIs(t, err, ErrSCIMForbidden)
		})
	}

	// The wrapped cause is kept for logs.
	_, err = s.AuthenticateSCIM(revokedSecret)
	require.ErrorIs(t, err, db.ErrSCIMTokenRevoked)
}
