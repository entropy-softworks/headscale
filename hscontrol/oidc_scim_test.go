package hscontrol

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"testing"

	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/oauth2-proxy/mockoidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newOIDCSCIMBrowser is [newOIDCGroupsBrowser] with SCIM provisioning
// enabled as scim adjusts it (link_by defaults to email). Emails must be
// verified.
func newOIDCSCIMBrowser(t *testing.T, scim func(*types.SCIMConfig)) *oidcBrowser {
	t.Helper()

	b := newOIDCBrowserWith(t, "", func(cfg *types.OIDCConfig) {
		cfg.Scope = append(cfg.Scope, "groups")
		cfg.EmailVerifiedRequired = true
		cfg.Groups = types.OIDCGroupsConfig{Enabled: true, Claim: "groups", Domain: "example.com"}
	})

	b.app.cfg.SCIM = types.SCIMConfig{
		Enabled:      true,
		GroupsDomain: "example.com",
		LinkBy:       types.SCIMLinkByEmail,
	}
	if scim != nil {
		scim(&b.app.cfg.SCIM)
	}

	return b
}

// provision creates a SCIM user as the identity provider would.
func (b *oidcBrowser) provision(t *testing.T, attrs types.SCIMUserAttributes) *types.User {
	t.Helper()

	user, c, err := b.app.state.CreateSCIMUser(attrs, true)
	require.NoError(t, err)
	b.app.Change(c)

	return user
}

// loginStatus runs a login as user for a new pending node and returns the
// response status, for logins expected to be refused.
func (b *oidcBrowser) loginStatus(t *testing.T, user *mockoidc.MockUser) int {
	t.Helper()

	b.idp.QueueUser(user)

	_, registerURL := b.pendingNode(t)
	status, _, _ := b.get(t, registerURL)

	return status
}

// groupsUserIdentifier is the provider identifier of [groupsUser]'s login.
func (b *oidcBrowser) groupsUserIdentifier() string {
	return (&types.OIDCClaims{Iss: b.idp.Issuer(), Sub: "groups-user"}).Identifier()
}

func (b *oidcBrowser) userCount(t *testing.T) int {
	t.Helper()

	users, err := b.app.state.ListAllUsers()
	require.NoError(t, err)

	return len(users)
}

// TestOIDCLoginLinksSCIMUserByEmail provisions a user and a group through
// SCIM before the user ever logs in, and checks that their first login
// links to the provisioned user instead of creating another: the SCIM
// group applies, the login owns the name and email from then on, and later
// SCIM updates change only the SCIM attributes.
func TestOIDCLoginLinksSCIMUserByEmail(t *testing.T) {
	b := newOIDCSCIMBrowser(t, nil)
	s := b.app.state

	provisioned := b.provision(t, types.SCIMUserAttributes{
		UserName:    "Jane@Example.com",
		DisplayName: "Jane from SCIM",
		Active:      true,
	})

	_, c, err := s.CreateSCIMGroup("example.com", "Eng", "", []types.UserID{types.UserID(provisioned.ID)})
	require.NoError(t, err)
	b.app.Change(c)

	_, err = s.SetPolicy([]byte(`{
		"tagOwners": {"tag:eng": ["group:eng@example.com"]},
		"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]
	}`))
	require.NoError(t, err)

	// The groups claim asserts "eng" too: SCIM owns that group, so the
	// login grants no membership of its own, and asserts another group,
	// which it does grant.
	page, body := b.loginAs(t, groupsUser("eng", "ops"))
	b.confirm(t, page, body)

	require.Equal(t, 1, b.userCount(t), "the login must link, not create a user")

	user, err := s.GetUserByID(types.UserID(provisioned.ID))
	require.NoError(t, err)
	assert.Equal(t, b.groupsUserIdentifier(), user.ProviderIdentifier.String, "the user is linked to the login")
	assert.Equal(t, util.RegisterMethodOIDC, user.Provider)
	assert.True(t, user.IsSCIMProvisioned(), "a linked user stays SCIM-managed")
	assert.Equal(t, "jane", user.Name, "the login owns the name")
	assert.Equal(t, groupsUserEmail, user.Email)
	assert.Equal(t, "Jane from SCIM", user.DisplayName, "a display name the login does not send is kept")
	assert.Equal(t, []string{"eng@example.com", "ops@example.com"}, user.GroupNames())

	var node types.NodeView

	for _, n := range s.ListNodes().All() {
		if n.User().ID() == provisioned.ID {
			node = n
		}
	}

	require.True(t, node.Valid(), "the node registers to the provisioned user")
	assert.True(t, s.NodeCanHaveTag(node, "tag:eng"), "the SCIM group applies to the linked user's node")

	// SCIM keeps managing its own attributes only.
	_, _, err = s.ReplaceSCIMUser(types.UserID(user.ID), types.SCIMUserAttributes{
		UserName:    "jane@example.com",
		DisplayName: "Renamed in the directory",
		Active:      true,
	})
	require.NoError(t, err)

	user, err = s.GetUserByID(types.UserID(provisioned.ID))
	require.NoError(t, err)
	assert.Equal(t, "jane", user.Name, "SCIM does not overwrite a linked user's name")
	assert.Equal(t, "Renamed in the directory", user.SCIMDisplayName)
	assert.Equal(t, "Jane from SCIM", user.DisplayName, "SCIM does not overwrite a linked user's display name")

	// A second login finds the linked user by its identifier.
	b.loginAs(t, groupsUser("ops"))
	assert.Equal(t, 1, b.userCount(t))
}

// TestOIDCLoginLinksSCIMUserBySCIMEmail covers a userName that is not the
// login's email (an Entra UPN, or a bare login name): the SCIM email
// matches instead.
func TestOIDCLoginLinksSCIMUserBySCIMEmail(t *testing.T) {
	b := newOIDCSCIMBrowser(t, nil)

	provisioned := b.provision(t, types.SCIMUserAttributes{UserName: "jdoe", Email: groupsUserEmail, Active: true})

	b.loginAs(t, groupsUser())

	require.Equal(t, 1, b.userCount(t))

	user, err := b.app.state.GetUserByID(types.UserID(provisioned.ID))
	require.NoError(t, err)
	assert.Equal(t, b.groupsUserIdentifier(), user.ProviderIdentifier.String)
}

// TestOIDCLoginDoesNotLinkUnverifiedEmail checks that an email the provider
// has not verified never claims a provisioned user, even with
// email_verified_required off (which only lets such an email be stored):
// anyone able to set an unverified email at the provider could otherwise
// take the account.
func TestOIDCLoginDoesNotLinkUnverifiedEmail(t *testing.T) {
	for _, required := range []bool{true, false} {
		t.Run("email_verified_required="+strconv.FormatBool(required), func(t *testing.T) {
			b := newOIDCSCIMBrowser(t, nil)
			b.oidcProvider(t).cfg.EmailVerifiedRequired = required

			provisioned := b.provision(t, types.SCIMUserAttributes{UserName: groupsUserEmail, Active: true})

			unverified := groupsUser()
			unverified.EmailVerified = false

			b.loginAs(t, unverified)

			assert.Equal(t, 2, b.userCount(t), "the unverified login gets a user of its own")

			user, err := b.app.state.GetUserByID(types.UserID(provisioned.ID))
			require.NoError(t, err)
			assert.False(t, user.ProviderIdentifier.Valid, "the provisioned user stays unlinked")

			// With provisioning required, the unverified login is refused outright.
			b.app.cfg.SCIM.RequireProvisioning = true
			unverified.Subject = "another-unverified-user"

			assert.Equal(t, http.StatusForbidden, b.loginStatus(t, unverified))
			assert.Equal(t, 2, b.userCount(t))
		})
	}
}

func (b *oidcBrowser) oidcProvider(t *testing.T) *AuthProviderOIDC {
	t.Helper()

	p, ok := b.app.authProvider.(*AuthProviderOIDC)
	require.True(t, ok)

	return p
}

// newSCIMLinkTestProvider returns an OIDC provider, outside any login flow,
// for an app with SCIM enabled as scim sets it, so tests can call the
// matching functions with claims the mock provider cannot emit.
func newSCIMLinkTestProvider(t *testing.T, scim types.SCIMConfig) (*Headscale, *AuthProviderOIDC) {
	t.Helper()

	app := createTestApp(t)
	scim.Enabled = true
	app.cfg.SCIM = scim

	return app, &AuthProviderOIDC{h: app, cfg: &types.OIDCConfig{EmailVerifiedRequired: true}}
}

func mustProvision(t *testing.T, app *Headscale, attrs types.SCIMUserAttributes) *types.User {
	t.Helper()

	attrs.Active = true

	u, _, err := app.state.CreateSCIMUser(attrs, true)
	require.NoError(t, err)

	return u
}

// findForLogin runs the email matching of a login with claims, returning
// the matched user or nil.
func findForLogin(t *testing.T, a *AuthProviderOIDC, claims *types.OIDCClaims) *types.User {
	t.Helper()

	u, err := a.findSCIMUserForLogin(claims, nil, nil)
	if err != nil {
		require.ErrorIs(t, err, db.ErrUserNotFound)
	}

	return u
}

// mergeUserInfo applies userinfo's email to claims as OIDCCallback does.
func mergeUserInfo(claims *types.OIDCClaims, info *types.OIDCUserInfo) {
	claims.Email, claims.EmailVerified = mergeEmailClaims(claims, info)
}

// TestSCIMLinkEmailFromUserinfo covers an ID token vouching for one email
// and userinfo sending another without email_verified: the userinfo email
// replaces the ID token's but the ID token's flag does not vouch for it, so
// it links nothing, and is stored only with email_verified_required off.
func TestSCIMLinkEmailFromUserinfo(t *testing.T) {
	app, a := newSCIMLinkTestProvider(t, types.SCIMConfig{LinkBy: types.SCIMLinkByEmail})

	mustProvision(t, app, types.SCIMUserAttributes{UserName: "a@example.com"})
	mustProvision(t, app, types.SCIMUserAttributes{UserName: "b@example.com"})

	claims := &types.OIDCClaims{Iss: "https://idp.example.com", Sub: "s", Email: "a@example.com", EmailVerified: true}
	mergeUserInfo(claims, &types.OIDCUserInfo{Sub: "s", Email: "b@example.com"})

	assert.Equal(t, "b@example.com", claims.Email)
	assert.Nil(t, findForLogin(t, a, claims), "an unverified userinfo email links nothing")

	var u types.User

	u.FromClaim(claims, true)
	assert.Empty(t, u.Email, "nor is it stored when verification is required")

	u.FromClaim(claims, false)
	assert.Equal(t, "b@example.com", u.Email)

	// Userinfo without an email keeps the ID token's verified pair.
	claims = &types.OIDCClaims{Iss: "https://idp.example.com", Sub: "s", Email: "a@example.com", EmailVerified: true}
	mergeUserInfo(claims, &types.OIDCUserInfo{Sub: "s", Name: "A"})

	got := findForLogin(t, a, claims)
	require.NotNil(t, got)
	assert.Equal(t, "a@example.com", got.SCIMUserName.String)
}

// TestSCIMLinkEmailLookalikes checks that emails compare with ASCII case
// folding only: the database's Unicode-aware lowercasing maps the Kelvin
// sign and the dotted capital I to ASCII letters, which must not let a
// lookalike address claim the ASCII account, or the reverse.
func TestSCIMLinkEmailLookalikes(t *testing.T) {
	app, a := newSCIMLinkTestProvider(t, types.SCIMConfig{LinkBy: types.SCIMLinkByEmail})

	mustProvision(t, app, types.SCIMUserAttributes{UserName: "kate@example.com"})
	mustProvision(t, app, types.SCIMUserAttributes{UserName: "İvy@example.com"})
	mustProvision(t, app, types.SCIMUserAttributes{UserName: "zed", Email: "zed@example.com"})

	login := func(email string) *types.User {
		return findForLogin(t, a, &types.OIDCClaims{
			Iss: "https://idp.example.com", Sub: "s", Email: email, EmailVerified: true,
		})
	}

	assert.Nil(t, login("Kate@example.com"), "a Kelvin sign does not match k")
	assert.Nil(t, login("ivy@example.com"), "i does not match a provisioned dotted capital I")
	assert.Nil(t, login("Ked@example.com"), "nor through the SCIM email")

	got := login("KATE@example.com")
	require.NotNil(t, got, "ASCII case still folds")
	assert.Equal(t, "kate@example.com", got.SCIMUserName.String)

	got = login("Zed@Example.com")
	require.NotNil(t, got)
	assert.Equal(t, "zed", got.SCIMUserName.String)
}

// TestSCIMLinkAmbiguousEmail checks the guard against two unlinked SCIM
// users with the same SCIM email, which SCIM writes never produce but a
// database edited by hand can hold: neither is linked.
func TestSCIMLinkAmbiguousEmail(t *testing.T) {
	app, a := newSCIMLinkTestProvider(t, types.SCIMConfig{LinkBy: types.SCIMLinkByEmail})

	one := mustProvision(t, app, types.SCIMUserAttributes{UserName: "one", Email: "one@example.com"})
	two := mustProvision(t, app, types.SCIMUserAttributes{UserName: "two", Email: "two@example.com"})

	require.NoError(t, app.state.DB().DB.Exec(
		"UPDATE users SET scim_email = ? WHERE id IN (?, ?)", "shared@example.com", one.ID, two.ID).Error)

	claims := &types.OIDCClaims{Iss: "https://idp.example.com", Sub: "s", Email: "shared@example.com", EmailVerified: true}
	assert.Nil(t, findForLogin(t, a, claims), "an ambiguous SCIM email links no one")

	require.NoError(t, app.state.DB().DB.Exec(
		"UPDATE users SET scim_email = ? WHERE id = ?", "two@example.com", two.ID).Error)

	got := findForLogin(t, a, claims)
	require.NotNil(t, got, "the guard only refuses ambiguity")
	assert.Equal(t, one.ID, got.ID)
}

// TestOIDCLoginLinksSCIMUserByExternalID links by the sub claim, which the
// mock provider emits, compared with the SCIM externalId; the email plays
// no part.
func TestOIDCLoginLinksSCIMUserByExternalID(t *testing.T) {
	b := newOIDCSCIMBrowser(t, func(c *types.SCIMConfig) {
		c.LinkBy = types.SCIMLinkByExternalID
		c.LinkClaim = "sub"
	})

	// Same email as the login, but the wrong externalId: not linked.
	decoy := b.provision(t, types.SCIMUserAttributes{UserName: groupsUserEmail, ExternalID: "someone-else", Active: true})
	provisioned := b.provision(t, types.SCIMUserAttributes{UserName: "jane.doe", ExternalID: "groups-user", Active: true})

	b.loginAs(t, groupsUser())

	require.Equal(t, 2, b.userCount(t))

	user, err := b.app.state.GetUserByID(types.UserID(provisioned.ID))
	require.NoError(t, err)
	assert.Equal(t, b.groupsUserIdentifier(), user.ProviderIdentifier.String)

	decoyUser, err := b.app.state.GetUserByID(types.UserID(decoy.ID))
	require.NoError(t, err)
	assert.False(t, decoyUser.ProviderIdentifier.Valid, "external_id mode ignores the email")
}

// TestFindSCIMUserForLoginByCustomClaim covers claims the mock provider
// cannot emit: a custom claim, a dotted path, the userinfo fallback, the ID
// token's precedence over userinfo, and non-string values.
func TestFindSCIMUserForLoginByCustomClaim(t *testing.T) {
	app := createTestApp(t)
	app.cfg.SCIM = types.SCIMConfig{Enabled: true, LinkBy: types.SCIMLinkByExternalID, LinkClaim: "oid"}
	a := &AuthProviderOIDC{h: app, cfg: &types.OIDCConfig{EmailVerifiedRequired: true}}

	oid, _, err := app.state.CreateSCIMUser(types.SCIMUserAttributes{UserName: "a", ExternalID: "0a1b-oid", Active: true}, true)
	require.NoError(t, err)

	nested, _, err := app.state.CreateSCIMUser(types.SCIMUserAttributes{UserName: "b", ExternalID: "nested-id", Active: true}, true)
	require.NoError(t, err)

	claims := &types.OIDCClaims{Iss: "https://idp.example.com", Sub: "s", Email: "b", EmailVerified: true}

	find := func(claim string, idClaims, infoClaims map[string]any) *types.User {
		t.Helper()

		app.cfg.SCIM.LinkClaim = claim

		u, err := a.findSCIMUserForLogin(claims, idClaims, infoClaims)
		if err != nil {
			require.ErrorIs(t, err, db.ErrUserNotFound)
		}

		return u
	}

	got := find("oid", map[string]any{"oid": "0a1b-oid"}, nil)
	require.NotNil(t, got)
	assert.Equal(t, oid.ID, got.ID)

	got = find("oid", map[string]any{}, map[string]any{"oid": "0a1b-oid"})
	require.NotNil(t, got, "userinfo is used when the ID token lacks the claim")
	assert.Equal(t, oid.ID, got.ID)

	got = find("oid", map[string]any{"oid": "0a1b-oid"}, map[string]any{"oid": "nested-id"})
	require.NotNil(t, got, "the ID token wins when both carry the claim")
	assert.Equal(t, oid.ID, got.ID)

	got = find("ext.id", map[string]any{"ext": map[string]any{"id": "nested-id"}}, nil)
	require.NotNil(t, got, "a dotted path reaches nested claims")
	assert.Equal(t, nested.ID, got.ID)

	assert.Nil(t, find("oid", map[string]any{"oid": "0A1B-OID"}, nil), "externalId compares exactly")
	assert.Nil(t, find("oid", map[string]any{"oid": 42.0}, nil), "non-string claims do not match")
	assert.Nil(t, find("oid", nil, nil))
}

// TestOIDCRequireProvisioning checks that with provisioning required, only
// users the identity provider provisioned may log in: an unknown login
// creates no user, and an OIDC user created before SCIM was enabled is
// refused too.
func TestOIDCRequireProvisioning(t *testing.T) {
	b := newOIDCSCIMBrowser(t, nil)

	// Created by a login before provisioning was required.
	legacy := &mockoidc.MockUser{Subject: "legacy", Email: "legacy@example.com", EmailVerified: true, PreferredUsername: "legacy"}
	b.loginAs(t, legacy)
	require.Equal(t, 1, b.userCount(t))

	b.app.cfg.SCIM.RequireProvisioning = true

	stranger := &mockoidc.MockUser{Subject: "stranger", Email: "stranger@example.com", EmailVerified: true}
	assert.Equal(t, http.StatusForbidden, b.loginStatus(t, stranger), "an unprovisioned login is refused")
	assert.Equal(t, 1, b.userCount(t), "a refused login creates no user")

	assert.Equal(t, http.StatusForbidden, b.loginStatus(t, legacy), "an existing user SCIM does not manage is refused")

	b.provision(t, types.SCIMUserAttributes{UserName: groupsUserEmail, Active: true})
	b.loginAs(t, groupsUser())
	b.loginAs(t, groupsUser())
	assert.Equal(t, 2, b.userCount(t), "a provisioned user logs in, and again once linked")
}

// TestOIDCLoginOfSuspendedSCIMUser checks that a provisioned user the
// directory has deactivated is refused at their first login, although the
// login is linked (the identity provider vouched for it), so that their
// next login after reactivation needs no second match.
func TestOIDCLoginOfSuspendedSCIMUser(t *testing.T) {
	b := newOIDCSCIMBrowser(t, nil)

	provisioned := b.provision(t, types.SCIMUserAttributes{UserName: groupsUserEmail, Active: false})

	assert.Equal(t, http.StatusForbidden, b.loginStatus(t, groupsUser()))

	user, err := b.app.state.GetUserByID(types.UserID(provisioned.ID))
	require.NoError(t, err)
	assert.True(t, user.IsSuspended())
	assert.Equal(t, b.groupsUserIdentifier(), user.ProviderIdentifier.String)
	assert.Zero(t, b.app.state.ListNodes().Len(), "a suspended user registers no node")
	assert.Equal(t, 1, b.userCount(t))
}

// TestOIDCConcurrentSCIMLinks races logins for one provisioned user. Logins
// of the same identity (a double submit) all end with the provisioned
// user. Logins of distinct identities sharing the verified email link it
// at most once: every other one either finds it linked or loses the link
// race, and is refused with a 403 either way; none takes over the user.
func TestOIDCConcurrentSCIMLinks(t *testing.T) {
	app := createTestApp(t)
	app.cfg.SCIM = types.SCIMConfig{Enabled: true, LinkBy: types.SCIMLinkByEmail, RequireProvisioning: true}
	a := &AuthProviderOIDC{h: app, cfg: &types.OIDCConfig{EmailVerifiedRequired: true}}

	const logins = 6

	run := func(t *testing.T, sub func(i int) string) ([]*types.User, []error) {
		t.Helper()

		var wg sync.WaitGroup

		users := make([]*types.User, logins)
		errs := make([]error, logins)

		for i := range logins {
			wg.Go(func() {
				claims := &types.OIDCClaims{
					Iss:           "https://idp.example.com",
					Sub:           sub(i),
					Email:         "race@example.com",
					EmailVerified: true,
					Username:      "race",
				}
				users[i], _, errs[i] = a.createOrUpdateUserFromClaim(claims, nil, nil)
			})
		}

		wg.Wait()

		return users, errs
	}

	t.Run("same identity", func(t *testing.T) {
		provisioned, _, err := app.state.CreateSCIMUser(types.SCIMUserAttributes{UserName: "race@example.com", Active: true}, true)
		require.NoError(t, err)

		users, errs := run(t, func(int) string { return "same" })
		for i := range logins {
			require.NoError(t, errs[i])
			assert.Equal(t, provisioned.ID, users[i].ID)
		}

		_, err = app.state.DeleteSCIMUser(types.UserID(provisioned.ID))
		require.NoError(t, err)
	})

	t.Run("distinct identities", func(t *testing.T) {
		provisioned, _, err := app.state.CreateSCIMUser(types.SCIMUserAttributes{UserName: "race@example.com", Active: true}, true)
		require.NoError(t, err)

		users, errs := run(t, func(i int) string { return fmt.Sprintf("distinct-%d", i) })

		winners := 0

		for i := range logins {
			if errs[i] == nil {
				winners++

				assert.Equal(t, provisioned.ID, users[i].ID)

				continue
			}

			herr, ok := errors.AsType[HTTPError](errs[i])
			require.True(t, ok, "a refused login is an HTTP error: %v", errs[i])
			assert.Equal(t, http.StatusForbidden, herr.Code,
				"a lost race looks like any refused login, revealing no provisioned account")
		}

		assert.Equal(t, 1, winners, "exactly one identity links the user")

		all, err := app.state.ListAllUsers()
		require.NoError(t, err)
		assert.Len(t, all, 1, "no refused login creates a user")
	})
}
