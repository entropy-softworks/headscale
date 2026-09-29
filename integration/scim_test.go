package integration

import (
	"crypto/tls"
	"crypto/x509"
	"maps"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	clientv1 "github.com/juanfont/headscale/gen/client/v1"
	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/integrationutil"
	"github.com/juanfont/headscale/integration/scimclient"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/oauth2-proxy/mockoidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const (
	scimGroupsDomain = "example.com"

	// scimPropagation bounds how long a SCIM write may take to reach a
	// connected client's netmap or packet filter.
	scimPropagation = 30 * time.Second
)

// scimEnv returns the headscale environment for OIDC plus SCIM, with SCIM
// groups qualified with scimGroupsDomain. OIDC group sync is left off so any
// group-based access in these tests can only come from SCIM. extra is merged
// last, so it can override the defaults.
func scimEnv(scenario *Scenario, extra map[string]string) map[string]string {
	env := map[string]string{
		"HEADSCALE_OIDC_ISSUER":             scenario.mockOIDC.Issuer(),
		"HEADSCALE_OIDC_CLIENT_ID":          scenario.mockOIDC.ClientID(),
		"HEADSCALE_OIDC_SCOPE":              "openid profile email",
		"CREDENTIALS_DIRECTORY_TEST":        "/tmp",
		"HEADSCALE_OIDC_CLIENT_SECRET_PATH": "${CREDENTIALS_DIRECTORY_TEST}/hs_client_oidc_secret",
		"HEADSCALE_SCIM_ENABLED":            "true",
		"HEADSCALE_SCIM_GROUPS_DOMAIN":      scimGroupsDomain,
	}

	maps.Copy(env, extra)

	return env
}

// scimHeadscaleOpts are the headscale options every SCIM test shares.
func scimHeadscaleOpts(scenario *Scenario, testName string, extraEnv map[string]string, pol *policyv2.Policy) []hsic.Option {
	opts := []hsic.Option{
		hsic.WithTestName(testName),
		hsic.WithConfigEnv(scimEnv(scenario, extraEnv)),
		hsic.WithFileInContainer("/tmp/hs_client_oidc_secret", []byte(scenario.mockOIDC.ClientSecret())),
	}

	if pol != nil {
		opts = append(opts, hsic.WithACLPolicy(pol))
	}

	return opts
}

// scimAllowAllPolicy lets every node reach every other node, so peer
// visibility only changes when a user is suspended or deleted.
func scimAllowAllPolicy() *policyv2.Policy {
	return &policyv2.Policy{
		ACLs: []policyv2.ACL{
			{
				Action:       "accept",
				Sources:      []policyv2.Alias{wildcard()},
				Destinations: []policyv2.AliasWithPorts{aliasWithPorts(wildcard(), tailcfg.PortRangeAny)},
			},
		},
	}
}

// createSCIMToken mints a SCIM bearer token with the CLI and returns the
// token and its id.
func createSCIMToken(t *testing.T, headscale ControlServer) (string, string) {
	t.Helper()

	var out clientv1.CreateScimTokenOutputBody

	err := executeAndUnmarshal(headscale, []string{
		"headscale", "scim", "tokens", "create",
		"--description", "integration test",
		"--expiration", "90d",
		"--output", "json",
	}, &out)
	require.NoError(t, err, "creating a SCIM token")
	require.True(t, strings.HasPrefix(out.Token, "hskey-scim-"), "SCIM token has an unexpected format: %q", out.Token)
	require.NotEmpty(t, out.ScimToken.Id, "SCIM token id")

	return out.Token, out.ScimToken.Id
}

func newSCIMClient(headscale ControlServer, token string) *scimclient.Client {
	return scimclient.New(headscale.GetEndpoint(), headscale.GetCert(), token)
}

// requireSCIMStatus fails the test unless the call succeeded at the transport
// level with one of the wanted status codes.
func requireSCIMStatus(t *testing.T, resp *scimclient.Response, err error, want ...int) {
	t.Helper()

	require.NoError(t, err, "SCIM call: %s", resp)
	require.NotNil(t, resp)
	require.Contains(t, want, resp.StatusCode, "unexpected SCIM status: %s", resp)
}

// provisionSCIMUser creates an active SCIM user whose userName and primary
// work email are email, as Entra ID and Okta do for a typical directory.
func provisionSCIMUser(t *testing.T, scim *scimclient.Client, email, externalID string, want ...int) *scimclient.User {
	t.Helper()

	if len(want) == 0 {
		want = []int{http.StatusCreated}
	}

	user, resp, err := scim.CreateUser(t.Context(), scimclient.User{
		ExternalID: externalID,
		UserName:   email,
		Name:       &scimclient.Name{GivenName: "Integration", FamilyName: "Test"},
		Active:     new(true),
		Emails:     []scimclient.Email{{Value: email, Type: "work", Primary: true}},
	})
	requireSCIMStatus(t, resp, err, want...)
	require.True(t, resp.IsSCIM(), "SCIM create must answer %s: %s", scimclient.ContentType, resp)
	require.NotEmpty(t, user.ID, "created SCIM user must have an id")
	require.Equal(t, email, user.UserName)
	require.Contains(t, user.Schemas, scimclient.SchemaUser)

	if assert.NotNil(t, user.Active, "created SCIM user must carry active") {
		require.True(t, *user.Active)
	}

	return user
}

// requireSCIMUserActive GETs the SCIM user and checks its active attribute.
func requireSCIMUserActive(t *testing.T, scim *scimclient.Client, id string, want bool) {
	t.Helper()

	got, resp, err := scim.GetUser(t.Context(), id)
	requireSCIMStatus(t, resp, err, http.StatusOK)
	require.Equal(t, id, got.ID)
	require.NotNil(t, got.Active, "SCIM user must carry active: %s", resp)
	require.Equal(t, want, *got.Active, "SCIM user active: %s", resp)
}

// loginOIDCNode starts a new client outside the scenario's users and logs it
// in through the mock provider, consuming the next queued identity. The
// login must succeed.
func loginOIDCNode(t *testing.T, scenario *Scenario, headscale ControlServer) TailscaleClient {
	t.Helper()

	client, err := scenario.CreateTailscaleNode("unstable",
		tsic.WithNetwork(scenario.networks[scenario.testDefaultNetwork]))
	require.NoError(t, err)

	u, err := client.LoginWithURL(headscale.GetEndpoint())
	require.NoError(t, err)

	_, err = doLoginURL(client.Hostname(), u)
	require.NoError(t, err)

	err = client.WaitForRunning(integrationutil.PeerSyncTimeout())
	require.NoError(t, err)

	return client
}

// usersWithEmail returns the headscale users whose email is email.
func usersWithEmail(users []*clientv1.User, email string) []*clientv1.User {
	var out []*clientv1.User

	for _, u := range users {
		if strings.EqualFold(u.Email, email) {
			out = append(out, u)
		}
	}

	return out
}

// packetFilterAdmits reports whether client's packet filter admits ip as a
// source. A filter that cannot be read fails ct rather than counting as
// "not admitted", so revocation checks cannot pass vacuously.
func packetFilterAdmits(ct assert.TestingT, client TailscaleClient, ip netip.Addr) bool {
	pf, err := client.PacketFilter()
	if !assert.NoError(ct, err, "reading %s's packet filter", client.Hostname()) {
		return false
	}

	for _, m := range pf {
		for _, src := range m.Srcs {
			if src.Contains(ip) {
				return true
			}
		}
	}

	return false
}

// seesPeer reports whether client's netmap contains peer. A status that
// cannot be read fails ct.
func seesPeer(ct assert.TestingT, client TailscaleClient, peer key.NodePublic) bool {
	status, err := client.Status()
	if !assert.NoError(ct, err, "reading %s's status", client.Hostname()) {
		return false
	}

	_, ok := status.Peer[peer]

	return ok
}

// scimNodeScenario starts headscale with OIDC and SCIM, an anchor node
// logged in as its own OIDC user, and returns the scenario, headscale and
// the anchor. The mock provider queue must list the anchor's identity first.
func scimNodeScenario(
	t *testing.T,
	testName string,
	oidcUsers []mockoidc.MockUser,
	extraEnv map[string]string,
	pol *policyv2.Policy,
) (*Scenario, ControlServer, TailscaleClient) {
	t.Helper()

	spec := ScenarioSpec{
		NodesPerUser: 1,
		Users:        []string{"anchor"},
		// The OIDC login creates the anchor's user; a CLI-created
		// user of the same name would only add noise to ListUsers.
		OIDCSkipUserCreation: true,
		OIDCUsers:            oidcUsers,
	}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)

	t.Cleanup(func() { scenario.ShutdownAssertNoPanics(t) })

	err = scenario.CreateHeadscaleEnvWithLoginURL(nil, scimHeadscaleOpts(scenario, testName, extraEnv, pol)...)
	requireNoErrHeadscaleEnv(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	clients, err := scenario.ListTailscaleClients()
	require.NoError(t, err)
	require.Len(t, clients, 1, "expected exactly the anchor client")

	require.NoError(t, scenario.WaitForTailscaleSync())

	return scenario, headscale, clients[0]
}

// TestSCIMProvisionLinkAndGroupAccess provisions a user and a group through
// SCIM before the user has ever logged in, then checks that the user's first
// OIDC login is linked to the provisioned user (same id, no duplicate) and
// that access granted by an ACL on the SCIM group reaches a connected peer,
// is revoked when SCIM removes the member and granted again when SCIM adds
// it back, all without the user logging in again and without any OIDC
// groups claim.
func TestSCIMProvisionLinkAndGroupAccess(t *testing.T) {
	IntegrationSkip(t)

	const engineer = "engineer"

	email := engineer + "@headscale.net"

	scenario, headscale, anchor := scimNodeScenario(t, "scimgroups",
		// The mock provider serves logins in order: the anchor first
		// (by the scenario), then the engineer's node.
		[]mockoidc.MockUser{
			oidcMockUser("anchor", true),
			oidcMockUser(engineer, true),
		},
		nil,
		&policyv2.Policy{
			ACLs: []policyv2.ACL{
				{
					Action:  "accept",
					Sources: []policyv2.Alias{groupp("group:engineering@" + scimGroupsDomain)},
					Destinations: []policyv2.AliasWithPorts{
						aliasWithPorts(prefixp("100.64.0.0/10"), tailcfg.PortRangeAny),
					},
				},
			},
		},
	)

	token, _ := createSCIMToken(t, headscale)
	scim := newSCIMClient(headscale, token)
	ctx := t.Context()

	// A provider looks the user up before creating it.
	found, resp, err := scim.FindUserByUserName(ctx, email)
	requireSCIMStatus(t, resp, err, http.StatusOK)
	require.Contains(t, found.Schemas, scimclient.SchemaListResponse)
	require.Zero(t, found.TotalResults, "the user must not exist before provisioning: %s", resp)

	user := provisionSCIMUser(t, scim, email, "ext-"+engineer)

	group, resp, err := scim.CreateGroup(ctx, scimclient.Group{
		ExternalID:  "ext-engineering",
		DisplayName: "Engineering",
		Members:     []scimclient.Ref{{Value: user.ID}},
	})
	requireSCIMStatus(t, resp, err, http.StatusCreated)
	require.NotEmpty(t, group.ID)
	require.Equal(t, "Engineering", group.DisplayName)
	require.Contains(t, group.Schemas, scimclient.SchemaGroup)
	require.Contains(t, refValues(group.Members), user.ID, "the new group must list its member: %s", resp)

	got, resp, err := scim.GetUser(ctx, user.ID)
	requireSCIMStatus(t, resp, err, http.StatusOK)
	require.Contains(t, refValues(got.Groups), group.ID, "the user's read-only groups must list the group: %s", resp)

	// The user's first login.
	node := loginOIDCNode(t, scenario, headscale)

	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		users, err := headscale.ListUsers()
		assert.NoError(ct, err)

		matches := usersWithEmail(users, email)
		if assert.Len(ct, matches, 1, "the login must not create a second user with the provisioned email") {
			assert.Equal(ct, user.ID, matches[0].Id, "the login must be linked to the provisioned user")
			assert.Equal(ct, "oidc", matches[0].Provider, "the linked user must carry the OIDC identity")
		}
	}, integrationutil.ScaledTimeout(30*time.Second), 1*time.Second,
		"the OIDC login must link to the SCIM-provisioned user")

	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		nodes, err := headscale.ListNodes()
		assert.NoError(ct, err)

		n := findNode(nodes, func(n *clientv1.Node) bool { return n.Name == node.Hostname() })
		if assert.NotNil(ct, n, "the engineer's node must be registered") {
			assert.Equal(ct, user.ID, n.User.Id, "the node must belong to the provisioned user")
		}
	}, integrationutil.ScaledTimeout(30*time.Second), 1*time.Second,
		"the engineer's node must belong to the provisioned user")

	found, resp, err = scim.FindUserByUserName(ctx, email)
	requireSCIMStatus(t, resp, err, http.StatusOK)
	require.Equal(t, 1, found.TotalResults, "the linked user must still be found by userName: %s", resp)
	require.Equal(t, user.ID, found.Resources[0].ID)

	nodeIP, err := node.IPv4()
	require.NoError(t, err)

	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		assert.True(ct, packetFilterAdmits(ct, anchor, nodeIP),
			"the anchor's packet filter must admit the SCIM group member")
	}, integrationutil.ScaledTimeout(scimPropagation), 1*time.Second,
		"SCIM group membership must grant access")

	_, resp, err = scim.RemoveMembers(ctx, group.ID, user.ID)
	requireSCIMStatus(t, resp, err, http.StatusOK, http.StatusNoContent)

	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		assert.False(ct, packetFilterAdmits(ct, anchor, nodeIP),
			"the anchor's packet filter must drop the removed member")
	}, integrationutil.ScaledTimeout(scimPropagation), 1*time.Second,
		"SCIM member removal must revoke access on connected peers")

	gotGroup, resp, err := scim.GetGroup(ctx, group.ID)
	requireSCIMStatus(t, resp, err, http.StatusOK)
	require.NotContains(t, refValues(gotGroup.Members), user.ID, "the removed member must be gone: %s", resp)

	_, resp, err = scim.AddMembers(ctx, group.ID, user.ID)
	requireSCIMStatus(t, resp, err, http.StatusOK, http.StatusNoContent)

	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		assert.True(ct, packetFilterAdmits(ct, anchor, nodeIP),
			"the anchor's packet filter must admit the re-added member")
	}, integrationutil.ScaledTimeout(scimPropagation), 1*time.Second,
		"SCIM member addition must grant access on connected peers")
}

// TestSCIMSuspendAndRestore adopts an existing OIDC user through SCIM,
// deactivates it the way Entra ID does (Replace active "False") and checks
// that its node drops out of the tailnet while staying connected, then
// reactivates it the way Okta does and checks that the peers come back
// without a new login.
func TestSCIMSuspendAndRestore(t *testing.T) {
	IntegrationSkip(t)

	const engineer = "engineer"

	email := engineer + "@headscale.net"

	scenario, headscale, anchor := scimNodeScenario(t, "scimsuspend",
		[]mockoidc.MockUser{
			oidcMockUser("anchor", true),
			oidcMockUser(engineer, true),
		},
		// Adoption is off by default; this test models migrating an
		// existing tailnet, where the operator turns it on.
		map[string]string{"HEADSCALE_SCIM_ADOPT_EXISTING_USERS": "true"},
		scimAllowAllPolicy(),
	)

	// The engineer logs in before SCIM knows about them.
	node := loginOIDCNode(t, scenario, headscale)
	nodeKey := node.MustStatus().Self.PublicKey
	anchorKey := anchor.MustStatus().Self.PublicKey
	anchorIP := anchor.MustIPv4()

	assertPeers := func(want bool, msg string) {
		t.Helper()

		assert.EventuallyWithT(t, func(ct *assert.CollectT) {
			assert.Equal(ct, want, seesPeer(ct, anchor, nodeKey), "anchor sees the engineer's node")
		}, integrationutil.ScaledTimeout(scimPropagation), 1*time.Second, msg+" (anchor)")

		assert.EventuallyWithT(t, func(ct *assert.CollectT) {
			assert.Equal(ct, want, seesPeer(ct, node, anchorKey), "the engineer's node sees the anchor")
		}, integrationutil.ScaledTimeout(scimPropagation), 1*time.Second, msg+" (engineer)")
	}

	assertPeers(true, "the anchor and the engineer must see each other before suspension")

	var oidcUser *clientv1.User

	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		users, err := headscale.ListUsers()
		assert.NoError(ct, err)

		oidcUser = findUserByEmail(users, email)
		assert.NotNil(ct, oidcUser, "the engineer's OIDC user must exist")
	}, integrationutil.ScaledTimeout(30*time.Second), 1*time.Second, "waiting for the engineer's OIDC user")
	require.NotNil(t, oidcUser)

	token, _ := createSCIMToken(t, headscale)
	scim := newSCIMClient(headscale, token)
	ctx := t.Context()

	// Adoption takes over the existing user; a server may answer 200 or
	// 201 for it.
	user := provisionSCIMUser(t, scim, email, "ext-"+engineer, http.StatusCreated, http.StatusOK)
	require.Equal(t, oidcUser.Id, user.ID, "SCIM must adopt the existing OIDC user with the same email")

	// Entra ID without the aadOptscim062020 flag.
	patched, resp, err := scim.PatchUserActiveLegacy(ctx, user.ID, false)
	requireSCIMStatus(t, resp, err, http.StatusOK, http.StatusNoContent)

	if resp.StatusCode == http.StatusOK && assert.NotNil(t, patched.Active, "PATCH response must carry active: %s", resp) {
		assert.False(t, *patched.Active, "PATCH response must show the user inactive")
	}

	requireSCIMUserActive(t, scim, user.ID, false)

	assertPeers(false, "a suspended user's node must lose its peers and disappear from theirs")

	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		status, err := node.Status()
		assert.NoError(ct, err)
		assert.Empty(ct, status.Peers(), "a suspended node's netmap must have no peers")
		assert.Equal(ct, "Running", status.BackendState, "a suspended node stays logged in")
	}, integrationutil.ScaledTimeout(scimPropagation), 1*time.Second,
		"the suspended node must stay connected with an empty netmap")

	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		assert.False(ct, packetFilterAdmits(ct, node, anchorIP),
			"a suspended node's packet filter must admit nobody")
	}, integrationutil.ScaledTimeout(scimPropagation), 1*time.Second,
		"the suspended node must get an empty packet filter")

	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		nodes, err := headscale.ListNodes()
		assert.NoError(ct, err)

		n := findNode(nodes, func(n *clientv1.Node) bool { return n.Name == node.Hostname() })
		if assert.NotNil(ct, n, "suspension must not delete the node") {
			assert.True(ct, n.Online, "the suspended node must stay connected")
		}
	}, integrationutil.ScaledTimeout(30*time.Second), 1*time.Second,
		"the suspended node must stay registered and online")

	// Okta, and Entra ID with the flag.
	patched, resp, err = scim.PatchUserActive(ctx, user.ID, true)
	requireSCIMStatus(t, resp, err, http.StatusOK, http.StatusNoContent)

	if resp.StatusCode == http.StatusOK && assert.NotNil(t, patched.Active, "PATCH response must carry active: %s", resp) {
		assert.True(t, *patched.Active, "PATCH response must show the user active")
	}

	requireSCIMUserActive(t, scim, user.ID, true)

	assertPeers(true, "reactivation must restore peers without a new login")
}

// TestSCIMDeleteUserRemovesNodes deprovisions a user with DELETE /Users/{id}
// and checks that the user and their node are gone from headscale and from
// a connected peer's netmap.
func TestSCIMDeleteUserRemovesNodes(t *testing.T) {
	IntegrationSkip(t)

	const engineer = "engineer"

	email := engineer + "@headscale.net"

	scenario, headscale, anchor := scimNodeScenario(t, "scimdelete",
		[]mockoidc.MockUser{
			oidcMockUser("anchor", true),
			oidcMockUser(engineer, true),
		},
		nil,
		scimAllowAllPolicy(),
	)

	token, _ := createSCIMToken(t, headscale)
	scim := newSCIMClient(headscale, token)
	ctx := t.Context()

	user := provisionSCIMUser(t, scim, email, "ext-"+engineer)

	node := loginOIDCNode(t, scenario, headscale)
	nodeKey := node.MustStatus().Self.PublicKey

	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		nodes, err := headscale.ListNodes()
		assert.NoError(ct, err)

		n := findNode(nodes, func(n *clientv1.Node) bool { return n.Name == node.Hostname() })
		if assert.NotNil(ct, n, "the engineer's node must be registered") {
			assert.Equal(ct, user.ID, n.User.Id, "the node must belong to the provisioned user")
		}
	}, integrationutil.ScaledTimeout(30*time.Second), 1*time.Second,
		"the engineer's node must belong to the provisioned user")

	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		assert.True(ct, seesPeer(ct, anchor, nodeKey), "the anchor must see the engineer's node")
	}, integrationutil.ScaledTimeout(scimPropagation), 1*time.Second,
		"the anchor must see the engineer's node before deprovisioning")

	resp, err := scim.DeleteUser(ctx, user.ID)
	requireSCIMStatus(t, resp, err, http.StatusNoContent)

	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		nodes, err := headscale.ListNodes()
		assert.NoError(ct, err)
		assert.Nil(ct,
			findNode(nodes, func(n *clientv1.Node) bool { return n.Name == node.Hostname() }),
			"the deprovisioned user's node must be deleted")
	}, integrationutil.ScaledTimeout(30*time.Second), 1*time.Second,
		"SCIM delete must remove the user's nodes")

	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		users, err := headscale.ListUsers()
		assert.NoError(ct, err)
		assert.Empty(ct, usersWithEmail(users, email), "the deprovisioned user must be deleted")
	}, integrationutil.ScaledTimeout(30*time.Second), 1*time.Second,
		"SCIM delete must remove the user")

	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		assert.False(ct, seesPeer(ct, anchor, nodeKey), "the anchor must no longer see the deleted node")
	}, integrationutil.ScaledTimeout(scimPropagation), 1*time.Second,
		"the deleted node must disappear from connected peers")

	_, resp, err = scim.GetUser(ctx, user.ID)
	requireSCIMStatus(t, resp, err, http.StatusNotFound)

	if scimErr := resp.Error(); assert.NotNil(t, scimErr, "404 must carry a SCIM error: %s", resp) {
		assert.Contains(t, scimErr.Schemas, scimclient.SchemaError)
		assert.Equal(t, "404", scimErr.Status)
	}

	found, resp, err := scim.FindUserByUserName(ctx, email)
	requireSCIMStatus(t, resp, err, http.StatusOK)
	assert.Zero(t, found.TotalResults, "a deleted user must not be found: %s", resp)
}

// TestSCIMAuth checks who may call the SCIM endpoint: only a live SCIM
// token. No token, a malformed one, an admin API key and a revoked SCIM
// token are all refused, and a SCIM token is in turn refused by the admin
// API.
func TestSCIMAuth(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		// SCIM requires OIDC, so the mock provider must run; no node
		// logs in.
		OIDCUsers: []mockoidc.MockUser{oidcMockUser("unused", true)},
	}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)

	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnvWithLoginURL(nil, scimHeadscaleOpts(scenario, "scimauth", nil, nil)...)
	requireNoErrHeadscaleEnv(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	ctx := t.Context()

	apiKey, err := headscale.Execute([]string{"headscale", "apikeys", "create", "--expiration", "24h"})
	require.NoError(t, err)

	apiKey = strings.TrimSpace(apiKey)
	require.NotEmpty(t, apiKey)

	token, tokenID := createSCIMToken(t, headscale)
	scim := newSCIMClient(headscale, token)

	refused := []struct{ name, bearer string }{
		{"no token", ""},
		{"garbage token", "hskey-scim-" + strings.Repeat("0", 32)},
		{"admin API key", apiKey},
	}

	for _, r := range refused {
		for _, path := range []string{"/ServiceProviderConfig", "/Users"} {
			resp, err := scim.WithToken(r.bearer).Get(ctx, path, nil)
			require.NoError(t, err, "%s GET %s: %s", r.name, path, resp)
			assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "%s GET %s must be refused: %s", r.name, path, resp)
		}
	}

	var spc map[string]any

	resp, err := scim.Get(ctx, "/ServiceProviderConfig", &spc)
	requireSCIMStatus(t, resp, err, http.StatusOK)
	require.True(t, resp.IsSCIM(), "ServiceProviderConfig must be %s: %s", scimclient.ContentType, resp)
	assert.Contains(t, spc["schemas"], scimclient.SchemaServiceProviderConfig)

	var users scimclient.ListResponse[scimclient.User]

	resp, err = scim.Get(ctx, "/Users", &users)
	requireSCIMStatus(t, resp, err, http.StatusOK)
	assert.Contains(t, users.Schemas, scimclient.SchemaListResponse)

	// A SCIM token is not an admin credential.
	assert.Equal(t, http.StatusUnauthorized, adminAPIStatus(t, headscale, token),
		"the admin API must refuse a SCIM token")
	assert.Equal(t, http.StatusOK, adminAPIStatus(t, headscale, apiKey),
		"the admin API must accept the admin key (control)")

	_, err = headscale.Execute([]string{"headscale", "scim", "tokens", "revoke", tokenID})
	require.NoError(t, err, "revoking the SCIM token")

	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := scim.Get(ctx, "/ServiceProviderConfig", nil)
		assert.NoError(ct, err)

		if assert.NotNil(ct, resp) {
			assert.Equal(ct, http.StatusUnauthorized, resp.StatusCode, "a revoked token must be refused: %s", resp)
		}
	}, integrationutil.ScaledTimeout(10*time.Second), 500*time.Millisecond,
		"a revoked SCIM token must stop authenticating")
}

// adminAPIStatus returns the status of GET /api/v1/user with token.
func adminAPIStatus(t *testing.T, headscale ControlServer, token string) int {
	t.Helper()

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(headscale.GetCert())

	hc := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
	}

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, headscale.GetEndpoint()+"/api/v1/user", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := hc.Do(req)
	require.NoError(t, err)

	defer resp.Body.Close()

	return resp.StatusCode
}

// TestSCIMRequireProvisioning checks scim.require_provisioning: a login by a
// user the identity provider has provisioned succeeds and is linked, a login
// by anyone else is refused and creates neither a user nor a node.
func TestSCIMRequireProvisioning(t *testing.T) {
	IntegrationSkip(t)

	const (
		provisioned = "provisioned"
		stranger    = "stranger"
	)

	spec := ScenarioSpec{
		// Served in order: the provisioned user's node logs in first.
		OIDCUsers: []mockoidc.MockUser{
			oidcMockUser(provisioned, true),
			oidcMockUser(stranger, true),
		},
	}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)

	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnvWithLoginURL(nil, scimHeadscaleOpts(scenario, "scimrequire",
		map[string]string{"HEADSCALE_SCIM_REQUIRE_PROVISIONING": "true"}, scimAllowAllPolicy())...)
	requireNoErrHeadscaleEnv(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	token, _ := createSCIMToken(t, headscale)
	scim := newSCIMClient(headscale, token)

	provisionedEmail := provisioned + "@headscale.net"
	strangerEmail := stranger + "@headscale.net"

	user := provisionSCIMUser(t, scim, provisionedEmail, "ext-"+provisioned)

	node := loginOIDCNode(t, scenario, headscale)

	strangerNode, err := scenario.CreateTailscaleNode("unstable",
		tsic.WithNetwork(scenario.networks[scenario.testDefaultNetwork]))
	require.NoError(t, err)

	u, err := strangerNode.LoginWithURL(headscale.GetEndpoint())
	require.NoError(t, err)

	_, err = doLoginURL(strangerNode.Hostname(), u)
	require.ErrorContains(t, err, "unexpected status code 403", "an unprovisioned user's login must be refused")

	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		users, err := headscale.ListUsers()
		assert.NoError(ct, err)

		matches := usersWithEmail(users, provisionedEmail)
		if assert.Len(ct, matches, 1, "the provisioned user must exist once") {
			assert.Equal(ct, user.ID, matches[0].Id, "the login must be linked to the provisioned user")
		}

		assert.Empty(ct, usersWithEmail(users, strangerEmail), "a refused login must not create a user")
	}, integrationutil.ScaledTimeout(30*time.Second), 1*time.Second,
		"only the provisioned user may exist")

	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		nodes, err := headscale.ListNodes()
		assert.NoError(ct, err)

		if assert.Len(ct, nodes, 1, "only the provisioned user's node may register") {
			assert.Equal(ct, node.Hostname(), nodes[0].Name)
			assert.Equal(ct, user.ID, nodes[0].User.Id)
		}
	}, integrationutil.ScaledTimeout(30*time.Second), 1*time.Second,
		"a refused login must not register a node")

	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		status, err := strangerNode.Status()
		assert.NoError(ct, err)
		assert.Equal(ct, "NeedsLogin", status.BackendState, "the refused node must stay logged out")
	}, integrationutil.ScaledTimeout(10*time.Second), 1*time.Second,
		"the refused node must not be logged in")
}

func refValues(refs []scimclient.Ref) []string {
	out := make([]string, 0, len(refs))
	for _, r := range refs {
		out = append(out, r.Value)
	}

	slices.Sort(out)

	return out
}
