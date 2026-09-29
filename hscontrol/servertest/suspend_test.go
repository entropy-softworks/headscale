package servertest_test

import (
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const suspendTestPolicy = `{
	"tagOwners": {"tag:server": ["alice@"]},
	"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}],
	"ssh": [{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self"], "users": ["autogroup:nonroot"]}]
}`

// TestSuspendUserCutsOffNodesAndRestoreReconnects checks Tailscale-style
// suspension end to end against real control clients: while alice is
// suspended her node stays connected but has no peers, is no one's peer, and
// accepts no traffic or SSH, while a tag-owned node registered with her key
// keeps working; restoring her reconnects everything without a new login.
func TestSuspendUserCutsOffNodesAndRestoreReconnects(t *testing.T) {
	t.Parallel()

	h := servertest.NewHarness(t, 1,
		servertest.WithServerOptions(servertest.WithBatchDelay(10*time.Millisecond)),
	)
	h.ChangePolicy(t, []byte(suspendTestPolicy))

	observer := h.Client(0)
	alice := h.Server.CreateUser(t, "alice")
	aliceNode := h.AddClient(t, servertest.WithUser(alice))
	tagged := h.AddClient(t, servertest.WithUser(alice), servertest.WithTags("tag:server"))

	h.WaitForMeshComplete(t, 10*time.Second)

	aliceID := findNodeID(t, h.Server, aliceNode.Name)

	c, err := h.Server.State().SuspendUser(types.UserID(alice.ID))
	require.NoError(t, err)
	require.False(t, c.IsEmpty(), "suspending must broadcast a change")
	h.Server.App.Change(c)

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Empty(c, aliceNode.Peers(), "a suspended user's node must have no peers")
		assert.Empty(c, aliceNode.Netmap().PacketFilter, "a suspended user's node must accept no traffic")
		assert.Empty(c, aliceNode.Netmap().SSHPolicy.Rules, "a suspended user's node must accept no SSH")

		_, seen := observer.PeerByName(aliceNode.Name)
		assert.False(c, seen, "no one may see a suspended user's node")

		_, seenByTagged := tagged.PeerByName(aliceNode.Name)
		assert.False(c, seenByTagged)

		_, taggedVisible := observer.PeerByName(tagged.Name)
		assert.True(c, taggedVisible, "tag-owned nodes are not suspended")

		assert.True(c, h.Server.App.MapBatcher().IsConnected(aliceID),
			"suspension keeps the control connection so restore needs no login")
	}, 10*time.Second, 20*time.Millisecond)

	again, err := h.Server.State().SuspendUser(types.UserID(alice.ID))
	require.NoError(t, err)
	assert.True(t, again.IsEmpty(), "suspending a suspended user changes nothing")

	c, err = h.Server.State().RestoreUser(types.UserID(alice.ID))
	require.NoError(t, err)
	require.False(t, c.IsEmpty(), "restoring must broadcast a change")
	h.Server.App.Change(c)

	h.WaitForMeshComplete(t, 10*time.Second)
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.NotEmpty(c, aliceNode.Netmap().PacketFilter, "a restored node must accept traffic again")
		_, seen := observer.PeerByName(aliceNode.Name)
		assert.True(c, seen, "a restored node must be visible again")
	}, 10*time.Second, 20*time.Millisecond)
}

// TestSuspendedUserCannotRegister checks that a suspended user's pre-auth keys
// register no node, while a tagged key they created still does.
func TestSuspendedUserCannotRegister(t *testing.T) {
	t.Parallel()

	h := servertest.NewHarness(t, 0)
	h.ChangePolicy(t, []byte(suspendTestPolicy))

	alice := h.Server.CreateUser(t, "alice")
	userKey := h.Server.CreatePreAuthKey(t, types.UserID(alice.ID))
	taggedKey := h.Server.CreateTaggedPreAuthKey(t, types.UserID(alice.ID), []string{"tag:server"})

	_, err := h.Server.State().SuspendUser(types.UserID(alice.ID))
	require.NoError(t, err)

	register := func(authKey string) error {
		_, _, err := h.Server.State().HandleNodeFromPreAuthKey(tailcfg.RegisterRequest{
			Auth:     &tailcfg.RegisterResponseAuth{AuthKey: authKey},
			NodeKey:  key.NewNode().Public(),
			Hostinfo: &tailcfg.Hostinfo{Hostname: "new-node"},
		}, key.NewMachine().Public())

		return err
	}

	require.ErrorIs(t, register(userKey), state.ErrUserSuspended)
	require.NoError(t, register(taggedKey), "a tagged key registers a tag-owned node")

	_, err = h.Server.State().RestoreUser(types.UserID(alice.ID))
	require.NoError(t, err)
	require.NoError(t, register(userKey), "a restored user's key registers again")
}
