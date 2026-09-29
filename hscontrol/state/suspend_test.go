package state

import (
	"testing"

	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// peerIDs returns the ids of id's peers in ns.
func peerIDs(ns *NodeStore, id types.NodeID) []types.NodeID {
	var ids []types.NodeID
	for _, p := range ns.ListPeers(id).All() {
		ids = append(ids, p.ID())
	}

	return ids
}

// TestNodeStoreSuspendedUsers checks that suspending a user removes their
// untagged nodes from peer computation in both directions and from route
// election, leaves tag-owned nodes alone, and that restoring undoes it.
func TestNodeStoreSuspendedUsers(t *testing.T) {
	const (
		alice types.UserID = 10
		bob   types.UserID = 20
	)

	f := newPrimariesFixture(t, 1, 2, 3)
	prefix := mp("192.168.1.0/24")

	// 1: alice's subnet router, 2: bob's router for the same prefix,
	// 3: a tag-owned node alice created.
	f.ns.UpdateNode(1, func(n *types.Node) { n.UserID = new(uint(alice)) })
	f.ns.UpdateNode(2, func(n *types.Node) { n.UserID = new(uint(bob)) })
	f.ns.UpdateNode(3, func(n *types.Node) {
		n.UserID = nil
		n.User = nil
		n.Tags = []string{"tag:server"}
	})
	f.advertise(1, prefix)
	f.advertise(2, prefix)
	f.advertise(3)
	f.requirePrimary(prefix, 1)

	f.ns.SetSuspendedUsers([]types.UserID{alice})

	assert.Empty(t, peerIDs(f.ns, 1), "a suspended user's node has no peers")
	assert.ElementsMatch(t, []types.NodeID{3}, peerIDs(f.ns, 2), "no one sees a suspended user's node")
	assert.ElementsMatch(t, []types.NodeID{2}, peerIDs(f.ns, 3), "tag-owned nodes are not suspended")
	f.requirePrimary(prefix, 2)
	assert.True(t, f.ns.IsSuspended(f.node(1)))
	assert.False(t, f.ns.IsSuspended(f.node(3)))

	f.ns.SetSuspendedUsers(nil)

	assert.ElementsMatch(t, []types.NodeID{2, 3}, peerIDs(f.ns, 1), "restoring reconnects the node")
	assert.False(t, f.ns.IsSuspended(f.node(1)))
	// The healthy primary that took over keeps the route (no flap back).
	f.requirePrimary(prefix, 2)
}

// node returns the view of id in the fixture's store.
func (f *primariesFixture) node(id types.NodeID) types.NodeView {
	f.t.Helper()

	n, ok := f.ns.GetNode(id)
	require.True(f.t, ok)

	return n
}

// TestSuspensionSurvivesRestart checks that a suspension is persisted and
// enforced again as soon as the server starts, before anyone reconnects.
func TestSuspensionSurvivesRestart(t *testing.T) {
	cfg := persistTestConfig(t.TempDir() + "/headscale.db")

	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(t, err)

	user := database.CreateUserForTest("alice")
	node := database.CreateRegisteredNodeForTest(user, "alice-node")
	require.NoError(t, database.Close())

	s, err := NewState(cfg)
	require.NoError(t, err)

	c, err := s.SuspendUser(types.UserID(user.ID))
	require.NoError(t, err)
	require.False(t, c.IsEmpty())
	require.NoError(t, s.Close())

	s, err = NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	nv, ok := s.GetNodeByID(node.ID)
	require.True(t, ok)
	assert.True(t, s.IsNodeSuspended(nv), "a suspension must be enforced from startup")

	got, err := s.GetUserByID(types.UserID(user.ID))
	require.NoError(t, err)
	assert.True(t, got.IsSuspended())

	filter, err := s.FilterForNode(nv)
	require.NoError(t, err)
	assert.Empty(t, filter)

	_, err = s.RestoreUser(types.UserID(user.ID))
	require.NoError(t, err)
	assert.False(t, s.IsNodeSuspended(nv))
}
