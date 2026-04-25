// Unit tests for OIDC-asserted group resolution in policy v2.
//
// Validates that Group.Resolve matches not only by user identifier
// (upstream behaviour) but also by a user's persisted OIDC groups claim.
package v2

import (
	"net/netip"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/juanfont/headscale/hscontrol/types"
	"go4.org/netipx"
	"gorm.io/gorm"
	"tailscale.com/types/views"
)

func TestGroupResolve_MatchesOIDCGroupClaim(t *testing.T) {
	alice := types.User{
		Model:  gorm.Model{ID: 1},
		Name:   "alice@example.com",
		Email:  "alice@example.com",
		Groups: []string{"security@example.com", "vpn-production@example.com"},
	}
	bob := types.User{
		Model:  gorm.Model{ID: 2},
		Name:   "bob@example.com",
		Email:  "bob@example.com",
		Groups: []string{"vpn-development@example.com"},
	}
	// A user whose identifier literally matches the group email (upstream
	// resolution path). Ensures the union keeps working.
	literal := types.User{
		Model: gorm.Model{ID: 3},
		Name:  "security@example.com",
		Email: "security@example.com",
	}

	users := types.Users{alice, bob, literal}

	aliceNode := nodeWithIPs(t, 1, "100.64.0.1")
	bobNode := nodeWithIPs(t, 2, "100.64.0.2")
	literalNode := nodeWithIPs(t, 3, "100.64.0.3")

	nodes := views.SliceOf([]types.NodeView{
		aliceNode.View(), bobNode.View(), literalNode.View(),
	})

	tests := []struct {
		name       string
		members    []Username
		wantPfxStr []string
	}{
		{
			name:    "resolves group by IdP claim",
			members: []Username{"security@example.com"},
			wantPfxStr: []string{
				"100.64.0.1/32", // alice has security@ in her groups
				"100.64.0.3/32", // literal user named security@example.com
			},
		},
		{
			name:    "resolves distinct IdP group",
			members: []Username{"vpn-development@example.com"},
			wantPfxStr: []string{
				"100.64.0.2/32", // bob only
			},
		},
		{
			name:    "returns empty set when group unmatched",
			members: []Username{"no-such-group@example.com"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pol := &Policy{
				Groups: Groups{
					Group("group:test"): tc.members,
				},
			}
			gotSet, err := Group("group:test").Resolve(pol, users, nodes)
			if err != nil && len(tc.wantPfxStr) > 0 {
				t.Fatalf("unexpected error: %v", err)
			}

			got := prefixStrings(gotSet)
			if diff := cmp.Diff(tc.wantPfxStr, got); diff != "" {
				t.Errorf("prefix mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// nodeWithIPs constructs a minimal Node owned by user ID uid carrying a
// single IPv4 address so we can exercise Group.Resolve.
func nodeWithIPs(t *testing.T, uid uint, ip string) *types.Node {
	t.Helper()
	addr := netip.MustParseAddr(ip)
	uidCopy := uid
	return &types.Node{
		ID:       types.NodeID(uid),
		UserID:   &uidCopy,
		User:     &types.User{Model: gorm.Model{ID: uid}},
		IPv4:     &addr,
		Hostname: "n",
	}
}

// prefixStrings extracts the set's prefixes in stable string form.
func prefixStrings(set *netipx.IPSet) []string {
	if set == nil {
		return nil
	}
	prefixes := set.Prefixes()
	if len(prefixes) == 0 {
		return nil
	}
	out := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		out = append(out, p.String())
	}
	return out
}
