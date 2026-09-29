package cli

import (
	"testing"
	"time"

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
