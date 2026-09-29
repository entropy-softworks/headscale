package scim

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Run `go test ./hscontrol/scim/ -run Golden -update` to rewrite the
// .golden files after an intended change, then review the diff.
var update = flag.Bool("update", false, "rewrite golden files")

func checkGolden(t *testing.T, path string, got []byte) {
	t.Helper()

	if *update {
		require.NoError(t, os.WriteFile(path, got, 0o600))

		return
	}

	want, err := os.ReadFile(path)
	require.NoError(t, err, "missing golden file; run with -update")
	assert.Equal(t, string(want), string(got))
}

func fixtures(t *testing.T, dir string) []string {
	t.Helper()

	files, err := filepath.Glob(filepath.Join("testdata", dir, "*.json"))
	require.NoError(t, err)
	require.NotEmpty(t, files)

	return files
}

func indentJSON(t *testing.T, v any) []byte {
	t.Helper()

	b, err := json.MarshalIndent(v, "", "  ")
	require.NoError(t, err)

	return append(b, '\n')
}

// TestGoldenDecode decodes every captured create/replace body and compares
// the re-encoded resource. The golden files prove that password, roles,
// extension blocks and unsupported attributes are dropped.
func TestGoldenDecode(t *testing.T) {
	for _, dir := range []string{"users", "groups"} {
		for _, file := range fixtures(t, dir) {
			t.Run(dir+"/"+filepath.Base(file), func(t *testing.T) {
				f, err := os.Open(file)
				require.NoError(t, err)

				defer f.Close()

				var resource any

				if dir == "users" {
					u, err := DecodeUser(f)
					require.NoError(t, err)
					require.NoError(t, u.Validate())

					u.ID = "1"
					resource = u
				} else {
					g, err := DecodeGroup(f)
					require.NoError(t, err)
					require.NoError(t, g.Validate())

					g.ID = "1"
					resource = g
				}

				got := indentJSON(t, resource)
				assert.NotContains(t, string(got), "password")
				assert.NotContains(t, string(got), "null")

				checkGolden(t, strings.TrimSuffix(file, ".json")+".golden", got)
			})
		}
	}
}
