package db

import (
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

const scimTokenMigrationID = "202609281330-credentials-scim-token-kind" //nolint:gosec // migration id

// preSCIMKinds is the kind list before scim_token existed.
const preSCIMKinds = `'api','authkey','oauth_client','oauth_token'`

func TestSCIMTokenLifecycle(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	secret, tok, err := db.CreateSCIMToken("entra", nil)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(secret, types.SCIMTokenPrefix), secret)
	assert.Contains(t, secret, tok.Prefix)
	assert.Equal(t, "entra", tok.Description)
	assert.Equal(t, types.SCIMTokenPrefix+tok.Prefix+"-***", tok.MaskedPrefix())

	// Only the hash is stored.
	var cred types.Credential
	require.NoError(t, db.DB.First(&cred, tok.ID).Error)
	assert.Equal(t, types.CredentialSCIMToken, cred.Kind)
	assert.NotContains(t, string(cred.Hash), secret[len(secret)-keySecretLength:])

	got, err := db.AuthenticateSCIMToken(secret)
	require.NoError(t, err)
	assert.Equal(t, tok.ID, got.ID)
	require.NotNil(t, got.LastSeen, "authentication records last use")

	// Within the interval the last-seen write is skipped.
	first := *got.LastSeen
	got, err = db.AuthenticateSCIMToken(secret)
	require.NoError(t, err)
	assert.True(t, first.Equal(*got.LastSeen))

	// Outside it, a new time is recorded.
	stale := time.Now().UTC().Add(-2 * scimTokenLastSeenInterval)
	require.NoError(t, db.DB.Model(&types.Credential{}).Where("id = ?", tok.ID).
		Update("last_seen", stale).Error)
	got, err = db.AuthenticateSCIMToken(secret)
	require.NoError(t, err)
	assert.True(t, got.LastSeen.After(stale))

	byID, err := db.GetSCIMTokenByID(tok.ID)
	require.NoError(t, err)
	assert.NotNil(t, byID.LastSeen)

	// Other kinds are not SCIM tokens.
	_, apiKey, err := db.CreateAPIKey(nil)
	require.NoError(t, err)
	_, err = db.GetSCIMTokenByID(apiKey.ID)
	require.ErrorIs(t, err, ErrSCIMTokenNotFound)
	require.ErrorIs(t, db.RevokeSCIMToken(apiKey.ID), ErrSCIMTokenNotFound)
	require.ErrorIs(t, db.DeleteSCIMToken(apiKey.ID), ErrSCIMTokenNotFound)

	list, err := db.ListSCIMTokens()
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, tok.ID, list[0].ID)

	// Revocation is kept for audit and is idempotent.
	require.NoError(t, db.RevokeSCIMToken(tok.ID))
	revoked, err := db.GetSCIMTokenByID(tok.ID)
	require.NoError(t, err)
	require.NotNil(t, revoked.Revoked)
	require.NoError(t, db.RevokeSCIMToken(tok.ID))
	again, err := db.GetSCIMTokenByID(tok.ID)
	require.NoError(t, err)
	assert.True(t, revoked.Revoked.Equal(*again.Revoked), "re-revoking keeps the first time")

	_, err = db.AuthenticateSCIMToken(secret)
	require.ErrorIs(t, err, ErrSCIMTokenRevoked)

	require.NoError(t, db.DeleteSCIMToken(tok.ID))
	require.ErrorIs(t, db.DeleteSCIMToken(tok.ID), ErrSCIMTokenNotFound)
	require.ErrorIs(t, db.RevokeSCIMToken(tok.ID), ErrSCIMTokenNotFound)

	_, err = db.AuthenticateSCIMToken(secret)
	require.ErrorIs(t, err, ErrSCIMTokenNotFound)
}

func TestAuthenticateSCIMTokenRejects(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	secret, _, err := db.CreateSCIMToken("", nil)
	require.NoError(t, err)

	past := time.Now().Add(-time.Minute)
	expired, _, err := db.CreateSCIMToken("expired", &past)
	require.NoError(t, err)

	future := time.Now().Add(time.Hour)
	live, _, err := db.CreateSCIMToken("live", &future)
	require.NoError(t, err)

	_, err = db.AuthenticateSCIMToken(live)
	require.NoError(t, err, "an unexpired token authenticates")

	apiKey, _, err := db.CreateAPIKey(nil)
	require.NoError(t, err)

	// Same identifier, another kind's prefix: the lookup is per kind.
	asAPIKey := "hskey-api-" + strings.TrimPrefix(secret, types.SCIMTokenPrefix)

	wrongSecret := secret[:len(secret)-1] + flipHex(secret[len(secret)-1])

	tests := []struct {
		name  string
		token string
		want  error
	}{
		{"empty", "", ErrSCIMTokenFailedToParse},
		{"admin api key", apiKey, ErrSCIMTokenFailedToParse},
		{"scim secret under api prefix", asAPIKey, ErrSCIMTokenFailedToParse},
		{"prefix only", types.SCIMTokenPrefix, ErrSCIMTokenFailedToParse},
		{"truncated", secret[:len(secret)-10], ErrSCIMTokenFailedToParse},
		{"wrong secret", wrongSecret, ErrSCIMTokenNotFound},
		{"unknown identifier", types.SCIMTokenPrefix + "000000000000-" + strings.Repeat("a", keySecretLength), ErrSCIMTokenNotFound},
		{"expired", expired, ErrSCIMTokenExpired},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := db.AuthenticateSCIMToken(tt.token)
			require.ErrorIs(t, err, tt.want)
		})
	}

	// A SCIM token is never accepted as an admin API key.
	_, err = db.AuthenticateAPIKey(secret)
	require.Error(t, err)

	valid, err := db.ValidateAPIKey(secret)
	assert.False(t, valid)
	require.Error(t, err)

	keys, err := db.ListAPIKeys()
	require.NoError(t, err)
	assert.Len(t, keys, 1, "scim tokens are not listed as api keys")
}

func flipHex(c byte) string {
	if c == '0' {
		return "1"
	}

	return "0"
}

// seedCredentialReferences creates one credential of every pre-scim kind and a
// node pointing at the pre-auth key, so a rebuild has foreign keys to keep. It
// returns the node's auth key id.
func seedCredentialReferences(t *testing.T, db *HSDatabase) uint64 {
	t.Helper()

	user := db.CreateUserForTest("scim-migration")
	node := db.CreateNodeForTest(user, "scim-migration")

	uid := types.UserID(user.ID)
	pak, err := db.CreatePreAuthKey(&uid, true, false, nil, nil)
	require.NoError(t, err)

	require.NoError(t, db.DB.Model(&types.Node{}).Where("id = ?", node.ID).
		Update("auth_key_id", pak.ID).Error)

	_, _, err = db.CreateAPIKey(nil)
	require.NoError(t, err)

	_, client, err := db.CreateOAuthClient([]string{"devices:core:read"}, nil, "c", nil)
	require.NoError(t, err)

	_, _, err = db.MintAccessToken(client.ClientID, []string{"devices:core:read"}, nil, nil)
	require.NoError(t, err)

	// A deleted credential leaves the AUTOINCREMENT counter ahead of max(id).
	_, gone, err := db.CreateAPIKey(nil)
	require.NoError(t, err)
	require.NoError(t, db.DestroyAPIKey(*gone))

	return pak.ID
}

func insertCredentialKind(db *gorm.DB, kind types.CredentialKind, identifier string) error {
	return db.Exec(`INSERT INTO credentials (kind, identifier, hash) VALUES (?, ?, ?)`,
		kind, identifier, "$sha256$00").Error
}

func credentialsSQLiteSchema(t *testing.T, db *gorm.DB) []string {
	t.Helper()

	var rows []string

	require.NoError(t, db.Raw(`SELECT type || ' ' || name || ' ' || sql FROM sqlite_master
WHERE tbl_name = 'credentials' ORDER BY type, name`).Scan(&rows).Error)

	return rows
}

// TestSQLiteSCIMTokenKindMigration puts the credentials table back to its
// pre-scim CHECK constraint, reopens the database so the migration runs, and
// asserts every credential and foreign key survived the table rebuild, the
// AUTOINCREMENT counter was kept, and the schema matches a fresh database
// (NewHeadscaleDatabase also validates it against schema.sql with squibble).
func TestSQLiteSCIMTokenKindMigration(t *testing.T) {
	dbPath := t.TempDir() + "/headscale_test.db"

	hsdb, err := NewHeadscaleDatabase(sqliteTestConfig(dbPath))
	require.NoError(t, err)

	fresh := credentialsSQLiteSchema(t, hsdb.DB)
	nodeKeyID := seedCredentialReferences(t, hsdb)

	var before []types.Credential
	require.NoError(t, hsdb.DB.Order("id").Find(&before).Error)

	seqBefore, err := sqliteSequence(hsdb.DB, "credentials")
	require.NoError(t, err)
	require.Greater(t, uint64(seqBefore), before[len(before)-1].ID) //nolint:gosec // non-negative counter

	// Downgrade the constraint with the same rebuild the migration uses.
	oldDDL := strings.Replace(credentialsDDLSQLite, credentialKindsSQL, preSCIMKinds, 1)
	require.NotEqual(t, credentialsDDLSQLite, oldDDL)
	require.NoError(t, hsdb.DB.Transaction(func(tx *gorm.DB) error {
		return rebuildCredentialsTableSQLite(tx, oldDDL)
	}))
	require.Error(t, insertCredentialKind(hsdb.DB, types.CredentialSCIMToken, "pre000000001"),
		"the downgraded table must reject scim_token")
	require.NoError(t, hsdb.DB.Exec(`DELETE FROM migrations WHERE id = ?`, scimTokenMigrationID).Error)
	require.NoError(t, hsdb.Close())

	hsdb, err = NewHeadscaleDatabase(sqliteTestConfig(dbPath))
	require.NoError(t, err)

	assert.Equal(t, fresh, credentialsSQLiteSchema(t, hsdb.DB), "migrated schema matches fresh")

	var after []types.Credential
	require.NoError(t, hsdb.DB.Order("id").Find(&after).Error)
	assert.Equal(t, before, after, "every credential survives the rebuild")

	seqAfter, err := sqliteSequence(hsdb.DB, "credentials")
	require.NoError(t, err)
	assert.Equal(t, seqBefore, seqAfter)

	var violations int64
	require.NoError(t, hsdb.DB.Raw(`SELECT COUNT(*) FROM pragma_foreign_key_check`).Scan(&violations).Error)
	assert.Zero(t, violations)

	var fks []string
	require.NoError(t, hsdb.DB.Raw(`SELECT "table" FROM pragma_foreign_key_list('nodes')`).Scan(&fks).Error)
	assert.Contains(t, fks, "credentials", "nodes still references credentials")

	var foreignKeys int
	require.NoError(t, hsdb.DB.Raw(`PRAGMA foreign_keys`).Scan(&foreignKeys).Error)
	assert.Equal(t, 1, foreignKeys, "foreign keys stay enabled")

	nodes, err := Read(hsdb.DB, func(rx *gorm.DB) (types.Nodes, error) {
		return ListNodes(rx)
	})
	require.NoError(t, err)
	require.Len(t, nodes, 1)
	require.NotNil(t, nodes[0].AuthKey)
	assert.Equal(t, nodeKeyID, nodes[0].AuthKey.ID)

	// The foreign key is enforced against the rebuilt table.
	require.Error(t, hsdb.DB.Exec(`DELETE FROM credentials WHERE id = ?`, nodeKeyID).Error)

	_, tok, err := hsdb.CreateSCIMToken("after", nil)
	require.NoError(t, err)
	assert.Greater(t, tok.ID, uint64(seqBefore), "deleted ids are not reused") //nolint:gosec // non-negative counter

	requireCredentialConstraints(t, hsdb.DB)
}

// TestSQLiteSCIMTokenKindMigrationIsAtomic fails the rebuild after the old
// table is dropped and asserts the transaction restored it untouched.
func TestSQLiteSCIMTokenKindMigrationIsAtomic(t *testing.T) {
	hsdb, err := newSQLiteTestDB()
	require.NoError(t, err)

	seedCredentialReferences(t, hsdb)

	var before []types.Credential
	require.NoError(t, hsdb.DB.Order("id").Find(&before).Error)

	err = hsdb.DB.Transaction(func(tx *gorm.DB) error {
		return rebuildCredentialsTableSQLite(tx, "CREATE TABLE credentials(this is not sql")
	})
	require.Error(t, err)

	var after []types.Credential
	require.NoError(t, hsdb.DB.Order("id").Find(&after).Error)
	assert.Equal(t, before, after)

	var backups int64
	require.NoError(t, hsdb.DB.Raw(`SELECT COUNT(*) FROM sqlite_master WHERE name = 'credentials_rebuild'`).
		Scan(&backups).Error)
	assert.Zero(t, backups)
}

func postgresKindCheck(t *testing.T, db *gorm.DB) []string {
	t.Helper()

	var defs []string

	require.NoError(t, db.Raw(`SELECT conname || ': ' || pg_get_constraintdef(oid) FROM pg_constraint
WHERE conrelid = 'credentials'::regclass AND contype = 'c'
  AND pg_get_constraintdef(oid) LIKE '%kind%' ORDER BY conname`).Scan(&defs).Error)

	return defs
}

// TestPostgresSCIMTokenKindMigration restores the pre-scim kind constraint,
// reruns the migration, and asserts the constraint matches a fresh database.
// The downgraded constraint is either under its generated name or renamed, so
// the migration must find it by column, not by name.
func TestPostgresSCIMTokenKindMigration(t *testing.T) {
	for _, oldName := range []string{credentialsKindCheckPostgres, "Legacy Kind Chk"} {
		t.Run(oldName, func(t *testing.T) {
			testPostgresSCIMTokenKindMigration(t, oldName)
		})
	}
}

func testPostgresSCIMTokenKindMigration(t *testing.T, oldName string) {
	t.Helper()

	u := newPostgresDBForTest(t)

	hsdb := newHeadscaleDBFromPostgresURL(t, u)

	fresh := postgresKindCheck(t, hsdb.DB)
	require.Len(t, fresh, 1)
	assert.True(t, strings.HasPrefix(fresh[0], credentialsKindCheckPostgres+": "), fresh[0])
	assert.Contains(t, fresh[0], "scim_token")

	nodeKeyID := seedCredentialReferences(t, hsdb)

	var before []types.Credential
	require.NoError(t, hsdb.DB.Order("id").Find(&before).Error)

	require.NoError(t, hsdb.DB.Exec(`ALTER TABLE credentials
  DROP CONSTRAINT `+credentialsKindCheckPostgres+`,
  ADD CONSTRAINT `+quotePostgresIdent(oldName)+` CHECK(kind IN (`+preSCIMKinds+`))`).Error)
	require.Error(t, insertCredentialKind(hsdb.DB, types.CredentialSCIMToken, "pre000000001"),
		"the downgraded table must reject scim_token")
	require.NoError(t, hsdb.DB.Exec(`DELETE FROM migrations WHERE id = ?`, scimTokenMigrationID).Error)
	require.NoError(t, hsdb.Close())

	hsdb = newHeadscaleDBFromPostgresURL(t, u)

	assert.Equal(t, fresh, postgresKindCheck(t, hsdb.DB), "migrated constraint matches fresh")

	var after []types.Credential
	require.NoError(t, hsdb.DB.Order("id").Find(&after).Error)
	require.Len(t, after, len(before))

	for i := range before {
		assert.Equal(t, before[i].ID, after[i].ID)
		assert.Equal(t, before[i].Kind, after[i].Kind)
		assert.Equal(t, before[i].Identifier, after[i].Identifier)
	}

	nodes, err := Read(hsdb.DB, func(rx *gorm.DB) (types.Nodes, error) {
		return ListNodes(rx)
	})
	require.NoError(t, err)
	require.Len(t, nodes, 1)
	require.NotNil(t, nodes[0].AuthKey)
	assert.Equal(t, nodeKeyID, nodes[0].AuthKey.ID)

	secret, _, err := hsdb.CreateSCIMToken("after", nil)
	require.NoError(t, err)
	_, err = hsdb.AuthenticateSCIMToken(secret)
	require.NoError(t, err)

	requireCredentialConstraints(t, hsdb.DB)
}
