package db

import (
	"errors"
	"fmt"
	"strings"

	"gorm.io/gorm"
)

var (
	errCredentialsRebuildFKViolation = errors.New("credentials rebuild left foreign key violations")
	errCredentialsKindCheck          = errors.New("unexpected credentials kind CHECK constraints")
)

// credentialsKindCheckPostgres is the name Postgres gives the inline column
// CHECK on credentials.kind in [credentialsDDLPostgres] (<table>_<column>_check).
// The migration re-creates it under the same name, so fresh and upgraded
// databases carry an identical constraint.
const credentialsKindCheckPostgres = "credentials_kind_check"

// credentialColumns is every column of the credentials table, in DDL order.
//
//nolint:gosec // column list, not a credential
const credentialColumns = `id, kind, identifier, hash, user_id, description, scopes, tags, reusable, ephemeral, used, last_seen, client_id, created_at, expiration, revoked`

// allowSCIMTokenKind widens the credentials.kind CHECK constraint to admit
// scim_token rows, leaving the table exactly as [credentialsDDLSQLite] /
// [credentialsDDLPostgres] create it on a fresh database. It is idempotent:
// a table that already admits scim_token (fresh databases, or ones whose
// 202609231200-create-credentials ran with the widened DDL) is left alone on
// SQLite and gets the same constraint back on Postgres.
func allowSCIMTokenKind(tx *gorm.DB) error {
	if tx.Name() != gormDialectSQLite {
		return tx.Transaction(widenKindCheckPostgres)
	}

	var ddl string

	err := tx.Raw(`SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'credentials'`).
		Scan(&ddl).Error
	if err != nil {
		return fmt.Errorf("reading credentials schema: %w", err)
	}

	if strings.Contains(ddl, `'scim_token'`) {
		return nil
	}

	return tx.Transaction(func(tx *gorm.DB) error {
		return rebuildCredentialsTableSQLite(tx, credentialsDDLSQLite)
	})
}

// kindChecksPostgres lists the CHECK constraints of the credentials table that
// constrain only its kind column, as (name, definition).
const kindChecksPostgres = `SELECT c.conname AS name, pg_get_constraintdef(c.oid) AS def
FROM pg_constraint c
JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = c.conkey[1]
WHERE c.conrelid = 'credentials'::regclass AND c.contype = 'c'
  AND cardinality(c.conkey) = 1 AND a.attname = 'kind'
ORDER BY c.conname`

type pgCheck struct {
	Name string
	Def  string
}

// widenKindCheckPostgres replaces every CHECK constraint on credentials.kind,
// whatever its name, with credentials_kind_check admitting every kind, then
// verifies exactly that one constraint remains. Matching by column rather than
// by name means a renamed constraint is replaced instead of left behind to
// keep rejecting scim_token.
func widenKindCheckPostgres(tx *gorm.DB) error {
	var checks []pgCheck

	err := tx.Raw(kindChecksPostgres).Scan(&checks).Error
	if err != nil {
		return fmt.Errorf("reading credentials kind constraints: %w", err)
	}

	for _, c := range checks {
		err := tx.Exec(`ALTER TABLE credentials DROP CONSTRAINT ` + quotePostgresIdent(c.Name)).Error
		if err != nil {
			return fmt.Errorf("dropping credentials constraint %q: %w", c.Name, err)
		}
	}

	err = tx.Exec(`ALTER TABLE credentials ADD CONSTRAINT ` + credentialsKindCheckPostgres +
		` CHECK(kind IN (` + credentialKindsSQL + `))`).Error
	if err != nil {
		return fmt.Errorf("adding credentials kind constraint: %w", err)
	}

	checks = nil

	err = tx.Raw(kindChecksPostgres).Scan(&checks).Error
	if err != nil {
		return fmt.Errorf("verifying credentials kind constraint: %w", err)
	}

	if len(checks) != 1 || checks[0].Name != credentialsKindCheckPostgres ||
		!strings.Contains(checks[0].Def, "'scim_token'") {
		return fmt.Errorf("%w: %v", errCredentialsKindCheck, checks)
	}

	return nil
}

// quotePostgresIdent quotes a Postgres identifier.
func quotePostgresIdent(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}

// rebuildCredentialsTableSQLite replaces the credentials table with one created
// by ddl, keeping every row, id, index and the AUTOINCREMENT counter. SQLite
// cannot alter a CHECK constraint, so this follows the table-rebuild procedure
// of https://www.sqlite.org/lang_altertable.html#otheralter, adapted so foreign
// keys stay enabled (db.go forbids disabling them). The caller must run it in a
// transaction.
//
// nodes.auth_key_id references credentials(id), which rules out the documented
// "create new, copy, drop old, rename new" order: with foreign keys on, a
// rename rewrites the REFERENCES clauses of other tables, and copying before
// the drop leaves nothing to clear the violations the drop records. Instead:
//
//  1. defer foreign key enforcement to COMMIT (PRAGMA defer_foreign_keys; it
//     resets itself at the end of the transaction);
//  2. copy the rows into a constraint-free holding table;
//  3. drop credentials — its implicit DELETE counts one deferred violation per
//     node pointing at a credential;
//  4. create credentials from ddl under the same name, so nodes' REFERENCES
//     credentials(id) now resolves to it;
//  5. copy the rows back — each re-inserted parent row cancels the violations
//     of the nodes pointing at it;
//  6. drop the holding table, recreate the indexes, restore the sequence and
//     assert PRAGMA foreign_key_check is clean for nodes and credentials.
//
// If any node referenced a missing credential, the deferred counter stays
// non-zero and COMMIT fails, rolling the whole rebuild back.
func rebuildCredentialsTableSQLite(tx *gorm.DB, ddl string) error {
	// Dropping the table deletes its AUTOINCREMENT counter; carry it over so
	// ids of deleted credentials are never handed out again.
	seq, err := sqliteSequence(tx, "credentials")
	if err != nil {
		return err
	}

	stmts := make([]string, 0, 6+len(credentialIndexes))
	stmts = append(stmts,
		`PRAGMA defer_foreign_keys = ON`,
		`CREATE TABLE credentials_rebuild AS SELECT `+credentialColumns+` FROM credentials`,
		`DROP TABLE credentials`,
		ddl,
		`INSERT INTO credentials (`+credentialColumns+`)
SELECT `+credentialColumns+` FROM credentials_rebuild ORDER BY id`,
		`DROP TABLE credentials_rebuild`,
	)
	stmts = append(stmts, credentialIndexes...)

	for _, stmt := range stmts {
		err := tx.Exec(stmt).Error
		if err != nil {
			return fmt.Errorf("rebuilding credentials table: %w", err)
		}
	}

	err = raiseSQLiteSequence(tx, "credentials", seq)
	if err != nil {
		return err
	}

	// Only the two tables the rebuild touched: nodes (children of credentials)
	// and credentials (children of users). A violation elsewhere predates this
	// migration and is not its to report.
	var violations int64

	err = tx.Raw(`SELECT (SELECT COUNT(*) FROM pragma_foreign_key_check('nodes'))
  + (SELECT COUNT(*) FROM pragma_foreign_key_check('credentials'))`).Scan(&violations).Error
	if err != nil {
		return fmt.Errorf("checking foreign keys after credentials rebuild: %w", err)
	}

	if violations > 0 {
		return fmt.Errorf("%w: %d", errCredentialsRebuildFKViolation, violations)
	}

	return nil
}
