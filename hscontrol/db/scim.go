package db

import (
	"fmt"
	"strings"

	"gorm.io/gorm"
)

// Column names written in more than one place.
const (
	colDisplayName  = "display_name"
	colExternalID   = "external_id"
	colExternalName = "external_name"
)

// scimUserIndexes are the users indexes added for SCIM, created by InitSchema
// and the migration. They must match schema.sql.
var scimUserIndexes = []string{
	`CREATE UNIQUE INDEX idx_users_external_id ON users(external_id) WHERE external_id IS NOT NULL`,
	`CREATE UNIQUE INDEX idx_users_scim_user_name_key ON users(scim_user_name_key) WHERE scim_user_name_key IS NOT NULL`,
}

// scimGroupIndexes are the groups indexes added for SCIM, created with the
// groups table (see groupIndexes) and by the migration.
var scimGroupIndexes = []string{
	`CREATE UNIQUE INDEX idx_groups_external_id ON groups(external_id) WHERE external_id IS NOT NULL`,
	`CREATE UNIQUE INDEX idx_groups_external_name ON groups(external_name) WHERE external_name IS NOT NULL`,
}

// scimUserColumns and scimGroupColumns are added to tables created before
// SCIM. The groups.source DEFAULT marks existing rows as created by OIDC
// logins, which they were, and lets SQLite add the NOT NULL column.
var (
	scimUserColumns = []struct{ name, ddl string }{
		{"provisioned_by", `ALTER TABLE users ADD COLUMN provisioned_by text`},
		{"scim_user_name", `ALTER TABLE users ADD COLUMN scim_user_name text`},
		{"scim_user_name_key", `ALTER TABLE users ADD COLUMN scim_user_name_key text`},
		{"scim_email", `ALTER TABLE users ADD COLUMN scim_email text`},
		{"scim_display_name", `ALTER TABLE users ADD COLUMN scim_display_name text`},
		{colExternalID, `ALTER TABLE users ADD COLUMN external_id text`},
		{"given_name", `ALTER TABLE users ADD COLUMN given_name text`},
		{"family_name", `ALTER TABLE users ADD COLUMN family_name text`},
	}
	scimGroupColumns = []struct{ name, ddl string }{
		{colDisplayName, `ALTER TABLE groups ADD COLUMN display_name text`},
		{colExternalID, `ALTER TABLE groups ADD COLUMN external_id text`},
		{colExternalName, `ALTER TABLE groups ADD COLUMN external_name text`},
		{"source", `ALTER TABLE groups ADD COLUMN source text NOT NULL DEFAULT 'oidc'`},
	}
)

// migrateSCIMColumns adds the SCIM columns and indexes to users and groups,
// with explicit DDL valid on both SQLite and Postgres. Each step is skipped
// when already applied, as on tables created with the current schema.
func migrateSCIMColumns(tx *gorm.DB) error {
	columns := map[string][]struct{ name, ddl string }{"users": scimUserColumns, "groups": scimGroupColumns}
	for _, table := range []string{"users", "groups"} {
		for _, col := range columns[table] {
			if tx.Migrator().HasColumn(table, col.name) {
				continue
			}

			err := tx.Exec(col.ddl).Error
			if err != nil {
				return fmt.Errorf("adding %s to %s: %w", col.name, table, err)
			}
		}
	}

	indexes := map[string][]string{"users": scimUserIndexes, "groups": scimGroupIndexes}
	for _, table := range []string{"users", "groups"} {
		for _, stmt := range indexes[table] {
			name := strings.Fields(stmt)[3]
			if tx.Migrator().HasIndex(table, name) {
				continue
			}

			err := tx.Exec(stmt).Error
			if err != nil {
				return fmt.Errorf("creating index %s: %w", name, err)
			}
		}
	}

	return nil
}
