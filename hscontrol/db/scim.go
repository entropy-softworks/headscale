package db

import (
	"database/sql"
	"errors"
	"fmt"
	"net/mail"
	"slices"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Errors returned by the SCIM persistence functions. A SCIM handler maps
// ErrSCIMConflict to 409 (scimType uniqueness), ErrSCIMInvalid to 400
// (scimType invalidValue), and ErrUserNotFound and ErrGroupNotFound to 404.
var (
	// ErrSCIMConflict is returned when a write would give a SCIM user or
	// group a userName, externalId or name another resource already holds.
	ErrSCIMConflict = errors.New("scim: resource conflicts with an existing one")
	// ErrSCIMInvalid is returned for an attribute value that cannot be
	// stored, such as an empty userName or a group name containing '@'.
	ErrSCIMInvalid = errors.New("scim: invalid attribute value")
	// ErrGroupNotFound is returned when no SCIM-managed group matches.
	ErrGroupNotFound = errors.New("group not found")
	// ErrSCIMUserLinked is returned when linking a SCIM user that is already
	// linked to a login.
	ErrSCIMUserLinked = errors.New("scim: user is already linked to a login")
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

// isUniqueViolation reports whether err, returned by a write through tx,
// violates a unique index. It relies on the dialect's typed error
// translation (the SQLite constraint code, Postgres SQLSTATE 23505), not on
// error text. The explicit checks before each write catch conflicts; this
// catches a concurrent write racing them.
func isUniqueViolation(tx *gorm.DB, err error) bool {
	if t, ok := tx.Dialector.(gorm.ErrorTranslator); ok {
		err = t.Translate(err)
	}

	return errors.Is(err, gorm.ErrDuplicatedKey)
}

// writeError wraps a failed write: a unique violation is ErrSCIMConflict.
func writeError(tx *gorm.DB, err error, what string) error {
	if isUniqueViolation(tx, err) {
		return fmt.Errorf("%w: %s: %w", ErrSCIMConflict, what, err)
	}

	return fmt.Errorf("%s: %w", what, err)
}

func nullString(s string) sql.NullString {
	return sql.NullString{String: s, Valid: s != ""}
}

// pageBounds converts a SCIM startIndex (1-based; values below 1 mean 1) and
// count into an offset and limit, and reports whether any row is wanted: a
// count of 0 or less asks only for the total (RFC 7644, section 3.4.2.4).
func pageBounds(startIndex, count int) (int, int, bool) {
	return max(startIndex, 1) - 1, count, count > 0
}

// SCIM users.
//
// A SCIM user is a [types.User] with ProvisionedBy 'scim'; its SCIM id is the
// user id. It is created unlinked (provider_identifier NULL) and linked to an
// OIDC identity at the user's first login, see [LinkSCIMUser]. The SCIM
// attributes live in their own columns (see [types.SCIMUserAttributes]);
// while the user is unlinked they are also written to the core columns, with
// Name the case-folded userName. No SCIM write ever gives an unlinked user a
// name or email another user has, so policy user references stay
// unambiguous.

// foldUserName is the case folding of userName keys and of the name and
// email comparisons against existing users.
func foldUserName(s string) string {
	return strings.ToLower(s)
}

// SCIMUserFilter selects SCIM users by attribute equality; empty fields match
// all. UserName compares case-insensitively (Unicode, folded in Go), Email
// case-insensitively with the database's LOWER (ASCII only on SQLite), and
// ExternalID exactly (it is caseExact in RFC 7643).
type SCIMUserFilter struct {
	UserName   string
	ExternalID string
	Email      string
}

func (f SCIMUserFilter) scope(tx *gorm.DB) *gorm.DB {
	tx = tx.Where("users.provisioned_by = ?", types.ProvisionedBySCIM)
	if f.UserName != "" {
		tx = tx.Where("users.scim_user_name_key = ?", foldUserName(f.UserName))
	}

	if f.ExternalID != "" {
		tx = tx.Where("users.external_id = ?", f.ExternalID)
	}

	if f.Email != "" {
		tx = tx.Where("LOWER(users.scim_email) = LOWER(?)", f.Email)
	}

	return tx
}

// normalizeSCIMUser trims attrs and validates them.
func normalizeSCIMUser(attrs types.SCIMUserAttributes) (types.SCIMUserAttributes, error) {
	attrs.UserName = strings.TrimSpace(attrs.UserName)
	attrs.ExternalID = strings.TrimSpace(attrs.ExternalID)
	attrs.Email = strings.TrimSpace(attrs.Email)

	if attrs.UserName == "" {
		return attrs, fmt.Errorf("%w: userName is required", ErrSCIMInvalid)
	}

	if attrs.Email != "" && !isEmailAddress(attrs.Email) {
		return attrs, fmt.Errorf("%w: email %q is not an email address", ErrSCIMInvalid, attrs.Email)
	}

	return attrs, nil
}

// coreEmail is the email an unlinked SCIM user gets: the SCIM email, or an
// email-shaped userName.
func coreEmail(attrs types.SCIMUserAttributes) string {
	if attrs.Email == "" && isEmailAddress(attrs.UserName) {
		return attrs.UserName
	}

	return attrs.Email
}

func isEmailAddress(s string) bool {
	addr, err := mail.ParseAddress(s)

	return err == nil && addr.Address == s
}

// checkSCIMUserUnique returns ErrSCIMConflict if a user other than self holds
// attrs' userName or externalId.
func checkSCIMUserUnique(tx *gorm.DB, self uint, attrs types.SCIMUserAttributes) error {
	checks := []struct{ what, column, value string }{
		{"userName", "scim_user_name_key", foldUserName(attrs.UserName)},
		{"externalId", colExternalID, attrs.ExternalID},
	}

	for _, c := range checks {
		if c.value == "" {
			continue
		}

		var n int64

		err := tx.Model(&types.User{}).Where("id != ? AND "+c.column+" = ?", self, c.value).Count(&n).Error
		if err != nil {
			return fmt.Errorf("checking %s uniqueness: %w", c.what, err)
		}

		if n > 0 {
			return fmt.Errorf("%w: %s %q is taken", ErrSCIMConflict, c.what, c.value)
		}
	}

	return nil
}

// usersNamedOrMailed returns the users other than self whose name or email,
// case-folded, is one of keys. The comparison runs in Go so it folds the
// same way on both databases; it reads every user, which a provisioning
// write can afford.
func usersNamedOrMailed(tx *gorm.DB, self uint, keys ...string) ([]types.User, error) {
	var all []types.User

	err := tx.Select("id", "name", "email", "provider", "provider_identifier", "provisioned_by").
		Where("id != ?", self).Find(&all).Error
	if err != nil {
		return nil, fmt.Errorf("loading users: %w", err)
	}

	var out []types.User

	for _, u := range all {
		if slices.Contains(keys, foldUserName(u.Name)) || (u.Email != "" && slices.Contains(keys, foldUserName(u.Email))) {
			out = append(out, u)
		}
	}

	return out, nil
}

// identityKeys returns the folded name and email an unlinked user with attrs
// would have.
func identityKeys(attrs types.SCIMUserAttributes) []string {
	keys := []string{foldUserName(attrs.UserName)}
	if email := foldUserName(coreEmail(attrs)); email != "" && email != keys[0] {
		keys = append(keys, email)
	}

	return keys
}

// writeSCIMUser stores attrs on user and marks it SCIM-provisioned. The core
// name, email and display name are only written while the user is unlinked:
// once linked, the login owns them. With onlyUnmanaged, the write applies
// only if the user is not yet SCIM-provisioned, and ErrSCIMConflict is
// returned otherwise, so two concurrent adoptions cannot both succeed.
func writeSCIMUser(tx *gorm.DB, user *types.User, attrs types.SCIMUserAttributes, onlyUnmanaged bool) error {
	cols := map[string]any{
		"provisioned_by":     types.ProvisionedBySCIM,
		"scim_user_name":     attrs.UserName,
		"scim_user_name_key": foldUserName(attrs.UserName),
		"scim_email":         attrs.Email,
		"scim_display_name":  attrs.DisplayName,
		colExternalID:        nullString(attrs.ExternalID),
		"given_name":         attrs.GivenName,
		"family_name":        attrs.FamilyName,
		"updated_at":         time.Now().UTC(),
	}
	if !user.ProviderIdentifier.Valid {
		cols["name"] = foldUserName(attrs.UserName)
		cols["email"] = coreEmail(attrs)
		cols[colDisplayName] = attrs.DisplayName
	}

	q := tx.Model(&types.User{}).Where("id = ?", user.ID)
	if onlyUnmanaged {
		q = q.Where("provisioned_by IS NULL")
	}

	res := q.UpdateColumns(cols)
	if res.Error != nil {
		return writeError(tx, res.Error, fmt.Sprintf("writing SCIM user %d", user.ID))
	}

	if res.RowsAffected == 0 {
		return fmt.Errorf("%w: user %d is already managed by SCIM", ErrSCIMConflict, user.ID)
	}

	return nil
}

// insertSCIMUser inserts user, reporting a unique violation as
// ErrSCIMConflict.
func insertSCIMUser(tx *gorm.DB, user *types.User) error {
	err := tx.Create(user).Error
	if err != nil {
		return writeError(tx, err, "creating SCIM user")
	}

	return nil
}

// CreateSCIMUser provisions a user from attrs (Active is ignored; see
// [types.SCIMUserAttributes]) and reports whether an existing user was
// adopted rather than created.
//
// It never creates a user whose name or email (case-insensitively) another
// user already has. When exactly one such user exists, it is an OIDC user
// not yet managed by SCIM whose stored email equals the userName, and adopt
// is set, that user is adopted: it keeps its login, nodes and core columns,
// and SCIM manages it from now on. Without adoption, provisioning a
// directory into a running tailnet would duplicate everyone who has already
// logged in, and deprovisioning them would not cut them off. Adoption is off
// unless scim.adopt_existing_users is set.
//
// Adoption matches the email only, never the name: an OIDC user's name comes
// from preferred_username, which is not unique and which several identity
// providers let users choose, so matching it would let anyone take over the
// identity being provisioned. Logins store an email only once the provider
// has verified it, unless email_verified_required is false: adoption then
// trusts the provider's unverified emails. Any OIDC user is a candidate: the
// db layer does not know the configured issuer, so a deployment with several
// OIDC issuers must disable adoption or keep emails distinct.
//
// Every other overlap, with a local user, a SCIM user, several users, or an
// OIDC user matching only by name, is ErrSCIMConflict (409), as is a taken
// userName (case-insensitively) or externalId; ErrSCIMInvalid is an empty
// userName or a malformed email.
func CreateSCIMUser(tx *gorm.DB, attrs types.SCIMUserAttributes, adopt bool) (*types.User, bool, error) {
	attrs, err := normalizeSCIMUser(attrs)
	if err != nil {
		return nil, false, err
	}

	err = checkSCIMUserUnique(tx, 0, attrs)
	if err != nil {
		return nil, false, err
	}

	keys := identityKeys(attrs)

	existing, err := usersNamedOrMailed(tx, 0, keys...)
	if err != nil {
		return nil, false, err
	}

	if len(existing) > 0 {
		user, err := adoptSCIMUser(tx, existing, keys[0], attrs, adopt)

		return user, err == nil, err
	}

	user := types.User{
		Name:            keys[0],
		DisplayName:     attrs.DisplayName,
		Email:           coreEmail(attrs),
		ProvisionedBy:   nullString(types.ProvisionedBySCIM),
		SCIMUserName:    nullString(attrs.UserName),
		SCIMUserNameKey: nullString(keys[0]),
		SCIMEmail:       attrs.Email,
		SCIMDisplayName: attrs.DisplayName,
		ExternalID:      nullString(attrs.ExternalID),
		GivenName:       attrs.GivenName,
		FamilyName:      attrs.FamilyName,
	}

	err = insertSCIMUser(tx, &user)
	if err != nil {
		return nil, false, err
	}

	created, err := GetUserByID(tx, types.UserID(user.ID))

	return created, false, err
}

// adoptSCIMUser adopts the one user in existing if [CreateSCIMUser] allows
// it, and otherwise explains the conflict.
func adoptSCIMUser(tx *gorm.DB, existing []types.User, key string, attrs types.SCIMUserAttributes, adopt bool) (*types.User, error) {
	if len(existing) > 1 {
		return nil, fmt.Errorf("%w: %d users already have the name or email of userName %q", ErrSCIMConflict, len(existing), attrs.UserName)
	}

	u := existing[0]

	switch {
	case u.IsSCIMProvisioned():
		return nil, fmt.Errorf("%w: SCIM user %d already has the name or email %q", ErrSCIMConflict, u.ID, attrs.UserName)
	case u.Provider != util.RegisterMethodOIDC || !u.ProviderIdentifier.Valid:
		return nil, fmt.Errorf("%w: local user %d (%s) has the name or email of userName %q; rename or delete it first", ErrSCIMConflict, u.ID, u.Name, attrs.UserName)
	case u.Email == "" || foldUserName(u.Email) != key ||
		types.FoldGroupName(u.Email) != types.FoldGroupName(attrs.UserName):
		// Only the email identifies the person; a name may be chosen by
		// anyone (see CreateSCIMUser). The ASCII-only comparison, the one
		// login linking uses, keeps a lookalike such as the Kelvin sign
		// from adopting the account with the plain ASCII email.
		return nil, fmt.Errorf("%w: OIDC user %d has the name or email of userName %q but not it as email; "+
			"adoption matches emails only", ErrSCIMConflict, u.ID, attrs.UserName)
	case !adopt:
		return nil, fmt.Errorf("%w: OIDC user %d has the name or email %q and adoption is disabled", ErrSCIMConflict, u.ID, attrs.UserName)
	}

	err := writeSCIMUser(tx, &u, attrs, true)
	if err != nil {
		return nil, err
	}

	return GetUserByID(tx, types.UserID(u.ID))
}

// ReplaceSCIMUser replaces all of a SCIM user's SCIM-managed attributes with
// attrs (PUT semantics: empty attributes are cleared; Active is ignored). It
// returns ErrUserNotFound when uid is not a SCIM user, ErrSCIMConflict when
// the userName or externalId is taken or, for an unlinked user, the new name
// or email is another user's, and ErrSCIMInvalid as [CreateSCIMUser] does.
func ReplaceSCIMUser(tx *gorm.DB, uid types.UserID, attrs types.SCIMUserAttributes) (*types.User, error) {
	user, err := GetSCIMUserByID(tx, uid)
	if err != nil {
		return nil, err
	}

	attrs, err = normalizeSCIMUser(attrs)
	if err != nil {
		return nil, err
	}

	err = checkSCIMUserUnique(tx, user.ID, attrs)
	if err != nil {
		return nil, err
	}

	if !user.ProviderIdentifier.Valid {
		others, err := usersNamedOrMailed(tx, user.ID, identityKeys(attrs)...)
		if err != nil {
			return nil, err
		}

		if len(others) > 0 {
			return nil, fmt.Errorf("%w: user %d already has the name or email of userName %q", ErrSCIMConflict, others[0].ID, attrs.UserName)
		}
	}

	err = writeSCIMUser(tx, user, attrs, false)
	if err != nil {
		return nil, err
	}

	return GetUserByID(tx, uid)
}

// PatchSCIMUser applies fn to the SCIM user's current attributes and stores
// the result as [ReplaceSCIMUser] does; it is how a SCIM PATCH is applied.
// An error from fn aborts the update and is returned as is.
func PatchSCIMUser(tx *gorm.DB, uid types.UserID, fn func(*types.SCIMUserAttributes) error) (*types.User, error) {
	user, err := GetSCIMUserByID(tx, uid)
	if err != nil {
		return nil, err
	}

	attrs := user.SCIMAttributes()

	err = fn(&attrs)
	if err != nil {
		return nil, err
	}

	return ReplaceSCIMUser(tx, uid, attrs)
}

func firstSCIMUser(tx *gorm.DB, filter SCIMUserFilter, query string, args ...any) (*types.User, error) {
	var user types.User

	q := preloadUserGroups(tx, "").Scopes(filter.scope)
	if query != "" {
		q = q.Where(query, args...)
	}

	err := q.Order("id").First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}

		return nil, fmt.Errorf("loading SCIM user: %w", err)
	}

	return &user, nil
}

// GetSCIMUserByID returns the SCIM user uid, or ErrUserNotFound when there is
// none or the user is not managed by SCIM.
func GetSCIMUserByID(tx *gorm.DB, uid types.UserID) (*types.User, error) {
	return firstSCIMUser(tx, SCIMUserFilter{}, "users.id = ?", uint(uid))
}

// GetSCIMUserByExternalID returns the SCIM user with the externalId (exact
// match), or ErrUserNotFound.
func GetSCIMUserByExternalID(tx *gorm.DB, externalID string) (*types.User, error) {
	if externalID == "" {
		return nil, ErrUserNotFound
	}

	return firstSCIMUser(tx, SCIMUserFilter{ExternalID: externalID}, "")
}

// GetSCIMUserByUserName returns the SCIM user with the userName, compared
// case-insensitively, or ErrUserNotFound.
func GetSCIMUserByUserName(tx *gorm.DB, userName string) (*types.User, error) {
	if userName == "" {
		return nil, ErrUserNotFound
	}

	return firstSCIMUser(tx, SCIMUserFilter{UserName: userName}, "")
}

// ListSCIMUsers returns one page of the SCIM users matching filter, ordered
// by id, and the total number of matches. startIndex is 1-based (values
// below 1 mean 1); a count of 0 or less returns no users, only the total.
// Users not managed by SCIM are never listed.
func ListSCIMUsers(tx *gorm.DB, filter SCIMUserFilter, startIndex, count int) ([]types.User, int64, error) {
	var total int64

	err := tx.Model(&types.User{}).Scopes(filter.scope).Count(&total).Error
	if err != nil {
		return nil, 0, fmt.Errorf("counting SCIM users: %w", err)
	}

	offset, limit, ok := pageBounds(startIndex, count)
	if !ok {
		return nil, total, nil
	}

	users := []types.User{}

	err = preloadUserGroups(tx, "").Scopes(filter.scope).Order("id").Offset(offset).Limit(limit).Find(&users).Error
	if err != nil {
		return nil, 0, fmt.Errorf("listing SCIM users: %w", err)
	}

	return users, total, nil
}

// FindUnlinkedSCIMUserByUserName returns the SCIM user not yet linked to a
// login whose userName equals userName case-insensitively, or
// ErrUserNotFound. An OIDC login with no user of its own calls it with its
// verified email, then [LinkSCIMUser]; verifying the email is the caller's
// job.
func FindUnlinkedSCIMUserByUserName(tx *gorm.DB, userName string) (*types.User, error) {
	if userName == "" {
		return nil, ErrUserNotFound
	}

	return firstSCIMUser(tx, SCIMUserFilter{UserName: userName}, "users.provider_identifier IS NULL")
}

// FindUnlinkedSCIMUsersByEmail returns up to limit SCIM users not yet
// linked to a login whose SCIM email equals email case-insensitively (see
// [SCIMUserFilter]), ordered by id. Unlike userName, the SCIM email is not
// unique, so a caller linking by it must refuse an ambiguous match.
func FindUnlinkedSCIMUsersByEmail(tx *gorm.DB, email string, limit int) ([]types.User, error) {
	if email == "" {
		return nil, nil
	}

	var users []types.User

	err := preloadUserGroups(tx, "").Scopes(SCIMUserFilter{Email: email}.scope).
		Where("users.provider_identifier IS NULL").Order("id").Limit(limit).Find(&users).Error
	if err != nil {
		return nil, fmt.Errorf("finding unlinked SCIM users by email: %w", err)
	}

	return users, nil
}

// FindUnlinkedSCIMUserByExternalID is [FindUnlinkedSCIMUserByUserName] for
// deployments that link by externalId: the login's value of the configured
// claim is compared exactly with the externalId.
func FindUnlinkedSCIMUserByExternalID(tx *gorm.DB, externalID string) (*types.User, error) {
	if externalID == "" {
		return nil, ErrUserNotFound
	}

	return firstSCIMUser(tx, SCIMUserFilter{ExternalID: externalID}, "users.provider_identifier IS NULL")
}

// LinkSCIMUser links the unlinked SCIM user uid to the OIDC identity
// providerIdentifier (see [types.OIDCClaims.Identifier]), making it an OIDC
// user that later logins find by that identifier. From then on the login
// owns the core name, email and display name: the caller applies the
// login's claims as for any OIDC user, and SCIM writes only its own columns.
// It returns ErrUserNotFound when uid is not a SCIM user, ErrSCIMUserLinked
// when it is already linked, and ErrSCIMConflict when another user has the
// identifier.
func LinkSCIMUser(tx *gorm.DB, uid types.UserID, providerIdentifier string) (*types.User, error) {
	if providerIdentifier == "" {
		return nil, fmt.Errorf("%w: empty provider identifier", ErrSCIMInvalid)
	}

	user, err := GetSCIMUserByID(tx, uid)
	if err != nil {
		return nil, err
	}

	if user.ProviderIdentifier.Valid {
		return nil, fmt.Errorf("%w: user %d", ErrSCIMUserLinked, uid)
	}

	var n int64

	err = tx.Model(&types.User{}).Where("provider_identifier = ?", providerIdentifier).Count(&n).Error
	if err != nil {
		return nil, fmt.Errorf("checking provider identifier: %w", err)
	}

	if n > 0 {
		return nil, fmt.Errorf("%w: provider identifier %q belongs to another user", ErrSCIMConflict, providerIdentifier)
	}

	// The IS NULL condition makes the link a compare-and-set: of two logins
	// linking the user concurrently, the one whose update finds it already
	// linked changes nothing and gets ErrSCIMUserLinked, rather than
	// overwriting the winner's identifier.
	res := tx.Model(&types.User{}).
		Where("id = ? AND provider_identifier IS NULL", uint(uid)).
		UpdateColumns(map[string]any{
			"provider_identifier": providerIdentifier,
			"provider":            util.RegisterMethodOIDC,
			"updated_at":          time.Now().UTC(),
		})
	if res.Error != nil {
		return nil, writeError(tx, res.Error, fmt.Sprintf("linking SCIM user %d", uid))
	}

	if res.RowsAffected == 0 {
		return nil, fmt.Errorf("%w: user %d", ErrSCIMUserLinked, uid)
	}

	return GetUserByID(tx, uid)
}

// SCIM groups.
//
// A SCIM group is a [types.Group] with Source 'scim'; its SCIM id is the
// group id. Its Name is the displayName qualified with the SCIM group domain
// (see [types.QualifyGroupName]), so displayNames are unique
// case-insensitively (ASCII folding) across all groups, and its ExternalName
// is the externalId qualified the same way. Policies select it by either, so
// among SCIM groups names and external names share one namespace.
//
// SCIM is authoritative for the groups it manages: only SCIM memberships
// grant them. OIDC logins never write memberships of a SCIM group, nor of an
// OIDC group named like a SCIM group's external name (the Entra case: the
// groups claim carries the object id that is also the SCIM externalId), and
// such memberships are removed when a group becomes SCIM-managed or gains
// the external name, and at startup (see [PurgeNonSCIMMembershipsOfSCIMGroups]).

// SCIMGroupFilter selects SCIM groups by attribute equality; empty fields
// match all. DisplayName compares as the group name does (qualified,
// ASCII case-insensitive), ExternalID exactly.
type SCIMGroupFilter struct {
	DisplayName string
	ExternalID  string
}

// scope restricts tx to the groups filter matches. A DisplayName that cannot
// be qualified matches nothing.
func (f SCIMGroupFilter) scope(domain string) func(*gorm.DB) *gorm.DB {
	return func(tx *gorm.DB) *gorm.DB {
		tx = tx.Where("groups.source = ?", types.GroupSourceSCIM)

		if f.DisplayName != "" {
			name, err := types.QualifyGroupName(f.DisplayName, domain)
			if err != nil {
				return tx.Where("1 = 0")
			}

			tx = tx.Where("groups.name = ?", name)
		}

		if f.ExternalID != "" {
			tx = tx.Where("groups.external_id = ?", f.ExternalID)
		}

		return tx
	}
}

// isDomainError reports whether err is about the domain, a configuration
// problem rather than a bad attribute value.
func isDomainError(err error) bool {
	return errors.Is(err, types.ErrGroupDomainMissing) || errors.Is(err, types.ErrGroupDomainContainsAt)
}

// qualifySCIMGroupName qualifies a displayName. A domain error is returned as
// is; any other is ErrSCIMInvalid.
func qualifySCIMGroupName(name, domain string) (string, error) {
	qualified, err := types.QualifyGroupName(name, domain)
	if err != nil {
		if isDomainError(err) {
			return "", err
		}

		return "", fmt.Errorf("%w: %w", ErrSCIMInvalid, err)
	}

	return qualified, nil
}

// qualifyExternalName returns the policy alias of a group externalId, or ""
// when there is none: no externalId, or one that cannot be qualified, such
// as one containing '@'. Such an externalId is still stored and matched as
// an id; only the alias is missing. A domain error is returned.
func qualifyExternalName(externalID, domain string) (string, error) {
	if externalID == "" {
		return "", nil
	}

	qualified, err := types.QualifyGroupName(externalID, domain)
	if err != nil {
		if isDomainError(err) {
			return "", err
		}

		return "", nil
	}

	return qualified, nil
}

func findGroup(tx *gorm.DB, query string, args ...any) (*types.Group, error) {
	var g types.Group

	err := tx.Where(query, args...).Order("id").Take(&g).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil //nolint:nilnil // absence is not an error here
	}

	if err != nil {
		return nil, fmt.Errorf("loading group: %w", err)
	}

	return &g, nil
}

// checkSCIMGroupNames returns ErrSCIMConflict if giving the group self (0
// for a new group) the name, externalID and externalName would clash with
// another group: a SCIM group's name or external name, or any group's
// external id or external name. A group created by logins with the name is
// not a clash; callers adopt or merge it.
func checkSCIMGroupNames(tx *gorm.DB, self uint, name, externalID, externalName string) error {
	type check struct {
		what, query string
		args        []any
	}

	checks := []check{{
		"displayName", "(name = ? OR external_name = ?) AND source = ?",
		[]any{name, name, types.GroupSourceSCIM},
	}}
	if externalID != "" {
		checks = append(checks, check{"externalId", "external_id = ?", []any{externalID}})
	}

	if externalName != "" {
		checks = append(checks, check{
			"externalId", "external_name = ? OR (name = ? AND source = ?)",
			[]any{externalName, externalName, types.GroupSourceSCIM},
		})
	}

	for _, c := range checks {
		g, err := findGroup(tx.Where("id != ?", self), c.query, c.args...)
		if err != nil {
			return err
		}

		if g != nil {
			return fmt.Errorf("%w: the %s clashes with group %d (%s)", ErrSCIMConflict, c.what, g.ID, g.Name)
		}
	}

	return nil
}

func saveGroupColumns(tx *gorm.DB, gid uint, cols map[string]any) error {
	cols["updated_at"] = time.Now().UTC()

	err := tx.Model(&types.Group{}).Where("id = ?", gid).UpdateColumns(cols).Error
	if err != nil {
		return writeError(tx, err, fmt.Sprintf("updating group %d", gid))
	}

	return nil
}

// insertSCIMGroup inserts g, reporting a unique violation as
// ErrSCIMConflict.
func insertSCIMGroup(tx *gorm.DB, g *types.Group) error {
	err := tx.Create(g).Error
	if err != nil {
		return writeError(tx, err, "creating SCIM group")
	}

	return nil
}

// purgeNonSCIMMemberships removes the memberships that SCIM's authority over
// g excludes: those from other sources of g itself and of the groups created
// by logins that are named like g's external name. It returns the users who
// lost one.
func purgeNonSCIMMemberships(tx *gorm.DB, gid uint) ([]types.UserID, error) {
	g, err := GetSCIMGroupByID(tx, gid)
	if err != nil {
		return nil, err
	}

	groupIDs := []uint{g.ID}

	if g.ExternalName.Valid {
		var alias []uint

		err = tx.Model(&types.Group{}).
			Where("source = ? AND name = ?", types.GroupSourceOIDC, g.ExternalName.String).
			Pluck("id", &alias).Error
		if err != nil {
			return nil, fmt.Errorf("loading groups named %q: %w", g.ExternalName.String, err)
		}

		groupIDs = append(groupIDs, alias...)
	}

	stale := tx.Model(&types.UserGroup{}).Where("group_id IN ? AND source != ?", groupIDs, types.GroupSourceSCIM)

	var ids []uint

	err = stale.Distinct().Pluck("user_id", &ids).Error
	if err != nil {
		return nil, fmt.Errorf("loading memberships to purge: %w", err)
	}

	if len(ids) == 0 {
		return nil, nil
	}

	err = tx.Where("group_id IN ? AND source != ?", groupIDs, types.GroupSourceSCIM).Delete(&types.UserGroup{}).Error
	if err != nil {
		return nil, fmt.Errorf("purging memberships of SCIM group %d: %w", gid, err)
	}

	return toUserIDs(ids), nil
}

func toUserIDs(ids []uint) []types.UserID {
	out := make([]types.UserID, 0, len(ids))
	for _, id := range ids {
		out = append(out, types.UserID(id))
	}

	slices.Sort(out)

	return out
}

// scimManagedNames returns those of names (qualified group names) that are
// the name or external name of a SCIM group; memberships of them are SCIM's
// alone.
func scimManagedNames(tx *gorm.DB, names []string) ([]string, error) {
	if len(names) == 0 {
		return nil, nil
	}

	var byName []string

	err := tx.Model(&types.Group{}).Where("source = ? AND name IN ?", types.GroupSourceSCIM, names).Pluck("name", &byName).Error
	if err != nil {
		return nil, fmt.Errorf("loading SCIM group names: %w", err)
	}

	var byExternal []string

	err = tx.Model(&types.Group{}).Where("source = ? AND external_name IN ?", types.GroupSourceSCIM, names).
		Pluck(colExternalName, &byExternal).Error
	if err != nil {
		return nil, fmt.Errorf("loading SCIM group external names: %w", err)
	}

	return slices.Concat(byName, byExternal), nil
}

// CreateSCIMGroup provisions a group named displayName in domain, with an
// optional externalId, and returns it with the users whose memberships it
// revoked.
//
// A group of that name created by OIDC logins is adopted rather than
// refused: it becomes SCIM-managed and keeps its id. As SCIM is then
// authoritative for it, its OIDC memberships (and those of a login-created
// group named like its external name) are removed at once: its members lose
// the access it grants until the identity provider pushes the group's
// members. [ReleaseSCIMGroup] hands a group back to OIDC. A name or external name
// clashing with a SCIM group's name or external name, or a taken externalId,
// is ErrSCIMConflict; an empty or unqualifiable displayName ErrSCIMInvalid.
func CreateSCIMGroup(tx *gorm.DB, domain, displayName, externalID string) (*types.Group, []types.UserID, error) {
	displayName = strings.TrimSpace(displayName)
	externalID = strings.TrimSpace(externalID)

	name, err := qualifySCIMGroupName(displayName, domain)
	if err != nil {
		return nil, nil, err
	}

	externalName, err := qualifyExternalName(externalID, domain)
	if err != nil {
		return nil, nil, err
	}

	existing, err := findGroup(tx, "name = ?", name)
	if err != nil {
		return nil, nil, err
	}

	var self uint
	if existing != nil {
		self = existing.ID
	}

	err = checkSCIMGroupNames(tx, self, name, externalID, externalName)
	if err != nil {
		return nil, nil, err
	}

	if existing != nil && existing.IsSCIM() {
		return nil, nil, fmt.Errorf("%w: group %q exists", ErrSCIMConflict, displayName)
	}

	if existing != nil {
		err = saveGroupColumns(tx, existing.ID, map[string]any{
			"source":        types.GroupSourceSCIM,
			colDisplayName:  displayName,
			colExternalID:   nullString(externalID),
			colExternalName: nullString(externalName),
		})
	} else {
		now := time.Now().UTC()
		g := types.Group{
			Name:         name,
			DisplayName:  displayName,
			ExternalID:   nullString(externalID),
			ExternalName: nullString(externalName),
			Source:       types.GroupSourceSCIM,
			CreatedAt:    now,
			UpdatedAt:    now,
		}
		err = insertSCIMGroup(tx, &g)
		self = g.ID
	}

	if err != nil {
		return nil, nil, err
	}

	revoked, err := purgeNonSCIMMemberships(tx, self)
	if err != nil {
		return nil, nil, err
	}

	g, err := GetSCIMGroupByID(tx, self)

	return g, revoked, err
}

func firstSCIMGroup(tx *gorm.DB, domain string, filter SCIMGroupFilter, query string, args ...any) (*types.Group, error) {
	var g types.Group

	q := tx.Model(&types.Group{}).Scopes(filter.scope(domain))
	if query != "" {
		q = q.Where(query, args...)
	}

	err := q.Order("id").First(&g).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrGroupNotFound
		}

		return nil, fmt.Errorf("loading SCIM group: %w", err)
	}

	return &g, nil
}

// GetSCIMGroupByID returns the SCIM group id, or ErrGroupNotFound when there
// is none or the group is not managed by SCIM.
func GetSCIMGroupByID(tx *gorm.DB, id uint) (*types.Group, error) {
	return firstSCIMGroup(tx, "", SCIMGroupFilter{}, "groups.id = ?", id)
}

// GetSCIMGroupByExternalID returns the SCIM group with the externalId (exact
// match), or ErrGroupNotFound.
func GetSCIMGroupByExternalID(tx *gorm.DB, externalID string) (*types.Group, error) {
	if externalID == "" {
		return nil, ErrGroupNotFound
	}

	return firstSCIMGroup(tx, "", SCIMGroupFilter{ExternalID: externalID}, "")
}

// GetSCIMGroupByDisplayName returns the SCIM group whose name is displayName
// qualified with domain, or ErrGroupNotFound.
func GetSCIMGroupByDisplayName(tx *gorm.DB, domain, displayName string) (*types.Group, error) {
	if displayName == "" {
		return nil, ErrGroupNotFound
	}

	return firstSCIMGroup(tx, domain, SCIMGroupFilter{DisplayName: displayName}, "")
}

// ListSCIMGroups returns one page of the SCIM groups matching filter, ordered
// by id, and the total number of matches; paging is as for [ListSCIMUsers].
// domain qualifies a DisplayName filter. Groups created by OIDC logins are
// never listed.
func ListSCIMGroups(tx *gorm.DB, domain string, filter SCIMGroupFilter, startIndex, count int) ([]types.Group, int64, error) {
	var total int64

	err := tx.Model(&types.Group{}).Scopes(filter.scope(domain)).Count(&total).Error
	if err != nil {
		return nil, 0, fmt.Errorf("counting SCIM groups: %w", err)
	}

	offset, limit, ok := pageBounds(startIndex, count)
	if !ok {
		return nil, total, nil
	}

	groups := []types.Group{}

	err = tx.Model(&types.Group{}).Scopes(filter.scope(domain)).Order("id").Offset(offset).Limit(limit).Find(&groups).Error
	if err != nil {
		return nil, 0, fmt.Errorf("listing SCIM groups: %w", err)
	}

	return groups, total, nil
}

// SCIMGroupMembers returns the users holding a SCIM membership of each of
// the groups, sorted by id. Groups without members are absent from the map.
func SCIMGroupMembers(tx *gorm.DB, groupIDs ...uint) (map[uint][]types.UserID, error) {
	out := make(map[uint][]types.UserID)
	if len(groupIDs) == 0 {
		return out, nil
	}

	var rows []types.UserGroup

	err := tx.Select("user_id", "group_id").
		Where("source = ? AND group_id IN ?", types.GroupSourceSCIM, groupIDs).
		Order("group_id, user_id").
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("listing SCIM group members: %w", err)
	}

	for _, r := range rows {
		out[r.GroupID] = append(out[r.GroupID], types.UserID(r.UserID))
	}

	return out, nil
}

// GroupMemberIDs returns the users with a membership of the group gid from
// any source, sorted: those whose policy resolution changes with the
// group's names.
func GroupMemberIDs(tx *gorm.DB, gid uint) ([]types.UserID, error) {
	return groupMemberIDs(tx, gid, "")
}

// groupMemberIDs returns the users with a membership of the group, from
// source, or from any source when source is empty.
func groupMemberIDs(tx *gorm.DB, gid uint, source types.GroupSource) ([]types.UserID, error) {
	var ids []uint

	q := tx.Model(&types.UserGroup{}).Where("group_id = ?", gid)
	if source != "" {
		q = q.Where("source = ?", source)
	}

	err := q.Distinct().Pluck("user_id", &ids).Error
	if err != nil {
		return nil, fmt.Errorf("loading members of group %d: %w", gid, err)
	}

	return toUserIDs(ids), nil
}

// ApplySCIMGroupOps applies ops, in order, to the SCIM group gid, and returns
// the users whose memberships or group names changed, whom the policy must
// re-resolve. domain qualifies renames and external ids.
//
//   - A rename to the name of a group created by OIDC logins absorbs that
//     group: it is deleted with its memberships, for the reasons
//     [CreateSCIMGroup] adopts such groups. A name clashing with a SCIM
//     group's name or external name is ErrSCIMConflict.
//   - Setting an external id removes the OIDC memberships of a login-created
//     group named like the new external name. An external id that cannot be
//     qualified (e.g. containing '@') is stored without an alias.
//   - Member ops write only SCIM memberships. Members must be SCIM users,
//     or ErrUserNotFound is returned.
//
// It returns ErrGroupNotFound when gid is not a SCIM group.
func ApplySCIMGroupOps(tx *gorm.DB, domain string, gid uint, ops ...types.SCIMGroupOp) ([]types.UserID, error) {
	var affected []types.UserID

	for _, op := range ops {
		g, err := GetSCIMGroupByID(tx, gid)
		if err != nil {
			return nil, err
		}

		var changed []types.UserID

		switch op.Kind {
		case types.SCIMGroupRename:
			changed, err = renameSCIMGroup(tx, domain, g, op.Value)
		case types.SCIMGroupSetExternalID:
			changed, err = setSCIMGroupExternalID(tx, domain, g, op.Value)
		case types.SCIMGroupAddMembers:
			changed, err = setSCIMGroupMembers(tx, gid, op.Members, true, false)
		case types.SCIMGroupRemoveMembers:
			changed, err = setSCIMGroupMembers(tx, gid, op.Members, false, true)
		case types.SCIMGroupReplaceMembers:
			changed, err = setSCIMGroupMembers(tx, gid, op.Members, true, true)
		default:
			err = fmt.Errorf("%w: unknown group operation %d", ErrSCIMInvalid, op.Kind)
		}

		if err != nil {
			return nil, err
		}

		affected = append(affected, changed...)
	}

	slices.Sort(affected)

	return slices.Compact(affected), nil
}

func renameSCIMGroup(tx *gorm.DB, domain string, g *types.Group, displayName string) ([]types.UserID, error) {
	displayName = strings.TrimSpace(displayName)

	name, err := qualifySCIMGroupName(displayName, domain)
	if err != nil {
		return nil, err
	}

	if name == g.Name {
		// A change of case or of the domain suffix only: the policy
		// resolves the group as before.
		return nil, saveGroupColumns(tx, g.ID, map[string]any{colDisplayName: displayName})
	}

	err = checkSCIMGroupNames(tx, g.ID, name, "", "")
	if err != nil {
		return nil, err
	}

	other, err := findGroup(tx, "name = ?", name)
	if err != nil {
		return nil, err
	}

	var absorbed []types.UserID

	if other != nil {
		absorbed, err = groupMemberIDs(tx, other.ID, "")
		if err != nil {
			return nil, err
		}

		err = tx.Delete(&types.Group{}, other.ID).Error
		if err != nil {
			return nil, fmt.Errorf("deleting group %d absorbed by a rename: %w", other.ID, err)
		}
	}

	err = saveGroupColumns(tx, g.ID, map[string]any{"name": name, colDisplayName: displayName})
	if err != nil {
		return nil, err
	}

	members, err := groupMemberIDs(tx, g.ID, "")
	if err != nil {
		return nil, err
	}

	return slices.Concat(absorbed, members), nil
}

func setSCIMGroupExternalID(tx *gorm.DB, domain string, g *types.Group, externalID string) ([]types.UserID, error) {
	externalID = strings.TrimSpace(externalID)

	externalName, err := qualifyExternalName(externalID, domain)
	if err != nil {
		return nil, err
	}

	if externalID == g.ExternalID.String && externalName == g.ExternalName.String {
		return nil, nil
	}

	err = checkSCIMGroupNames(tx, g.ID, g.Name, externalID, externalName)
	if err != nil {
		return nil, err
	}

	err = saveGroupColumns(tx, g.ID, map[string]any{
		colExternalID:   nullString(externalID),
		colExternalName: nullString(externalName),
	})
	if err != nil {
		return nil, err
	}

	if externalName == g.ExternalName.String {
		return nil, nil
	}

	revoked, err := purgeNonSCIMMemberships(tx, g.ID)
	if err != nil {
		return nil, err
	}

	members, err := groupMemberIDs(tx, g.ID, "")
	if err != nil {
		return nil, err
	}

	return append(revoked, members...), nil
}

// setSCIMGroupMembers adds (add), removes (remove), or with both replaces
// the group's SCIM memberships with members, and returns the users whose
// SCIM membership changed.
func setSCIMGroupMembers(tx *gorm.DB, gid uint, members []types.UserID, add, remove bool) ([]types.UserID, error) {
	members = slices.Clone(members)
	slices.Sort(members)
	members = slices.Compact(members)

	if add && len(members) > 0 {
		var found []uint

		err := tx.Model(&types.User{}).
			Where("id IN ? AND provisioned_by = ?", members, types.ProvisionedBySCIM).
			Pluck("id", &found).Error
		if err != nil {
			return nil, fmt.Errorf("checking group members: %w", err)
		}

		if len(found) != len(members) {
			var missing []types.UserID

			for _, m := range members {
				if !slices.Contains(found, uint(m)) {
					missing = append(missing, m)
				}
			}

			return nil, fmt.Errorf("%w: members %v", ErrUserNotFound, missing)
		}
	}

	current, err := groupMemberIDs(tx, gid, types.GroupSourceSCIM)
	if err != nil {
		return nil, err
	}

	var toAdd, toRemove []types.UserID

	if add {
		for _, m := range members {
			if !slices.Contains(current, m) {
				toAdd = append(toAdd, m)
			}
		}
	}

	if remove {
		// A replace removes the current members not listed; a remove,
		// the listed members that are current.
		for _, c := range current {
			if slices.Contains(members, c) != add {
				toRemove = append(toRemove, c)
			}
		}
	}

	if len(toRemove) > 0 {
		err = tx.Where("group_id = ? AND source = ? AND user_id IN ?", gid, types.GroupSourceSCIM, toRemove).
			Delete(&types.UserGroup{}).Error
		if err != nil {
			return nil, fmt.Errorf("removing SCIM group members: %w", err)
		}
	}

	if len(toAdd) > 0 {
		now := time.Now().UTC()

		rows := make([]types.UserGroup, 0, len(toAdd))
		for _, uid := range toAdd {
			rows = append(rows, types.UserGroup{
				UserID:    uint(uid),
				GroupID:   gid,
				Source:    types.GroupSourceSCIM,
				CreatedAt: now,
			})
		}

		err = tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&rows).Error
		if err != nil {
			return nil, fmt.Errorf("adding SCIM group members: %w", err)
		}
	}

	return append(toAdd, toRemove...), nil
}

// DeleteSCIMGroup deletes the SCIM group id with all of its memberships,
// whatever their source (the directory no longer has the group), and the
// non-SCIM memberships of login-created groups named like its external name.
// It returns the users who lost a membership, or ErrGroupNotFound.
func DeleteSCIMGroup(tx *gorm.DB, id uint) ([]types.UserID, error) {
	revoked, err := purgeNonSCIMMemberships(tx, id)
	if err != nil {
		return nil, err
	}

	members, err := groupMemberIDs(tx, id, "")
	if err != nil {
		return nil, err
	}

	err = tx.Delete(&types.Group{}, id).Error
	if err != nil {
		return nil, fmt.Errorf("deleting SCIM group %d: %w", id, err)
	}

	affected := append(revoked, members...)
	slices.Sort(affected)

	return slices.Compact(affected), nil
}

// ReleaseSCIMGroup hands the SCIM group id back to OIDC logins, for when
// SCIM provisioning is turned off: SCIM's ownership of a group is otherwise
// permanent, and logins could never grant it again. The group keeps its id,
// name and display name; its SCIM memberships and its external id (and so
// its external-name alias) are removed, and logins asserting it grant it
// again from their next sync. It returns the users who lost a membership,
// or ErrGroupNotFound.
func ReleaseSCIMGroup(tx *gorm.DB, id uint) ([]types.UserID, error) {
	_, err := GetSCIMGroupByID(tx, id)
	if err != nil {
		return nil, err
	}

	members, err := groupMemberIDs(tx, id, "")
	if err != nil {
		return nil, err
	}

	err = tx.Where("group_id = ? AND source = ?", id, types.GroupSourceSCIM).Delete(&types.UserGroup{}).Error
	if err != nil {
		return nil, fmt.Errorf("removing SCIM memberships of group %d: %w", id, err)
	}

	err = saveGroupColumns(tx, id, map[string]any{
		"source":        types.GroupSourceOIDC,
		colExternalID:   sql.NullString{},
		colExternalName: sql.NullString{},
	})
	if err != nil {
		return nil, err
	}

	return members, nil
}

// PurgeNonSCIMMembershipsOfSCIMGroups removes every membership that SCIM's
// authority excludes (see [CreateSCIMGroup]): memberships from other sources
// of SCIM groups, and of groups created by logins that are named like a SCIM
// group's external name. It runs at startup, catching memberships written
// before the group became SCIM-managed by an older version, and returns how
// many it removed.
func PurgeNonSCIMMembershipsOfSCIMGroups(tx *gorm.DB) (int64, error) {
	res := tx.Where(`source != ? AND group_id IN (
  SELECT id FROM groups WHERE source = ?
  UNION
  SELECT o.id FROM groups o JOIN groups s ON s.external_name = o.name
  WHERE s.source = ? AND o.source = ?
)`, types.GroupSourceSCIM, types.GroupSourceSCIM, types.GroupSourceSCIM, types.GroupSourceOIDC).Delete(&types.UserGroup{})
	if res.Error != nil {
		return 0, fmt.Errorf("purging memberships of SCIM groups: %w", res.Error)
	}

	return res.RowsAffected, nil
}

// DeleteOrphanedOIDCGroups deletes the groups created by OIDC logins that no
// longer have any membership, and returns how many it deleted. Such groups
// grant nothing (the policy resolves groups through memberships only), and
// a login asserting one again recreates it. SCIM groups are kept, as the
// directory owns them even while empty.
func DeleteOrphanedOIDCGroups(tx *gorm.DB) (int64, error) {
	res := tx.Where(
		"source = ? AND NOT EXISTS (SELECT 1 FROM user_groups WHERE user_groups.group_id = groups.id)",
		types.GroupSourceOIDC,
	).Delete(&types.Group{})
	if res.Error != nil {
		return 0, fmt.Errorf("deleting orphaned OIDC groups: %w", res.Error)
	}

	return res.RowsAffected, nil
}
