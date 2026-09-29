package db

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

const scimDomain = "example.com"

var errPatchRejected = errors.New("patch rejected")

func createSCIMUser(t *testing.T, db *HSDatabase, attrs types.SCIMUserAttributes) (*types.User, bool, error) {
	t.Helper()

	return createSCIMUserAdopt(t, db, attrs, true)
}

func createSCIMUserAdopt(t *testing.T, db *HSDatabase, attrs types.SCIMUserAttributes, adopt bool) (*types.User, bool, error) {
	t.Helper()

	var adopted bool

	user, err := Write(db.DB, func(tx *gorm.DB) (*types.User, error) {
		u, a, err := CreateSCIMUser(tx, attrs, adopt)
		adopted = a

		return u, err
	})

	return user, adopted, err
}

func mustSCIMUser(t *testing.T, db *HSDatabase, userName, externalID string) *types.User {
	t.Helper()

	user, adopted, err := createSCIMUser(t, db, types.SCIMUserAttributes{UserName: userName, ExternalID: externalID})
	require.NoError(t, err)
	require.False(t, adopted)

	return user
}

func createOIDCUser(t *testing.T, db *HSDatabase, name, email, sub string) *types.User {
	t.Helper()

	user, err := db.CreateUser(types.User{
		Name:               name,
		Email:              email,
		ProviderIdentifier: sql.NullString{String: "https://idp.example.com/" + sub, Valid: true},
		Provider:           util.RegisterMethodOIDC,
	})
	require.NoError(t, err)

	return user
}

func TestCreateSCIMUser(t *testing.T) {
	groupsTestDBs(t, func(t *testing.T, db *HSDatabase) {
		t.Helper()

		db.CreateUserForTest("carol")

		alice, adopted, err := createSCIMUser(t, db, types.SCIMUserAttributes{
			UserName:    " Alice@Example.com ",
			ExternalID:  "ext-alice",
			DisplayName: "Alice Liddell",
			GivenName:   "Alice",
			FamilyName:  "Liddell",
		})
		require.NoError(t, err)
		assert.False(t, adopted)
		assert.Equal(t, "alice@example.com", alice.Name, "name is the lowercased userName")
		assert.Equal(t, "Alice@Example.com", alice.SCIMUserName.String, "userName is kept verbatim")
		assert.Equal(t, "Alice@Example.com", alice.Email, "an email-shaped userName is the email")
		assert.Equal(t, "ext-alice", alice.ExternalID.String)
		assert.Equal(t, "Alice Liddell", alice.DisplayName)
		assert.Equal(t, "Alice", alice.GivenName)
		assert.Equal(t, "Liddell", alice.FamilyName)
		assert.True(t, alice.IsSCIMProvisioned())
		assert.False(t, alice.ProviderIdentifier.Valid, "a SCIM user is unlinked until they log in")

		plain := mustSCIMUser(t, db, "bob", "")
		assert.Equal(t, "bob", plain.Name)
		assert.Empty(t, plain.Email, "a userName that is not an email address is not an email")
		assert.False(t, plain.ExternalID.Valid, "no externalId is NULL, not empty")

		withEmail, _, err := createSCIMUser(t, db, types.SCIMUserAttributes{UserName: "dan", Email: "dan@example.com"})
		require.NoError(t, err)
		assert.Equal(t, "dan@example.com", withEmail.Email)

		tests := []struct {
			name    string
			attrs   types.SCIMUserAttributes
			wantErr error
		}{
			{"userName differing in case", types.SCIMUserAttributes{UserName: "ALICE@example.COM"}, ErrSCIMConflict},
			{"externalId taken", types.SCIMUserAttributes{UserName: "other", ExternalID: "ext-alice"}, ErrSCIMConflict},
			{"local user's name", types.SCIMUserAttributes{UserName: "Carol"}, ErrSCIMConflict},
			{"empty userName", types.SCIMUserAttributes{UserName: "  "}, ErrSCIMInvalid},
			{"malformed email", types.SCIMUserAttributes{UserName: "eve", Email: "not an email"}, ErrSCIMInvalid},
		}
		for _, tt := range tests {
			_, _, err := createSCIMUser(t, db, tt.attrs)
			require.ErrorIs(t, err, tt.wantErr, tt.name)
		}

		// A failed create leaves nothing behind.
		var count int64
		require.NoError(t, db.DB.Model(&types.User{}).Count(&count).Error)
		assert.EqualValues(t, 4, count)

		// An externalId differing only in case is a different id (caseExact).
		_, _, err = createSCIMUser(t, db, types.SCIMUserAttributes{UserName: "frank", ExternalID: "EXT-ALICE"})
		require.NoError(t, err)
	})
}

func TestCreateSCIMUserAdoptsOIDCUser(t *testing.T) {
	groupsTestDBs(t, func(t *testing.T, db *HSDatabase) {
		t.Helper()

		dave := createOIDCUser(t, db, "dave", "Dave@Example.com", "dave")
		node := db.CreateRegisteredNodeForTest(dave, "dave-node")

		adoptedUser, adopted, err := createSCIMUser(t, db, types.SCIMUserAttributes{
			UserName:   "dave@example.com",
			ExternalID: "ext-dave",
			GivenName:  "Dave",
		})
		require.NoError(t, err)
		assert.True(t, adopted, "an existing OIDC user with the userName as email is adopted")
		assert.Equal(t, dave.ID, adoptedUser.ID)
		assert.True(t, adoptedUser.IsSCIMProvisioned())
		assert.Equal(t, dave.ProviderIdentifier, adoptedUser.ProviderIdentifier, "the login is kept")
		assert.Equal(t, "dave", adoptedUser.Name, "a linked user's name belongs to OIDC")
		assert.Equal(t, "ext-dave", adoptedUser.ExternalID.String)
		assert.Equal(t, "Dave", adoptedUser.GivenName)
		assert.Equal(t, "Dave@Example.com", adoptedUser.Email, "a linked user's email belongs to OIDC")
		assert.Empty(t, adoptedUser.SCIMEmail, "no SCIM email was sent")

		nodes, err := ListNodesByUser(db.DB, types.UserID(dave.ID))
		require.NoError(t, err)
		require.Len(t, nodes, 1)
		assert.Equal(t, node.ID, nodes[0].ID)

		// Adopted once: a second create is a conflict, not a re-adoption.
		_, _, err = createSCIMUser(t, db, types.SCIMUserAttributes{UserName: "dave@example.com"})
		require.ErrorIs(t, err, ErrSCIMConflict)

		// Two OIDC users with the email are ambiguous.
		createOIDCUser(t, db, "erin", "erin@example.com", "erin-a")
		createOIDCUser(t, db, "erin2", "erin@example.com", "erin-b")
		_, _, err = createSCIMUser(t, db, types.SCIMUserAttributes{UserName: "erin@example.com"})
		require.ErrorIs(t, err, ErrSCIMConflict)

		// Local users are never adopted, and never duplicated: their name
		// or email makes the create a conflict.
		_, err = db.CreateUser(types.User{Name: "gina", Email: "gina@example.com"})
		require.NoError(t, err)

		for _, userName := range []string{"gina@example.com", "GINA"} {
			_, _, err = createSCIMUser(t, db, types.SCIMUserAttributes{UserName: userName})
			require.ErrorIs(t, err, ErrSCIMConflict, userName)
		}

		// An OIDC user matching by name only is not adopted: names are not
		// unique, and users may choose them. It still blocks a duplicate.
		henry := createOIDCUser(t, db, "Henry@Example.com", "", "henry")
		_, _, err = createSCIMUser(t, db, types.SCIMUserAttributes{UserName: "henry@example.com"})
		require.ErrorIs(t, err, ErrSCIMConflict)

		got, err := db.GetUserByID(types.UserID(henry.ID))
		require.NoError(t, err)
		assert.False(t, got.IsSCIMProvisioned())

		// The email attribute alone must not pick the user to adopt.
		createOIDCUser(t, db, "ivan", "ivan@example.com", "ivan")
		_, _, err = createSCIMUser(t, db, types.SCIMUserAttributes{UserName: "ivan.p", Email: "ivan@example.com"})
		require.ErrorIs(t, err, ErrSCIMConflict)

		// Adoption can be disabled; the user is then a conflict.
		jane := createOIDCUser(t, db, "jane", "jane@example.com", "jane")
		_, _, err = createSCIMUserAdopt(t, db, types.SCIMUserAttributes{UserName: "jane@example.com"}, false)
		require.ErrorIs(t, err, ErrSCIMConflict)

		got, err = db.GetUserByID(types.UserID(jane.ID))
		require.NoError(t, err)
		assert.False(t, got.IsSCIMProvisioned())
	})
}

// TestCreateSCIMUserDoesNotAdoptByName is the takeover the email-only rule
// prevents: mallory sets her preferred_username to carol's address, but her
// verified email is her own, so provisioning carol must not hand mallory
// carol's identity (her groups, her deactivation, her future SCIM login).
func TestCreateSCIMUserDoesNotAdoptByName(t *testing.T) {
	groupsTestDBs(t, func(t *testing.T, db *HSDatabase) {
		t.Helper()

		mallory := createOIDCUser(t, db, "carol@example.com", "mallory@example.com", "mallory")

		_, _, err := createSCIMUser(t, db, types.SCIMUserAttributes{UserName: "carol@example.com"})
		require.ErrorIs(t, err, ErrSCIMConflict)

		got, err := db.GetUserByID(types.UserID(mallory.ID))
		require.NoError(t, err)
		assert.False(t, got.IsSCIMProvisioned(), "mallory is not adopted")
		assert.False(t, got.SCIMUserName.Valid)

		// An email match is ambiguous when another user has the name.
		zoe := createOIDCUser(t, db, "zoe", "zoe@example.com", "zoe")
		createOIDCUser(t, db, "zoe@example.com", "impostor@example.com", "impostor")

		_, _, err = createSCIMUser(t, db, types.SCIMUserAttributes{UserName: "zoe@example.com"})
		require.ErrorIs(t, err, ErrSCIMConflict)

		got, err = db.GetUserByID(types.UserID(zoe.ID))
		require.NoError(t, err)
		assert.False(t, got.IsSCIMProvisioned())
	})
}

// TestCreateSCIMUserDoesNotAdoptLookalikes checks that a userName differing
// from an OIDC user's email only by a Unicode lookalike, such as the Kelvin
// sign for K, conflicts instead of adopting that user.
func TestCreateSCIMUserDoesNotAdoptLookalikes(t *testing.T) {
	groupsTestDBs(t, func(t *testing.T, db *HSDatabase) {
		t.Helper()

		kate := createOIDCUser(t, db, "kate", "kate@example.com", "kate")

		_, _, err := createSCIMUser(t, db, types.SCIMUserAttributes{UserName: "\u212Aate@example.com"})
		require.ErrorIs(t, err, ErrSCIMConflict)

		got, err := db.GetUserByID(types.UserID(kate.ID))
		require.NoError(t, err)
		assert.False(t, got.IsSCIMProvisioned(), "kate is not adopted by a lookalike")

		// The ASCII spelling, in any case, still adopts her.
		adopted, _, err := createSCIMUser(t, db, types.SCIMUserAttributes{UserName: "Kate@Example.com"})
		require.NoError(t, err)
		assert.Equal(t, kate.ID, adopted.ID)
	})
}

// TestAdoptSCIMUserRace checks that of two adoptions of the same user that
// both passed their checks, only the first writes: the second finds the user
// managed and is a conflict, rather than overwriting the first.
func TestAdoptSCIMUserRace(t *testing.T) {
	groupsTestDBs(t, func(t *testing.T, db *HSDatabase) {
		t.Helper()

		dave := createOIDCUser(t, db, "dave", "dave@example.com", "dave")

		for i, userName := range []string{"dave@example.com", "dave@example.com"} {
			err := db.Write(func(tx *gorm.DB) error {
				return writeSCIMUser(tx, dave, types.SCIMUserAttributes{UserName: userName, ExternalID: "ext"}, true)
			})
			if i == 0 {
				require.NoError(t, err)

				continue
			}

			require.ErrorIs(t, err, ErrSCIMConflict)
		}
	})
}

// TestSCIMWriteRaceIsConflict checks the unique-index backstop: an insert
// that a concurrent write made conflicting after the checks passed is
// ErrSCIMConflict, detected from the driver's typed error.
func TestSCIMWriteRaceIsConflict(t *testing.T) {
	groupsTestDBs(t, func(t *testing.T, db *HSDatabase) {
		t.Helper()

		mustSCIMUser(t, db, "alice@example.com", "ext-alice")
		mustSCIMGroup(t, db, "Eng", "guid")

		inserts := []struct {
			name string
			fn   func(tx *gorm.DB) error
		}{
			{"userName key", func(tx *gorm.DB) error {
				return insertSCIMUser(tx, &types.User{Name: "other", SCIMUserNameKey: sql.NullString{String: "alice@example.com", Valid: true}})
			}},
			{"user externalId", func(tx *gorm.DB) error {
				return insertSCIMUser(tx, &types.User{Name: "other2", ExternalID: sql.NullString{String: "ext-alice", Valid: true}})
			}},
			{"group name", func(tx *gorm.DB) error {
				return insertSCIMGroup(tx, &types.Group{Name: "eng@example.com", Source: types.GroupSourceSCIM})
			}},
			{"group external name", func(tx *gorm.DB) error {
				return insertSCIMGroup(tx, &types.Group{
					Name: "x@example.com", Source: types.GroupSourceSCIM,
					ExternalName: sql.NullString{String: "guid@example.com", Valid: true},
				})
			}},
		}
		for _, tt := range inserts {
			err := db.Write(tt.fn)
			require.ErrorIs(t, err, ErrSCIMConflict, tt.name)
		}

		// Without a clash the same inserts succeed.
		err := db.Write(func(tx *gorm.DB) error {
			return insertSCIMGroup(tx, &types.Group{Name: "y@example.com"})
		})
		require.NoError(t, err)
	})
}

// TestSCIMUserNameFoldsUnicode checks that userName uniqueness and lookups
// fold case the same way on both databases, Unicode included (SQLite's
// lower() only folds ASCII).
func TestSCIMUserNameFoldsUnicode(t *testing.T) {
	groupsTestDBs(t, func(t *testing.T, db *HSDatabase) {
		t.Helper()

		arne := mustSCIMUser(t, db, "Ärne", "")
		assert.Equal(t, "ärne", arne.Name)

		_, _, err := createSCIMUser(t, db, types.SCIMUserAttributes{UserName: "ärne"})
		require.ErrorIs(t, err, ErrSCIMConflict)

		got, err := GetSCIMUserByUserName(db.DB, "äRNE")
		require.NoError(t, err)
		assert.Equal(t, arne.ID, got.ID)

		users, total, err := ListSCIMUsers(db.DB, SCIMUserFilter{UserName: "ÄRNE"}, 1, 10)
		require.NoError(t, err)
		assert.EqualValues(t, 1, total)
		require.Len(t, users, 1)

		// A local user with a non-ASCII name is found as well.
		_, err = db.CreateUser(types.User{Name: "Øyvind"})
		require.NoError(t, err)
		_, _, err = createSCIMUser(t, db, types.SCIMUserAttributes{UserName: "øYVIND"})
		require.ErrorIs(t, err, ErrSCIMConflict)
	})
}

func TestSCIMUserLookups(t *testing.T) {
	groupsTestDBs(t, func(t *testing.T, db *HSDatabase) {
		t.Helper()

		alice := mustSCIMUser(t, db, "Alice@Example.com", "ext-alice")
		local := db.CreateUserForTest("local")

		get := func(fn func(tx *gorm.DB) (*types.User, error)) (*types.User, error) {
			return Read(db.DB, fn)
		}

		tests := []struct {
			name   string
			lookup func(tx *gorm.DB) (*types.User, error)
			want   *types.User
		}{
			{"by id", func(tx *gorm.DB) (*types.User, error) { return GetSCIMUserByID(tx, types.UserID(alice.ID)) }, alice},
			{"by id of a local user", func(tx *gorm.DB) (*types.User, error) { return GetSCIMUserByID(tx, types.UserID(local.ID)) }, nil},
			{"by unknown id", func(tx *gorm.DB) (*types.User, error) { return GetSCIMUserByID(tx, 9999) }, nil},
			{"by externalId", func(tx *gorm.DB) (*types.User, error) { return GetSCIMUserByExternalID(tx, "ext-alice") }, alice},
			{"by externalId in another case", func(tx *gorm.DB) (*types.User, error) { return GetSCIMUserByExternalID(tx, "EXT-ALICE") }, nil},
			{"by empty externalId", func(tx *gorm.DB) (*types.User, error) { return GetSCIMUserByExternalID(tx, "") }, nil},
			{"by userName in another case", func(tx *gorm.DB) (*types.User, error) { return GetSCIMUserByUserName(tx, "alice@EXAMPLE.com") }, alice},
			{"by local user's name", func(tx *gorm.DB) (*types.User, error) { return GetSCIMUserByUserName(tx, "local") }, nil},
		}
		for _, tt := range tests {
			got, err := get(tt.lookup)
			if tt.want == nil {
				require.ErrorIs(t, err, ErrUserNotFound, tt.name)

				continue
			}

			require.NoError(t, err, tt.name)
			assert.Equal(t, tt.want.ID, got.ID, tt.name)
		}
	})
}

func TestListSCIMUsers(t *testing.T) {
	groupsTestDBs(t, func(t *testing.T, db *HSDatabase) {
		t.Helper()

		db.CreateUserForTest("local")

		ids := make([]uint, 0, 5)

		for _, name := range []string{"u1@example.com", "u2@example.com", "U3@Example.com", "u4@example.com", "u5"} {
			email := ""
			if strings.Contains(name, "@") {
				email = name
			}

			u, _, err := createSCIMUser(t, db, types.SCIMUserAttributes{UserName: name, ExternalID: "ext-" + name, Email: email})
			require.NoError(t, err)

			ids = append(ids, u.ID)
		}

		tests := []struct {
			name       string
			filter     SCIMUserFilter
			start      int
			count      int
			wantIDs    []uint
			wantTotal  int64
			wantNoRows bool
		}{
			{name: "first page", start: 1, count: 2, wantIDs: ids[:2], wantTotal: 5},
			{name: "start below 1 is 1", start: 0, count: 2, wantIDs: ids[:2], wantTotal: 5},
			{name: "last partial page", start: 4, count: 10, wantIDs: ids[3:], wantTotal: 5},
			{name: "past the end", start: 6, count: 2, wantIDs: []uint{}, wantTotal: 5},
			{name: "count 0 is the total only", start: 1, count: 0, wantTotal: 5, wantNoRows: true},
			{name: "negative count is 0", start: 1, count: -3, wantTotal: 5, wantNoRows: true},
			{name: "userName case-insensitive", filter: SCIMUserFilter{UserName: "u3@example.COM"}, start: 1, count: 10, wantIDs: ids[2:3], wantTotal: 1},
			{name: "email case-insensitive", filter: SCIMUserFilter{Email: "U2@EXAMPLE.COM"}, start: 1, count: 10, wantIDs: ids[1:2], wantTotal: 1},
			{name: "externalId exact", filter: SCIMUserFilter{ExternalID: "ext-u5"}, start: 1, count: 10, wantIDs: ids[4:], wantTotal: 1},
			{name: "externalId other case", filter: SCIMUserFilter{ExternalID: "EXT-U5"}, start: 1, count: 10, wantIDs: []uint{}, wantTotal: 0},
			{name: "filters combine", filter: SCIMUserFilter{UserName: "u1@example.com", ExternalID: "ext-u2@example.com"}, start: 1, count: 10, wantIDs: []uint{}, wantTotal: 0},
			{name: "local users are not listed", filter: SCIMUserFilter{UserName: "local"}, start: 1, count: 10, wantIDs: []uint{}, wantTotal: 0},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				var total int64

				users, err := Read(db.DB, func(rx *gorm.DB) ([]types.User, error) {
					u, n, err := ListSCIMUsers(rx, tt.filter, tt.start, tt.count)
					total = n

					return u, err
				})
				require.NoError(t, err)
				assert.Equal(t, tt.wantTotal, total)

				if tt.wantNoRows {
					assert.Empty(t, users)

					return
				}

				got := make([]uint, 0, len(users))
				for _, u := range users {
					got = append(got, u.ID)
				}

				assert.Equal(t, tt.wantIDs, got)
			})
		}
	})
}

func TestReplaceAndPatchSCIMUser(t *testing.T) {
	groupsTestDBs(t, func(t *testing.T, db *HSDatabase) {
		t.Helper()

		alice, _, err := createSCIMUser(t, db, types.SCIMUserAttributes{
			UserName: "alice@example.com", ExternalID: "ext-alice", GivenName: "Alice", DisplayName: "Alice",
		})
		require.NoError(t, err)
		bob := mustSCIMUser(t, db, "bob@example.com", "ext-bob")
		local := db.CreateUserForTest("local")
		createOIDCUser(t, db, "olga", "olga@example.com", "olga")

		replace := func(uid uint, attrs types.SCIMUserAttributes) (*types.User, error) {
			return Write(db.DB, func(tx *gorm.DB) (*types.User, error) {
				return ReplaceSCIMUser(tx, types.UserID(uid), attrs)
			})
		}

		got, err := replace(alice.ID, types.SCIMUserAttributes{UserName: "Alicia@Example.com", FamilyName: "Liddell"})
		require.NoError(t, err)
		assert.Equal(t, "Alicia@Example.com", got.SCIMUserName.String)
		assert.Equal(t, "alicia@example.com", got.Name, "an unlinked user's name follows the userName")
		assert.Equal(t, "Alicia@Example.com", got.Email)
		assert.False(t, got.ExternalID.Valid, "PUT clears an omitted externalId")
		assert.Empty(t, got.GivenName, "PUT clears an omitted givenName")
		assert.Empty(t, got.DisplayName)
		assert.Equal(t, "Liddell", got.FamilyName)

		// The old externalId is free again.
		_, err = replace(bob.ID, types.SCIMUserAttributes{UserName: "bob@example.com", ExternalID: "ext-alice"})
		require.NoError(t, err)

		tests := []struct {
			name    string
			uid     uint
			attrs   types.SCIMUserAttributes
			wantErr error
		}{
			{"another user's userName", alice.ID, types.SCIMUserAttributes{UserName: "BOB@example.com"}, ErrSCIMConflict},
			{"another user's externalId", alice.ID, types.SCIMUserAttributes{UserName: "alicia@example.com", ExternalID: "ext-alice"}, ErrSCIMConflict},
			{"a local user's name", alice.ID, types.SCIMUserAttributes{UserName: "local"}, ErrSCIMConflict},
			{"an OIDC user's email", alice.ID, types.SCIMUserAttributes{UserName: "OLGA@example.com"}, ErrSCIMConflict},
			{"an OIDC user's email as email", alice.ID, types.SCIMUserAttributes{UserName: "al", Email: "olga@example.com"}, ErrSCIMConflict},
			{"empty userName", alice.ID, types.SCIMUserAttributes{}, ErrSCIMInvalid},
			{"not a SCIM user", local.ID, types.SCIMUserAttributes{UserName: "x"}, ErrUserNotFound},
		}
		for _, tt := range tests {
			_, err := replace(tt.uid, tt.attrs)
			require.ErrorIs(t, err, tt.wantErr, tt.name)
		}

		// Keeping one's own userName, in another case, is not a conflict.
		_, err = replace(alice.ID, types.SCIMUserAttributes{UserName: "ALICIA@example.com"})
		require.NoError(t, err)

		patch := func(uid uint, fn func(*types.SCIMUserAttributes) error) (*types.User, error) {
			return Write(db.DB, func(tx *gorm.DB) (*types.User, error) {
				return PatchSCIMUser(tx, types.UserID(uid), fn)
			})
		}

		got, err = patch(bob.ID, func(a *types.SCIMUserAttributes) error {
			a.GivenName = "Bob"

			return nil
		})
		require.NoError(t, err)
		assert.Equal(t, "Bob", got.GivenName)
		assert.Equal(t, "ext-alice", got.ExternalID.String, "a patch keeps the attributes it does not touch")
		assert.Equal(t, "bob@example.com", got.SCIMUserName.String)

		_, err = patch(bob.ID, func(a *types.SCIMUserAttributes) error {
			a.GivenName = "Robert"

			return errPatchRejected
		})
		require.ErrorIs(t, err, errPatchRejected)

		got, err = db.GetUserByID(types.UserID(bob.ID))
		require.NoError(t, err)
		assert.Equal(t, "Bob", got.GivenName, "a rejected patch writes nothing")

		// Once linked, the login owns the name, email and display name: a
		// replace leaves them alone and keeps SCIM's values apart.
		_, err = Write(db.DB, func(tx *gorm.DB) (*types.User, error) {
			return LinkSCIMUser(tx, types.UserID(bob.ID), "https://idp.example.com/bob")
		})
		require.NoError(t, err)
		require.NoError(t, db.DB.Model(&types.User{}).Where("id = ?", bob.ID).Updates(map[string]any{
			"name": "bobby", "email": "bobby@idp.example.com", "display_name": "Bobby",
		}).Error)

		got, err = replace(bob.ID, types.SCIMUserAttributes{
			UserName: "robert@example.com", Email: "robert@example.com", DisplayName: "Robert",
		})
		require.NoError(t, err)
		assert.Equal(t, "bobby", got.Name)
		assert.Equal(t, "bobby@idp.example.com", got.Email)
		assert.Equal(t, "Bobby", got.DisplayName)
		assert.Equal(t, "robert@example.com", got.SCIMUserName.String)
		assert.Equal(t, "robert@example.com", got.SCIMAttributes().Email, "SCIM reads its own values back")
		assert.Equal(t, "Robert", got.SCIMAttributes().DisplayName)

		// A linked user's SCIM email may equal another user's: it is not
		// the core email the policy resolves.
		_, err = replace(bob.ID, types.SCIMUserAttributes{UserName: "robert@example.com", Email: "olga@example.com"})
		require.NoError(t, err)
	})
}

func TestLinkSCIMUser(t *testing.T) {
	groupsTestDBs(t, func(t *testing.T, db *HSDatabase) {
		t.Helper()

		alice := mustSCIMUser(t, db, "Alice@Example.com", "00u-alice")
		bob := mustSCIMUser(t, db, "bob@example.com", "")
		dave := createOIDCUser(t, db, "dave", "dave@example.com", "dave")

		find := func(fn func(tx *gorm.DB, key string) (*types.User, error), key string) (*types.User, error) {
			return Read(db.DB, func(rx *gorm.DB) (*types.User, error) { return fn(rx, key) })
		}

		got, err := find(FindUnlinkedSCIMUserByUserName, "alice@example.COM")
		require.NoError(t, err)
		assert.Equal(t, alice.ID, got.ID)

		got, err = find(FindUnlinkedSCIMUserByExternalID, "00u-alice")
		require.NoError(t, err)
		assert.Equal(t, alice.ID, got.ID)

		for _, tc := range []struct {
			fn  func(tx *gorm.DB, key string) (*types.User, error)
			key string
		}{
			{FindUnlinkedSCIMUserByExternalID, "00U-ALICE"},
			{FindUnlinkedSCIMUserByExternalID, ""},
			{FindUnlinkedSCIMUserByUserName, ""},
			{FindUnlinkedSCIMUserByUserName, "dave@example.com"},
		} {
			_, err = find(tc.fn, tc.key)
			require.ErrorIs(t, err, ErrUserNotFound, tc.key)
		}

		link := func(uid uint, pid string) (*types.User, error) {
			return Write(db.DB, func(tx *gorm.DB) (*types.User, error) {
				return LinkSCIMUser(tx, types.UserID(uid), pid)
			})
		}

		linked, err := link(alice.ID, "https://idp.example.com/alice")
		require.NoError(t, err)
		assert.Equal(t, util.RegisterMethodOIDC, linked.Provider)
		assert.Equal(t, "https://idp.example.com/alice", linked.ProviderIdentifier.String)
		assert.True(t, linked.IsSCIMProvisioned(), "a linked user stays SCIM-managed")

		byLogin, err := db.GetUserByOIDCIdentifier("https://idp.example.com/alice")
		require.NoError(t, err)
		assert.Equal(t, alice.ID, byLogin.ID, "later logins find the user by their identifier")

		_, err = find(FindUnlinkedSCIMUserByUserName, "alice@example.com")
		require.ErrorIs(t, err, ErrUserNotFound, "a linked user is no longer a link candidate")

		tests := []struct {
			name    string
			uid     uint
			pid     string
			wantErr error
		}{
			{"already linked", alice.ID, "https://idp.example.com/other", ErrSCIMUserLinked},
			{"identifier of another user", bob.ID, dave.ProviderIdentifier.String, ErrSCIMConflict},
			{"not a SCIM user", dave.ID, "https://idp.example.com/x", ErrUserNotFound},
			{"empty identifier", bob.ID, "", ErrSCIMInvalid},
		}
		for _, tt := range tests {
			_, err := link(tt.uid, tt.pid)
			require.ErrorIs(t, err, tt.wantErr, tt.name)
		}
	})
}

// TestLinkSCIMUserConcurrent races logins with distinct identities to link
// the same SCIM user: exactly one wins, the others get ErrSCIMUserLinked,
// and the stored identifier is the winner's. Without the compare-and-set
// update, Postgres' read committed lets several see the user unlinked and
// the last writer silently takes it over.
func TestLinkSCIMUserConcurrent(t *testing.T) {
	groupsTestDBs(t, func(t *testing.T, db *HSDatabase) {
		t.Helper()

		erin := mustSCIMUser(t, db, "erin@example.com", "")

		const logins = 8

		var (
			wg      sync.WaitGroup
			winners atomic.Int32
			winner  atomic.Value
			errs    = make([]error, logins)
		)

		for i := range logins {
			wg.Go(func() {
				pid := fmt.Sprintf("https://idp.example.com/erin-%d", i)

				_, err := Write(db.DB, func(tx *gorm.DB) (*types.User, error) {
					return LinkSCIMUser(tx, types.UserID(erin.ID), pid)
				})
				if err == nil {
					winners.Add(1)
					winner.Store(pid)
				}

				errs[i] = err
			})
		}

		wg.Wait()

		require.Equal(t, int32(1), winners.Load(), "exactly one login may link the user")

		for _, err := range errs {
			if err != nil {
				require.ErrorIs(t, err, ErrSCIMUserLinked)
			}
		}

		got, err := db.GetUserByID(types.UserID(erin.ID))
		require.NoError(t, err)
		assert.Equal(t, winner.Load(), got.ProviderIdentifier.String, "the winner's identifier is kept")
	})
}

func TestFindUnlinkedSCIMUsersByEmail(t *testing.T) {
	groupsTestDBs(t, func(t *testing.T, db *HSDatabase) {
		t.Helper()

		// Unlinked SCIM users cannot share an email (it is also their core
		// email, which no SCIM write duplicates), so an ambiguous match can
		// only arise from data written outside SCIM; callers still guard.
		for _, attrs := range []types.SCIMUserAttributes{
			{UserName: "alice", Email: "Alice@Example.com"},
			{UserName: "bob", Email: "bob@example.com"},
		} {
			_, _, err := createSCIMUser(t, db, attrs)
			require.NoError(t, err)
		}

		find := func(email string) []types.User {
			users, err := Read(db.DB, func(rx *gorm.DB) ([]types.User, error) {
				return FindUnlinkedSCIMUsersByEmail(rx, email, 2)
			})
			require.NoError(t, err)

			return users
		}

		alice := find("alice@example.com")
		require.Len(t, alice, 1, "the SCIM email compares case-insensitively")
		assert.Equal(t, "alice", alice[0].SCIMUserName.String)
		assert.Len(t, find("bob@example.com"), 1)
		assert.Empty(t, find(""))
		assert.Empty(t, find("nobody@example.com"))

		_, err := Write(db.DB, func(tx *gorm.DB) (*types.User, error) {
			return LinkSCIMUser(tx, types.UserID(alice[0].ID), "https://idp.example.com/alice")
		})
		require.NoError(t, err)
		assert.Empty(t, find("alice@example.com"), "a linked user is no longer a candidate")
	})
}

func createSCIMGroup(t *testing.T, db *HSDatabase, displayName, externalID string) (*types.Group, []types.UserID, error) {
	t.Helper()

	var revoked []types.UserID

	g, err := Write(db.DB, func(tx *gorm.DB) (*types.Group, error) {
		g, r, err := CreateSCIMGroup(tx, scimDomain, displayName, externalID)
		revoked = r

		return g, err
	})

	return g, revoked, err
}

func mustSCIMGroup(t *testing.T, db *HSDatabase, displayName, externalID string) *types.Group {
	t.Helper()

	g, revoked, err := createSCIMGroup(t, db, displayName, externalID)
	require.NoError(t, err)
	require.Empty(t, revoked)

	return g
}

func applyGroupOps(t *testing.T, db *HSDatabase, gid uint, ops ...types.SCIMGroupOp) ([]types.UserID, error) {
	t.Helper()

	return Write(db.DB, func(tx *gorm.DB) ([]types.UserID, error) {
		return ApplySCIMGroupOps(tx, scimDomain, gid, ops...)
	})
}

func scimMembers(t *testing.T, db *HSDatabase, gid uint) []types.UserID {
	t.Helper()

	m, err := SCIMGroupMembers(db.DB, gid)
	require.NoError(t, err)

	return m[gid]
}

func TestCreateSCIMGroup(t *testing.T) {
	groupsTestDBs(t, func(t *testing.T, db *HSDatabase) {
		t.Helper()

		eng := mustSCIMGroup(t, db, " Engineering ", "Abc-123")
		assert.Equal(t, "engineering@example.com", eng.Name)
		assert.Equal(t, "Engineering", eng.DisplayName)
		assert.Equal(t, "Abc-123", eng.ExternalID.String)
		assert.Equal(t, "abc-123@example.com", eng.ExternalName.String)
		assert.Equal(t, types.GroupSourceSCIM, eng.Source)

		ops := mustSCIMGroup(t, db, "ops@example.com", "")
		assert.Equal(t, "ops@example.com", ops.Name, "a name qualified with the domain is accepted")
		assert.False(t, ops.ExternalID.Valid)
		assert.False(t, ops.ExternalName.Valid)

		tests := []struct {
			name        string
			displayName string
			externalID  string
			wantErr     error
		}{
			{"displayName in another case", "ENGINEERING", "", ErrSCIMConflict},
			{"externalId taken", "Other", "Abc-123", ErrSCIMConflict},
			{"externalId folding to a taken external name", "Other", "ABC-123", ErrSCIMConflict},
			{"empty displayName", " ", "", ErrSCIMInvalid},
			{"displayName in another domain", "eng@other.example", "", ErrSCIMInvalid},
		}
		for _, tt := range tests {
			_, _, err := createSCIMGroup(t, db, tt.displayName, tt.externalID)
			require.ErrorIs(t, err, tt.wantErr, tt.name)
		}

		// An externalId that cannot be qualified is kept, without an alias.
		at := mustSCIMGroup(t, db, "At", "a@b")
		assert.Equal(t, "a@b", at.ExternalID.String)
		assert.False(t, at.ExternalName.Valid)

		got, err := GetSCIMGroupByExternalID(db.DB, "a@b")
		require.NoError(t, err)
		assert.Equal(t, at.ID, got.ID)

		_, _, err = createSCIMGroup(t, db, "Other", "a@b")
		require.ErrorIs(t, err, ErrSCIMConflict, "such an externalId is still unique")

		_, err = Write(db.DB, func(tx *gorm.DB) (*types.Group, error) {
			g, _, err := CreateSCIMGroup(tx, "", "Eng", "")

			return g, err
		})
		require.ErrorIs(t, err, types.ErrGroupDomainMissing, "a missing domain is a configuration error")
		require.NotErrorIs(t, err, ErrSCIMInvalid)
	})
}

func TestCreateSCIMGroupAdoptsOIDCGroup(t *testing.T) {
	groupsTestDBs(t, func(t *testing.T, db *HSDatabase) {
		t.Helper()

		alice := types.UserID(db.CreateUserForTest("alice").ID)
		setUserGroups(t, db, alice, types.GroupSourceOIDC, "eng@example.com")

		var oidcGroup types.Group
		require.NoError(t, db.DB.Where("name = ?", "eng@example.com").Take(&oidcGroup).Error)
		assert.Equal(t, types.GroupSourceOIDC, oidcGroup.Source, "groups created by logins are OIDC groups")

		_, total, err := listSCIMGroups(t, db, SCIMGroupFilter{}, 1, 10)
		require.NoError(t, err)
		assert.Zero(t, total, "OIDC groups are not listed")

		g, revoked, err := createSCIMGroup(t, db, "Eng", "guid-eng")
		require.NoError(t, err)
		assert.Equal(t, oidcGroup.ID, g.ID, "the row is adopted, not duplicated")
		assert.Equal(t, types.GroupSourceSCIM, g.Source)
		assert.Equal(t, "Eng", g.DisplayName)
		assert.Equal(t, "guid-eng@example.com", g.ExternalName.String)
		assert.Equal(t, []types.UserID{alice}, revoked)

		assert.Empty(t, userGroupNames(t, db, alice), "SCIM is authoritative: OIDC memberships are revoked")

		// And stay revoked when a login asserts the group again.
		assert.False(t, setUserGroups(t, db, alice, types.GroupSourceOIDC, "eng@example.com"))
		user, err := db.GetUserByID(alice)
		require.NoError(t, err)
		assert.False(t, user.InGroup("eng@example.com"))

		_, _, err = createSCIMGroup(t, db, "eng", "")
		require.ErrorIs(t, err, ErrSCIMConflict, "an adopted group is a SCIM group")
	})
}

func listSCIMGroups(t *testing.T, db *HSDatabase, filter SCIMGroupFilter, start, count int) ([]types.Group, int64, error) {
	t.Helper()

	var total int64

	groups, err := Read(db.DB, func(rx *gorm.DB) ([]types.Group, error) {
		g, n, err := ListSCIMGroups(rx, scimDomain, filter, start, count)
		total = n

		return g, err
	})

	return groups, total, err
}

func TestSCIMGroupLookupsAndList(t *testing.T) {
	groupsTestDBs(t, func(t *testing.T, db *HSDatabase) {
		t.Helper()

		setUserGroups(t, db, types.UserID(db.CreateUserForTest("alice").ID), types.GroupSourceOIDC, "oidc-only@example.com")

		ids := make([]uint, 0, 3)
		for _, name := range []string{"G1", "G2", "G3"} {
			ids = append(ids, mustSCIMGroup(t, db, name, "ext-"+name).ID)
		}

		lookups := []struct {
			name   string
			lookup func(tx *gorm.DB) (*types.Group, error)
			want   uint
		}{
			{"by id", func(tx *gorm.DB) (*types.Group, error) { return GetSCIMGroupByID(tx, ids[1]) }, ids[1]},
			{"by unknown id", func(tx *gorm.DB) (*types.Group, error) { return GetSCIMGroupByID(tx, 9999) }, 0},
			{"by externalId", func(tx *gorm.DB) (*types.Group, error) { return GetSCIMGroupByExternalID(tx, "ext-G3") }, ids[2]},
			{"by externalId in another case", func(tx *gorm.DB) (*types.Group, error) { return GetSCIMGroupByExternalID(tx, "EXT-G3") }, 0},
			{"by displayName in another case", func(tx *gorm.DB) (*types.Group, error) { return GetSCIMGroupByDisplayName(tx, scimDomain, "g1") }, ids[0]},
			{"by an OIDC group's name", func(tx *gorm.DB) (*types.Group, error) {
				return GetSCIMGroupByDisplayName(tx, scimDomain, "oidc-only")
			}, 0},
			{"by an unqualifiable displayName", func(tx *gorm.DB) (*types.Group, error) {
				return GetSCIMGroupByDisplayName(tx, scimDomain, "g1@other.example")
			}, 0},
		}
		for _, tt := range lookups {
			got, err := Read(db.DB, tt.lookup)
			if tt.want == 0 {
				require.ErrorIs(t, err, ErrGroupNotFound, tt.name)

				continue
			}

			require.NoError(t, err, tt.name)
			assert.Equal(t, tt.want, got.ID, tt.name)
		}

		lists := []struct {
			name      string
			filter    SCIMGroupFilter
			start     int
			count     int
			wantIDs   []uint
			wantTotal int64
		}{
			{"all", SCIMGroupFilter{}, 1, 10, ids, 3},
			{"second page", SCIMGroupFilter{}, 3, 2, ids[2:], 3},
			{"total only", SCIMGroupFilter{}, 1, 0, nil, 3},
			{"displayName", SCIMGroupFilter{DisplayName: "G2"}, 1, 10, ids[1:2], 1},
			{"externalId", SCIMGroupFilter{ExternalID: "ext-G1"}, 1, 10, ids[:1], 1},
			{"no match", SCIMGroupFilter{DisplayName: "nope"}, 1, 10, nil, 0},
		}
		for _, tt := range lists {
			groups, total, err := listSCIMGroups(t, db, tt.filter, tt.start, tt.count)
			require.NoError(t, err, tt.name)
			assert.Equal(t, tt.wantTotal, total, tt.name)

			var got []uint
			for _, g := range groups {
				got = append(got, g.ID)
			}

			assert.Equal(t, tt.wantIDs, got, tt.name)
		}
	})
}

func TestApplySCIMGroupMemberOps(t *testing.T) {
	groupsTestDBs(t, func(t *testing.T, db *HSDatabase) {
		t.Helper()

		a := types.UserID(mustSCIMUser(t, db, "a", "").ID)
		b := types.UserID(mustSCIMUser(t, db, "b", "").ID)
		c := types.UserID(mustSCIMUser(t, db, "c", "").ID)
		local := types.UserID(db.CreateUserForTest("local").ID)
		g := mustSCIMGroup(t, db, "Eng", "")

		// An OIDC membership of the same group, written before it was
		// SCIM-managed, which member ops leave alone.
		require.NoError(t, db.DB.Create(&types.UserGroup{UserID: uint(local), GroupID: g.ID, Source: types.GroupSourceOIDC}).Error)

		steps := []struct {
			name        string
			op          types.SCIMGroupOp
			wantChanged []types.UserID
			wantMembers []types.UserID
		}{
			{"add", types.SCIMGroupOp{Kind: types.SCIMGroupAddMembers, Members: []types.UserID{b, a, a}}, []types.UserID{a, b}, []types.UserID{a, b}},
			{"add existing", types.SCIMGroupOp{Kind: types.SCIMGroupAddMembers, Members: []types.UserID{a}}, nil, []types.UserID{a, b}},
			{"remove", types.SCIMGroupOp{Kind: types.SCIMGroupRemoveMembers, Members: []types.UserID{a, c}}, []types.UserID{a}, []types.UserID{b}},
			{"replace", types.SCIMGroupOp{Kind: types.SCIMGroupReplaceMembers, Members: []types.UserID{a, c}}, []types.UserID{a, b, c}, []types.UserID{a, c}},
			{"replace with the same", types.SCIMGroupOp{Kind: types.SCIMGroupReplaceMembers, Members: []types.UserID{c, a}}, nil, []types.UserID{a, c}},
			{"replace with none", types.SCIMGroupOp{Kind: types.SCIMGroupReplaceMembers}, []types.UserID{a, c}, nil},
		}
		for _, st := range steps {
			changed, err := applyGroupOps(t, db, g.ID, st.op)
			require.NoError(t, err, st.name)
			assert.Equal(t, st.wantChanged, changed, st.name)
			assert.Equal(t, st.wantMembers, scimMembers(t, db, g.ID), st.name)
		}

		user, err := db.GetUserByID(local)
		require.NoError(t, err)
		assert.Equal(t, []string{"eng@example.com"}, user.GroupNames(), "SCIM ops leave OIDC memberships alone")

		// Ops apply in order, in one transaction.
		changed, err := applyGroupOps(t, db, g.ID,
			types.SCIMGroupOp{Kind: types.SCIMGroupAddMembers, Members: []types.UserID{a, b}},
			types.SCIMGroupOp{Kind: types.SCIMGroupRemoveMembers, Members: []types.UserID{a}},
		)
		require.NoError(t, err)
		assert.Equal(t, []types.UserID{a, b}, changed)
		assert.Equal(t, []types.UserID{b}, scimMembers(t, db, g.ID))

		_, err = applyGroupOps(t, db, g.ID,
			types.SCIMGroupOp{Kind: types.SCIMGroupRemoveMembers, Members: []types.UserID{b}},
			types.SCIMGroupOp{Kind: types.SCIMGroupAddMembers, Members: []types.UserID{local}},
		)
		require.ErrorIs(t, err, ErrUserNotFound, "only SCIM users can be SCIM members")
		assert.Equal(t, []types.UserID{b}, scimMembers(t, db, g.ID), "a failed op rolls back the earlier ones")

		_, err = applyGroupOps(t, db, g.ID, types.SCIMGroupOp{Kind: types.SCIMGroupAddMembers, Members: []types.UserID{9999}})
		require.ErrorIs(t, err, ErrUserNotFound)

		_, err = applyGroupOps(t, db, g.ID, types.SCIMGroupOp{Kind: 0})
		require.ErrorIs(t, err, ErrSCIMInvalid)

		_, err = applyGroupOps(t, db, 9999, types.SCIMGroupOp{Kind: types.SCIMGroupAddMembers, Members: []types.UserID{a}})
		require.ErrorIs(t, err, ErrGroupNotFound)

		other := mustSCIMGroup(t, db, "Other", "")
		_, err = applyGroupOps(t, db, other.ID, types.SCIMGroupOp{Kind: types.SCIMGroupAddMembers, Members: []types.UserID{a, c}})
		require.NoError(t, err)

		members, err := SCIMGroupMembers(db.DB, g.ID, other.ID, 9999)
		require.NoError(t, err)
		assert.Equal(t, map[uint][]types.UserID{g.ID: {b}, other.ID: {a, c}}, members)

		// Deleting a user drops their memberships.
		require.NoError(t, db.DestroyUser(c))
		assert.Equal(t, []types.UserID{a}, scimMembers(t, db, other.ID))
	})
}

func TestApplySCIMGroupRenameAndExternalID(t *testing.T) {
	groupsTestDBs(t, func(t *testing.T, db *HSDatabase) {
		t.Helper()

		a := types.UserID(mustSCIMUser(t, db, "a", "").ID)
		oidcUser := types.UserID(db.CreateUserForTest("oidcuser").ID)

		g := mustSCIMGroup(t, db, "Eng", "")
		mustSCIMGroup(t, db, "Taken", "taken-id")

		_, err := applyGroupOps(t, db, g.ID, types.SCIMGroupOp{Kind: types.SCIMGroupAddMembers, Members: []types.UserID{a}})
		require.NoError(t, err)

		get := func() *types.Group {
			t.Helper()

			got, err := GetSCIMGroupByID(db.DB, g.ID)
			require.NoError(t, err)

			return got
		}

		changed, err := applyGroupOps(t, db, g.ID, types.SCIMGroupOp{Kind: types.SCIMGroupRename, Value: "ENG"})
		require.NoError(t, err)
		assert.Empty(t, changed, "a change of case resolves the same")
		assert.Equal(t, "ENG", get().DisplayName)
		assert.Equal(t, "eng@example.com", get().Name)

		changed, err = applyGroupOps(t, db, g.ID, types.SCIMGroupOp{Kind: types.SCIMGroupRename, Value: "Platform"})
		require.NoError(t, err)
		assert.Equal(t, []types.UserID{a}, changed)
		assert.Equal(t, "platform@example.com", get().Name)

		_, err = applyGroupOps(t, db, g.ID, types.SCIMGroupOp{Kind: types.SCIMGroupRename, Value: "taken"})
		require.ErrorIs(t, err, ErrSCIMConflict)

		_, err = applyGroupOps(t, db, g.ID, types.SCIMGroupOp{Kind: types.SCIMGroupRename, Value: ""})
		require.ErrorIs(t, err, ErrSCIMInvalid)

		// Renaming onto a group created by logins absorbs it: its OIDC
		// memberships are revoked, as SCIM now owns the name.
		setUserGroups(t, db, oidcUser, types.GroupSourceOIDC, "sre@example.com")
		setUserGroups(t, db, a, types.GroupSourceOIDC, "sre@example.com")

		changed, err = applyGroupOps(t, db, g.ID, types.SCIMGroupOp{Kind: types.SCIMGroupRename, Value: "SRE"})
		require.NoError(t, err)
		assert.Equal(t, []types.UserID{a, oidcUser}, changed)

		var count int64
		require.NoError(t, db.DB.Model(&types.Group{}).Where("name = ?", "sre@example.com").Count(&count).Error)
		assert.EqualValues(t, 1, count, "the OIDC row is gone")
		assert.Equal(t, g.ID, get().ID)
		assert.Empty(t, userGroupNames(t, db, oidcUser))
		assert.Equal(t, []types.UserID{a}, scimMembers(t, db, g.ID))
		assert.Equal(t, []string{"sre@example.com"}, userGroupNames(t, db, a), "only the SCIM membership remains")

		changed, err = applyGroupOps(t, db, g.ID, types.SCIMGroupOp{Kind: types.SCIMGroupSetExternalID, Value: "Guid-1"})
		require.NoError(t, err)
		assert.Equal(t, []types.UserID{a}, changed)
		assert.Equal(t, "Guid-1", get().ExternalID.String)
		assert.Equal(t, "guid-1@example.com", get().ExternalName.String)

		changed, err = applyGroupOps(t, db, g.ID, types.SCIMGroupOp{Kind: types.SCIMGroupSetExternalID, Value: "guid-1"})
		require.NoError(t, err)
		assert.Empty(t, changed, "a change of case keeps the external name")
		assert.Equal(t, "guid-1", get().ExternalID.String)

		_, err = applyGroupOps(t, db, g.ID, types.SCIMGroupOp{Kind: types.SCIMGroupSetExternalID, Value: "TAKEN-ID"})
		require.ErrorIs(t, err, ErrSCIMConflict)

		changed, err = applyGroupOps(t, db, g.ID, types.SCIMGroupOp{Kind: types.SCIMGroupSetExternalID})
		require.NoError(t, err)
		assert.Equal(t, []types.UserID{a}, changed)
		assert.False(t, get().ExternalID.Valid)
		assert.False(t, get().ExternalName.Valid)
	})
}

func TestDeleteSCIMGroup(t *testing.T) {
	groupsTestDBs(t, func(t *testing.T, db *HSDatabase) {
		t.Helper()

		a := types.UserID(mustSCIMUser(t, db, "a", "").ID)
		o := types.UserID(db.CreateUserForTest("oscar").ID)
		g := mustSCIMGroup(t, db, "Eng", "")

		_, err := applyGroupOps(t, db, g.ID, types.SCIMGroupOp{Kind: types.SCIMGroupAddMembers, Members: []types.UserID{a}})
		require.NoError(t, err)
		setUserGroups(t, db, o, types.GroupSourceOIDC, "eng@example.com", "ops@example.com")
		assert.Equal(t, []string{"ops@example.com"}, userGroupNames(t, db, o), "logins do not grant SCIM groups")
		// A membership written before the group was SCIM-managed.
		require.NoError(t, db.DB.Create(&types.UserGroup{UserID: uint(o), GroupID: g.ID, Source: types.GroupSourceOIDC}).Error)

		del := func(id uint) ([]types.UserID, error) {
			return Write(db.DB, func(tx *gorm.DB) ([]types.UserID, error) { return DeleteSCIMGroup(tx, id) })
		}

		members, err := del(g.ID)
		require.NoError(t, err)
		assert.Equal(t, []types.UserID{a, o}, members)

		assert.Empty(t, userGroupNames(t, db, a))
		assert.Equal(t, []string{"ops@example.com"}, userGroupNames(t, db, o), "all of the group's memberships go")

		_, err = del(g.ID)
		require.ErrorIs(t, err, ErrGroupNotFound)

		var ops types.Group
		require.NoError(t, db.DB.Where("name = ?", "ops@example.com").Take(&ops).Error)
		_, err = del(ops.ID)
		require.ErrorIs(t, err, ErrGroupNotFound, "OIDC groups are not deleted through SCIM")
	})
}

func TestDeleteOrphanedOIDCGroups(t *testing.T) {
	groupsTestDBs(t, func(t *testing.T, db *HSDatabase) {
		t.Helper()

		alice := types.UserID(db.CreateUserForTest("alice").ID)
		setUserGroups(t, db, alice, types.GroupSourceOIDC, "eng@example.com", "old@example.com")
		setUserGroups(t, db, alice, types.GroupSourceOIDC, "eng@example.com")
		mustSCIMGroup(t, db, "Empty", "")

		gc := func() int64 {
			n, err := Write(db.DB, DeleteOrphanedOIDCGroups)
			require.NoError(t, err)

			return n
		}

		assert.EqualValues(t, 1, gc())
		assert.Zero(t, gc())

		var names []string
		require.NoError(t, db.DB.Model(&types.Group{}).Order("name").Pluck("name", &names).Error)
		assert.Equal(t, []string{"empty@example.com", "eng@example.com"}, names,
			"groups with members and empty SCIM groups are kept")
	})
}

// TestSCIMMigration rewinds a database to the schema before SCIM and checks
// that the migration brings it back to the current schema (squibble
// validates it on SQLite) with existing groups marked as OIDC groups.
func TestSCIMMigration(t *testing.T) {
	rewind := []string{
		`DROP INDEX idx_users_external_id`,
		`DROP INDEX idx_users_scim_user_name_key`,
		`DROP INDEX idx_groups_external_id`,
		`DROP INDEX idx_groups_external_name`,
		`ALTER TABLE users DROP COLUMN provisioned_by`,
		`ALTER TABLE users DROP COLUMN scim_user_name`,
		`ALTER TABLE users DROP COLUMN scim_user_name_key`,
		`ALTER TABLE users DROP COLUMN scim_email`,
		`ALTER TABLE users DROP COLUMN scim_display_name`,
		`ALTER TABLE users DROP COLUMN external_id`,
		`ALTER TABLE users DROP COLUMN given_name`,
		`ALTER TABLE users DROP COLUMN family_name`,
		`ALTER TABLE groups DROP COLUMN display_name`,
		`ALTER TABLE groups DROP COLUMN external_id`,
		`ALTER TABLE groups DROP COLUMN external_name`,
		`ALTER TABLE groups DROP COLUMN source`,
		`INSERT INTO groups (name) VALUES ('legacy@example.com')`,
		`DELETE FROM migrations WHERE id = '202609281400-scim'`,
	}

	check := func(t *testing.T, db *HSDatabase) {
		t.Helper()

		var g types.Group
		require.NoError(t, db.DB.Where("name = ?", "legacy@example.com").Take(&g).Error)
		assert.Equal(t, types.GroupSourceOIDC, g.Source)

		mustSCIMUser(t, db, "alice@example.com", "ext")
		mustSCIMGroup(t, db, "Eng", "guid")

		_, _, err := createSCIMUser(t, db, types.SCIMUserAttributes{UserName: "ALICE@example.com"})
		require.ErrorIs(t, err, ErrSCIMConflict)
	}

	t.Run("sqlite", func(t *testing.T) {
		dbPath := t.TempDir() + "/headscale_test.db"

		db, err := NewHeadscaleDatabase(sqliteTestConfig(dbPath))
		require.NoError(t, err)

		for _, stmt := range rewind {
			require.NoError(t, db.DB.Exec(stmt).Error, stmt)
		}

		require.NoError(t, db.Close())

		db, err = NewHeadscaleDatabase(sqliteTestConfig(dbPath))
		require.NoError(t, err)

		check(t, db)
	})

	t.Run("postgres", func(t *testing.T) {
		u := newPostgresDBForTest(t)

		db := newHeadscaleDBFromPostgresURL(t, u)
		for _, stmt := range rewind {
			require.NoError(t, db.DB.Exec(stmt).Error, stmt)
		}

		require.NoError(t, db.Close())

		check(t, newHeadscaleDBFromPostgresURL(t, u))
	})
}

// TestSCIMGroupRevokesEntraAliasMemberships covers the Entra case: logins
// assert groups by object id, which is also the SCIM externalId. Once a
// SCIM group has that externalId, SCIM alone decides who is in it: the
// login-created group named by the id loses its memberships at once, and
// later logins asserting the id do not grant it again.
func TestSCIMGroupRevokesEntraAliasMemberships(t *testing.T) {
	groupsTestDBs(t, func(t *testing.T, db *HSDatabase) {
		t.Helper()

		const alias = "6f1e-guid@example.com"

		alice := types.UserID(db.CreateUserForTest("alice").ID)
		bob := types.UserID(mustSCIMUser(t, db, "bob", "").ID)
		setUserGroups(t, db, alice, types.GroupSourceOIDC, alias, "other@example.com")

		inAlias := func(uid types.UserID) bool {
			t.Helper()

			u, err := db.GetUserByID(uid)
			require.NoError(t, err)

			return u.InGroup(alias)
		}
		require.True(t, inAlias(alice))

		g, revoked, err := createSCIMGroup(t, db, "Engineering", "6F1E-GUID")
		require.NoError(t, err)
		assert.Equal(t, []types.UserID{alice}, revoked)
		assert.False(t, inAlias(alice), "revoked at once")
		assert.Equal(t, []string{"other@example.com"}, userGroupNames(t, db, alice), "other groups are untouched")

		assert.False(t, setUserGroups(t, db, alice, types.GroupSourceOIDC, alias, "other@example.com"),
			"a login asserting the id changes nothing")
		assert.False(t, inAlias(alice), "and grants nothing")

		// Only SCIM membership grants it.
		_, err = applyGroupOps(t, db, g.ID, types.SCIMGroupOp{Kind: types.SCIMGroupAddMembers, Members: []types.UserID{bob}})
		require.NoError(t, err)
		assert.True(t, inAlias(bob))

		// Setting the externalId later revokes the same way.
		carol := types.UserID(db.CreateUserForTest("carol").ID)
		setUserGroups(t, db, carol, types.GroupSourceOIDC, "guid-2@example.com")

		changed, err := applyGroupOps(t, db, g.ID, types.SCIMGroupOp{Kind: types.SCIMGroupSetExternalID, Value: "guid-2"})
		require.NoError(t, err)
		assert.Equal(t, []types.UserID{bob, carol}, changed)
		assert.Empty(t, userGroupNames(t, db, carol))

		// Deleting the SCIM group removes any alias membership left.
		require.NoError(t, db.DB.Create(&types.UserGroup{UserID: uint(carol), GroupID: aliasGroupID(t, db, "guid-2@example.com"), Source: types.GroupSourceOIDC}).Error)

		affected, err := Write(db.DB, func(tx *gorm.DB) ([]types.UserID, error) { return DeleteSCIMGroup(tx, g.ID) })
		require.NoError(t, err)
		assert.Equal(t, []types.UserID{bob, carol}, affected)
		assert.Empty(t, userGroupNames(t, db, carol))

		// With the SCIM group gone, logins grant the id again.
		assert.True(t, setUserGroups(t, db, alice, types.GroupSourceOIDC, alias))
		assert.True(t, inAlias(alice))
	})
}

// aliasGroupID returns the id of the group named name, creating it as a
// login would.
func aliasGroupID(t *testing.T, db *HSDatabase, name string) uint {
	t.Helper()

	ids, err := ensureGroups(db.DB, []string{name})
	require.NoError(t, err)

	return ids[0]
}

// TestPurgeNonSCIMMembershipsOfSCIMGroups checks the startup purge of
// memberships written before a group became SCIM-managed.
func TestPurgeNonSCIMMembershipsOfSCIMGroups(t *testing.T) {
	groupsTestDBs(t, func(t *testing.T, db *HSDatabase) {
		t.Helper()

		alice := types.UserID(db.CreateUserForTest("alice").ID)
		bob := types.UserID(mustSCIMUser(t, db, "bob", "").ID)
		g := mustSCIMGroup(t, db, "Eng", "guid")

		_, err := applyGroupOps(t, db, g.ID, types.SCIMGroupOp{Kind: types.SCIMGroupAddMembers, Members: []types.UserID{bob}})
		require.NoError(t, err)

		setUserGroups(t, db, alice, types.GroupSourceOIDC, "kept@example.com")

		// Written behind SetUserGroups' back, as an older version could.
		for _, gid := range []uint{g.ID, aliasGroupID(t, db, "guid@example.com")} {
			require.NoError(t, db.DB.Create(&types.UserGroup{UserID: uint(alice), GroupID: gid, Source: types.GroupSourceOIDC}).Error)
		}

		n, err := Write(db.DB, PurgeNonSCIMMembershipsOfSCIMGroups)
		require.NoError(t, err)
		assert.EqualValues(t, 2, n)
		assert.Equal(t, []string{"kept@example.com"}, userGroupNames(t, db, alice))
		assert.Equal(t, []types.UserID{bob}, scimMembers(t, db, g.ID))

		n, err = Write(db.DB, PurgeNonSCIMMembershipsOfSCIMGroups)
		require.NoError(t, err)
		assert.Zero(t, n)
	})
}

// TestSCIMGroupNamespace checks that among SCIM groups names and external
// names share one namespace, in both directions, since the policy matches
// either; a login-created group named like an external name is allowed.
func TestSCIMGroupNamespace(t *testing.T) {
	groupsTestDBs(t, func(t *testing.T, db *HSDatabase) {
		t.Helper()

		a := mustSCIMGroup(t, db, "Alpha", "ext-a")
		b := mustSCIMGroup(t, db, "Beta", "")

		_, _, err := createSCIMGroup(t, db, "ext-a", "")
		require.ErrorIs(t, err, ErrSCIMConflict, "a name equal to another SCIM group's external name")

		_, _, err = createSCIMGroup(t, db, "Gamma", "alpha")
		require.ErrorIs(t, err, ErrSCIMConflict, "an external name equal to another SCIM group's name")

		_, err = applyGroupOps(t, db, b.ID, types.SCIMGroupOp{Kind: types.SCIMGroupRename, Value: "EXT-A"})
		require.ErrorIs(t, err, ErrSCIMConflict, "renaming onto another SCIM group's external name")

		_, err = applyGroupOps(t, db, b.ID, types.SCIMGroupOp{Kind: types.SCIMGroupSetExternalID, Value: "Alpha"})
		require.ErrorIs(t, err, ErrSCIMConflict, "an external id onto another SCIM group's name")

		// A group's own name and external name may coincide.
		_, err = applyGroupOps(t, db, b.ID, types.SCIMGroupOp{Kind: types.SCIMGroupSetExternalID, Value: "beta"})
		require.NoError(t, err)

		// A login-created group named like an external name is the
		// intended alias, not a clash.
		setUserGroups(t, db, types.UserID(db.CreateUserForTest("alice").ID), types.GroupSourceOIDC, "ext-c@example.com")
		c := mustSCIMGroupRevoking(t, db, "Charlie", "ext-c")
		assert.NotEqual(t, a.ID, c.ID)
	})
}

func mustSCIMGroupRevoking(t *testing.T, db *HSDatabase, displayName, externalID string) *types.Group {
	t.Helper()

	g, _, err := createSCIMGroup(t, db, displayName, externalID)
	require.NoError(t, err)

	return g
}

// TestReleaseSCIMGroup checks that a released group is an OIDC group again:
// its SCIM memberships and alias are gone, it is no longer listed through
// SCIM, and logins grant it again.
func TestReleaseSCIMGroup(t *testing.T) {
	groupsTestDBs(t, func(t *testing.T, db *HSDatabase) {
		t.Helper()

		alice := types.UserID(db.CreateUserForTest("alice").ID)
		bob := types.UserID(mustSCIMUser(t, db, "bob", "").ID)
		g := mustSCIMGroup(t, db, "Eng", "guid")

		_, err := applyGroupOps(t, db, g.ID, types.SCIMGroupOp{Kind: types.SCIMGroupAddMembers, Members: []types.UserID{bob}})
		require.NoError(t, err)

		release := func(id uint) ([]types.UserID, error) {
			return Write(db.DB, func(tx *gorm.DB) ([]types.UserID, error) { return ReleaseSCIMGroup(tx, id) })
		}

		affected, err := release(g.ID)
		require.NoError(t, err)
		assert.Equal(t, []types.UserID{bob}, affected)
		assert.Empty(t, userGroupNames(t, db, bob))

		_, err = GetSCIMGroupByID(db.DB, g.ID)
		require.ErrorIs(t, err, ErrGroupNotFound)

		var got types.Group
		require.NoError(t, db.DB.Take(&got, g.ID).Error)
		assert.Equal(t, types.GroupSourceOIDC, got.Source)
		assert.Equal(t, "eng@example.com", got.Name)
		assert.Equal(t, "Eng", got.DisplayName)
		assert.False(t, got.ExternalID.Valid)
		assert.False(t, got.ExternalName.Valid)

		assert.True(t, setUserGroups(t, db, alice, types.GroupSourceOIDC, "eng@example.com", "guid@example.com"))
		assert.Equal(t, []string{"eng@example.com", "guid@example.com"}, userGroupNames(t, db, alice),
			"logins grant the group and its former alias again")

		_, err = release(g.ID)
		require.ErrorIs(t, err, ErrGroupNotFound)

		// SCIM can take it over again later.
		_, revoked, err := createSCIMGroup(t, db, "Eng", "")
		require.NoError(t, err)
		assert.Equal(t, []types.UserID{alice}, revoked)
	})
}

func TestListSCIMUsersByID(t *testing.T) {
	groupsTestDBs(t, func(t *testing.T, db *HSDatabase) {
		t.Helper()

		local := db.CreateUserForTest("local")
		b := mustSCIMUser(t, db, "b@example.com", "")
		a := mustSCIMUser(t, db, "a@example.com", "")

		ids := make([]types.UserID, 0, 4+scimUserIDChunk)
		ids = append(ids, types.UserID(b.ID), types.UserID(local.ID), 9999, types.UserID(a.ID))
		// More ids than one IN list takes, to cover chunking.
		for i := range scimUserIDChunk {
			ids = append(ids, types.UserID(100000+i))
		}

		users, err := ListSCIMUsersByID(db.DB, ids...)
		require.NoError(t, err)

		got := make([]uint, 0, len(users))
		for _, u := range users {
			got = append(got, u.ID)
		}

		assert.Equal(t, []uint{b.ID, a.ID}, got, "only SCIM users, by id")

		users, err = ListSCIMUsersByID(db.DB)
		require.NoError(t, err)
		assert.Empty(t, users)
	})
}
