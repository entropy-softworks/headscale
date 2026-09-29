package types

import (
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestUserSCIMAttributes(t *testing.T) {
	u := User{
		Name:          "alice",
		DisplayName:   "Alice Liddell",
		Email:         "alice@example.com",
		ProvisionedBy: sql.NullString{String: ProvisionedBySCIM, Valid: true},
		SCIMUserName:  sql.NullString{String: "Alice@Example.com", Valid: true},
		// The login's claims, which SCIM does not present.
		SCIMDisplayName: "Alice L.",
		SCIMEmail:       "alice.liddell@example.com",
		ExternalID:      sql.NullString{String: "00u1", Valid: true},
		GivenName:       "Alice",
		FamilyName:      "Liddell",
	}

	assert.True(t, u.IsSCIMProvisioned())
	assert.Equal(t, SCIMUserAttributes{
		UserName:    "Alice@Example.com",
		ExternalID:  "00u1",
		DisplayName: "Alice L.",
		GivenName:   "Alice",
		FamilyName:  "Liddell",
		Email:       "alice.liddell@example.com",
		Active:      true,
	}, u.SCIMAttributes())

	u.SuspendedAt = sql.NullTime{Time: time.Now(), Valid: true}
	assert.False(t, u.SCIMAttributes().Active, "a suspended user is inactive")

	assert.False(t, (&User{}).IsSCIMProvisioned())
	assert.False(t, (&User{ProvisionedBy: sql.NullString{String: "other", Valid: true}}).IsSCIMProvisioned())
	assert.False(t, (*User)(nil).IsSCIMProvisioned())
}
