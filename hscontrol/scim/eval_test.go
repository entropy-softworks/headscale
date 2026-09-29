package scim

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testUser() *User {
	return &User{
		ID:          "42",
		ExternalID:  "Ext-ABC",
		UserName:    "Alice.Smith@Example.com",
		DisplayName: "Alice Smith",
		Active:      new(true),
		Name:        &Name{GivenName: "Alice", FamilyName: "Smith"},
		Emails: []Email{
			{Value: "alice@work.example", Type: "work", Primary: true},
			{Value: "alice@home.example", Type: "home"},
		},
		Meta: &Meta{
			ResourceType: ResourceTypeUser,
			LastModified: time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC),
		},
	}
}

func TestMatch(t *testing.T) {
	tests := []struct {
		filter string
		want   bool
	}{
		// userName is caseExact=false (Okta randomUsernameCaps).
		{`userName eq "alice.smith@example.com"`, true},
		{`userName eq "ALICE.SMITH@EXAMPLE.COM"`, true},
		{`userName eq "bob"`, false},
		{`userName ne "bob"`, true},
		{`userName ne "alice.smith@example.com"`, false},
		// externalId and id are caseExact=true (RFC 7643 section 3.1).
		{`externalId eq "Ext-ABC"`, true},
		{`externalId eq "ext-abc"`, false},
		{`id eq "42"`, true},
		// Entra ID email lookup (value path + sub-attribute).
		{`emails[type eq "work"].value eq "ALICE@work.example"`, true},
		{`emails[type eq "home"].value eq "alice@work.example"`, false},
		{`emails[type eq "work" and primary eq true]`, true},
		{`emails[type eq "home" and primary eq true]`, false},
		{`emails[not (type eq "work")]`, true},
		{`emails[type pr]`, true},
		{`emails[display pr]`, false},
		{`emails[type eq "work" or type eq "other"]`, true},
		{`emails[type ne "work"]`, true},
		// Multi-valued without sub-attribute compares "value".
		{`emails co "home.example"`, true},
		{`emails.value ew ".example"`, true},
		{`emails.type eq "other"`, false},
		// Complex sub-attribute.
		{`name.givenName sw "ali"`, true},
		{`name.familyName co "mit"`, true},
		{`name.formatted pr`, false},
		// Booleans, presence, null.
		{`active eq true`, true},
		{`active eq false`, false},
		{`active ne false`, true},
		{`title pr`, false},
		{`title eq null`, true},
		{`userName eq null`, false},
		{`title ne "x"`, true},
		{`title eq "x"`, false},
		{`title gt "x"`, false},
		{`displayName pr`, true},
		// Dates and ordering.
		{`meta.lastModified gt "2026-01-01T00:00:00Z"`, true},
		{`meta.lastModified lt "2026-01-01T00:00:00+01:00"`, false},
		{`meta.lastModified ge "2026-05-01T12:00:00Z"`, true},
		{`meta.lastModified le "2026-05-01T14:00:00+02:00"`, true},
		{`displayName gt "alice a"`, true},
		{`displayName lt "alice a"`, false},
		// Type mismatches never match (except ne).
		{`active eq "true"`, false},
		{`userName eq 1`, false},
		{`userName gt 1`, false},
		{`active eq null`, false},
		// Logic.
		{`userName eq "bob" or externalId eq "Ext-ABC"`, true},
		{`userName eq "alice.smith@example.com" and active eq false`, false},
		{`not (userName eq "bob")`, true},
		// URN prefixes and case-insensitive attribute names.
		{`urn:ietf:params:scim:schemas:core:2.0:User:USERNAME eq "alice.smith@example.com"`, true},
		{`urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department eq "x"`, false},
		// Sub-attribute of a simple attribute.
		{`userName.x eq "y"`, false},
		{`userName[value eq "y"]`, false},
	}

	u := testUser()

	for _, tt := range tests {
		t.Run(tt.filter, func(t *testing.T) {
			e, err := ParseFilter(tt.filter)
			require.NoError(t, err)

			got, err := Match(e, u)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestMatchMapAndExtension(t *testing.T) {
	obj := map[string]any{
		"userName": "a",
		"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": map[string]any{
			"department": "Eng",
		},
		"count": 3.0,
	}

	for filter, want := range map[string]bool{
		`urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department eq "eng"`: true,
		`count gt 2`: true,
		`count le 2`: false,
		`count eq 3`: true,
		`count ne 3`: false,
	} {
		e, err := ParseFilter(filter)
		require.NoError(t, err)

		got, err := Match(e, obj)
		require.NoError(t, err)
		assert.Equal(t, want, got, filter)
	}

	got, err := Match(nil, obj)
	require.NoError(t, err)
	assert.True(t, got)

	_, err = Match(&PresentExpr{}, make(chan int))
	require.Error(t, err)

	_, err = Match(&PresentExpr{}, []int{1})
	require.Error(t, err)
}

func TestExtractEquality(t *testing.T) {
	tests := []struct {
		filter string
		attrs  []string
		want   Equality
		ok     bool
	}{
		{`userName eq "Alice"`, nil, Equality{Attr: "userName", Value: "Alice", Exact: true}, true},
		{`USERNAME eq "Alice"`, []string{"userName"}, Equality{Attr: "userName", Value: "Alice", Exact: true}, true},
		{`externalId eq "x"`, []string{"userName", "externalId"}, Equality{Attr: "externalId", Value: "x", Exact: true}, true},
		{`displayName eq "Group1"`, []string{"displayName"}, Equality{Attr: "displayName", Value: "Group1", Exact: true}, true},
		{`emails[type eq "work"].value eq "a@b.c"`, []string{"emails.value"}, Equality{Attr: "emails.value", Value: "a@b.c"}, true},
		{`emails[type eq "work"].value eq "a@b.c"`, []string{"emails.type"}, Equality{Attr: "emails.type", Value: "work"}, true},
		{`userName eq "a" and active eq true`, []string{"userName"}, Equality{Attr: "userName", Value: "a"}, true},
		{`active eq true and (userName eq "a" and externalId eq "b")`, []string{"externalId"}, Equality{Attr: "externalId", Value: "b"}, true},
		{`name.givenName eq "x"`, nil, Equality{Attr: "name.givenName", Value: "x", Exact: true}, true},
		{`emails eq "a@b.c"`, []string{"emails.value"}, Equality{Attr: "emails.value", Value: "a@b.c", Exact: true}, true},
		{`EMAILS eq "a@b.c" and active eq true`, nil, Equality{Attr: "emails.value", Value: "a@b.c"}, true},
		{`members eq "1"`, nil, Equality{Attr: "members.value", Value: "1", Exact: true}, true},
		{`name eq "x"`, nil, Equality{Attr: "name", Value: "x", Exact: true}, true},
		{`userName eq "a" or userName eq "b"`, nil, Equality{}, false},
		{`not (userName eq "a")`, nil, Equality{}, false},
		{`userName ne "a"`, nil, Equality{}, false},
		{`userName co "a"`, nil, Equality{}, false},
		{`active eq true`, nil, Equality{}, false},
		{`userName pr`, nil, Equality{}, false},
		{`externalId eq "x"`, []string{"userName"}, Equality{}, false},
		{`urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber eq "1"`, nil, Equality{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.filter, func(t *testing.T) {
			e, err := ParseFilter(tt.filter)
			require.NoError(t, err)

			got, ok := ExtractEquality(e, tt.attrs...)
			assert.Equal(t, tt.ok, ok)
			assert.Equal(t, tt.want, got)
		})
	}
}
