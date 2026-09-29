package scim

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeUserActiveForms(t *testing.T) {
	tests := []struct {
		body string
		want *bool
	}{
		{`{"userName":"a","active":true}`, new(true)},
		{`{"userName":"a","active":false}`, new(false)},
		{`{"userName":"a","active":"True"}`, new(true)},
		{`{"userName":"a","active":"False"}`, new(false)},
		{`{"userName":"a","active":"FALSE"}`, new(false)},
		{`{"userName":"a","active":" true "}`, new(true)},
		{`{"userName":"a"}`, nil},
	}

	for _, tt := range tests {
		t.Run(tt.body, func(t *testing.T) {
			u, err := DecodeUser(strings.NewReader(tt.body))
			require.NoError(t, err)
			assert.Equal(t, tt.want, u.Active)
		})
	}
}

func TestDecodeUserErrors(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		scimType ScimType
	}{
		{"malformed", `{"userName":`, ScimTypeInvalidSyntax},
		{"not an object", `[]`, ScimTypeInvalidSyntax},
		{"active not boolean", `{"userName":"a","active":"yes"}`, ScimTypeInvalidValue},
		{"active number", `{"userName":"a","active":1}`, ScimTypeInvalidValue},
		{"primary not boolean", `{"userName":"a","emails":[{"value":"x","primary":"maybe"}]}`, ScimTypeInvalidValue},
		{"userName wrong type", `{"userName":5}`, ScimTypeInvalidValue},
		{"email wrong type", `{"userName":"a","emails":[{"value":5}]}`, ScimTypeInvalidValue},
		{"name wrong type", `{"userName":"a","name":"x"}`, ScimTypeInvalidValue},
		{"trailing garbage", `{"userName":"a"}}`, ScimTypeInvalidSyntax},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeUser(strings.NewReader(tt.body))
			require.Error(t, err)
			assert.Equal(t, tt.scimType, AsError(err).ScimType)
			assert.Equal(t, 400, AsError(err).Status)

			// Details never leak Go types or struct names.
			for _, leak := range []string{"Go ", "struct", "scim.", "float64", "of type", "unmarshal"} {
				assert.NotContains(t, AsError(err).Detail, leak)
			}
		})
	}
}

func TestDecodeBodyTooLarge(t *testing.T) {
	body := `{"userName":"` + strings.Repeat("a", MaxBodySize) + `"}`

	_, err := DecodeUser(strings.NewReader(body))
	require.Error(t, err)
	assert.Equal(t, 413, AsError(err).Status)
}

func TestDecodeUserDropsReadOnlyAndSecrets(t *testing.T) {
	body := `{
		"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
		"id":"client-chosen","userName":"a","password":"hunter2",
		"groups":[{"value":"g"}],"meta":{"resourceType":"User"},
		"roles":[],"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"department":"x"},
		"USERNAME":"b"
	}`

	u, err := DecodeUser(strings.NewReader(body))
	require.NoError(t, err)

	assert.Empty(t, u.ID)
	assert.Nil(t, u.Groups)
	assert.Nil(t, u.Meta)
	// encoding/json matches keys case-insensitively; the last one wins.
	assert.Equal(t, "b", u.UserName)

	out, err := json.Marshal(u)
	require.NoError(t, err)
	assert.NotContains(t, string(out), "hunter2")
	assert.NotContains(t, string(out), "password")
	assert.NotContains(t, string(out), "roles")
	assert.NotContains(t, string(out), "enterprise")
}

func TestUserEncodingOmitsEmpty(t *testing.T) {
	u := User{UserName: "a", Name: &Name{}}

	// active is always emitted; unset means true.
	out, err := json.Marshal(u)
	require.NoError(t, err)
	assert.JSONEq(t, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"a","active":true}`, string(out))

	// Pointer and value encode identically; schemas is always canonical.
	u.Schemas = []string{"bogus"}
	u.Active = new(false)
	u.Meta = &Meta{
		ResourceType: ResourceTypeUser,
		Created:      time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		Location:     UserLocation("https://hs/scim/v2/", "1"),
	}

	out, err = json.Marshal(&u)
	require.NoError(t, err)
	assert.JSONEq(t, `{
		"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
		"userName":"a","active":false,
		"meta":{"resourceType":"User","created":"2026-01-02T03:04:05Z","location":"https://hs/scim/v2/Users/1"}
	}`, string(out))
}

func TestGroupEncodingAndDecode(t *testing.T) {
	g, err := DecodeGroup(strings.NewReader(`{
		"id":"x","displayName":"eng","meta":{"location":"y"},
		"members":[{"value":"1","display":"alice","$ref":null},{"value":"2","type":"User"}]
	}`))
	require.NoError(t, err)
	assert.Empty(t, g.ID)
	assert.Nil(t, g.Meta)
	assert.Equal(t, []string{"1", "2"}, g.MemberIDs())
	assert.Empty(t, g.Members[0].Display)

	out, err := json.Marshal(Group{ID: "5", DisplayName: "eng"})
	require.NoError(t, err)
	assert.JSONEq(t, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"id":"5","displayName":"eng"}`, string(out))
	assert.Equal(t, "https://hs/scim/v2/Groups/5", GroupLocation("https://hs/scim/v2", "5"))
}

func TestUserValidate(t *testing.T) {
	tests := []struct {
		name     string
		user     User
		scimType ScimType
	}{
		{"ok", User{UserName: "a"}, ""},
		{"ok with extension schemas", User{UserName: "a", Schemas: []string{SchemaUser, SchemaEnterpriseUser}}, ""},
		{"blank userName", User{UserName: "  "}, ScimTypeInvalidValue},
		{"wrong schema", User{UserName: "a", Schemas: []string{SchemaGroup}}, ScimTypeInvalidSyntax},
		{"email without value", User{UserName: "a", Emails: []Email{{Type: "work"}}}, ScimTypeInvalidValue},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.user.Validate()
			if tt.scimType == "" {
				require.NoError(t, err)

				return
			}

			require.Error(t, err)
			assert.Equal(t, tt.scimType, AsError(err).ScimType)
		})
	}
}

func TestGroupValidate(t *testing.T) {
	require.NoError(t, (&Group{DisplayName: "g"}).Validate())
	assert.Equal(t, ScimTypeInvalidValue, AsError((&Group{}).Validate()).ScimType)
	assert.Equal(t, ScimTypeInvalidSyntax,
		AsError((&Group{DisplayName: "g", Schemas: []string{SchemaUser}}).Validate()).ScimType)
	assert.Equal(t, ScimTypeInvalidValue,
		AsError((&Group{DisplayName: "g", Members: []Member{{}}}).Validate()).ScimType)
}

func TestUserHelpers(t *testing.T) {
	u := User{}
	assert.True(t, u.IsActive())
	assert.Empty(t, u.PrimaryEmail())

	u.Active = new(false)
	assert.False(t, u.IsActive())

	u.Emails = []Email{{Value: "a"}, {Value: "b", Primary: true}}
	assert.Equal(t, "b", u.PrimaryEmail())

	u.Emails[1].Primary = false
	assert.Equal(t, "a", u.PrimaryEmail())
}

func TestDecodeUserPrimaryAndLimits(t *testing.T) {
	u, err := DecodeUser(strings.NewReader(`{"userName":"a","emails":[
		{"value":"1","primary":true},{"value":"2","primary":"True"},{"value":"3"}]}`))
	require.NoError(t, err)
	assert.Equal(t, []Email{{Value: "1"}, {Value: "2", Primary: true}, {Value: "3"}}, u.Emails)

	emails := make([]string, MaxEmails+1)
	for i := range emails {
		emails[i] = `{"value":"e"}`
	}

	_, err = DecodeUser(strings.NewReader(`{"userName":"a","emails":[` + strings.Join(emails, ",") + `]}`))
	require.ErrorIs(t, err, ErrInvalidValue)

	big := &User{UserName: "a", Emails: make([]Email, MaxEmails+1)}
	require.ErrorIs(t, big.Validate(), ErrInvalidValue)

	members := make([]string, MaxMembersPerRequest+1)
	for i := range members {
		members[i] = `{"value":"m"}`
	}

	_, err = DecodeGroup(strings.NewReader(`{"displayName":"g","members":[` + strings.Join(members, ",") + `]}`))
	require.Error(t, err)
	assert.Equal(t, 413, AsError(err).Status)
}
