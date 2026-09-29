package scim

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// baseUser is the resource the PATCH fixtures are applied to.
func baseUser() *User {
	return &User{
		ID:          "7",
		ExternalID:  "ext-7",
		UserName:    "test.user@okta.local",
		DisplayName: "Old Name",
		Active:      new(true),
		Name:        &Name{GivenName: "Old", FamilyName: "Name", Formatted: "Old Name"},
		Emails: []Email{
			{Value: "old@example.com", Type: "work", Primary: true},
		},
		Meta: &Meta{ResourceType: ResourceTypeUser, Created: time.Unix(0, 0).UTC()},
	}
}

func baseGroup() *Group {
	return &Group{
		ID:          "g1",
		DisplayName: "old",
		Members: []Member{
			{Value: "3"},
			{Value: "a71aac5b-f8b0-4c4e-8f2e-5f4c1d1e1b2a"},
			{Value: "89bb1940-b905-4575-9e7f-6f887cfb368e"},
		},
	}
}

func renderOps(ops []Operation) string {
	var sb strings.Builder
	for _, op := range ops {
		sb.WriteString(op.String())
		sb.WriteByte('\n')
	}

	return sb.String()
}

// TestGoldenPatch normalises every captured vendor PATCH body, applies it to
// a fixed resource, and compares the canonical operations and the result.
func TestGoldenPatch(t *testing.T) {
	for _, kind := range []string{"user", "group"} {
		for _, file := range fixtures(t, filepath.Join("patch", kind)) {
			t.Run(kind+"/"+filepath.Base(file), func(t *testing.T) {
				body, err := os.ReadFile(file)
				require.NoError(t, err)

				req, err := DecodePatch(bytes.NewReader(body))
				require.NoError(t, err)

				var (
					ops      []Operation
					resource any
					members  []Operation
				)

				if kind == "user" {
					ops, err = NormalizeUserPatch(req)
					require.NoError(t, err)

					u := baseUser()
					require.NoError(t, ApplyUserPatch(u, ops))

					resource = u
				} else {
					ops, err = NormalizeGroupPatch(req)
					require.NoError(t, err)

					g := baseGroup()
					members, err = ApplyGroupPatch(g, ops)
					require.NoError(t, err)

					resource = g
				}

				var out bytes.Buffer
				out.WriteString("# operations\n")
				out.WriteString(renderOps(ops))

				if kind == "group" {
					out.WriteString("# membership operations for the handler\n")
					out.WriteString(renderOps(members))
				}

				out.WriteString("# result\n")
				out.Write(indentJSON(t, resource))

				checkGolden(t, strings.TrimSuffix(file, ".json")+".golden", out.Bytes())
			})
		}
	}
}

func patchOf(t *testing.T, ops string) *PatchRequest {
	t.Helper()

	req, err := DecodePatch(strings.NewReader(
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":` + ops + `}`))
	require.NoError(t, err)

	return req
}

func TestDecodePatchErrors(t *testing.T) {
	for _, body := range []string{
		`{`,
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"]}`,
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[]}`,
		`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"Operations":[{"op":"add"}]}`,
	} {
		_, err := DecodePatch(strings.NewReader(body))
		require.ErrorIs(t, err, ErrInvalidSyntax, body)
	}

	req, err := DecodePatch(strings.NewReader(`{"Operations":{"op":"add"}}`))
	assert.Nil(t, req)
	require.ErrorIs(t, err, ErrInvalidValue)

	// schemas may be omitted; "operations" matches case-insensitively.
	req, err = DecodePatch(strings.NewReader(`{"operations":[{"op":"add","path":"displayName","value":"x"}]}`))
	require.NoError(t, err)
	assert.Len(t, req.Operations, 1)
}

func TestNormalizeUserPatchForms(t *testing.T) {
	tests := []struct {
		name string
		ops  string
		want []string
	}{
		{"string bool lower", `[{"op":"replace","path":"active","value":"true"}]`, []string{"set active true"}},
		{"op case", `[{"op":"REPLACE","path":"active","value":true}]`, []string{"set active true"}},
		{"nested name pathless", `[{"op":"replace","value":{"name":{"givenName":"x","middleName":"m"}}}]`, []string{`set name.givenName "x"`, "ignore name.middleName (not stored)"}},
		{
			"name path object", `[{"op":"add","path":"name","value":{"familyName":"y","FORMATTED":"z"}}]`,
			[]string{`set name.familyName "y"`, `set name.formatted "z"`},
		},
		{"remove name", `[{"op":"remove","path":"name"}]`, []string{"remove name"}},
		{"null name", `[{"op":"replace","path":"name","value":null}]`, []string{"remove name"}},
		{"ignored name sub", `[{"op":"replace","path":"name.honorificPrefix","value":"Dr"}]`, []string{"ignore name.honorificPrefix (not stored)"}},
		{
			"core urn pathless block", `[{"op":"replace","value":{"urn:ietf:params:scim:schemas:core:2.0:User":{"displayName":"d"}}}]`,
			[]string{`set displayName "d"`},
		},
		{
			"extension block pathless", `[{"op":"replace","value":{"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"department":"d"}}}]`,
			[]string{"ignore urn:ietf:params:scim:schemas:extension:enterprise:2.0:User (extension schema)"},
		},
		{"schemas and id skipped", `[{"op":"replace","value":{"schemas":["x"],"id":"1","meta":{},"userName":"u"}}]`, []string{`set userName "u"`}},
		{"externalId number", `[{"op":"replace","path":"externalId","value":12345}]`, []string{`set externalId "12345"`}},
		{
			"emails single object", `[{"op":"add","path":"emails","value":{"value":"a@b","type":"work"}}]`,
			[]string{`append emails [{"value":"a@b","type":"work"}]`},
		},
		{"emails remove all", `[{"op":"remove","path":"emails"}]`, []string{"remove emails"}},
		{
			"email filter object", `[{"op":"replace","path":"emails[type eq \"work\"]","value":{"value":"n@b","primary":"True","display":"x"}}]`,
			[]string{`set emails[type eq "work"] {"value":"n@b","primary":true}`},
		},
		{
			"email filter object null key", `[{"op":"add","path":"emails[type eq \"work\"]","value":{"type":null,"value":1}}]`,
			[]string{`set emails[type eq "work"] {"value":"1"}`},
		},
		{
			"remove emails by value", `[{"op":"remove","path":"emails","value":[{"value":"a@x"},{"value":"b@x"}]}]`,
			[]string{`remove emails[value eq "a@x" or value eq "b@x"]`},
		},
		{"remove emails empty value", `[{"op":"remove","path":"emails","value":[]}]`, nil},
		{
			"unknown attrs ignored", `[{"op":"replace","path":"favouriteColour","value":"x"},{"op":"replace","value":{"members":[]}}]`,
			[]string{"ignore favouriteColour (unknown attribute)", "ignore members (unknown attribute)"},
		},
		{"email filter remove sub", `[{"op":"remove","path":"emails[type eq \"work\"].type"}]`, []string{`remove emails[type eq "work"].type`}},
		{"email filter null", `[{"op":"replace","path":"emails[type eq \"work\"].value","value":null}]`, []string{`remove emails[type eq "work"].value`}},
		{
			"ignored attrs", `[{"op":"add","path":"password","value":"x"},{"op":"add","path":"roles","value":[]},{"op":"replace","path":"addresses[type eq \"work\"].formatted","value":"x"}]`,
			[]string{"ignore password (not stored)", "ignore roles (not stored)", `ignore addresses[type eq "work"].formatted (not stored)`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ops, err := NormalizeUserPatch(patchOf(t, tt.ops))
			require.NoError(t, err)

			var got []string
			for _, op := range ops {
				got = append(got, op.String())
			}

			assert.Equal(t, tt.want, got)
		})
	}
}

func TestNormalizePatchErrors(t *testing.T) {
	tests := []struct {
		name     string
		group    bool
		ops      string
		scimType ScimType
	}{
		{"unknown op", false, `[{"op":"move","path":"userName","value":"x"}]`, ScimTypeInvalidSyntax},
		{"pathless remove", false, `[{"op":"remove"}]`, ScimTypeNoTarget},
		{"pathless non-object", false, `[{"op":"replace","value":"x"}]`, ScimTypeInvalidSyntax},
		{"bad path", false, `[{"op":"replace","path":"user name","value":"x"}]`, ScimTypeInvalidPath},
		{"bad path chars", false, `[{"op":"replace","path":"a\u0001","value":"x"}]`, ScimTypeInvalidPath},
		{"bad filter in path", false, `[{"op":"replace","path":"emails[type eq]","value":"x"}]`, ScimTypeInvalidPath},
		{"unclosed filter", false, `[{"op":"replace","path":"emails[type eq \"x\"","value":"x"}]`, ScimTypeInvalidPath},
		{"filter on sub", false, `[{"op":"replace","path":"name.givenName[x eq \"y\"]","value":"x"}]`, ScimTypeInvalidPath},
		{"bad sub after filter", false, `[{"op":"replace","path":"emails[type eq \"x\"].1","value":"x"}]`, ScimTypeInvalidPath},
		{"trailing garbage", false, `[{"op":"replace","path":"emails[type eq \"x\"] x","value":"x"}]`, ScimTypeInvalidPath},
		{"path starts with bracket", false, `[{"op":"replace","path":"[x]","value":"x"}]`, ScimTypeInvalidPath},
		{"id", false, `[{"op":"replace","path":"id","value":"x"}]`, ScimTypeMutability},
		{"groups", false, `[{"op":"add","path":"groups","value":[{"value":"g"}]}]`, ScimTypeMutability},
		{"meta", true, `[{"op":"replace","path":"meta.created","value":"x"}]`, ScimTypeMutability},
		{"bad key pathless", false, `[{"op":"replace","value":{"a b":"x"}}]`, ScimTypeInvalidPath},
		{"userName sub", false, `[{"op":"replace","path":"userName.x","value":"x"}]`, ScimTypeInvalidPath},
		{"userName object", false, `[{"op":"replace","path":"userName","value":{"a":1}}]`, ScimTypeInvalidValue},
		{"active not bool", false, `[{"op":"replace","path":"active","value":"yes"}]`, ScimTypeInvalidValue},
		{"name filter", false, `[{"op":"replace","path":"name[givenName eq \"x\"]","value":"x"}]`, ScimTypeInvalidPath},
		{"name unknown sub", false, `[{"op":"replace","path":"name.nick","value":"x"}]`, ScimTypeInvalidPath},
		{"name not object", false, `[{"op":"replace","path":"name","value":"x"}]`, ScimTypeInvalidValue},
		{"name sub not string", false, `[{"op":"replace","value":{"name":{"givenName":true}}}]`, ScimTypeInvalidValue},
		{"emails.value without filter", false, `[{"op":"replace","path":"emails.value","value":"x"}]`, ScimTypeInvalidPath},
		{"emails not list", false, `[{"op":"replace","path":"emails","value":"x"}]`, ScimTypeInvalidValue},
		{"emails bad object", false, `[{"op":"replace","path":"emails","value":{"value":1}}]`, ScimTypeInvalidValue},
		{"emails missing value", false, `[{"op":"replace","path":"emails","value":[{"type":"work"}]}]`, ScimTypeInvalidValue},
		{"email filter non-object", false, `[{"op":"replace","path":"emails[type eq \"work\"]","value":"x"}]`, ScimTypeInvalidValue},
		{"email filter bad sub", false, `[{"op":"replace","path":"emails[type eq \"work\"].nope","value":"x"}]`, ScimTypeInvalidPath},
		{"email primary not bool", false, `[{"op":"replace","path":"emails[type eq \"work\"].primary","value":"x"}]`, ScimTypeInvalidValue},
		{"email filter object bad", false, `[{"op":"replace","path":"emails[type eq \"work\"]","value":{"nope":"x"}}]`, ScimTypeInvalidPath},
		{"nested core block", false, `[{"op":"replace","value":{"urn:ietf:params:scim:schemas:core:2.0:User":{"urn:ietf:params:scim:schemas:core:2.0:User":{}}}}]`, ScimTypeInvalidSyntax},
		{"space before sub", false, `[{"op":"replace","path":"emails[type eq \"x\"] .value","value":"x"}]`, ScimTypeInvalidPath},
		{"sub inside value filter", false, `[{"op":"remove","path":"emails[value.x eq \"y\"]"}]`, ScimTypeInvalidPath},
		{"remove emails bad value", false, `[{"op":"remove","path":"emails","value":"x"}]`, ScimTypeInvalidValue},
		{"email object bad value", false, `[{"op":"add","path":"emails[type eq \"w\"]","value":{"value":{}}}]`, ScimTypeInvalidValue},
		{"email object bad primary", false, `[{"op":"add","path":"emails[type eq \"w\"]","value":{"primary":"x"}}]`, ScimTypeInvalidValue},
		{"group id", true, `[{"op":"replace","path":"id","value":"x"}]`, ScimTypeMutability},
		{"members sub", true, `[{"op":"remove","path":"members.value"}]`, ScimTypeInvalidPath},
		{"members add filter", true, `[{"op":"add","path":"members[value eq \"1\"]","value":[]}]`, ScimTypeInvalidPath},
		{"members filter display", true, `[{"op":"remove","path":"members[display eq \"alice\"]"}]`, ScimTypeInvalidPath},
		{"members filter and", true, `[{"op":"remove","path":"members[value eq \"1\" and value eq \"2\"]"}]`, ScimTypeInvalidPath},
		{"members filter or bad", true, `[{"op":"remove","path":"members[value eq \"1\" or value pr]"}]`, ScimTypeInvalidPath},
		{"members filter or bad left", true, `[{"op":"remove","path":"members[value pr or value eq \"1\"]"}]`, ScimTypeInvalidPath},
		{"members filter empty", true, `[{"op":"remove","path":"members[value eq \"\"]"}]`, ScimTypeInvalidPath},
		{"add members null", true, `[{"op":"add","path":"members","value":null}]`, ScimTypeInvalidValue},
		{"members not list", true, `[{"op":"add","path":"members","value":"1"}]`, ScimTypeInvalidValue},
		{"member not object", true, `[{"op":"add","path":"members","value":[1]}]`, ScimTypeInvalidValue},
		{"member without value", true, `[{"op":"add","path":"members","value":[{"display":"x"}]}]`, ScimTypeInvalidValue},
		{"second op fails", true, `[{"op":"add","path":"displayName","value":"x"},{"op":"remove"}]`, ScimTypeNoTarget},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			if tt.group {
				_, err = NormalizeGroupPatch(patchOf(t, tt.ops))
			} else {
				_, err = NormalizeUserPatch(patchOf(t, tt.ops))
			}

			require.Error(t, err)
			assert.Equal(t, tt.scimType, AsError(err).ScimType, err.Error())
			assert.Contains(t, AsError(err).Detail, "Operations[")
		})
	}
}

func TestNormalizeGroupPatchForms(t *testing.T) {
	ops, err := NormalizeGroupPatch(patchOf(t, `[
		{"op":"add","path":"members","value":["1",{"value":"2"},"1"]},
		{"op":"add","path":"members","value":{"value":"3"}},
		{"op":"replace","path":"members","value":null},
		{"op":"remove","path":"externalId"},
		{"op":"replace","path":"urn:ietf:params:scim:schemas:core:2.0:Group:displayName","value":"n"}
	]`))
	require.NoError(t, err)

	got := renderOps(ops)
	assert.Equal(t, `add-members ["1","2"]
add-members ["3"]
replace-members []
remove externalId
set displayName "n"
`, got)
}

func TestApplyUserPatchEmails(t *testing.T) {
	apply := func(t *testing.T, u *User, ops string) error {
		t.Helper()

		norm, err := NormalizeUserPatch(patchOf(t, ops))
		require.NoError(t, err)

		return ApplyUserPatch(u, norm)
	}

	t.Run("upsert seeds type from filter", func(t *testing.T) {
		u := &User{UserName: "a"}
		require.NoError(t, apply(t, u, `[{"op":"replace","path":"emails[type eq \"work\"].value","value":"w@x"}]`))
		assert.Equal(t, []Email{{Value: "w@x", Type: "work"}}, u.Emails)
	})

	t.Run("upsert seeds value from filter", func(t *testing.T) {
		u := &User{UserName: "a"}
		require.NoError(t, apply(t, u, `[{"op":"add","path":"emails[value eq \"v@x\"].type","value":"home"}]`))
		assert.Equal(t, []Email{{Value: "v@x", Type: "home"}}, u.Emails)
	})

	t.Run("upsert without value fails validation", func(t *testing.T) {
		u := &User{UserName: "a"}
		err := apply(t, u, `[{"op":"add","path":"emails[type eq \"work\"].primary","value":true}]`)
		require.ErrorIs(t, err, ErrInvalidValue)
	})

	t.Run("primary moves", func(t *testing.T) {
		u := &User{UserName: "a", Emails: []Email{{Value: "1", Type: "work", Primary: true}, {Value: "2", Type: "home"}}}
		require.NoError(t, apply(t, u, `[{"op":"replace","path":"emails[value eq \"2\"].primary","value":true}]`))
		assert.Equal(t, "2", u.PrimaryEmail())
		assert.False(t, u.Emails[0].Primary)

		require.NoError(t, apply(t, u, `[{"op":"replace","path":"emails[value eq \"2\"].primary","value":false}]`))
		assert.False(t, u.Emails[1].Primary)
	})

	t.Run("append dedupes case-insensitively and keeps one primary", func(t *testing.T) {
		u := &User{UserName: "a", Emails: []Email{{Value: "A@x", Primary: true}}}
		require.NoError(t, apply(t, u, `[{"op":"add","path":"emails","value":[{"value":"a@X","type":"work"},{"value":"b@x","primary":true}]}]`))
		assert.Equal(t, []Email{{Value: "a@X", Type: "work"}, {Value: "b@x", Primary: true}}, u.Emails)
	})

	t.Run("replace list", func(t *testing.T) {
		u := &User{UserName: "a", Emails: []Email{{Value: "old"}}}
		require.NoError(t, apply(t, u, `[{"op":"replace","path":"emails","value":[{"value":"new"}]}]`))
		assert.Equal(t, []Email{{Value: "new"}}, u.Emails)
	})

	t.Run("remove subs", func(t *testing.T) {
		u := &User{UserName: "a", Emails: []Email{
			{Value: "1", Type: "work", Primary: true},
			{Value: "2", Type: "home"},
			{Value: "3", Type: "other"},
		}}
		require.NoError(t, apply(t, u, `[
			{"op":"remove","path":"emails[type eq \"work\"].primary"},
			{"op":"remove","path":"emails[type eq \"home\"].type"},
			{"op":"remove","path":"emails[type eq \"other\"].value"},
			{"op":"remove","path":"emails[type eq \"none\"]"}
		]`))
		assert.Equal(t, []Email{{Value: "1", Type: "work"}, {Value: "2"}}, u.Emails)

		require.NoError(t, apply(t, u, `[{"op":"remove","path":"emails[value pr]"}]`))
		assert.Nil(t, u.Emails)
	})

	t.Run("multiple matches all updated", func(t *testing.T) {
		u := &User{UserName: "a", Emails: []Email{{Value: "1", Type: "work"}, {Value: "2", Type: "work"}}}
		require.NoError(t, apply(t, u, `[{"op":"replace","path":"emails[type eq \"work\"].type","value":"home"}]`))
		assert.Equal(t, []Email{{Value: "1", Type: "home"}, {Value: "2", Type: "home"}}, u.Emails)
	})
}

func TestApplyUserPatchScalars(t *testing.T) {
	u := baseUser()

	ops, err := NormalizeUserPatch(patchOf(t, `[
		{"op":"remove","path":"externalId"},
		{"op":"remove","path":"active"},
		{"op":"remove","path":"name.givenName"},
		{"op":"replace","path":"name.formatted","value":"F"},
		{"op":"remove","path":"emails"}
	]`))
	require.NoError(t, err)
	require.NoError(t, ApplyUserPatch(u, ops))

	assert.Empty(t, u.ExternalID)
	assert.Nil(t, u.Active)
	assert.Equal(t, &Name{FamilyName: "Name", Formatted: "F"}, u.Name)
	assert.Nil(t, u.Emails)

	// A nil name gets allocated; removing a sub of a nil name is a no-op.
	u = &User{UserName: "a"}
	require.NoError(t, ApplyUserPatch(u, []Operation{
		RemoveAttribute{Path: Path{Attr: "name", Sub: "familyName"}},
		SetAttribute{Path: Path{Attr: "name", Sub: "givenName"}, Value: "G"},
	}))
	assert.Equal(t, &Name{GivenName: "G"}, u.Name)

	// Removing userName is caught by validation.
	err = ApplyUserPatch(baseUser(), []Operation{RemoveAttribute{Path: Path{Attr: "userName"}}})
	require.ErrorIs(t, err, ErrInvalidValue)
}

func TestApplyUserPatchRejectsBadOps(t *testing.T) {
	for _, op := range []Operation{
		AddMembers{IDs: []string{"1"}},
		SetAttribute{Path: Path{Attr: "userName"}, Value: 1},
		SetAttribute{Path: Path{Attr: "active"}, Value: "true"},
		SetAttribute{Path: Path{Attr: "nope"}, Value: "x"},
		SetAttribute{Path: Path{Attr: "emails"}, Value: "x"},
		SetAttribute{Path: Path{Attr: "emails", Filter: &PresentExpr{Path: AttrPath{Attr: "value"}}, Sub: "value"}, Value: 1},
		SetAttribute{Path: Path{Attr: "emails", Filter: &PresentExpr{Path: AttrPath{Attr: "value"}}, Sub: "type"}, Value: 1},
		SetAttribute{Path: Path{Attr: "emails", Filter: &PresentExpr{Path: AttrPath{Attr: "value"}}, Sub: "primary"}, Value: 1},
		SetAttribute{Path: Path{Attr: "emails", Filter: &PresentExpr{Path: AttrPath{Attr: "value"}}, Sub: "x"}, Value: 1},
		RemoveAttribute{Path: Path{Attr: "nope"}},
	} {
		u := baseUser()
		err := ApplyUserPatch(u, []Operation{op})
		require.Error(t, err, op.String())
	}
}

func TestApplyGroupPatch(t *testing.T) {
	g := baseGroup()

	members, err := ApplyGroupPatch(g, []Operation{
		SetAttribute{Path: Path{Attr: "externalId"}, Value: "e"},
		AddMembers{IDs: []string{"3", "4"}},
		RemoveMembers{IDs: []string{"a71aac5b-f8b0-4c4e-8f2e-5f4c1d1e1b2a", "nope"}},
		RemoveAttribute{Path: Path{Attr: "externalId"}},
	})
	require.NoError(t, err)
	assert.Len(t, members, 2)
	assert.Equal(t, []string{"3", "89bb1940-b905-4575-9e7f-6f887cfb368e", "4"}, g.MemberIDs())
	assert.Empty(t, g.ExternalID)

	_, err = ApplyGroupPatch(g, []Operation{RemoveMembers{IDs: g.MemberIDs()}})
	require.NoError(t, err)
	assert.Nil(t, g.Members)

	_, err = ApplyGroupPatch(baseGroup(), []Operation{RemoveAttribute{Path: Path{Attr: "displayName"}}})
	require.ErrorIs(t, err, ErrInvalidValue)

	for _, op := range []Operation{
		SetAttribute{Path: Path{Attr: "members"}, Value: "x"},
		SetAttribute{Path: Path{Attr: "displayName"}, Value: 1},
		RemoveAttribute{Path: Path{Attr: "members"}},
	} {
		_, err = ApplyGroupPatch(baseGroup(), []Operation{op})
		require.Error(t, err, op.String())
	}
}

// fast runs f and fails if it takes longer than a second. The inputs below
// took seconds to minutes before the request limits and linear-time
// membership handling; now they finish in milliseconds, so the bound leaves
// ample headroom for slow CI machines and -race.
func fast(t *testing.T, name string, f func()) {
	t.Helper()

	start := time.Now()

	f()

	elapsed := time.Since(start)
	t.Logf("%s: %v", name, elapsed)
	assert.Less(t, elapsed, time.Second, name)
}

func memberValues(prefix string, n int) string {
	vals := make([]string, n)
	for i := range vals {
		vals[i] = `{"value":"` + prefix + strconv.Itoa(i) + `"}`
	}

	return "[" + strings.Join(vals, ",") + "]"
}

func TestPatchResourceLimits(t *testing.T) {
	t.Run("members at the limit are linear", func(t *testing.T) {
		g := &Group{DisplayName: "g"}
		for i := range MaxMembersPerRequest {
			g.Members = append(g.Members, Member{Value: "old" + strconv.Itoa(i)})
		}

		body := `{"Operations":[{"op":"add","path":"members","value":` + memberValues("new", MaxMembersPerRequest) + `}]}`

		fast(t, "add 10k members to a 10k group", func() {
			req, err := DecodePatch(strings.NewReader(body))
			require.NoError(t, err)

			ops, err := NormalizeGroupPatch(req)
			require.NoError(t, err)

			_, err = ApplyGroupPatch(g, ops)
			require.NoError(t, err)
		})
		assert.Len(t, g.Members, 2*MaxMembersPerRequest)

		ids := g.MemberIDs()

		fast(t, "remove 10k members from a 20k group", func() {
			_, err := ApplyGroupPatch(g, []Operation{RemoveMembers{IDs: ids[:MaxMembersPerRequest]}})
			require.NoError(t, err)
		})
		assert.Len(t, g.Members, MaxMembersPerRequest)

		fast(t, "dedupe 10k", func() {
			assert.Len(t, dedupe(slices.Concat(ids, ids)), 2*MaxMembersPerRequest)
		})
	})

	t.Run("58k members in 1 MiB is rejected", func(t *testing.T) {
		body := `{"Operations":[{"op":"add","path":"members","value":` + memberValues("", 58000) + `}]}`
		require.Less(t, len(body), MaxBodySize)

		fast(t, "reject 58k members", func() {
			req, err := DecodePatch(strings.NewReader(body))
			require.NoError(t, err)

			_, err = NormalizeGroupPatch(req)
			require.Error(t, err)
			assert.Equal(t, 413, AsError(err).Status)
		})
	})

	t.Run("member budget spans operations", func(t *testing.T) {
		ops := make([]string, 0, MaxOperations)
		for i := range MaxOperations {
			ops = append(ops, `{"op":"add","path":"members","value":`+memberValues(strconv.Itoa(i)+"-", 11)+`}`)
		}

		req, err := DecodePatch(strings.NewReader(`{"Operations":[` + strings.Join(ops, ",") + `]}`))
		require.NoError(t, err)

		_, err = NormalizeGroupPatch(req)
		require.Error(t, err)
		assert.Equal(t, 413, AsError(err).Status)
	})

	t.Run("48k-term member filter is rejected", func(t *testing.T) {
		terms := make([]string, 48000)
		for i := range terms {
			terms[i] = `value eq \"` + strconv.Itoa(i) + `\"`
		}

		body := `{"Operations":[{"op":"remove","path":"members[` + strings.Join(terms, " or ") + `]"}]}`

		fast(t, "reject 48k-term filter", func() {
			req, err := DecodePatch(strings.NewReader(body))
			require.NoError(t, err)

			_, err = NormalizeGroupPatch(req)
			require.ErrorIs(t, err, ErrInvalidPath)
		})
	})

	t.Run("longest accepted member filter", func(t *testing.T) {
		var terms []string

		path := ""

		for i := 0; ; i++ {
			next := `members[` + strings.Join(append(terms, `value eq "`+strconv.Itoa(i)+`"`), " or ") + `]`
			if len(next) > MaxPathLength {
				break
			}

			terms = append(terms, `value eq "`+strconv.Itoa(i)+`"`)
			path = next
		}

		p, err := ParsePath(path)
		require.NoError(t, err)

		ops, err := membersOp(opRemove, p, nil)
		require.NoError(t, err)

		rm, ok := ops[0].(RemoveMembers)
		require.True(t, ok)
		assert.Len(t, rm.IDs, len(terms))
	})

	t.Run("nested core schema blocks are rejected", func(t *testing.T) {
		const depth = 9000

		body := `{"Operations":[{"op":"replace","value":` +
			strings.Repeat(`{"`+SchemaUser+`":`, depth) + `{}` + strings.Repeat(`}`, depth) + `}]}`

		fast(t, "reject 9k nested blocks", func() {
			req, err := DecodePatch(strings.NewReader(body))
			require.NoError(t, err)

			_, err = NormalizeUserPatch(req)
			require.ErrorIs(t, err, ErrInvalidSyntax)
		})
	})

	t.Run("too many operations", func(t *testing.T) {
		ops := strings.Repeat(`{"op":"replace","path":"active","value":true},`, MaxOperations)

		_, err := DecodePatch(strings.NewReader(`{"Operations":[` + ops + `{"op":"replace","path":"active","value":true}]}`))
		require.Error(t, err)
		assert.Equal(t, 413, AsError(err).Status)

		// NormalizeUserPatch enforces the limit for hand-built requests too.
		_, err = NormalizeUserPatch(&PatchRequest{Operations: make([]PatchOperation, MaxOperations+1)})
		require.Error(t, err)
		assert.Equal(t, 413, AsError(err).Status)
	})

	t.Run("too many emails", func(t *testing.T) {
		vals := make([]string, MaxEmails+1)
		for i := range vals {
			vals[i] = `{"value":"e` + strconv.Itoa(i) + `@x"}`
		}

		_, err := NormalizeUserPatch(patchOf(t, `[{"op":"add","path":"emails","value":[`+strings.Join(vals, ",")+`]}]`))
		require.ErrorIs(t, err, ErrInvalidValue)

		// Appending within the per-request limit still cannot grow a user
		// past MaxEmails.
		u := &User{UserName: "a", Emails: make([]Email, MaxEmails)}
		for i := range u.Emails {
			u.Emails[i].Value = "old" + strconv.Itoa(i)
		}

		ops, err := NormalizeUserPatch(patchOf(t, `[{"op":"add","path":"emails","value":[{"value":"new@x"}]}]`))
		require.NoError(t, err)
		require.ErrorIs(t, ApplyUserPatch(u, ops), ErrInvalidValue)
	})

	t.Run("path length", func(t *testing.T) {
		_, err := ParsePath(strings.Repeat("a", MaxPathLength+1))
		require.ErrorIs(t, err, ErrInvalidPath)
	})
}

// TestEmailObjectReplaceKeyOrder: all sub-attributes of a filtered emails
// object apply to the elements the filter selected before the operation,
// whatever the key order.
func TestEmailObjectReplaceKeyOrder(t *testing.T) {
	for _, value := range []string{
		`{"type":"home","value":"q@b"}`,
		`{"value":"q@b","type":"home"}`,
	} {
		t.Run(value, func(t *testing.T) {
			u := &User{UserName: "a", Emails: []Email{
				{Value: "a@x", Type: "work", Primary: true},
				{Value: "h@x", Type: "home"},
			}}

			ops, err := NormalizeUserPatch(patchOf(t, `[{"op":"replace","path":"emails[type eq \"work\"]","value":`+value+`}]`))
			require.NoError(t, err)
			require.NoError(t, ApplyUserPatch(u, ops))

			assert.Equal(t, []Email{
				{Value: "q@b", Type: "home", Primary: true},
				{Value: "h@x", Type: "home"},
			}, u.Emails)
		})
	}

	t.Run("upsert and primary", func(t *testing.T) {
		u := &User{UserName: "a", Emails: []Email{{Value: "h@x", Type: "home", Primary: true}}}

		ops, err := NormalizeUserPatch(patchOf(t,
			`[{"op":"add","path":"emails[type eq \"work\"]","value":{"primary":true,"value":"w@x"}}]`))
		require.NoError(t, err)
		require.NoError(t, ApplyUserPatch(u, ops))

		assert.Equal(t, []Email{
			{Value: "h@x", Type: "home"},
			{Value: "w@x", Type: "work", Primary: true},
		}, u.Emails)
	})

	t.Run("wrong value type", func(t *testing.T) {
		p := Path{Attr: "emails", Filter: &PresentExpr{Path: AttrPath{Attr: "value"}}}
		err := ApplyUserPatch(baseUser(), []Operation{SetAttribute{Path: p, Value: "x"}})
		require.ErrorIs(t, err, ErrInvalidValue)
	})
}

func TestRemoveEmailsByValue(t *testing.T) {
	u := &User{UserName: "a", Emails: []Email{{Value: "A@x"}, {Value: "b@x"}, {Value: "c@x", Primary: true}}}

	ops, err := NormalizeUserPatch(patchOf(t, `[{"op":"remove","path":"emails","value":[{"value":"a@X"},{"value":"c@x"}]}]`))
	require.NoError(t, err)
	require.NoError(t, ApplyUserPatch(u, ops))
	assert.Equal(t, []Email{{Value: "b@x"}}, u.Emails)
}

func TestIgnoredAttributesAreSkipped(t *testing.T) {
	ops, err := NormalizeGroupPatch(patchOf(t, `[{"op":"replace","value":{"owner":"x","displayName":"n"}}]`))
	require.NoError(t, err)
	assert.Equal(t, "ignore owner (unknown attribute)\nset displayName \"n\"\n", renderOps(ops))

	g := baseGroup()
	members, err := ApplyGroupPatch(g, ops)
	require.NoError(t, err)
	assert.Empty(t, members)
	assert.Equal(t, "n", g.DisplayName)

	require.NoError(t, ApplyUserPatch(baseUser(), []Operation{IgnoredAttribute{Path: Path{Attr: "title"}}}))
}
