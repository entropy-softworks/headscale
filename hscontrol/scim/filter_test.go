package scim

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseFilter(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string // canonical String() of the tree
	}{
		// Entra ID (learn.microsoft.com use-scim-to-provision-users-and-groups).
		{"entra userName", `userName eq "Test_User_dfeef4c5-5681-4387-b016-bdf221e82081"`, `userName eq "Test_User_dfeef4c5-5681-4387-b016-bdf221e82081"`},
		{"entra externalId", `externalId eq "0a21f0f2-8d2a-4f8e-bf98-7363c4aed4ef"`, `externalId eq "0a21f0f2-8d2a-4f8e-bf98-7363c4aed4ef"`},
		{"entra email value path", `emails[type eq "work"].value eq "Test_User@testuser.com"`, `emails[type eq "work" and value eq "Test_User@testuser.com"]`},
		{"entra group displayName", `displayName eq "Group1DisplayName"`, `displayName eq "Group1DisplayName"`},
		{"entra and", `userName eq "a" and externalId eq "b"`, `userName eq "a" and externalId eq "b"`},
		// Okta.
		{"okta userName", `userName eq "test.user@okta.local"`, `userName eq "test.user@okta.local"`},
		// Case-insensitive names and operators; URN prefix.
		{"case", `USERNAME EQ "a"`, `userName eq "a"`},
		{"urn prefix", `urn:ietf:params:scim:schemas:core:2.0:User:userName eq "a"`, `userName eq "a"`},
		{"urn sub attr", `urn:ietf:params:scim:schemas:core:2.0:User:name.givenName sw "B"`, `name.givenName sw "B"`},
		{"sub attr", `name.familyName co "O'Malley"`, `name.familyName co "O'Malley"`},
		// Operators and literals.
		{"pr", `title pr`, `title pr`},
		{"ne", `userName ne "a"`, `userName ne "a"`},
		{"ew", `userName ew "@example.com"`, `userName ew "@example.com"`},
		{"gt date", `meta.lastModified gt "2011-05-13T04:42:34Z"`, `meta.lastModified gt "2011-05-13T04:42:34Z"`},
		{"ge number", `x ge 1.5e3`, `x ge 1500`},
		{"lt negative", `x lt -2`, `x lt -2`},
		{"bool", `active eq true`, `active eq true`},
		{"bool case", `active eq False`, `active eq false`},
		{"null", `externalId eq null`, `externalId eq null`},
		{"escapes", `displayName eq "a \"b\" \\ é \n"`, `displayName eq "a \"b\" \\ é \n"`},
		// Precedence: not > and > or.
		{"or/and precedence", `a eq 1 or b eq 2 and c eq 3`, `a eq 1 or b eq 2 and c eq 3`},
		{"parens", `(a eq 1 or b eq 2) and c eq 3`, `(a eq 1 or b eq 2) and c eq 3`},
		{"not", `not (userName eq "a") and active eq true`, `not (userName eq "a") and active eq true`},
		{"NOT upper", `NOT(userName eq "a")`, `not (userName eq "a")`},
		{"value path or", `emails[type eq "work" or type eq "home"]`, `emails[type eq "work" or type eq "home"]`},
		{"value path not", `emails[not (value pr)]`, `emails[not (value pr)]`},
		{
			"rfc example", `userType eq "Employee" and (emails co "example.com" or emails.value co "example.org")`,
			`userType eq "Employee" and (emails co "example.com" or emails.value co "example.org")`,
		},
		{"attr named like keyword", `and eq "x"`, `and eq "x"`},
		{"whitespace", "  userName\teq\n\"a\"  ", `userName eq "a"`},
		{"members value", `members[value eq "1"]`, `members[value eq "1"]`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := ParseFilter(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.want, e.String())

			// String() output re-parses to the same tree.
			again, err := ParseFilter(e.String())
			require.NoError(t, err)
			assert.Equal(t, e.String(), again.String())
		})
	}
}

func TestParseFilterLongChain(t *testing.T) {
	// A flat chain is not nesting: it must parse and round-trip even though
	// it is far longer than the nesting limit.
	terms := make([]string, 200)
	for i := range terms {
		terms[i] = `a eq 1`
	}

	for _, op := range []string{" and ", " or "} {
		e, err := ParseFilter(strings.Join(terms, op))
		require.NoError(t, err)

		again, err := ParseFilter(e.String())
		require.NoError(t, err)
		assert.Equal(t, e.String(), again.String())
	}
}

func TestParseFilterAST(t *testing.T) {
	e, err := ParseFilter(`urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber eq "42"`)
	require.NoError(t, err)

	c, ok := e.(*CompareExpr)
	require.True(t, ok)
	assert.Equal(t, AttrPath{URI: SchemaEnterpriseUser, Attr: "employeeNumber"}, c.Path)
	assert.True(t, c.Path.IsExtension())
	assert.Equal(t, OpEq, c.Op)
	assert.Equal(t, "42", c.Value)

	e, err = ParseFilter(`emails[type eq "work"]`)
	require.NoError(t, err)

	vp, ok := e.(*ValuePathExpr)
	require.True(t, ok)
	assert.Equal(t, "emails", vp.Path.Attr)
	assert.Equal(t, &CompareExpr{Path: AttrPath{Attr: "type"}, Op: OpEq, Value: "work"}, vp.Filter)
}

func TestParseFilterErrors(t *testing.T) {
	tests := []string{
		``,
		`userName`,
		`userName eq`,
		`userName xx "a"`,
		`userName eq "a`,
		`userName eq "\x"`,
		`userName eq "a" and`,
		`userName eq "a" or and`,
		`(userName eq "a"`,
		`userName eq "a")`,
		`userName eq bare`,
		`userName eq 0x10`,
		`userName eq 1_000`,
		`active gt true`,
		`x lt null`,
		`userName co 1`,
		`userName sw true`,
		`emails[type eq "work"`,
		`emails[type eq "work"]]`,
		`emails[addresses[type eq "x"]]`,
		`name.givenName[x eq "y"]`,
		`emails[type eq "work"].1bad eq "x"`,
		`emails[type eq "work"].value`,
		`emails[type eq "work"] .value eq "x"`,
		`emails[value.foo eq "x"]`,
		`emails[urn:ietf:params:scim:schemas:core:2.0:User:value eq "x"]`,
		`1userName eq "a"`,
		`user.name.x eq "a"`,
		`urn:ietf:params:scim:schemas:core:2.0 eq "a"`,
		`userName eq "a" userName eq "b"`,
		`not userName eq "a"`,
		"userName eq \"a\" \x01",
		"userName eq \"\xaf\"",
		`[`,
		strings.Repeat("(", 40) + `a eq 1` + strings.Repeat(")", 40),
		strings.Repeat("a", MaxFilterLength+1),
	}

	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			_, err := ParseFilter(input)
			require.Error(t, err)
			require.ErrorIs(t, err, ErrInvalidFilter)
		})
	}
}

func TestParseAttrPath(t *testing.T) {
	p, err := ParseAttrPath(" Name.GivenName ")
	require.NoError(t, err)
	assert.Equal(t, AttrPath{Attr: "name", Sub: "givenName"}, p)
	assert.Equal(t, "name.givenName", p.String())
	assert.False(t, p.IsExtension())

	p, err = ParseAttrPath("urn:ietf:params:scim:schemas:core:2.0:Group:members")
	require.NoError(t, err)
	assert.False(t, p.IsExtension())
	assert.Equal(t, "members", p.Attr)

	_, err = ParseAttrPath("a b")
	require.Error(t, err)
}

// FuzzParseFilter checks that the parser never panics and that every
// accepted filter survives a String()/ParseFilter round trip.
func FuzzParseFilter(f *testing.F) {
	for _, s := range []string{
		`userName eq "a"`,
		`emails[type eq "work"].value eq "x@y"`,
		`not (a pr) or (b gt 1 and c le "2011-05-13T04:42:34Z")`,
		`urn:ietf:params:scim:schemas:core:2.0:User:name.givenName sw "B"`,
		`members[value eq "1" or value eq "2"]`,
		`x eq null and y ne false`,
		`displayName eq "é\"\\"`,
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		e, err := ParseFilter(s)
		if err != nil {
			require.ErrorIs(t, err, ErrInvalidFilter)

			return
		}

		again, err := ParseFilter(e.String())
		require.NoError(t, err, "re-parsing %q (from %q)", e.String(), s)
		assert.Equal(t, e.String(), again.String())

		// The evaluator must not panic on any accepted filter.
		_, err = Match(e, map[string]any{
			"userName": "a",
			"emails":   []any{map[string]any{"value": "x@y", "type": "work"}},
			"name":     map[string]any{"givenName": "B"},
			"x":        1.0,
		})
		require.NoError(t, err)
	})
}
