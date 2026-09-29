package apiscim

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBearerToken(t *testing.T) {
	for header, want := range map[string]string{
		"Bearer tok":   "tok",
		"bearer tok":   "tok",
		"BEARER  tok ": "tok",
		"Basic tok":    "",
		"Bearer":       "",
		"Bearer ":      "",
		"":             "",
	} {
		got, ok := bearerToken(header)
		assert.Equal(t, want, got, header)
		assert.Equal(t, want != "", ok, header)
	}
}

func TestWantsAttribute(t *testing.T) {
	tests := []struct {
		attrs, excluded []string
		want            bool
	}{
		{want: true},
		{excluded: []string{"members"}, want: false},
		{excluded: []string{"Members"}, want: false},
		{excluded: []string{"urn:ietf:params:scim:schemas:core:2.0:Group:members"}, want: false},
		{excluded: []string{"members.display"}, want: true},
		{excluded: []string{"displayName"}, want: true},
		{attrs: []string{"displayName"}, want: false},
		{attrs: []string{"displayName", "members.value"}, want: true},
		{attrs: []string{"members"}, excluded: []string{"members"}, want: false},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.want, wantsAttribute(tt.attrs, tt.excluded, "members"), "%v %v", tt.attrs, tt.excluded)
	}
}
