package scim

import (
	"encoding/json"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseListRequest(t *testing.T) {
	tests := []struct {
		query     string
		start     int
		count     int
		filter    string
		attrs     []string
		excluded  []string
		errorType ScimType
	}{
		{query: "", start: 1, count: MaxPageSize},
		// Okta: GET /Users?filter=userName eq "x"&startIndex=1&count=100
		{query: `filter=userName+eq+"test.user%40okta.local"&startIndex=1&count=100`, start: 1, count: 100, filter: `userName eq "test.user@okta.local"`},
		// Entra ID group lookup.
		{query: `filter=displayName+eq+"Group1"&excludedAttributes=members`, start: 1, count: MaxPageSize, filter: `displayName eq "Group1"`, excluded: []string{"members"}},
		{query: "startIndex=0&count=-5", start: 1, count: 0},
		{query: "startIndex=-3", start: 1, count: MaxPageSize},
		{query: "startIndex=51&count=5000", start: 51, count: MaxPageSize},
		{query: "STARTINDEX=3&Count=7", start: 3, count: 7},
		{query: "attributes=userName,+name.givenName,&excludedAttributes=", start: 1, count: MaxPageSize, attrs: []string{"userName", "name.givenName"}},
		{query: "startIndex=abc", errorType: ScimTypeInvalidValue},
		{query: "count=1.5", errorType: ScimTypeInvalidValue},
		{query: "filter=userName+eq", errorType: ScimTypeInvalidFilter},
		{query: "attributes=bad+attr", errorType: ScimTypeInvalidValue},
	}

	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			q, err := url.ParseQuery(tt.query)
			require.NoError(t, err)

			req, err := ParseListRequest(q)
			if tt.errorType != "" {
				require.Error(t, err)
				assert.Equal(t, tt.errorType, AsError(err).ScimType)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.start, req.StartIndex)
			assert.Equal(t, tt.count, req.Count)
			assert.Equal(t, tt.attrs, req.Attributes)
			assert.Equal(t, tt.excluded, req.ExcludedAttributes)

			if tt.filter == "" {
				assert.Nil(t, req.Filter)
			} else {
				require.NotNil(t, req.Filter)
				assert.Equal(t, tt.filter, req.Filter.String())
			}
		})
	}
}

func TestParseProjection(t *testing.T) {
	attrs, excluded, err := ParseProjection(url.Values{"attributes": {"userName,emails"}, "excludedattributes": {"members"}})
	require.NoError(t, err)
	assert.Equal(t, []string{"userName", "emails"}, attrs)
	assert.Equal(t, []string{"members"}, excluded)

	_, _, err = ParseProjection(url.Values{"excludedAttributes": {"a b"}})
	require.ErrorIs(t, err, ErrInvalidValue)
}

func TestQueryParamCaseDeterministic(t *testing.T) {
	q := url.Values{"COUNT": {"3"}, "Count": {"2"}, "cOUNT": {"9"}}
	for range 50 {
		v, ok := queryParam(q, "count")
		require.True(t, ok)
		// No exact spelling: the lexically smallest key ("COUNT") wins.
		assert.Equal(t, "3", v)
	}

	q["count"] = []string{"7"}
	v, _ := queryParam(q, "count")
	assert.Equal(t, "7", v)

	_, ok := queryParam(q, "filter")
	assert.False(t, ok)
}

func TestPaginate(t *testing.T) {
	items := []int{1, 2, 3, 4, 5}

	assert.Equal(t, []int{1, 2, 3, 4, 5}, Paginate(&ListRequest{StartIndex: 1, Count: 10}, items))
	assert.Equal(t, []int{3, 4}, Paginate(&ListRequest{StartIndex: 3, Count: 2}, items))
	assert.Equal(t, []int{5}, Paginate(&ListRequest{StartIndex: 5, Count: 2}, items))
	assert.Empty(t, Paginate(&ListRequest{StartIndex: 6, Count: 2}, items))
	assert.Empty(t, Paginate(&ListRequest{StartIndex: 1, Count: 0}, items))
}

func TestListResponseJSON(t *testing.T) {
	// An empty filter result is still a 200 ListResponse (Entra ID).
	out, err := json.Marshal(NewListResponse(&ListRequest{StartIndex: 1}, 0, nil))
	require.NoError(t, err)
	assert.JSONEq(t, `{
		"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
		"totalResults":0,"itemsPerPage":0,"startIndex":1,"Resources":[]
	}`, string(out))

	out, err = json.Marshal(NewListResponse(nil, 12, []any{Group{ID: "1", DisplayName: "g"}}))
	require.NoError(t, err)
	assert.JSONEq(t, `{
		"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
		"totalResults":12,"itemsPerPage":1,"startIndex":1,
		"Resources":[{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"id":"1","displayName":"g"}]
	}`, string(out))
}

func TestProject(t *testing.T) {
	g := &Group{ID: "1", DisplayName: "eng", Members: []Member{{Value: "u1"}}}
	u := testUser()

	tests := []struct {
		name     string
		resource any
		attrs    []string
		excluded []string
		want     string
	}{
		{
			name:     "entra excludedAttributes=members",
			resource: g,
			excluded: []string{"members"},
			want:     `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"id":"1","displayName":"eng"}`,
		},
		{
			name:     "id and schemas cannot be excluded",
			resource: g,
			excluded: []string{"id", "SCHEMAS", "urn:ietf:params:scim:schemas:core:2.0:Group:displayName", "nope", "bad attr"},
			want:     `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"id":"1","members":[{"value":"u1"}]}`,
		},
		{
			name:     "exclude sub-attributes",
			resource: u,
			excluded: []string{"name.givenName", "emails.type", "meta", "externalId", "active", "displayName", "userName.x"},
			want: `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"42",
				"userName":"Alice.Smith@Example.com","name":{"familyName":"Smith"},
				"emails":[{"value":"alice@work.example","primary":true},{"value":"alice@home.example"}]}`,
		},
		{
			name:     "complex attributes emptied by exclusion are dropped",
			resource: u,
			excluded: []string{
				"name.givenName", "name.familyName",
				"emails.value", "emails.type", "emails.primary",
				"meta", "externalId", "active", "displayName",
			},
			want: `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"42","userName":"Alice.Smith@Example.com"}`,
		},
		{
			name:     "partially emptied multi-valued attribute keeps the rest",
			resource: map[string]any{"id": "1", "emails": []any{map[string]any{"value": "a"}, map[string]any{"value": "b", "type": "t"}, "s"}},
			excluded: []string{"emails.value"},
			want:     `{"id":"1","emails":[{"type":"t"},"s"]}`,
		},
		{
			name:     "attributes projection keeps id",
			resource: u,
			attrs:    []string{"userName", "name.givenName", "name.familyName", "emails.value", "emails.type", "nothing", "id.x", "bad attr"},
			want: `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"42",
				"userName":"Alice.Smith@Example.com","name":{"givenName":"Alice","familyName":"Smith"},
				"emails":[{"value":"alice@work.example","type":"work"},{"value":"alice@home.example","type":"home"}]}`,
		},
		{
			name:     "attributes then excluded",
			resource: u,
			attrs:    []string{"userName", "displayName"},
			excluded: []string{"displayName"},
			want:     `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"42","userName":"Alice.Smith@Example.com"}`,
		},
		{
			name:     "sub-attribute missing on some elements",
			resource: map[string]any{"id": "1", "emails": []any{map[string]any{"value": "a"}, map[string]any{"type": "x"}, "str"}},
			attrs:    []string{"emails.value", "name.givenName"},
			want:     `{"id":"1","emails":[{"value":"a"},{},{}]}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Project(tt.resource, tt.attrs, tt.excluded)
			require.NoError(t, err)

			out, err := json.Marshal(got)
			require.NoError(t, err)
			assert.JSONEq(t, tt.want, string(out))
		})
	}

	same, err := Project(g, nil, nil)
	require.NoError(t, err)
	assert.Same(t, g, same)

	_, err = Project(make(chan int), []string{"id"}, nil)
	require.Error(t, err)

	_, err = Project([]int{1}, []string{"id"}, nil)
	require.Error(t, err)
}
