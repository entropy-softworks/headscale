package scim

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServiceProviderConfigJSON(t *testing.T) {
	out, err := json.Marshal(NewServiceProviderConfig("https://hs.example.com/scim/v2/"))
	require.NoError(t, err)

	assert.JSONEq(t, `{
		"schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
		"patch": {"supported": true},
		"bulk": {"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter": {"supported": true, "maxResults": 1000},
		"changePassword": {"supported": false},
		"sort": {"supported": false},
		"etag": {"supported": false},
		"authenticationSchemes": [{
			"type": "oauthbearertoken",
			"name": "OAuth Bearer Token",
			"description": "Authentication with a bearer token issued by headscale, sent as \"Authorization: Bearer <token>\".",
			"specUri": "https://www.rfc-editor.org/info/rfc6750",
			"primary": true
		}],
		"meta": {
			"resourceType": "ServiceProviderConfig",
			"location": "https://hs.example.com/scim/v2/ServiceProviderConfig"
		}
	}`, string(out))
}

func TestResourceTypes(t *testing.T) {
	rts := NewResourceTypes("https://hs/scim/v2")
	require.Len(t, rts, 2)

	out, err := json.Marshal(rts[0])
	require.NoError(t, err)
	assert.JSONEq(t, `{
		"schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
		"id": "User", "name": "User", "endpoint": "/Users",
		"description": "User Account",
		"schema": "urn:ietf:params:scim:schemas:core:2.0:User",
		"meta": {"resourceType": "ResourceType", "location": "https://hs/scim/v2/ResourceTypes/User"}
	}`, string(out))
	assert.Equal(t, "/Groups", rts[1].Endpoint)
	assert.Equal(t, SchemaGroup, rts[1].Schema)
}

func findAttr(attrs []Attribute, name string) (Attribute, bool) {
	for _, a := range attrs {
		if a.Name == name {
			return a, true
		}
	}

	return Attribute{}, false
}

func TestSchemas(t *testing.T) {
	schemas := NewSchemas("https://hs/scim/v2")
	require.Len(t, schemas, 2)
	assert.Equal(t, SchemaUser, schemas[0].ID)
	assert.Equal(t, "https://hs/scim/v2/Schemas/"+SchemaUser, schemas[0].Meta.Location)
	assert.Equal(t, SchemaGroup, schemas[1].ID)

	userName, ok := findAttr(schemas[0].Attributes, "userName")
	require.True(t, ok)
	assert.True(t, userName.Required)
	assert.False(t, userName.CaseExact)
	assert.Equal(t, UniquenessServer, userName.Uniqueness)

	groups, ok := findAttr(schemas[0].Attributes, "groups")
	require.True(t, ok)
	assert.Equal(t, MutabilityReadOnly, groups.Mutability)
	assert.True(t, groups.MultiValued)

	displayName, ok := findAttr(schemas[1].Attributes, "displayName")
	require.True(t, ok)
	assert.True(t, displayName.Required)
	assert.Equal(t, UniquenessServer, displayName.Uniqueness,
		"group names are unique in headscale, as persistence enforces")

	members, ok := findAttr(schemas[1].Attributes, "members")
	require.True(t, ok)

	value, ok := findAttr(members.SubAttributes, "value")
	require.True(t, ok)
	assert.Equal(t, MutabilityImmutable, value.Mutability)

	// Boolean characteristics must be emitted even when false.
	out, err := json.Marshal(userName)
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(out, &m))
	assert.Contains(t, m, "caseExact")
	assert.Contains(t, m, "multiValued")
}

func TestCaseExactTable(t *testing.T) {
	tests := map[string]bool{
		"id":             true,
		"externalId":     true,
		"EXTERNALID":     true,
		"userName":       false,
		"displayName":    false,
		"emails.value":   false,
		"emails.type":    false,
		"members.value":  false,
		"members.$ref":   true,
		"meta.location":  true,
		"unknownAttr":    false,
		"name.givenName": false,
	}

	for path, want := range tests {
		assert.Equal(t, want, IsCaseExact(path), path)
	}
}
