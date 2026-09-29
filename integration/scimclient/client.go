// Package scimclient is a minimal SCIM 2.0 client (RFC 7643, RFC 7644) for
// integration tests. It speaks the wire protocol the way identity providers
// do, including the non-standard PATCH forms Entra ID and Okta send, so the
// tests exercise headscale's /scim/v2 endpoint as a real provider would.
//
// Every call returns the raw [Response] next to the decoded resource so tests
// can assert on status codes and error bodies. A transport failure, a
// successful response that is not application/scim+json, or a body that does
// not decode is returned as an error.
package scimclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Schema URNs used in requests and responses.
const (
	SchemaUser                  = "urn:ietf:params:scim:schemas:core:2.0:User"
	SchemaGroup                 = "urn:ietf:params:scim:schemas:core:2.0:Group"
	SchemaPatchOp               = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	SchemaListResponse          = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	SchemaError                 = "urn:ietf:params:scim:api:messages:2.0:Error"
	SchemaServiceProviderConfig = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"

	// ContentType is the SCIM media type (RFC 7644 section 3.1).
	ContentType = "application/scim+json"

	// BasePath is where headscale serves SCIM, relative to server_url.
	BasePath = "/scim/v2"

	requestTimeout = 30 * time.Second
)

var errContentType = errors.New("unexpected content type")

// Name is the SCIM user's name complex attribute.
type Name struct {
	Formatted  string `json:"formatted,omitempty"`
	GivenName  string `json:"givenName,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
}

// Email is one entry of a SCIM user's emails.
type Email struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

// Ref is a reference to another resource: a user's group or a group's member.
type Ref struct {
	Value   string `json:"value"`
	Ref     string `json:"$ref,omitempty"`
	Display string `json:"display,omitempty"`
}

// Meta is the resource metadata (RFC 7643 section 3.1).
type Meta struct {
	ResourceType string `json:"resourceType,omitempty"`
	Created      string `json:"created,omitempty"`
	LastModified string `json:"lastModified,omitempty"`
	Location     string `json:"location,omitempty"`
	Version      string `json:"version,omitempty"`
}

// User is a SCIM user resource. Active is a pointer so a response that omits
// it is distinguishable from active=false.
type User struct {
	Schemas     []string `json:"schemas,omitempty"`
	ID          string   `json:"id,omitempty"`
	ExternalID  string   `json:"externalId,omitempty"`
	UserName    string   `json:"userName"`
	Name        *Name    `json:"name,omitempty"`
	DisplayName string   `json:"displayName,omitempty"`
	Active      *bool    `json:"active,omitempty"`
	Emails      []Email  `json:"emails,omitempty"`
	Groups      []Ref    `json:"groups,omitempty"`
	Meta        *Meta    `json:"meta,omitempty"`
}

// Group is a SCIM group resource.
type Group struct {
	Schemas     []string `json:"schemas,omitempty"`
	ID          string   `json:"id,omitempty"`
	ExternalID  string   `json:"externalId,omitempty"`
	DisplayName string   `json:"displayName"`
	Members     []Ref    `json:"members,omitempty"`
	Meta        *Meta    `json:"meta,omitempty"`
}

// ListResponse is a SCIM list response (RFC 7644 section 3.4.2).
type ListResponse[T any] struct {
	Schemas      []string `json:"schemas"`
	TotalResults int      `json:"totalResults"`
	StartIndex   int      `json:"startIndex"`
	ItemsPerPage int      `json:"itemsPerPage"`
	Resources    []T      `json:"Resources"` //nolint:tagliatelle // RFC 7644 capitalises it
}

// Error is a SCIM error body (RFC 7644 section 3.12). Status is a string on
// the wire.
type Error struct {
	Schemas  []string `json:"schemas"`
	Status   string   `json:"status"`
	ScimType string   `json:"scimType,omitempty"`
	Detail   string   `json:"detail,omitempty"`
}

// PatchOperation is one operation of a PATCH request. Value is any so tests
// can send the exact shape a provider sends (strings for booleans included).
type PatchOperation struct {
	Op    string `json:"op"`
	Path  string `json:"path,omitempty"`
	Value any    `json:"value,omitempty"`
}

// PatchRequest is a SCIM PatchOp message.
type PatchRequest struct {
	Schemas    []string         `json:"schemas"`
	Operations []PatchOperation `json:"Operations"` //nolint:tagliatelle // RFC 7644 capitalises it
}

// Response is the raw HTTP outcome of a SCIM call.
type Response struct {
	StatusCode  int
	ContentType string
	Body        []byte
}

// String renders the response for assertion messages.
func (r *Response) String() string {
	if r == nil {
		return "<no response>"
	}

	return fmt.Sprintf("HTTP %d (%s): %s", r.StatusCode, r.ContentType, strings.TrimSpace(string(r.Body)))
}

// IsSCIM reports whether the response's media type is application/scim+json.
func (r *Response) IsSCIM() bool {
	mt, _, err := mime.ParseMediaType(r.ContentType)

	return err == nil && mt == ContentType
}

// Error decodes the body as a SCIM error, or returns nil if it is not one.
func (r *Response) Error() *Error {
	var e Error

	err := json.Unmarshal(r.Body, &e)
	if err != nil || len(e.Schemas) == 0 {
		return nil
	}

	return &e
}

// Client calls a headscale SCIM endpoint with a bearer token.
type Client struct {
	base  string
	token string
	hc    *http.Client
}

// New returns a client for the SCIM endpoint under serverURL (headscale's
// server_url, as the test harness's GetEndpoint returns it). caPEM is the CA
// the server's certificate chains to; with none, TLS is not verified against
// a custom pool (the system pool is used). token may be empty to test
// unauthenticated requests.
func New(serverURL string, caPEM []byte, token string) *Client {
	transport := http.DefaultTransport.(*http.Transport).Clone() //nolint:forcetypeassert

	if len(caPEM) > 0 {
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(caPEM)
		transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}

	return &Client{
		base:  strings.TrimSuffix(serverURL, "/") + BasePath,
		token: token,
		hc:    &http.Client{Timeout: requestTimeout, Transport: transport},
	}
}

// WithToken returns a copy of c that authenticates with token instead; an
// empty token sends no Authorization header.
func (c *Client) WithToken(token string) *Client {
	cp := *c
	cp.token = token

	return &cp
}

// URL returns the absolute URL of path under the SCIM base.
func (c *Client) URL(path string) string {
	return c.base + path
}

// Do sends a request with an optional JSON body and returns the raw
// response. It does not check the content type.
func (c *Client) Do(ctx context.Context, method, path string, body any) (*Response, error) {
	var reader io.Reader

	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("encoding %s %s body: %w", method, path, err)
		}

		reader = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.URL(path), reader)
	if err != nil {
		return nil, fmt.Errorf("building %s %s: %w", method, path, err)
	}

	req.Header.Set("Accept", ContentType)

	if body != nil {
		req.Header.Set("Content-Type", ContentType)
	}

	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading %s %s response: %w", method, path, err)
	}

	return &Response{
		StatusCode:  resp.StatusCode,
		ContentType: resp.Header.Get("Content-Type"),
		Body:        respBody,
	}, nil
}

// call sends the request and, on a 2xx response with a body, checks the
// media type and decodes the body into out (if non-nil). Non-2xx responses
// are returned without error so callers can assert on them; their content
// type is checked too, since RFC 7644 section 3.12 errors are SCIM
// documents, except for 401s, which an auth layer may render itself.
func (c *Client) call(ctx context.Context, method, path string, body, out any) (*Response, error) {
	resp, err := c.Do(ctx, method, path, body)
	if err != nil {
		return nil, err
	}

	if len(bytes.TrimSpace(resp.Body)) == 0 {
		return resp, nil
	}

	if !resp.IsSCIM() && resp.StatusCode != http.StatusUnauthorized {
		return resp, fmt.Errorf("%w for %s %s: %s", errContentType, method, path, resp)
	}

	if out == nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp, nil
	}

	err = json.Unmarshal(resp.Body, out)
	if err != nil {
		return resp, fmt.Errorf("decoding %s %s response: %w: %s", method, path, err, resp)
	}

	return resp, nil
}

// Get fetches path and decodes a 2xx body into out (if non-nil), e.g. for
// the discovery endpoints (/ServiceProviderConfig, /Schemas, /ResourceTypes).
func (c *Client) Get(ctx context.Context, path string, out any) (*Response, error) {
	return c.call(ctx, http.MethodGet, path, nil, out)
}

// CreateUser POSTs u to /Users. Schemas defaults to the core user schema.
func (c *Client) CreateUser(ctx context.Context, u User) (*User, *Response, error) {
	if len(u.Schemas) == 0 {
		u.Schemas = []string{SchemaUser}
	}

	var out User

	resp, err := c.call(ctx, http.MethodPost, "/Users", u, &out)

	return &out, resp, err
}

// GetUser fetches /Users/{id}.
func (c *Client) GetUser(ctx context.Context, id string) (*User, *Response, error) {
	var out User

	resp, err := c.call(ctx, http.MethodGet, "/Users/"+url.PathEscape(id), nil, &out)

	return &out, resp, err
}

// FindUserByUserName lists /Users with the filter userName eq "userName",
// the lookup every provider does before creating a user.
func (c *Client) FindUserByUserName(ctx context.Context, userName string) (*ListResponse[User], *Response, error) {
	filter := "userName eq " + strconv.Quote(userName)

	var out ListResponse[User]

	resp, err := c.call(ctx, http.MethodGet, "/Users?filter="+url.QueryEscape(filter), nil, &out)

	return &out, resp, err
}

// PutUser replaces /Users/{id} with u.
func (c *Client) PutUser(ctx context.Context, id string, u User) (*User, *Response, error) {
	if len(u.Schemas) == 0 {
		u.Schemas = []string{SchemaUser}
	}

	var out User

	resp, err := c.call(ctx, http.MethodPut, "/Users/"+url.PathEscape(id), u, &out)

	return &out, resp, err
}

// PatchUser sends ops to /Users/{id}. The decoded user is empty when the
// server answers 204 No Content.
func (c *Client) PatchUser(ctx context.Context, id string, ops ...PatchOperation) (*User, *Response, error) {
	var out User

	resp, err := c.call(ctx, http.MethodPatch, "/Users/"+url.PathEscape(id), patch(ops), &out)

	return &out, resp, err
}

// PatchUserActiveLegacy sets active the way Entra ID does without the
// aadOptscim062020 flag: a capitalised "Replace" op with the boolean as the
// string "True" or "False".
func (c *Client) PatchUserActiveLegacy(ctx context.Context, id string, active bool) (*User, *Response, error) {
	value := "False"
	if active {
		value = "True"
	}

	return c.PatchUser(ctx, id, PatchOperation{Op: "Replace", Path: "active", Value: value})
}

// PatchUserActive sets active the way Okta and flagged Entra ID do: a
// path-less "replace" whose value is {"active": <bool>}.
func (c *Client) PatchUserActive(ctx context.Context, id string, active bool) (*User, *Response, error) {
	return c.PatchUser(ctx, id, PatchOperation{Op: "replace", Value: map[string]any{"active": active}})
}

// DeleteUser deletes /Users/{id}.
func (c *Client) DeleteUser(ctx context.Context, id string) (*Response, error) {
	return c.call(ctx, http.MethodDelete, "/Users/"+url.PathEscape(id), nil, nil)
}

// CreateGroup POSTs g to /Groups. Schemas defaults to the core group schema.
func (c *Client) CreateGroup(ctx context.Context, g Group) (*Group, *Response, error) {
	if len(g.Schemas) == 0 {
		g.Schemas = []string{SchemaGroup}
	}

	var out Group

	resp, err := c.call(ctx, http.MethodPost, "/Groups", g, &out)

	return &out, resp, err
}

// GetGroup fetches /Groups/{id}.
func (c *Client) GetGroup(ctx context.Context, id string) (*Group, *Response, error) {
	var out Group

	resp, err := c.call(ctx, http.MethodGet, "/Groups/"+url.PathEscape(id), nil, &out)

	return &out, resp, err
}

// PatchGroup sends ops to /Groups/{id}. The decoded group is empty when the
// server answers 204 No Content.
func (c *Client) PatchGroup(ctx context.Context, id string, ops ...PatchOperation) (*Group, *Response, error) {
	var out Group

	resp, err := c.call(ctx, http.MethodPatch, "/Groups/"+url.PathEscape(id), patch(ops), &out)

	return &out, resp, err
}

// AddMembers adds users to the group the way Entra ID does: one "Add" op on
// the members path with an array of {"value": id}.
func (c *Client) AddMembers(ctx context.Context, groupID string, userIDs ...string) (*Group, *Response, error) {
	members := make([]map[string]string, 0, len(userIDs))
	for _, id := range userIDs {
		members = append(members, map[string]string{"value": id})
	}

	return c.PatchGroup(ctx, groupID, PatchOperation{Op: "Add", Path: "members", Value: members})
}

// RemoveMembers removes users from the group the way Okta does: one
// "remove" op per member, addressed by a members[value eq "id"] filter.
func (c *Client) RemoveMembers(ctx context.Context, groupID string, userIDs ...string) (*Group, *Response, error) {
	ops := make([]PatchOperation, 0, len(userIDs))
	for _, id := range userIDs {
		ops = append(ops, PatchOperation{Op: "remove", Path: "members[value eq " + strconv.Quote(id) + "]"})
	}

	return c.PatchGroup(ctx, groupID, ops...)
}

// RenameGroup replaces the group's displayName.
func (c *Client) RenameGroup(ctx context.Context, groupID, displayName string) (*Group, *Response, error) {
	return c.PatchGroup(ctx, groupID, PatchOperation{Op: "replace", Path: "displayName", Value: displayName})
}

// DeleteGroup deletes /Groups/{id}.
func (c *Client) DeleteGroup(ctx context.Context, id string) (*Response, error) {
	return c.call(ctx, http.MethodDelete, "/Groups/"+url.PathEscape(id), nil, nil)
}

func patch(ops []PatchOperation) PatchRequest {
	return PatchRequest{Schemas: []string{SchemaPatchOp}, Operations: ops}
}
