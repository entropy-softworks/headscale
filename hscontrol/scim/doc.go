// Package scim implements the protocol layer of a SCIM 2.0 service provider
// (RFC 7643, RFC 7644) for provisioning headscale users and groups from an
// identity provider.
//
// The package is pure: it has no database, HTTP routing or headscale state.
// It decodes and validates request bodies, parses filters and PATCH
// operations into canonical forms, applies those to resource structs, builds
// list responses and discovery documents, and renders SCIM errors. An HTTP
// handler is expected to be thin:
//
//	GET    /Users?filter=...   ParseListRequest, ExtractEquality (DB lookup), Match, Paginate, Project, NewListResponse
//	POST   /Users              DecodeUser, Validate, store (409 via Uniqueness), 201
//	PUT    /Users/{id}         DecodeUser, Validate, replace, 200
//	PATCH  /Users/{id}         DecodePatch, NormalizeUserPatch, load, ApplyUserPatch, store, 200
//	PATCH  /Groups/{id}        DecodePatch, NormalizeGroupPatch, load, ApplyGroupPatch, persist membership, 204 or 200
//	errors                     WriteError (status, RFC 7644 body, application/scim+json)
//
// # Resources
//
// [User] supports id, externalId, userName, name (formatted, givenName,
// familyName), displayName, active, emails (value, type, primary), groups
// (read-only) and meta. [Group] supports id, externalId, displayName,
// members and meta. Unknown attributes, extension schema blocks, "roles" and
// "password" are accepted and dropped; password is never stored or echoed.
// Responses always carry schemas (and, for users, active) and never contain
// null. At most one email is primary: if a request marks several, the last
// one wins, for POST, PUT and PATCH alike.
//
// # Limits
//
// One request is bounded so that an authenticated client cannot make the
// server do unbounded work: [MaxBodySize] bytes, [MaxOperations] PATCH
// operations, [MaxMembersPerRequest] member references (413 beyond each),
// [MaxPathLength] bytes per PATCH path, [MaxFilterLength] bytes per filter,
// one level of core schema block in a path-less PATCH value, and
// [MaxEmails] emails per user. Membership changes run in linear time.
//
// # Filters
//
// [ParseFilter] implements the RFC 7644 section 3.4.2.2 grammar, plus the
// ".subAttr" suffix after a value path that Entra ID uses. Filters are
// limited to [MaxFilterLength] bytes and 32 levels of nesting; string
// literals must be valid UTF-8.
//
//	filter    = orExpr                     ; lowest precedence
//	orExpr    = andExpr *("or" andExpr)
//	andExpr   = unary *("and" unary)
//	unary     = "not" "(" filter ")" / "(" filter ")" / attrExpr ; highest
//	attrExpr  = attrPath "pr"
//	          / attrPath compareOp compValue
//	          / attrPath "[" valFilter "]" ["." subAttr compareOp compValue]
//	attrPath  = [URI ":"] ATTRNAME ["." ATTRNAME]
//	compareOp = "eq" / "ne" / "co" / "sw" / "ew" / "gt" / "ge" / "lt" / "le"
//	compValue = false / null / true / number / string
//
// Keywords, operators and attribute names are case-insensitive. Comparison
// follows the schema's caseExact: userName, displayName and emails.value
// compare case-insensitively (Okta's Runscope suite looks users up with a
// randomly re-cased userName); id and externalId are caseExact per RFC 7643
// section 3.1, so an externalId lookup is byte-exact.
//
// # PATCH normalisation
//
// Clients disagree on PATCH. [NormalizeUserPatch] and [NormalizeGroupPatch]
// map each form to canonical [Operation] values:
//
//	input                                                    canonical
//	{"op":"Replace","path":"active","value":"False"}          SetAttribute active=false      (Entra ID, no flag)
//	{"op":"replace","value":{"active":false}}                SetAttribute active=false      (Okta OIN, Entra ID flag)
//	{"op":"replace","value":{"name.givenName":"x"}}          SetAttribute name.givenName    (Entra ID flag)
//	{"op":"replace","value":{"name":{"givenName":"x"}}}      SetAttribute name.givenName
//	{"op":"replace","path":"name","value":{"givenName":"x"}} SetAttribute name.givenName
//	{"op":"Replace","path":"emails[type eq \"work\"].value"}  SetAttribute (upsert)          (Entra ID)
//	{"op":"add","path":"emails","value":[...]}               SetAttribute emails, Append
//	{"op":"replace","value":{"id":"…","displayName":"x"}}    SetAttribute displayName       (Okta group rename; id skipped)
//	{"op":"Add","path":"members","value":[{"value":"1"}]}    AddMembers [1]
//	{"op":"Remove","path":"members","value":[{"value":"1"}]} RemoveMembers [1]              (Entra ID no flag, Authentik)
//	{"op":"remove","path":"members[value eq \"1\"]"}         RemoveMembers [1]              (Okta, Entra ID flag)
//	{"op":"replace","path":"members","value":[...]}          ReplaceMembers                 (Okta)
//	{"op":"remove","path":"members"}                         ReplaceMembers []
//	{"op":"remove","path":"x"} / value null                  RemoveAttribute x
//
// Further forms: {"op":"remove","path":"emails","value":[...]} removes the
// listed emails (like members), and emails[filter] with an object value
// becomes one SetAttribute carrying an [EmailPatch], applied to the emails
// the filter selected, so key order in the object does not matter.
//
// Ops are case-insensitive; booleans may be "True"/"False" strings.
// Paths to extension schemas, to RFC core attributes headscale does not
// store (title, phoneNumbers, addresses, nickName, ...) and to unknown
// attributes are accepted and reported as [IgnoredAttribute], which the
// apply functions skip: Entra ID's default attribute mappings send the
// former, and custom Entra ID or Okta mappings produce the latter, which
// would otherwise make every update fail. Malformed paths and unknown
// sub-attributes of supported attributes are invalidPath, read-only
// attributes (id, meta, groups) are mutability, and a path-less remove is
// noTarget.
//
// # Discovery
//
// [NewServiceProviderConfig], [NewResourceTypes] and [NewSchemas] describe
// exactly what this package implements: PATCH and filtering supported
// (maxResults [MaxPageSize]), bulk, sort, etag and changePassword not, and
// bearer-token authentication. Authentik decides whether to use filters
// from this document.
//
// # References
//
//   - RFC 7643, SCIM Core Schema: https://www.rfc-editor.org/rfc/rfc7643
//   - RFC 7644, SCIM Protocol: https://www.rfc-editor.org/rfc/rfc7644
//   - Entra ID: https://learn.microsoft.com/entra/identity/app-provisioning/use-scim-to-provision-users-and-groups
//   - Entra ID quirks and the aadOptscim062020 flag:
//     https://learn.microsoft.com/entra/identity/app-provisioning/application-provisioning-config-problem-scim-compatibility
//   - Okta: https://developer.okta.com/docs/reference/scim/scim-20/
//   - Authentik: https://docs.goauthentik.io/docs/add-secure-apps/providers/scim/
package scim
