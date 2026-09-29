// Package apiscim serves the SCIM 2.0 provisioning endpoint (RFC 7643, RFC
// 7644) at /scim/v2, through which an identity provider (Entra ID, Okta,
// Authentik, ...) creates, updates, suspends and deletes headscale users and
// manages the groups the policy references as group:<name>@<domain>.
//
// It is a thin net/http layer over two packages: hscontrol/scim, the pure
// protocol package (decoding, filters, PATCH normalisation, projection, error
// bodies), and hscontrol/state, which persists SCIM users and groups and
// brings the NodeStore and policy up to date. It is plain chi rather than
// Huma: SCIM speaks application/scim+json with RFC 7644 error bodies, which
// Huma's content negotiation and problem+json errors would fight.
//
// # Routes
//
//	GET    /ServiceProviderConfig
//	GET    /ResourceTypes, /ResourceTypes/{id}
//	GET    /Schemas, /Schemas/{id}
//	GET    /Users           filter, startIndex, count, attributes, excludedAttributes
//	POST   /Users           201 + Location
//	GET    /Users/{id}
//	PUT    /Users/{id}      200
//	PATCH  /Users/{id}      200 with the resource
//	DELETE /Users/{id}      204
//	GET    /Groups          as /Users
//	POST   /Groups          201 + Location
//	GET    /Groups/{id}
//	PUT    /Groups/{id}     200
//	PATCH  /Groups/{id}     204, or 200 with the resource when attributes or
//	                        excludedAttributes is given
//	DELETE /Groups/{id}     204
//
// Anything else is a SCIM 404 (405, with Allow, for a known path with
// another method).
//
// # Authentication
//
// Every route, discovery included, requires "Authorization: Bearer <token>"
// with a SCIM token (hskey-scim-…) or an OAuth access token granting the scim
// scope (see [state.State.AuthenticateSCIM]). RFC 7644 section 4 lets a
// service provider serve discovery unauthenticated, but Entra ID and Okta
// send the token on every request, and requiring it everywhere leaves no
// unauthenticated surface to reason about. A missing or unknown credential is
// 401 with a WWW-Authenticate: Bearer challenge; an OAuth token without the
// scim scope is 403. Failures are logged at warn level with the client
// address and cause, never the token, and the cause is never returned.
//
// # Semantics
//
//   - ids are the decimal headscale user and group ids; any other id is 404.
//   - Request bodies may be application/scim+json or application/json (or
//     carry no Content-Type); other media types are 415. Bodies are capped at
//     [scim.MaxBodySize]. Responses are always application/scim+json.
//   - PUT /Users replaces every attribute headscale stores, except that an
//     omitted "active" keeps the user's current state instead of reactivating
//     them: suspension is the security-relevant attribute, every client that
//     manages it (Okta, Authentik, Entra ID) always sends it, and a client that
//     omits it should not lift a deprovisioning by accident. POST defaults an
//     omitted active to true.
//   - headscale stores one email per user, the primary one; it is returned as
//     {"value":…,"type":"work","primary":true}, so that Entra ID's
//     emails[type eq "work"].value updates target it.
//   - Group members must be SCIM users: an unknown or non-decimal member id in
//     POST, PUT or a PATCH add/replace is 400 invalidValue (RFC 7644 section
//     3.12; noTarget is for PATCH paths whose filter matches nothing). Removing
//     a member that is not one is a no-op.
//   - Group PATCH answers 204 (what Entra ID expects; Okta accepts either)
//     unless attributes or excludedAttributes asks for the resource.
//   - Lists are ordered by id, so pages are stable. A filter headscale can
//     answer with an index (userName or externalId equality alone) is paged
//     in the database; any other filter is evaluated in memory over the
//     candidates an equality narrows to, or all SCIM resources. That read is
//     bounded only by the directory size, which is acceptable because the
//     clients' own lookups (userName, externalId, displayName) are indexed
//     and the rest are rare, admin-driven queries.
//   - POST /Users for a userName that is the email of an existing OIDC user
//     is a 409, unless scim.adopt_existing_users is set: operators enable it
//     to bring an existing tailnet under SCIM, and the new SCIM user then
//     takes over that account and its nodes (logged at warn level).
//   - A write that committed but could not refresh in-memory state (see
//     [state.ErrSCIMRefresh]) is answered as a success and logged, since a
//     retried create would meet its own conflict.
//   - Every change the state layer reports is broadcast to connected nodes,
//     including the partial changes of a failed user deletion.
package apiscim

import (
	"context"
	"errors"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/juanfont/headscale/hscontrol/scim"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/juanfont/headscale/hscontrol/util/zlog/zf"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// BasePath is where the endpoint is mounted on the main HTTP router.
const BasePath = "/scim/v2"

// Backend is the dependency surface of the SCIM endpoint: the state layer,
// the sink that distributes changes to connected nodes, and the config
// (server_url for meta.location, scim.* for the groups domain and user
// adoption).
type Backend struct {
	State  *state.State
	Change func(...change.Change)
	Cfg    *types.Config
}

type api struct {
	Backend
}

// routeMethods are the methods the endpoint routes, for the Allow header.
var routeMethods = []string{
	http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete,
}

// Handler returns the SCIM endpoint, with routes relative to [BasePath]; mount
// it there with chi's Mount.
func Handler(b Backend) http.Handler {
	a := &api{Backend: b}

	r := chi.NewRouter()
	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		scim.WriteError(w, scim.NotFound("no such endpoint %s", r.URL.Path))
	})
	r.MethodNotAllowed(func(w http.ResponseWriter, req *http.Request) {
		// chi's own 405 sets Allow; a custom handler must do it itself.
		path := req.URL.Path
		if rctx := chi.RouteContext(req.Context()); rctx != nil && rctx.RoutePath != "" {
			path = rctx.RoutePath
		}

		for _, m := range routeMethods {
			if r.Match(chi.NewRouteContext(), m, path) {
				w.Header().Add("Allow", m)
			}
		}

		scim.WriteError(w, scim.MethodNotAllowed("method %s not allowed on %s", req.Method, req.URL.Path))
	})
	r.Use(a.authenticate, acceptJSONBody)

	r.Get("/ServiceProviderConfig", a.serviceProviderConfig)
	r.Get("/ResourceTypes", a.resourceTypes)
	r.Get("/ResourceTypes/{id}", a.resourceType)
	r.Get("/Schemas", a.schemas)
	r.Get("/Schemas/{id}", a.schema)

	r.Get("/Users", a.listUsers)
	r.Post("/Users", a.createUser)
	r.Get("/Users/{id}", a.getUser)
	r.Put("/Users/{id}", a.replaceUser)
	r.Patch("/Users/{id}", a.patchUser)
	r.Delete("/Users/{id}", a.deleteUser)

	r.Get("/Groups", a.listGroups)
	r.Post("/Groups", a.createGroup)
	r.Get("/Groups/{id}", a.getGroup)
	r.Put("/Groups/{id}", a.replaceGroup)
	r.Patch("/Groups/{id}", a.patchGroup)
	r.Delete("/Groups/{id}", a.deleteGroup)

	return r
}

// baseURL is the absolute URL of the endpoint, for meta.location. It is read
// per request: server_url is fixed in production but set late in tests.
func (a *api) baseURL() string {
	return strings.TrimRight(a.Cfg.ServerURL, "/") + BasePath
}

func (a *api) groupsDomain() string {
	return a.Cfg.SCIM.GroupsDomain
}

// broadcast sends the non-empty changes to connected nodes.
func (a *api) broadcast(cs ...change.Change) {
	if a.Change == nil {
		return
	}

	var out []change.Change

	for _, c := range cs {
		if !c.IsEmpty() {
			out = append(out, c)
		}
	}

	if len(out) > 0 {
		a.Change(out...)
	}
}

type principalKey struct{}

// principal returns the credential the request authenticated with.
func principal(r *http.Request) types.SCIMPrincipal {
	p, _ := r.Context().Value(principalKey{}).(types.SCIMPrincipal)

	return p
}

// authenticate requires a SCIM credential on every request.
func (a *api) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bearer, ok := bearerToken(r.Header.Get("Authorization"))
		if !ok {
			log.Warn().Str(zf.Path, r.URL.Path).Str(zf.ClientAddress, r.RemoteAddr).
				Msg("scim request without bearer token")
			w.Header().Set("WWW-Authenticate", `Bearer realm="headscale-scim"`)
			scim.WriteError(w, scim.Unauthorized("a bearer token is required"))

			return
		}

		p, err := a.State.AuthenticateSCIM(bearer)

		switch {
		case errors.Is(err, state.ErrSCIMForbidden):
			log.Warn().Err(err).Str(zf.Path, r.URL.Path).Str(zf.ClientAddress, r.RemoteAddr).
				Msg("scim request forbidden")
			w.Header().Set("WWW-Authenticate",
				`Bearer realm="headscale-scim", error="insufficient_scope", scope="scim"`)
			scim.WriteError(w, scim.Forbidden("the credential does not grant the scim scope"))

			return
		case err != nil:
			log.Warn().Err(err).Str(zf.Path, r.URL.Path).Str(zf.ClientAddress, r.RemoteAddr).
				Msg("scim request unauthenticated")
			w.Header().Set("WWW-Authenticate", `Bearer realm="headscale-scim", error="invalid_token"`)
			scim.WriteError(w, scim.Unauthorized("invalid bearer token"))

			return
		}

		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, p)))
	})
}

// bearerToken extracts the credential of an "Authorization: Bearer <token>"
// header; the scheme is case-insensitive (RFC 7235 section 2.1).
func bearerToken(header string) (string, bool) {
	scheme, token, ok := strings.Cut(strings.TrimSpace(header), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}

	token = strings.TrimSpace(token)

	return token, token != ""
}

// acceptJSONBody refuses request bodies that are not JSON. Entra ID sends
// application/scim+json, Okta and Authentik application/json; a missing
// Content-Type is tolerated as the body is parsed as JSON regardless.
func acceptJSONBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost, http.MethodPut, http.MethodPatch:
		default:
			next.ServeHTTP(w, r)

			return
		}

		ct := r.Header.Get("Content-Type")
		if ct != "" {
			mt, _, err := mime.ParseMediaType(ct)
			if err != nil || (mt != scim.ContentType && mt != "application/json") {
				scim.WriteError(w, &scim.Error{
					Status: http.StatusUnsupportedMediaType,
					Detail: "request body must be " + scim.ContentType + " or application/json",
				})

				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// writeError writes err as a SCIM error and logs it: server errors at error
// level with their cause, client errors at debug.
func writeError(w http.ResponseWriter, r *http.Request, err error) {
	se := scim.AsError(err)

	level := zerolog.DebugLevel
	if se.Status >= http.StatusInternalServerError {
		level = zerolog.ErrorLevel
	}

	log.WithLevel(level).Err(se.Unwrap()).
		Str(zf.Method, r.Method).
		Str(zf.Path, r.URL.Path).
		Int(zf.StatusCode, se.Status).
		Str(zf.SCIMErrorType, string(se.ScimType)).
		Str(zf.SCIMErrorDetail, se.Detail).
		EmbedObject(principal(r)).
		Msg("scim request failed")

	scim.WriteError(w, se)
}

// projection is a request's attributes and excludedAttributes. Handlers
// parse it before writing anything, so an invalid projection fails the
// request instead of hiding a committed write behind an error.
type projection struct {
	attrs, excluded []string
}

func (p projection) isSet() bool {
	return len(p.attrs) > 0 || len(p.excluded) > 0
}

func parseProjection(r *http.Request) (projection, error) {
	attrs, excluded, err := scim.ParseProjection(r.URL.Query())

	return projection{attrs: attrs, excluded: excluded}, err
}

// writeResource writes v projected as p asks. Projecting a resource that
// marshals cannot fail, short of a bug; that is a 500.
func writeResource(w http.ResponseWriter, p projection, status int, location string, v any) {
	out, err := scim.Project(v, p.attrs, p.excluded)
	if err != nil {
		scim.WriteError(w, err)

		return
	}

	_ = scim.WriteResource(w, status, location, out)
}

// committed reports whether err is from a write that committed but could
// not bring in-memory state up to date (see [state.ErrSCIMRefresh]). The
// write stands, and its result is returned to the client: answering 500
// would make the client retry a change that is already stored. The
// failure is logged for the operator.
func committed(r *http.Request, err error) bool {
	if !errors.Is(err, state.ErrSCIMRefresh) {
		return false
	}

	log.Error().Err(err).Str(zf.Method, r.Method).Str(zf.Path, r.URL.Path).
		EmbedObject(principal(r)).Msg("scim write committed, but refreshing in-memory state failed")

	return true
}

// wantsAttribute reports whether a projection keeps the top-level attribute
// name, so that a handler can skip computing an attribute that is dropped
// anyway (Entra ID reads groups with excludedAttributes=members).
func wantsAttribute(attrs, excluded []string, name string) bool {
	matches := func(list []string) bool {
		for _, a := range list {
			p, err := scim.ParseAttrPath(a)
			if err == nil && !p.IsExtension() && strings.EqualFold(p.Attr, name) {
				return true
			}
		}

		return false
	}

	for _, a := range excluded {
		p, err := scim.ParseAttrPath(a)
		if err == nil && !p.IsExtension() && p.Sub == "" && strings.EqualFold(p.Attr, name) {
			return false
		}
	}

	return len(attrs) == 0 || matches(attrs)
}

// parseID parses a resource id: the decimal database id. Anything else names
// no resource.
func parseID(s string) (uint, bool) {
	id, err := strconv.ParseUint(s, 10, strconv.IntSize)

	return uint(id), err == nil && id > 0
}

func formatID[T ~uint | ~uint64](id T) string {
	return strconv.FormatUint(uint64(id), 10)
}
