package hscontrol

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/juanfont/headscale/hscontrol/db"
	hsstate "github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/templates"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/juanfont/headscale/hscontrol/util/zlog/zf"
	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"
	"tailscale.com/util/rands"
)

const (
	randomByteSize           = 16
	defaultOAuthOptionsCount = 3
	authCacheExpiration      = time.Minute * 15

	// Registrations may use authCacheMaxEntries slots; SSH checks may also use
	// the reserve so new registrations cannot fill all pending OIDC capacity.
	authCacheMaxEntries = 1024
	authCacheSSHReserve = 64

	// cookieNamePrefixLen is the number of leading characters from a
	// state/nonce value that [getCookieName] splices into the cookie name.
	// State and nonce values that are shorter than this are rejected at
	// the callback boundary so [getCookieName] cannot panic on a slice
	// out-of-range.
	cookieNamePrefixLen = 6
)

var errOIDCStateTooShort = errors.New("oidc state parameter is too short")

var (
	errEmptyOIDCCallbackParams = errors.New("empty OIDC callback params")
	errNoOIDCIDToken           = errors.New("extracting ID token")
	errOIDCAllowedDomains      = errors.New(
		"authenticated principal does not match any allowed domain",
	)
	errOIDCAllowedGroups = errors.New("authenticated principal is not in any allowed group")
	errOIDCAllowedUsers  = errors.New(
		"authenticated principal does not match any allowed user",
	)
	errOIDCUnverifiedEmail = errors.New("authenticated principal has an unverified email")
	errOIDCNotProvisioned  = errors.New("authenticated principal is not provisioned through SCIM")
	errOIDCSCIMLinkLost    = errors.New("provisioned user is linked to another login")
	errInvalidPKCEMethod   = errors.New("invalid pkce.method")
)

// AuthInfo contains both auth ID and verifier information for OIDC validation.
type AuthInfo struct {
	AuthID       types.AuthID
	Verifier     *string
	Registration bool
}

type AuthProviderOIDC struct {
	h         *Headscale
	serverURL string
	cfg       *types.OIDCConfig

	// authCacheMu serializes non-evicting admission and single-use consumption.
	// Reads use Peek to preserve insertion order, so the oldest entry expires first.
	authCacheMu            sync.Mutex
	authCacheRegistrations atomic.Int64
	authCache              *expirable.LRU[string, AuthInfo]

	oidcProvider *oidc.Provider
	oauth2Config *oauth2.Config
}

func NewAuthProviderOIDC(
	ctx context.Context,
	h *Headscale,
	serverURL string,
	cfg *types.OIDCConfig,
) (*AuthProviderOIDC, error) {
	// Use the caller's context (bounded, see app.go) so a slow or unreachable
	// issuer fails discovery within the timeout instead of hanging startup.
	oidcProvider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("creating OIDC provider from issuer config: %w", err)
	}

	oauth2Config := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     oidcProvider.Endpoint(),
		RedirectURL:  oidcCallbackURL(serverURL),
		Scopes:       cfg.Scope,
	}

	a := &AuthProviderOIDC{
		h:         h,
		serverURL: serverURL,
		cfg:       cfg,

		oidcProvider: oidcProvider,
		oauth2Config: oauth2Config,
	}
	a.authCache = expirable.NewLRU[string, AuthInfo](
		authCacheMaxEntries+authCacheSSHReserve,
		func(_ string, info AuthInfo) {
			if info.Registration {
				a.authCacheRegistrations.Add(-1)
			}
		},
		authCacheExpiration,
	)

	return a, nil
}

// cookiesSecure reports whether the OIDC cookies should carry the Secure flag.
// It keys off the configured server_url scheme, not req.TLS, so cookies stay
// Secure behind a TLS-terminating reverse proxy (where the proxy→Headscale hop
// is plain HTTP and req.TLS is nil). Deriving it from config avoids trusting a
// spoofable X-Forwarded-Proto header.
func (a *AuthProviderOIDC) cookiesSecure() bool {
	return strings.HasPrefix(a.serverURL, "https://")
}

func oidcCallbackURL(serverURL string) string {
	return strings.TrimSuffix(serverURL, "/") + "/oidc/callback"
}

func (a *AuthProviderOIDC) oidcCallbackPath() string {
	if u, err := url.Parse(oidcCallbackURL(a.serverURL)); err == nil { //nolint:noinlineerr
		return u.Path
	}

	return "/oidc/callback"
}

func (a *AuthProviderOIDC) AuthURL(authID types.AuthID) string {
	return authPathURL(a.serverURL, "auth", authID)
}

func (a *AuthProviderOIDC) AuthHandler(
	writer http.ResponseWriter,
	req *http.Request,
) {
	a.authHandler(writer, req, false)
}

func (a *AuthProviderOIDC) RegisterURL(authID types.AuthID) string {
	return authPathURL(a.serverURL, "register", authID)
}

// RegisterHandler registers the OIDC callback handler with the given router.
// It puts NodeKey in cache so the callback can retrieve it using the oidc state param.
// Listens in /register/:auth_id.
func (a *AuthProviderOIDC) RegisterHandler(
	writer http.ResponseWriter,
	req *http.Request,
) {
	a.authHandler(writer, req, true)
}

// authHandler takes an incoming request that needs to be authenticated and
// validates and prepares it for the OIDC flow.
func (a *AuthProviderOIDC) authHandler(
	writer http.ResponseWriter,
	req *http.Request,
	registration bool,
) {
	authID, err := authIDFromRequest(req)
	if err != nil {
		httpUserError(writer, err)
		return
	}

	authReq, ok := a.h.state.GetAuthCacheEntry(authID)
	if !ok {
		httpUserError(writer, NewHTTPError(http.StatusGone, "login session expired, try again", nil))
		return
	}

	if registration && !authReq.IsRegistration() {
		httpUserError(writer, NewHTTPError(http.StatusBadRequest, "auth session is not for node registration", nil))
		return
	}

	if !registration && !authReq.IsSSHCheck() {
		httpUserError(writer, NewHTTPError(http.StatusBadRequest, "auth session is not for SSH check", nil))
		return
	}

	state := rands.HexString(64)
	nonce := rands.HexString(64)

	registrationInfo := AuthInfo{
		AuthID:       authID,
		Registration: registration,
	}

	extras := make([]oauth2.AuthCodeOption, 0, len(a.cfg.ExtraParams)+defaultOAuthOptionsCount)
	// Add PKCE verification if enabled
	if a.cfg.PKCE.Enabled {
		verifier := oauth2.GenerateVerifier()
		registrationInfo.Verifier = &verifier

		extras = append(extras, oauth2.AccessTypeOffline)

		switch a.cfg.PKCE.Method {
		case types.PKCEMethodS256:
			extras = append(extras, oauth2.S256ChallengeOption(verifier))
		case types.PKCEMethodPlain:
			// oauth2 does not have a plain challenge option, so we add it manually
			extras = append(extras, oauth2.SetAuthURLParam("code_challenge_method", "plain"), oauth2.SetAuthURLParam("code_challenge", verifier))
		default:
			// An unknown method must not silently emit no challenge: a
			// verifier was generated and is sent at token exchange, so a
			// missing challenge degrades to no-PKCE without anyone noticing.
			httpError(writer, NewHTTPError(http.StatusInternalServerError, "internal server error", fmt.Errorf("%w: %q", errInvalidPKCEMethod, a.cfg.PKCE.Method)))
			return
		}
	}

	// Add any extra parameters from configuration
	for k, v := range a.cfg.ExtraParams {
		extras = append(extras, oauth2.SetAuthURLParam(k, v))
	}

	extras = append(extras, oidc.Nonce(nonce))

	if !a.addAuthInfoToState(state, registrationInfo) {
		writer.Header().Set("Retry-After", "10")
		httpUserError(writer, NewHTTPError(http.StatusServiceUnavailable, "too many pending OIDC logins, try again later", nil))

		return
	}

	a.setCSRFCookie(writer, req, "state", state)
	a.setCSRFCookie(writer, req, "nonce", nonce)

	authURL := a.oauth2Config.AuthCodeURL(state, extras...)
	log.Debug().Caller().Msgf("redirecting to %s for authentication", authURL)

	http.Redirect(writer, req, authURL, http.StatusFound)
}

// OIDCCallbackHandler handles the callback from the OIDC endpoint
// Retrieves the nkey from the state cache and adds the node to the users email user
// TODO: A confirmation page for new nodes should be added to avoid phishing vulnerabilities
// TODO: Add groups information from OIDC tokens into node HostInfo
// Listens in /oidc/callback.
func (a *AuthProviderOIDC) OIDCCallbackHandler(
	writer http.ResponseWriter,
	req *http.Request,
) {
	code, state, err := extractCodeAndStateParamFromRequest(req)
	if err != nil {
		httpUserError(writer, err)
		return
	}

	stateCookieName := getCookieName("state", state)

	cookieState, err := req.Cookie(stateCookieName)
	if err != nil {
		httpUserError(writer, NewHTTPError(http.StatusBadRequest, "state not found", err))
		return
	}

	if state != cookieState.Value {
		httpUserError(writer, NewHTTPError(http.StatusForbidden, "state did not match", nil))
		return
	}

	// A cookie-bound callback spends its state even if authentication fails;
	// retrying then requires a fresh login flow rather than reusing the callback.
	authInfo := a.getAuthInfoFromState(state)
	if authInfo == nil {
		httpUserError(writer, NewHTTPError(http.StatusGone, "login session expired, try again", nil))
		return
	}

	if req.URL.Query().Get("error") != "" {
		httpUserError(writer, NewHTTPError(http.StatusForbidden, "OIDC authentication failed", nil))
		return
	}

	oauth2Token, err := a.getOauth2Token(req.Context(), code, authInfo)
	if err != nil {
		httpUserError(writer, err)
		return
	}

	idToken, err := a.extractIDToken(req.Context(), oauth2Token)
	if err != nil {
		httpUserError(writer, err)
		return
	}

	if idToken.Nonce == "" {
		httpUserError(writer, NewHTTPError(http.StatusBadRequest, "nonce not found in IDToken", err))
		return
	}

	nonceCookieName := getCookieName("nonce", idToken.Nonce)

	nonce, err := req.Cookie(nonceCookieName)
	if err != nil {
		httpUserError(writer, NewHTTPError(http.StatusBadRequest, "nonce not found", err))
		return
	}

	if idToken.Nonce != nonce.Value {
		httpUserError(writer, NewHTTPError(http.StatusForbidden, "nonce did not match", nil))
		return
	}

	// The state/nonce cookies have served their CSRF purpose; clear them so a
	// single-use pair does not linger in the browser until MaxAge.
	a.clearOIDCCallbackCookie(writer, stateCookieName)
	a.clearOIDCCallbackCookie(writer, nonceCookieName)

	nodeExpiry := a.determineNodeExpiry(idToken.Expiry)

	var claims types.OIDCClaims
	if err := idToken.Claims(&claims); err != nil { //nolint:noinlineerr
		httpUserError(writer, fmt.Errorf("decoding ID token claims: %w", err))
		return
	}

	// Fetch user information (email, groups, name, etc) from the userinfo endpoint
	// https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
	var userinfo *oidc.UserInfo

	userinfo, err = a.oidcProvider.UserInfo(req.Context(), oauth2.StaticTokenSource(oauth2Token))
	if err != nil {
		util.LogErr(err, "could not get userinfo; only using claims from id token")
	}

	// The [oidc.UserInfo] type only decodes some fields (Subject, Profile, Email, EmailVerified).
	// We are interested in other fields too (e.g. groups are required for allowedGroups) so we
	// decode into our own [types.OIDCUserInfo] type using the underlying claims struct.
	var userinfo2 types.OIDCUserInfo

	userinfoValid := userinfo != nil && userinfo.Claims(&userinfo2) == nil && userinfo2.Sub == claims.Sub
	if userinfoValid {
		// Update the user with the userinfo claims (with id token claims as fallback).
		// TODO(kradalby): there might be more interesting fields here that we have not found yet.
		claims.Email, claims.EmailVerified = mergeEmailClaims(&claims, &userinfo2)
		claims.Username = cmp.Or(userinfo2.PreferredUsername, claims.Username)
		claims.Name = cmp.Or(userinfo2.Name, claims.Name)

		claims.ProfilePictureURL = cmp.Or(userinfo2.Picture, claims.ProfilePictureURL)
		if userinfo2.Groups != nil {
			claims.Groups = userinfo2.Groups
		}
	}

	// The user claims are now updated from the userinfo endpoint so we can verify the user
	// against allowed emails, email domains, and groups.
	err = doOIDCAuthorization(a.cfg, &claims)
	if err != nil {
		a.revokeGroupsOfDeniedUser(&claims)
		httpUserError(writer, err)

		return
	}

	idClaims, infoClaims := loginClaims(idToken, userinfo, userinfoValid)
	idpGroups := a.loginGroups(claims.Sub, idClaims, infoClaims)

	user, linkChanges, err := a.createOrUpdateUserFromClaim(&claims, idClaims, infoClaims)
	if err != nil {
		if _, ok := errors.AsType[HTTPError](err); !ok {
			err = NewHTTPError(http.StatusInternalServerError, "could not create or update user", err)
		}

		httpUserError(writer, err)

		return
	}

	err = a.admitLogin(user, linkChanges, idpGroups)
	if err != nil {
		httpUserError(writer, err)

		return
	}

	// If this is a registration flow, render the confirmation
	// interstitial instead of finalising the registration immediately.
	// Without an explicit user click, a single GET to
	// /register/{auth_id} could silently complete a registration when
	// the IdP allows silent SSO.
	if authInfo.Registration {
		a.beginRegistrationConfirmation(writer, req, authInfo.AuthID, user, nodeExpiry)

		return
	}

	// If this is not a registration callback, then it is an SSH
	// check-mode auth callback. Confirm the OIDC identity is the owner
	// of the SSH source node before recording approval; without this
	// check any tailnet user could approve a check-mode prompt for any
	// other user's node, defeating the stolen-key protection that
	// check-mode is meant to provide.

	authReq, ok := a.h.state.GetAuthCacheEntry(authInfo.AuthID)
	if !ok {
		log.Debug().Caller().Str("auth_id", authInfo.AuthID.String()).Msg("auth session expired before authorization completed")
		httpUserError(writer, NewHTTPError(http.StatusGone, "login session expired, try again", nil))

		return
	}

	if !authReq.IsSSHCheck() {
		log.Warn().Caller().
			Str("auth_id", authInfo.AuthID.String()).
			Msg("OIDC callback hit non-registration path with auth request that is not an SSH check binding")
		httpUserError(writer, NewHTTPError(http.StatusBadRequest, "auth session is not for SSH check", nil))

		return
	}

	binding := authReq.SSHCheckBinding()

	srcNode, ok := a.h.state.GetNodeByID(binding.SrcNodeID)
	if !ok {
		log.Warn().Caller().
			Str("auth_id", authInfo.AuthID.String()).
			Uint64("src_node_id", binding.SrcNodeID.Uint64()).
			Msg("SSH check src node no longer exists")
		httpUserError(writer, NewHTTPError(http.StatusGone, "src node no longer exists", nil))

		return
	}

	// Strict identity binding: only the user that owns the src node
	// may approve an SSH check for that node. Tagged source nodes are
	// rejected because they have no user owner to compare against.
	if srcNode.IsTagged() || !srcNode.UserID().Valid() {
		log.Warn().Caller().
			Str("auth_id", authInfo.AuthID.String()).
			Uint64("src_node_id", binding.SrcNodeID.Uint64()).
			Bool("src_is_tagged", srcNode.IsTagged()).
			Str("oidc_user", user.Username()).
			Msg("SSH check rejected: src node has no user owner")
		httpUserError(writer, NewHTTPError(http.StatusForbidden, "src node has no user owner", nil))

		return
	}

	if srcNode.UserID().Get() != user.ID {
		log.Warn().Caller().
			Str("auth_id", authInfo.AuthID.String()).
			Uint64("src_node_id", binding.SrcNodeID.Uint64()).
			Uint("src_owner_id", srcNode.UserID().Get()).
			Uint("oidc_user_id", user.ID).
			Str("oidc_user", user.Username()).
			Msg("SSH check rejected: OIDC user is not the owner of src node")
		httpUserError(writer, NewHTTPError(http.StatusForbidden, "OIDC user is not the owner of the SSH source node", nil))

		return
	}

	// Identity verified — record the verdict for the waiting follow-up.
	authReq.FinishAuth(types.AuthVerdict{})

	content := renderAuthSuccessTemplate(user)

	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.WriteHeader(http.StatusOK)

	if _, err := writer.Write(content.Bytes()); err != nil { //nolint:noinlineerr
		util.LogErr(err, "Failed to write HTTP response")
	}
}

// mergeEmailClaims keeps each verification flag with the address it describes.
func mergeEmailClaims(
	claims *types.OIDCClaims,
	userinfo *types.OIDCUserInfo,
) (string, types.FlexibleBoolean) {
	if userinfo.Email == "" {
		return claims.Email, claims.EmailVerified
	}

	if userinfo.Email == claims.Email {
		return claims.Email, claims.EmailVerified || userinfo.EmailVerified
	}

	return userinfo.Email, userinfo.EmailVerified
}

func (a *AuthProviderOIDC) determineNodeExpiry(idTokenExpiration time.Time) *time.Time {
	if a.cfg.UseExpiryFromToken {
		return &idTokenExpiration
	}

	return nil
}

func extractCodeAndStateParamFromRequest(
	req *http.Request,
) (string, string, error) {
	query := req.URL.Query()
	code := query.Get("code")
	state := query.Get("state")

	if (code == "" && query.Get("error") == "") || state == "" {
		return "", "", NewHTTPError(http.StatusBadRequest, "missing code or state parameter", errEmptyOIDCCallbackParams)
	}

	// Reject states that are too short for [getCookieName] to splice
	// into a cookie name. Without this guard a request with
	// ?state=abc panics on the slice out-of-range and is recovered by
	// chi's [middleware.Recoverer], amplifying small-DoS log noise.
	if len(state) < cookieNamePrefixLen {
		return "", "", NewHTTPError(http.StatusBadRequest, "invalid state parameter", errOIDCStateTooShort)
	}

	return code, state, nil
}

// getOauth2Token exchanges the code from the callback for an oauth2 token.
func (a *AuthProviderOIDC) getOauth2Token(
	ctx context.Context,
	code string,
	authInfo *AuthInfo,
) (*oauth2.Token, error) {
	var exchangeOpts []oauth2.AuthCodeOption

	if a.cfg.PKCE.Enabled && authInfo.Verifier != nil {
		exchangeOpts = []oauth2.AuthCodeOption{oauth2.VerifierOption(*authInfo.Verifier)}
	}

	oauth2Token, err := a.oauth2Config.Exchange(ctx, code, exchangeOpts...)
	if err != nil {
		return nil, NewHTTPError(http.StatusForbidden, "invalid code", fmt.Errorf("exchanging code for token: %w", err))
	}

	return oauth2Token, nil
}

// extractIDToken extracts the ID token from the oauth2 token.
func (a *AuthProviderOIDC) extractIDToken(
	ctx context.Context,
	oauth2Token *oauth2.Token,
) (*oidc.IDToken, error) {
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return nil, NewHTTPError(http.StatusBadRequest, "no id_token", errNoOIDCIDToken)
	}

	verifier := a.oidcProvider.Verifier(&oidc.Config{ClientID: a.cfg.ClientID})

	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, NewHTTPError(http.StatusForbidden, "failed to verify id_token", fmt.Errorf("verifying ID token: %w", err))
	}

	return idToken, nil
}

// validateOIDCAllowedDomains checks that if AllowedDomains is provided,
// that the authenticated principal ends with @<alloweddomain>.
func validateOIDCAllowedDomains(
	allowedDomains []string,
	claims *types.OIDCClaims,
) error {
	if len(allowedDomains) > 0 {
		if _, domain, found := strings.CutLast(claims.Email, "@"); !found ||
			!slices.Contains(allowedDomains, domain) {
			return NewHTTPError(http.StatusUnauthorized, "unauthorised domain", errOIDCAllowedDomains)
		}
	}

	return nil
}

// validateOIDCAllowedGroups checks if AllowedGroups is provided,
// and that the user has one group in the list.
// claims.Groups can be populated by adding a client scope named
// 'groups' that contains group membership.
func validateOIDCAllowedGroups(
	allowedGroups []string,
	claims *types.OIDCClaims,
) error {
	for _, group := range allowedGroups {
		if slices.Contains(claims.Groups, group) {
			return nil
		}
	}

	return NewHTTPError(http.StatusUnauthorized, "unauthorised group", errOIDCAllowedGroups)
}

// validateOIDCAllowedUsers checks that if AllowedUsers is provided,
// that the authenticated principal is part of that list.
func validateOIDCAllowedUsers(
	allowedUsers []string,
	claims *types.OIDCClaims,
) error {
	if !slices.Contains(allowedUsers, claims.Email) {
		return NewHTTPError(http.StatusUnauthorized, "unauthorised user", errOIDCAllowedUsers)
	}

	return nil
}

// doOIDCAuthorization applies authorization tests to claims.
//
// The following tests are always applied:
//
// - [validateOIDCAllowedGroups]
//
// The following tests are applied if cfg.EmailVerifiedRequired=false
// or claims.email_verified=true:
//
// - [validateOIDCAllowedDomains]
// - [validateOIDCAllowedUsers]
//
// NOTE that, contrary to the function name, [validateOIDCAllowedUsers]
// only checks the email address -- not the username.
func doOIDCAuthorization(
	cfg *types.OIDCConfig,
	claims *types.OIDCClaims,
) error {
	if len(cfg.AllowedGroups) > 0 {
		err := validateOIDCAllowedGroups(cfg.AllowedGroups, claims)
		if err != nil {
			return err
		}
	}

	trustEmail := !cfg.EmailVerifiedRequired || bool(claims.EmailVerified)

	hasEmailTests := len(cfg.AllowedDomains) > 0 || len(cfg.AllowedUsers) > 0
	if !trustEmail && hasEmailTests {
		return NewHTTPError(http.StatusUnauthorized, "unverified email", errOIDCUnverifiedEmail)
	}

	if len(cfg.AllowedDomains) > 0 {
		err := validateOIDCAllowedDomains(cfg.AllowedDomains, claims)
		if err != nil {
			return err
		}
	}

	if len(cfg.AllowedUsers) > 0 {
		err := validateOIDCAllowedUsers(cfg.AllowedUsers, claims)
		if err != nil {
			return err
		}
	}

	return nil
}

func (a *AuthProviderOIDC) addAuthInfoToState(state string, info AuthInfo) bool {
	a.authCacheMu.Lock()
	defer a.authCacheMu.Unlock()

	// Len includes expired entries until the sweeper removes their bucket.
	for {
		oldest, _, ok := a.authCache.GetOldest()
		if !ok {
			break
		}

		if _, live := a.authCache.Peek(oldest); live {
			break
		}

		a.authCache.Remove(oldest)
	}

	if a.authCache.Contains(state) || a.authCache.Len() >= a.authCache.Cap() {
		return false
	}

	if info.Registration && a.authCacheRegistrations.Load() >= int64(a.authCache.Cap()-authCacheSSHReserve) {
		return false
	}

	// Increment before Add: an expiry callback may run as soon as it is stored.
	if info.Registration {
		a.authCacheRegistrations.Add(1)
	}

	a.authCache.Add(state, info)

	return true
}

// loginClaims decodes a login's ID token and userinfo claims into generic
// maps. Userinfo is only used when it belongs to the same subject as the ID
// token; otherwise its map is nil.
func loginClaims(
	idToken *oidc.IDToken,
	userinfo *oidc.UserInfo,
	userinfoValid bool,
) (map[string]any, map[string]any) {
	var infoClaims map[string]any
	if userinfoValid {
		infoClaims = rawClaims(userinfo.Claims)
	}

	return rawClaims(idToken.Claims), infoClaims
}

// loginGroups returns the qualified groups a login asserts, or nil when group
// sync is disabled.
func (a *AuthProviderOIDC) loginGroups(sub string, idClaims, infoClaims map[string]any) []string {
	if !a.cfg.Groups.Enabled {
		return nil
	}

	return a.groupsFromClaims(sub, idClaims, infoClaims)
}

// admitLogin finishes a login for user once it has been created or updated:
// it broadcasts what linking a provisioned user changed, refuses a suspended
// user, and syncs the login's groups. Linking can change what the policy
// resolves (the login now owns the user's email), and the user may already own
// nodes registered with a pre-auth key; as for groups, only the policy delta
// is sent, never a user change ahead of registration (#2888).
func (a *AuthProviderOIDC) admitLogin(
	user *types.User,
	linkChanges []change.Change,
	groups []string,
) error {
	if len(linkChanges) > 0 {
		a.h.Change(linkChanges...)
	}

	// A suspended user may neither register nodes nor approve SSH sessions.
	if user.IsSuspended() {
		return NewHTTPError(http.StatusForbidden, "your account is suspended", hsstate.ErrUserSuspended)
	}

	err := a.syncLoginGroups(user, groups)
	if err != nil {
		return NewHTTPError(http.StatusInternalServerError, "could not update user groups", err)
	}

	return nil
}

// syncLoginGroups makes groups the user's OIDC memberships and broadcasts the
// change now. The registration or SSH check that follows sees the policy
// manager already updated and reports no policy change of its own, and a user
// who abandons the flow must still lose revoked groups. Only the policy delta
// is sent, so a new node's registration still announces the node itself (see
// #2888).
func (a *AuthProviderOIDC) syncLoginGroups(user *types.User, groups []string) error {
	if !a.cfg.Groups.Enabled {
		return nil
	}

	c, err := a.h.state.SetUserGroups(types.UserID(user.ID), types.GroupSourceOIDC, groups)
	if !c.IsEmpty() {
		a.h.Change(c)
	}

	return err
}

// revokeGroupsOfDeniedUser removes the OIDC group memberships of an existing
// user whom the identity provider authenticated but authorization rejected,
// such as someone no longer in allowed_groups: they must not keep the access
// their last successful login granted to their other nodes.
func (a *AuthProviderOIDC) revokeGroupsOfDeniedUser(claims *types.OIDCClaims) {
	if !a.cfg.Groups.Enabled {
		return
	}

	user, err := a.h.state.GetUserByOIDCIdentifier(claims.Identifier())
	if err != nil {
		if !errors.Is(err, db.ErrUserNotFound) {
			log.Error().Err(err).Msg("looking up denied OIDC user to revoke their groups")
		}

		return
	}

	c, err := a.h.state.SetUserGroups(types.UserID(user.ID), types.GroupSourceOIDC, nil)
	if err != nil {
		log.Error().Err(err).EmbedObject(user).Msg("revoking groups of denied OIDC user")

		return
	}

	if !c.IsEmpty() {
		a.h.Change(c)
	}
}

// rawClaims decodes a token's claims into a generic map, returning nil if
// they cannot be decoded.
func rawClaims(decode func(any) error) map[string]any {
	var claims map[string]any

	err := decode(&claims)
	if err != nil {
		return nil
	}

	return claims
}

// groupsFromClaims returns the qualified names of the groups asserted in the
// configured claim. The userinfo response is preferred when it carries the
// claim, as it does for the standard claims; otherwise the ID token is used.
// Names that cannot be qualified are skipped and logged.
func (a *AuthProviderOIDC) groupsFromClaims(sub string, idClaims, infoClaims map[string]any) []string {
	names, found := types.GroupsFromClaims(infoClaims, a.cfg.Groups.Claim)
	if !found {
		names, found = types.GroupsFromClaims(idClaims, a.cfg.Groups.Claim)
	}

	// Fail closed: no claim means no memberships, but an identity provider
	// that stopped sending it (a scope or mapper change, a userinfo outage,
	// an Entra ID group overage) should not do so silently.
	if !found {
		log.Info().
			Str(zf.OIDCSubject, sub).
			Str(zf.OIDCGroupsClaim, a.cfg.Groups.Claim).
			Msg("OIDC groups claim missing from the ID token and userinfo; the user's synced groups are cleared")
	}

	groups := make([]string, 0, len(names))

	for _, name := range names {
		qualified, err := types.QualifyGroupName(name, a.cfg.Groups.Domain)
		if err != nil {
			log.Warn().
				Err(err).
				Str(zf.GroupName, name).
				Str(zf.OIDCGroupsClaim, a.cfg.Groups.Claim).
				Msg("ignoring OIDC group that cannot be used in policies")

			continue
		}

		groups = append(groups, qualified)
	}

	return groups
}

// getAuthInfoFromState retrieves and consumes the auth info for a state. The
// entry is removed on read so a state is single-use: a replayed callback cannot
// resolve the same auth session twice, even within the cache TTL.
func (a *AuthProviderOIDC) getAuthInfoFromState(state string) *AuthInfo {
	a.authCacheMu.Lock()
	defer a.authCacheMu.Unlock()

	authInfo, ok := a.authCache.Peek(state)
	a.authCache.Remove(state)

	if !ok {
		return nil
	}

	return &authInfo
}

// createOrUpdateUserFromClaim returns the user the login is for, created or
// updated from its claims. idClaims and infoClaims are the raw ID token and
// userinfo claims (infoClaims may be nil), read when linking by a custom
// claim.
//
// With SCIM enabled, a login with no user of its own is first matched to an
// unlinked provisioned user (see [AuthProviderOIDC.linkSCIMUser]), which it
// is linked to and then updates like any returning login. With
// scim.require_provisioning, a login matching no provisioned user, or
// belonging to a user SCIM does not manage, is refused with a 403 instead
// of creating or updating a user.
//
// The changes returned are the policy deltas of a link, which the caller
// broadcasts; creating or updating a user returns none, the registration or
// SSH check that follows announcing what changed (#2888). A refused or
// failed login returns an [HTTPError].
func (a *AuthProviderOIDC) createOrUpdateUserFromClaim(
	claims *types.OIDCClaims,
	idClaims, infoClaims map[string]any,
) (*types.User, []change.Change, error) {
	var (
		user    *types.User
		err     error
		newUser bool
		changes []change.Change
	)

	user, err = a.h.state.GetUserByOIDCIdentifier(claims.Identifier())
	if err != nil && !errors.Is(err, db.ErrUserNotFound) {
		return nil, nil, fmt.Errorf("creating or updating user: %w", err)
	}

	scim := a.h.cfg.SCIM

	if user == nil && scim.Enabled {
		var c change.Change

		user, c, err = a.linkSCIMUser(claims, idClaims, infoClaims)
		if err != nil {
			return nil, nil, err
		}

		if !c.IsEmpty() {
			changes = append(changes, c)
		}
	}

	if scim.Enabled && scim.RequireProvisioning && !user.IsSCIMProvisioned() {
		e := log.Warn().Str(zf.OIDCIdentifier, claims.Identifier())
		if user != nil {
			e = e.EmbedObject(user)
		}

		e.Msg("refusing OIDC login of a user not provisioned through SCIM")

		return nil, nil, errNotProvisioned
	}

	// if the user is still not found, create a new empty user.
	if user == nil {
		newUser = true
		user = &types.User{}
	}

	user.FromClaim(claims, a.cfg.EmailVerifiedRequired)

	if newUser {
		user, _, err = a.h.state.CreateUser(*user)
		if err != nil {
			return nil, nil, fmt.Errorf("creating user: %w", err)
		}

		return user, nil, nil
	}

	_, c, err := a.h.state.UpdateUser(types.UserID(user.ID), func(u *types.User) error {
		*u = *user
		return nil
	})
	if err != nil {
		return nil, nil, fmt.Errorf("updating user: %w", err)
	}

	// Only a link's own update is broadcast; see above.
	if len(changes) > 0 && !c.IsEmpty() {
		changes = append(changes, c)
	}

	return user, changes, nil
}

// errNotProvisioned refuses a login under scim.require_provisioning.
var errNotProvisioned = newHTTPUserError(
	http.StatusForbidden,
	"user is not provisioned through SCIM",
	"Your account has not been provisioned for this tailnet. "+
		"Ask your administrator to assign you to Headscale in your identity provider.",
	errOIDCNotProvisioned,
)

// errSCIMLinkLost refuses a login whose provisioned user another login
// linked first. It is a plain 403, like any refused login, so the page does
// not tell whoever logged in that a provisioned account exists; the server
// logs the detail.
var errSCIMLinkLost = NewHTTPError(
	http.StatusForbidden,
	"provisioned user was linked to another login",
	errOIDCSCIMLinkLost,
)

// linkSCIMUser links the login to the unlinked SCIM-provisioned user it
// matches, if any, and returns that user (nil when none matches) with the
// change to broadcast. How a login matches is set by scim.link_by:
//
//   - "email": the login's email, only if the provider asserts it verified
//     (email_verified true for that address; see [mergeEmailClaims])
//     whatever email_verified_required says, equals the SCIM userName with ASCII case folding ([sameEmail]).
//     Failing that, it equals the SCIM email of exactly one unlinked user:
//     identity providers often provision a userName that is not the login's
//     email (Entra's UPN against its mail claim), and both values are the
//     provider's own assertions about the person.
//   - "external_id": the string value of scim.link_claim, read from the ID
//     token and else from userinfo (a literal claim name first, then a
//     dotted path, as for groups), equals the SCIM externalId exactly.
//
// If another login links the user between the caller's lookup and the
// link, the user is looked up again by the login's identifier: a concurrent
// login of the same identity (a double submit) then proceeds with the user
// the other linked, while a different identity is refused with a 403 (or,
// if it finds no candidate left, handled as any unmatched login).
func (a *AuthProviderOIDC) linkSCIMUser(
	claims *types.OIDCClaims,
	idClaims, infoClaims map[string]any,
) (*types.User, change.Change, error) {
	identifier := claims.Identifier()

	candidate, err := a.findSCIMUserForLogin(claims, idClaims, infoClaims)
	if err != nil && !errors.Is(err, db.ErrUserNotFound) {
		return nil, change.Change{}, err
	}

	if candidate == nil {
		// A concurrent login of the same identity may have linked the
		// user since this one looked it up.
		existing, err := a.h.state.GetUserByOIDCIdentifier(identifier)
		if err != nil && !errors.Is(err, db.ErrUserNotFound) {
			return nil, change.Change{}, fmt.Errorf("looking up OIDC user: %w", err)
		}

		return existing, change.Change{}, nil
	}

	user, c, err := a.h.state.LinkSCIMUser(types.UserID(candidate.ID), identifier)
	switch {
	case err == nil:
		log.Info().EmbedObject(user).Str(zf.OIDCIdentifier, identifier).
			Msg("linked OIDC login to SCIM-provisioned user")

		return user, c, nil
	case errors.Is(err, db.ErrSCIMUserLinked), errors.Is(err, db.ErrSCIMConflict):
		existing, lerr := a.h.state.GetUserByOIDCIdentifier(identifier)
		if lerr == nil {
			return existing, change.Change{}, nil
		}

		log.Warn().Err(err).Uint(zf.UserID, candidate.ID).Str(zf.OIDCIdentifier, identifier).
			Msg("SCIM user was linked to another OIDC login first")

		return nil, change.Change{}, errSCIMLinkLost
	default:
		return nil, change.Change{}, fmt.Errorf("linking SCIM user %d: %w", candidate.ID, err)
	}
}

// findSCIMUserForLogin returns the unlinked SCIM user the login matches
// under scim.link_by (see [AuthProviderOIDC.linkSCIMUser]), or
// [db.ErrUserNotFound].
func (a *AuthProviderOIDC) findSCIMUserForLogin(
	claims *types.OIDCClaims,
	idClaims, infoClaims map[string]any,
) (*types.User, error) {
	scim := a.h.cfg.SCIM

	var (
		user *types.User
		err  error
	)

	switch scim.LinkBy {
	case types.SCIMLinkByExternalID:
		value, ok := types.StringClaim(idClaims, scim.LinkClaim)
		if !ok {
			value, ok = types.StringClaim(infoClaims, scim.LinkClaim)
		}

		if !ok {
			log.Debug().Str(zf.SCIMLinkClaim, scim.LinkClaim).
				Msg("OIDC login carries no string link claim; not linking a SCIM user")

			return nil, db.ErrUserNotFound
		}

		user, err = a.h.state.FindUnlinkedSCIMUserByExternalID(value)
	default:
		// Linking always needs the provider to vouch for the email, even
		// when email_verified_required is off for storing it: an
		// unverified email would hand the account to whoever typed it.
		email := claims.TrustedEmail(true)
		if email == "" {
			return nil, db.ErrUserNotFound
		}

		user, err = a.h.state.FindUnlinkedSCIMUserByUserName(email)
		if err == nil && !sameEmail(user.SCIMUserName.String, email) {
			user, err = nil, db.ErrUserNotFound
		}

		if errors.Is(err, db.ErrUserNotFound) {
			user, err = a.findSCIMUserBySCIMEmail(email)
		}
	}

	if err != nil && !errors.Is(err, db.ErrUserNotFound) {
		return nil, fmt.Errorf("finding SCIM user for OIDC login: %w", err)
	}

	return user, err
}

// scimEmailCandidates bounds the SCIM users fetched by email; more matches
// than that are ambiguous anyway.
const scimEmailCandidates = 8

// findSCIMUserBySCIMEmail returns the one unlinked SCIM user whose SCIM
// email is email (see [sameEmail]), or [db.ErrUserNotFound] when there is
// none or the match is ambiguous.
func (a *AuthProviderOIDC) findSCIMUserBySCIMEmail(email string) (*types.User, error) {
	users, err := a.h.state.FindUnlinkedSCIMUsersByEmail(email, scimEmailCandidates)
	if err != nil {
		return nil, err
	}

	var matches []*types.User

	for i := range users {
		if sameEmail(users[i].SCIMEmail, email) {
			matches = append(matches, &users[i])
		}
	}

	switch {
	case len(matches) == 1 && len(users) < scimEmailCandidates:
		return matches[0], nil
	case len(matches) == 0:
		return nil, db.ErrUserNotFound
	default:
		log.Warn().Str(zf.UserEmail, email).Int(zf.UserCount, len(matches)).
			Msg("several unlinked SCIM users have the login's email; not linking any")

		return nil, db.ErrUserNotFound
	}
}

// sameEmail reports whether two emails are equal with ASCII case folding
// only. The database lookups fold with strings.ToLower or SQL LOWER, which
// map lookalikes such as the Kelvin sign 'K' (U+212A) or the dotted 'İ' to
// ASCII letters; linking re-checks their candidates here, so an address
// spelled with a lookalike never claims the account of the ASCII one, or
// the reverse.
func sameEmail(a, b string) bool {
	return types.FoldGroupName(a) == types.FoldGroupName(b)
}

// registerConfirmCSRFCookie is the cookie name used to bind the
// /register/confirm POST handler's CSRF token to the OIDC callback that
// rendered the interstitial. It includes a per-session prefix derived
// from the auth ID so cookies for unrelated registrations on the same
// browser do not collide.
const registerConfirmCSRFCookie = "headscale_register_confirm"

// registrationLinkSpentMsg is logged when a user returns to a
// registration link whose session is gone, which is usually a reload or a
// back button after they already confirmed. The page the user sees comes
// from [userMessageForStatusCode].
const registrationLinkSpentMsg = "registration link already used or expired"

const registrationLinkSpentUserMsg = "This link has already been used or has expired. " +
	"If your device is connected you are done; otherwise start the login again."

var errRegistrationLinkSpent = newHTTPUserError(
	http.StatusGone,
	registrationLinkSpentMsg,
	registrationLinkSpentUserMsg,
	nil,
)

// registerConfirmURL is the browser-facing URL of the confirmation page.
// It is built from server_url, like [AuthProviderOIDC.RegisterURL] and the
// OIDC redirect URI, so a Headscale that a reverse proxy serves under a
// path prefix hands the browser a URL that resolves.
func (a *AuthProviderOIDC) registerConfirmURL(authID types.AuthID) string {
	return authPathURL(a.serverURL, "register/confirm", authID)
}

// setRegisterConfirmCookie writes the per-session register-confirm CSRF
// cookie. Pass the CSRF token and authCacheExpiration seconds to set it;
// pass ("", -1) to clear it after the registration is finalised.
func (a *AuthProviderOIDC) setRegisterConfirmCookie(
	writer http.ResponseWriter,
	req *http.Request,
	authID types.AuthID,
	value string,
	maxAge int,
) {
	// Scope the cookie to the browser-facing path, which carries the
	// reverse proxy's prefix; the routed path does not.
	path := "/register/confirm/" + authID.String()
	if u, err := url.Parse(a.registerConfirmURL(authID)); err == nil { //nolint:noinlineerr
		path = u.Path
	}

	//nolint:gosec // G124: Secure from server_url scheme or req.TLS; HttpOnly + SameSite already set
	http.SetCookie(writer, &http.Cookie{
		Name:     registerConfirmCSRFCookie,
		Value:    value,
		Path:     path,
		MaxAge:   maxAge,
		Secure:   a.cookiesSecure() || req.TLS != nil,
		HttpOnly: true,
		// Lax, not Strict: the callback sets this cookie and immediately
		// redirects to the confirmation page. That hop ends a redirect
		// chain which began cross-site at the IdP, and Firefox evaluates
		// the whole chain, so a Strict cookie is withheld and the
		// confirmation page 403s. Lax still never rides a cross-site
		// POST, so the confirm submission stays protected.
		SameSite: http.SameSiteLaxMode,
	})
}

// beginRegistrationConfirmation captures the resolved OIDC identity and
// node expiry into the cached [types.AuthRequest], sets the CSRF cookie, and
// redirects the browser to the confirmation page.
//
// The interstitial is served from its own URL rather than written inline
// here, because this request carries the single-use OAuth authorization
// code. A page rendered on this response leaves the browser parked on the
// code-bearing URL, and anything that reloads it — an extension calling
// window.location.reload(), the back button, pull-to-refresh, a prerender
// — re-enters the callback with a spent code and paints an error over the
// interstitial. Redirecting keeps the code exchange one-shot and makes the
// page the user waits on safe to reload.
func (a *AuthProviderOIDC) beginRegistrationConfirmation(
	writer http.ResponseWriter,
	req *http.Request,
	authID types.AuthID,
	user *types.User,
	nodeExpiry *time.Time,
) {
	authReq, ok := a.h.state.GetAuthCacheEntry(authID)
	if !ok {
		log.Debug().Caller().Str("auth_id", authID.String()).Msg("registration session expired before authorization completed")
		httpUserError(writer, NewHTTPError(http.StatusGone, "login session expired, try again", nil))

		return
	}

	if !authReq.IsRegistration() {
		log.Warn().Caller().
			Str("auth_id", authID.String()).
			Msg("OIDC callback hit registration path with auth request that is not a node registration")
		httpUserError(writer, NewHTTPError(http.StatusBadRequest, "auth session is not for node registration", nil))

		return
	}

	csrf := rands.HexString(32)

	authReq.SetPendingConfirmation(&types.PendingRegistrationConfirmation{
		UserID:     user.ID,
		NodeExpiry: nodeExpiry,
		CSRF:       csrf,
	})

	a.setRegisterConfirmCookie(writer, req, authID, csrf, int(authCacheExpiration.Seconds()))

	// 303 See Other so the browser issues a fresh GET for the
	// confirmation page and leaves the code-bearing URL behind as a
	// transient hop rather than a history entry it can return to.
	http.Redirect(writer, req, a.registerConfirmURL(authID), http.StatusSeeOther)
}

// RegisterConfirmGetHandler renders the OIDC registration confirmation
// interstitial. It is reached via the redirect that
// [AuthProviderOIDC.beginRegistrationConfirmation] issues from the OIDC
// callback, and it is safe to reload: it only reads the pending
// confirmation captured on the cached [types.AuthRequest] and never touches
// the one-time code exchange.
//
// Listens in GET /register/confirm/:auth_id.
func (a *AuthProviderOIDC) RegisterConfirmGetHandler(
	writer http.ResponseWriter,
	req *http.Request,
) {
	authID, err := authIDFromRequest(req)
	if err != nil {
		httpUserError(writer, err)

		return
	}

	authReq, ok := a.h.state.GetAuthCacheEntry(authID)
	if !ok {
		httpUserError(writer, errRegistrationLinkSpent)

		return
	}

	pending := authReq.PendingConfirmation()
	if pending == nil {
		httpUserError(writer, NewHTTPError(http.StatusForbidden, "registration not OIDC-authorized", nil))

		return
	}

	// Only the browser that completed the OIDC flow holds this cookie, and
	// holding it is what authorises the confirm POST. Requiring it here too
	// keeps the device details, and the token that finalises the
	// registration, away from anyone who merely knows the auth ID — which
	// the node being registered does.
	cookie, err := req.Cookie(registerConfirmCSRFCookie)
	if err != nil {
		httpUserError(writer, NewHTTPError(http.StatusForbidden, "missing csrf cookie", err))

		return
	}

	if cookie.Value != pending.CSRF {
		httpUserError(writer, NewHTTPError(http.StatusForbidden, "csrf token mismatch", nil))

		return
	}

	user, err := a.h.state.GetUserByID(types.UserID(pending.UserID))
	if err != nil {
		httpUserError(writer, fmt.Errorf("looking up user: %w", err))

		return
	}

	regData := authReq.RegistrationData()

	info := templates.RegisterConfirmInfo{
		FormAction:    a.registerConfirmURL(authID),
		CSRFTokenName: registerConfirmCSRFCookie,
		CSRFToken:     pending.CSRF,
		User:          user.Display(),
		Hostname:      regData.Hostname,
		MachineKey:    regData.MachineKey.ShortString(),
	}
	if regData.Hostinfo != nil {
		info.OS = regData.Hostinfo.OS
	}

	// The page carries the token that finalises the registration, so no
	// shared cache or history restore may serve it back.
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.WriteHeader(http.StatusOK)

	if _, err := writer.Write([]byte(templates.RegisterConfirm(info).Render())); err != nil { //nolint:noinlineerr
		util.LogErr(err, "Failed to write HTTP response")
	}
}

// RegisterConfirmHandler is the POST endpoint behind the OIDC
// registration confirmation interstitial. It validates the CSRF cookie
// against the form-submitted token, finalises the registration via
// [AuthProviderOIDC.handleRegistration], and renders the success page.
func (a *AuthProviderOIDC) RegisterConfirmHandler(
	writer http.ResponseWriter,
	req *http.Request,
) {
	authID, err := authIDFromRequest(req)
	if err != nil {
		httpUserError(writer, err)

		return
	}

	// Cap the form body. The confirmation form is a single CSRF token,
	// so 4 KiB is generous and prevents an unauthenticated client from
	// submitting an arbitrarily large body to ParseForm.
	req.Body = http.MaxBytesReader(writer, req.Body, 4*1024)

	if err := req.ParseForm(); err != nil { //nolint:noinlineerr,gosec // body is bounded above
		httpUserError(writer, NewHTTPError(http.StatusBadRequest, "invalid form", err))

		return
	}

	formCSRF := req.PostFormValue(registerConfirmCSRFCookie) //nolint:gosec // body is bounded above
	if formCSRF == "" {
		httpUserError(writer, NewHTTPError(http.StatusBadRequest, "missing csrf token", nil))

		return
	}

	cookie, err := req.Cookie(registerConfirmCSRFCookie)
	if err != nil {
		httpUserError(writer, NewHTTPError(http.StatusForbidden, "missing csrf cookie", err))

		return
	}

	if cookie.Value != formCSRF {
		httpUserError(writer, NewHTTPError(http.StatusForbidden, "csrf token mismatch", nil))

		return
	}

	authReq, ok := a.h.state.GetAuthCacheEntry(authID)
	if !ok {
		httpUserError(writer, errRegistrationLinkSpent)

		return
	}

	pending := authReq.PendingConfirmation()
	if pending == nil {
		httpUserError(writer, NewHTTPError(http.StatusForbidden, "registration not OIDC-authorized", nil))

		return
	}

	if pending.CSRF != cookie.Value {
		httpUserError(writer, NewHTTPError(http.StatusForbidden, "csrf token does not match cached registration", nil))

		return
	}

	user, err := a.h.state.GetUserByID(types.UserID(pending.UserID))
	if err != nil {
		httpUserError(writer, fmt.Errorf("looking up user: %w", err))

		return
	}

	newNode, err := a.handleRegistration(user, authID, pending.NodeExpiry)
	if err != nil {
		if errors.Is(err, db.ErrNodeNotFoundRegistrationCache) {
			httpUserError(writer, newHTTPUserError(
				http.StatusGone,
				registrationLinkSpentMsg,
				registrationLinkSpentUserMsg,
				err,
			))

			return
		}

		httpUserError(writer, err)

		return
	}

	// Clear the CSRF cookie now that the registration is final.
	a.setRegisterConfirmCookie(writer, req, authID, "", -1)

	content := renderRegistrationSuccessTemplate(user, newNode)

	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.WriteHeader(http.StatusOK)

	// [renderRegistrationSuccessTemplate]'s output only embeds
	// HTML-escaped values from a server-side template, so the gosec
	// XSS warning is a false positive here.
	if _, err := writer.Write(content.Bytes()); err != nil { //nolint:noinlineerr,gosec
		util.LogErr(err, "Failed to write HTTP response")
	}
}

func (a *AuthProviderOIDC) handleRegistration(
	user *types.User,
	registrationID types.AuthID,
	expiry *time.Time,
) (bool, error) {
	node, nodeChange, err := a.h.state.HandleNodeFromAuthPath(
		registrationID,
		types.UserID(user.ID),
		expiry,
		util.RegisterMethodOIDC,
	)
	if err != nil {
		a.h.Change(nodeChange)

		if errors.Is(err, types.ErrHostinfoTooLarge) {
			return false, newHTTPUserError(http.StatusBadRequest, "node report too large",
				"This device reports too much data. Ask your administrator to reduce its reported metadata, then sign in again.", err)
		}

		return false, fmt.Errorf("registering node: %w", err)
	}

	// This is a bit of a back and forth, but we have a bit of a chicken and egg
	// dependency here.
	// Because the way the policy manager works, we need to have the node
	// in the database, then add it to the policy manager and then we can
	// approve the route. This means we get this dance where the node is
	// first added to the database, then we add it to the policy manager via
	// SaveNode (which automatically updates the policy manager) and then we can auto approve the routes.
	// As that only approves the struct object, we need to save it again and
	// ensure we send an update.
	// This works, but might be another good candidate for doing some sort of
	// eventbus.
	routesChange, err := a.h.state.AutoApproveRoutes(node)

	// Send both changes. Empty changes are ignored by Change().
	a.h.Change(nodeChange, routesChange)

	if err != nil {
		return false, fmt.Errorf("auto approving routes: %w", err)
	}

	return !nodeChange.IsEmpty(), nil
}

func renderRegistrationSuccessTemplate(
	user *types.User,
	newNode bool,
) *bytes.Buffer {
	result := templates.AuthSuccessResult{
		Title:   "Headscale - Node Reauthenticated",
		Heading: "Node reauthenticated",
		Verb:    "Reauthenticated",
		User:    user.Display(),
		Message: "You can now close this window.",
	}
	if newNode {
		result.Title = "Headscale - Node Registered"
		result.Heading = "Node registered"
		result.Verb = "Registered"
	}

	return bytes.NewBufferString(templates.AuthSuccess(result).Render())
}

func renderAuthSuccessTemplate(
	user *types.User,
) *bytes.Buffer {
	result := templates.AuthSuccessResult{
		Title:   "Headscale - SSH Session Authorized",
		Heading: "SSH session authorized",
		Verb:    "Authorized",
		User:    user.Display(),
		Message: "You may return to your terminal.",
	}

	return bytes.NewBufferString(templates.AuthSuccess(result).Render())
}

// getCookieName generates a unique cookie name based on a cookie value. It
// uses at most [cookieNamePrefixLen] bytes of value, and fewer if value is
// shorter, so a short value (e.g. a malformed nonce from a misbehaving IdP)
// yields a non-matching name rather than panicking with slice-out-of-range.
func getCookieName(baseName, value string) string {
	n := min(len(value), cookieNamePrefixLen)

	return fmt.Sprintf("%s_%s", baseName, value[:n])
}

// clearOIDCCallbackCookie expires an OIDC callback cookie by name. Matching
// the browser-facing path the cookie was set with is required for the browser
// to drop it.
func (a *AuthProviderOIDC) clearOIDCCallbackCookie(w http.ResponseWriter, name string) {
	//nolint:gosec // G124: a deletion cookie (empty value, MaxAge<0); security attributes are moot
	http.SetCookie(w, &http.Cookie{
		Name:   name,
		Path:   a.oidcCallbackPath(),
		MaxAge: -1,
	})
}

func (a *AuthProviderOIDC) setCSRFCookie(
	w http.ResponseWriter,
	r *http.Request,
	name string,
	val string,
) {
	//nolint:gosec // G124: Secure from server_url scheme or req.TLS; HttpOnly + SameSite set below
	c := &http.Cookie{
		Path:     a.oidcCallbackPath(),
		Name:     getCookieName(name, val),
		Value:    val,
		MaxAge:   int(time.Hour.Seconds()),
		Secure:   a.cookiesSecure() || r.TLS != nil,
		HttpOnly: true,
		// Lax, not Strict: the OIDC callback is a cross-site top-level GET
		// redirect from the IdP that must still carry this cookie. Strict
		// would drop it and break login. Setting it explicitly also stops
		// pre-Lax-default browsers from sending it on other cross-site
		// requests.
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, c)
}
