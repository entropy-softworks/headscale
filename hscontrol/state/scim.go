package state

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol/scope"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util/zlog/zf"
	"github.com/rs/zerolog/log"
)

// Errors returned by [State.AuthenticateSCIM]. The SCIM HTTP layer maps
// ErrSCIMUnauthenticated to 401 Unauthorized (with a WWW-Authenticate: Bearer
// challenge) and ErrSCIMForbidden to 403 Forbidden. The wrapped cause is for
// logs only and must not be echoed to the client.
var (
	ErrSCIMUnauthenticated = errors.New("scim: missing or invalid bearer credential")
	ErrSCIMForbidden       = errors.New("scim: credential lacks the scim scope")
)

// AuthenticateSCIM authenticates the bearer credential of a SCIM request (the
// value after "Bearer " in the Authorization header) and returns the principal
// it identifies. Two credentials are accepted:
//
//   - a SCIM token (hskey-scim-…), the long-lived secret every SCIM client can
//     be configured with; it must be unrevoked and unexpired;
//   - an OAuth access token (hskey-oauthtok-…) whose scopes grant
//     [scope.SCIM] — Entra ID's OAuth client-credentials option. "all" does
//     not grant scim, see [scope.SCIM].
//
// Everything else is ErrSCIMUnauthenticated, deliberately including admin API
// keys (hskey-api-…): those are all-access on the admin APIs, and keeping
// provisioning on its own credential means the secret stored in an identity
// provider can neither administer the tailnet nor be revoked only by breaking
// the operator's CLI access. An authentic OAuth token without the scim scope
// is ErrSCIMForbidden. The token prefix picks the credential kind, so no
// lookup is made for a credential of any other kind.
func (s *State) AuthenticateSCIM(bearer string) (types.SCIMPrincipal, error) {
	switch {
	case strings.HasPrefix(bearer, types.SCIMTokenPrefix):
		tok, err := s.db.AuthenticateSCIMToken(bearer)
		if err != nil {
			return types.SCIMPrincipal{}, fmt.Errorf("%w: %w", ErrSCIMUnauthenticated, err)
		}

		return types.SCIMPrincipal{
			Kind:         types.CredentialSCIMToken,
			CredentialID: tok.ID,
			Identifier:   tok.Prefix,
		}, nil

	case strings.HasPrefix(bearer, types.AccessTokenPrefix):
		at, err := s.db.AuthenticateAccessToken(bearer)
		if err != nil {
			return types.SCIMPrincipal{}, fmt.Errorf("%w: %w", ErrSCIMUnauthenticated, err)
		}

		if !scope.Grants(scope.Parse(at.Scopes), scope.SCIM) {
			return types.SCIMPrincipal{}, ErrSCIMForbidden
		}

		return types.SCIMPrincipal{
			Kind:         types.CredentialOAuthToken,
			CredentialID: at.ID,
			Identifier:   at.Prefix,
			ClientID:     at.ClientID,
		}, nil

	default:
		return types.SCIMPrincipal{}, ErrSCIMUnauthenticated
	}
}

// CreateSCIMToken creates a SCIM bearer token, returning the plaintext (shown
// once) and the stored token. A nil expiration never expires.
func (s *State) CreateSCIMToken(description string, expiration *time.Time) (string, *types.SCIMToken, error) {
	secret, tok, err := s.db.CreateSCIMToken(description, expiration)
	if err != nil {
		return "", nil, err
	}

	log.Info().EmbedObject(tok).Msg("scim token created")

	return secret, tok, nil
}

// ListSCIMTokens returns every SCIM token, without secrets.
func (s *State) ListSCIMTokens() ([]types.SCIMToken, error) {
	return s.db.ListSCIMTokens()
}

// GetSCIMTokenByID returns a SCIM token by its database id.
func (s *State) GetSCIMTokenByID(id uint64) (*types.SCIMToken, error) {
	return s.db.GetSCIMTokenByID(id)
}

// RevokeSCIMToken revokes a SCIM token, keeping it listed for audit.
func (s *State) RevokeSCIMToken(id uint64) error {
	err := s.db.RevokeSCIMToken(id)
	if err != nil {
		return err
	}

	log.Info().Uint64(zf.SCIMTokenID, id).Msg("scim token revoked")

	return nil
}

// DeleteSCIMToken permanently deletes a SCIM token.
func (s *State) DeleteSCIMToken(id uint64) error {
	err := s.db.DeleteSCIMToken(id)
	if err != nil {
		return err
	}

	log.Info().Uint64(zf.SCIMTokenID, id).Msg("scim token deleted")

	return nil
}
