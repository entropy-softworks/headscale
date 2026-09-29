package db

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util/zlog/zf"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

var (
	ErrSCIMTokenNotFound      = fmt.Errorf("scim token not found: %w", gorm.ErrRecordNotFound)
	ErrSCIMTokenFailedToParse = errors.New("failed to parse scim token")
	ErrSCIMTokenExpired       = errors.New("scim token expired")
	ErrSCIMTokenRevoked       = errors.New("scim token revoked")
)

// scimTokenLastSeenInterval bounds how often authentication records a SCIM
// token's last use. A provisioning sync issues a burst of requests; one write
// per interval is enough to tell a live token from a stale one.
const scimTokenLastSeenInterval = time.Minute

// credentialToSCIMToken projects a unified credentials row onto the
// [types.SCIMToken] shape. The lookup prefix is stored as the row's identifier.
func credentialToSCIMToken(c *types.Credential) *types.SCIMToken {
	return &types.SCIMToken{
		ID:          c.ID,
		Prefix:      c.Identifier,
		Description: c.Description,
		CreatedAt:   c.CreatedAt,
		Expiration:  c.Expiration,
		LastSeen:    c.LastSeen,
		Revoked:     c.Revoked,
	}
}

// CreateSCIMToken stores a new SCIM bearer token and returns the plaintext
// (hskey-scim-<prefix>-<secret>, shown ONCE) alongside the stored token. A nil
// expiration never expires.
func (hsdb *HSDatabase) CreateSCIMToken(
	description string,
	expiration *time.Time,
) (string, *types.SCIMToken, error) {
	tokenStr, prefix, hash := generateSecret(types.SCIMTokenPrefix)

	now := time.Now().UTC()
	cred := types.Credential{
		Kind:        types.CredentialSCIMToken,
		Identifier:  prefix,
		Hash:        hash,
		Description: description,
		Expiration:  expiration,
		CreatedAt:   &now,
	}

	err := hsdb.Write(func(tx *gorm.DB) error {
		return tx.Create(&cred).Error
	})
	if err != nil {
		return "", nil, fmt.Errorf("saving scim token: %w", err)
	}

	return tokenStr, credentialToSCIMToken(&cred), nil
}

// ListSCIMTokens returns every SCIM token, revoked ones included, by ascending
// id. Secrets are never stored, so none can be returned.
func (hsdb *HSDatabase) ListSCIMTokens() ([]types.SCIMToken, error) {
	var creds []types.Credential

	err := hsdb.DB.Where("kind = ?", types.CredentialSCIMToken).Order("id").Find(&creds).Error
	if err != nil {
		return nil, err
	}

	tokens := make([]types.SCIMToken, 0, len(creds))
	for i := range creds {
		tokens = append(tokens, *credentialToSCIMToken(&creds[i]))
	}

	return tokens, nil
}

// GetSCIMTokenByID returns the SCIM token with the given id, or
// [ErrSCIMTokenNotFound].
func (hsdb *HSDatabase) GetSCIMTokenByID(id uint64) (*types.SCIMToken, error) {
	var cred types.Credential

	err := hsdb.DB.First(&cred, "kind = ? AND id = ?", types.CredentialSCIMToken, id).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrSCIMTokenNotFound
	}

	if err != nil {
		return nil, err
	}

	return credentialToSCIMToken(&cred), nil
}

// RevokeSCIMToken marks a SCIM token revoked so it no longer authenticates,
// keeping the row (and its last-seen time) for audit. Revoking an already
// revoked token keeps the original revocation time. An unknown id returns
// [ErrSCIMTokenNotFound].
func (hsdb *HSDatabase) RevokeSCIMToken(id uint64) error {
	res := hsdb.DB.Model(&types.Credential{}).
		Where("kind = ? AND id = ?", types.CredentialSCIMToken, id).
		Update("revoked", gorm.Expr("COALESCE(revoked, ?)", time.Now().UTC()))

	return scimTokenAffected(res)
}

// DeleteSCIMToken permanently removes a SCIM token. An unknown id returns
// [ErrSCIMTokenNotFound].
func (hsdb *HSDatabase) DeleteSCIMToken(id uint64) error {
	res := hsdb.DB.Where("kind = ? AND id = ?", types.CredentialSCIMToken, id).
		Delete(&types.Credential{})

	return scimTokenAffected(res)
}

// scimTokenAffected maps a write that matched no SCIM token row to
// [ErrSCIMTokenNotFound].
func scimTokenAffected(res *gorm.DB) error {
	if res.Error != nil {
		return res.Error
	}

	if res.RowsAffected == 0 {
		return ErrSCIMTokenNotFound
	}

	return nil
}

// AuthenticateSCIMToken validates a presented hskey-scim- bearer token and
// returns the matching token. The secret is compared in constant time (see
// [verifySecret]); an unknown prefix and a wrong secret both return
// [ErrSCIMTokenNotFound]. A revoked or expired token returns
// [ErrSCIMTokenRevoked] or [ErrSCIMTokenExpired]. On success the token's last
// use is recorded, at most once per [scimTokenLastSeenInterval].
func (hsdb *HSDatabase) AuthenticateSCIMToken(tokenStr string) (*types.SCIMToken, error) {
	rest, found := strings.CutPrefix(tokenStr, types.SCIMTokenPrefix)
	if !found {
		return nil, ErrSCIMTokenFailedToParse
	}

	prefix, secret, err := parsePrefixedKey(rest, ErrSCIMTokenFailedToParse)
	if err != nil {
		return nil, err
	}

	cred, err := authenticateCredential(
		hsdb.DB, types.CredentialSCIMToken, prefix, secret, ErrSCIMTokenNotFound,
	)
	if err != nil {
		return nil, err
	}

	if cred.Revoked != nil {
		return nil, ErrSCIMTokenRevoked
	}

	now := time.Now().UTC()

	if cred.Expiration != nil && cred.Expiration.Before(now) {
		return nil, ErrSCIMTokenExpired
	}

	if cred.LastSeen == nil || now.Sub(*cred.LastSeen) >= scimTokenLastSeenInterval {
		// Best effort: a failed bookkeeping write must not fail the request.
		err := hsdb.DB.Model(&types.Credential{}).Where("id = ?", cred.ID).
			Update("last_seen", now).Error
		if err != nil {
			log.Warn().Err(err).Uint64(zf.SCIMTokenID, cred.ID).
				Msg("recording scim token last use")
		} else {
			cred.LastSeen = &now
		}
	}

	return credentialToSCIMToken(cred), nil
}
