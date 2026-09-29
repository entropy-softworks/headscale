package types

import (
	"time"

	"github.com/juanfont/headscale/hscontrol/util/zlog/zf"
	"github.com/rs/zerolog"
)

// SCIMTokenPrefix prefixes a SCIM bearer token: hskey-scim-<prefix>-<secret>.
// The SCIM authentication entry point dispatches on it, so it is one canonical
// constant shared by the db, state and api layers.
const SCIMTokenPrefix = "hskey-scim-" //nolint:gosec // prefix, not a credential

// SCIMToken is a long-lived bearer credential an identity provider presents to
// the SCIM 2.0 provisioning endpoints ("Secret Token" in Entra ID, the HTTP
// header token in Okta). It is the API projection of a [Credential] of kind
// scim_token, is accepted only by the SCIM endpoints, and never by the v1/v2
// admin APIs. Only a hash of the secret is stored; the plaintext is shown once,
// at creation.
type SCIMToken struct {
	ID          uint64
	Prefix      string
	Description string

	CreatedAt  *time.Time
	Expiration *time.Time
	LastSeen   *time.Time
	Revoked    *time.Time
}

// MaskedPrefix returns the token in its display form, hskey-scim-<prefix>-***.
// SECURITY: never log or display the secret or its hash.
func (t *SCIMToken) MaskedPrefix() string {
	return SCIMTokenPrefix + t.Prefix + "-***"
}

// MarshalZerologObject implements [zerolog.LogObjectMarshaler] for safe logging.
// SECURITY: intentionally does NOT log the secret or hash.
func (t *SCIMToken) MarshalZerologObject(e *zerolog.Event) {
	if t == nil {
		return
	}

	e.Uint64(zf.SCIMTokenID, t.ID)
	e.Str(zf.SCIMTokenPrefix, t.MaskedPrefix())

	if t.Expiration != nil {
		e.Time(zf.SCIMTokenExpiration, *t.Expiration)
	}

	if t.Revoked != nil {
		e.Time(zf.SCIMTokenRevoked, *t.Revoked)
	}
}

// SCIMPrincipal identifies the credential a SCIM request authenticated with.
// Kind is [CredentialSCIMToken] or [CredentialOAuthToken]; CredentialID is that
// row's id; Identifier is the public token prefix; ClientID is the issuing
// OAuth client for an access token and empty for a SCIM token. It carries no
// secret material and is safe to log.
type SCIMPrincipal struct {
	Kind         CredentialKind
	CredentialID uint64
	Identifier   string
	ClientID     string
}

// MarshalZerologObject implements [zerolog.LogObjectMarshaler].
func (p SCIMPrincipal) MarshalZerologObject(e *zerolog.Event) {
	e.Str(zf.SCIMPrincipalKind, string(p.Kind))
	e.Uint64(zf.SCIMPrincipalCredentialID, p.CredentialID)

	if p.ClientID != "" {
		e.Str(zf.SCIMPrincipalClientID, p.ClientID)
	}
}
