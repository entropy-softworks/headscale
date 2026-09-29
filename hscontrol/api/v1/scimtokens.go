package apiv1

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/juanfont/headscale/hscontrol/types"
)

func init() {
	registrations = append(registrations, registerSCIMTokens)
}

// ScimToken is a SCIM bearer token as listed: the masked prefix identifies it,
// the secret is never returned after creation. Timestamps are nullable
// pointers, matching ApiKey.
type ScimToken struct {
	ID          string     `format:"uint64"    json:"id"`
	Prefix      string     `json:"prefix"`
	Description string     `json:"description"`
	CreatedAt   *time.Time `json:"createdAt"   nullable:"true"`
	Expiration  *time.Time `json:"expiration"  nullable:"true"`
	LastSeen    *time.Time `json:"lastSeen"    nullable:"true"`
	Revoked     *time.Time `json:"revoked"     nullable:"true"`
}

// CreateScimTokenRequestBody is the create request. A missing expiration never
// expires; one that is not in the future is rejected with 400.
type CreateScimTokenRequestBody struct {
	Description string     `json:"description,omitempty"`
	Expiration  *time.Time `json:"expiration,omitempty"`
}

type (
	createScimTokenInput struct {
		Body CreateScimTokenRequestBody
	}
	createScimTokenOutput struct {
		Body struct {
			// Token is the plaintext bearer token, returned only here.
			Token     string    `json:"token"`
			ScimToken ScimToken `json:"scimToken"`
		}
	}
)

type listScimTokensOutput struct {
	Body struct {
		ScimTokens []ScimToken `json:"scimTokens" nullable:"false"`
	}
}

type (
	scimTokenIDInput struct {
		ID string `format:"uint64" path:"id"`
	}
	emptyScimTokenOutput struct {
		Body struct{}
	}
)

func registerSCIMTokens(api huma.API, b Backend) {
	huma.Register(api, huma.Operation{
		OperationID: "createScimToken",
		Method:      http.MethodPost,
		Path:        "/api/v1/scim/token",
		Summary:     "Create SCIM token",
		Description: "Creates a bearer token for an identity provider's SCIM client. " +
			"The token is returned once and cannot be retrieved again.",
		Tags:     []string{"ScimTokens"},
		Security: bearerAuth,
	}, func(ctx context.Context, in *createScimTokenInput) (*createScimTokenOutput, error) {
		// A token born expired could never authenticate; refuse rather than
		// hand out a dead secret.
		if in.Body.Expiration != nil && !in.Body.Expiration.After(time.Now()) {
			return nil, huma.Error400BadRequest("expiration must be in the future")
		}

		secret, tok, err := b.State.CreateSCIMToken(in.Body.Description, in.Body.Expiration)
		if err != nil {
			return nil, mapError("creating scim token", err)
		}

		out := &createScimTokenOutput{}
		out.Body.Token = secret
		out.Body.ScimToken = scimTokenFromState(tok)

		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "listScimTokens",
		Method:      http.MethodGet,
		Path:        "/api/v1/scim/token",
		Summary:     "List SCIM tokens",
		Tags:        []string{"ScimTokens"},
		Security:    bearerAuth,
	}, func(ctx context.Context, _ *struct{}) (*listScimTokensOutput, error) {
		toks, err := b.State.ListSCIMTokens()
		if err != nil {
			return nil, mapError("listing scim tokens", err)
		}

		out := &listScimTokensOutput{}

		out.Body.ScimTokens = make([]ScimToken, len(toks))
		for i := range toks {
			out.Body.ScimTokens[i] = scimTokenFromState(&toks[i])
		}

		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "revokeScimToken",
		Method:      http.MethodPost,
		Path:        "/api/v1/scim/token/{id}/revoke",
		Summary:     "Revoke SCIM token",
		Description: "Revokes a SCIM token; it stops authenticating but stays listed.",
		Tags:        []string{"ScimTokens"},
		Security:    bearerAuth,
	}, func(ctx context.Context, in *scimTokenIDInput) (*emptyScimTokenOutput, error) {
		id, err := parseSCIMTokenID(in.ID)
		if err != nil {
			return nil, err
		}

		err = b.State.RevokeSCIMToken(id)
		if err != nil {
			return nil, mapError("revoking scim token", err)
		}

		return &emptyScimTokenOutput{}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "deleteScimToken",
		Method:      http.MethodDelete,
		Path:        "/api/v1/scim/token/{id}",
		Summary:     "Delete SCIM token",
		Tags:        []string{"ScimTokens"},
		Security:    bearerAuth,
	}, func(ctx context.Context, in *scimTokenIDInput) (*emptyScimTokenOutput, error) {
		id, err := parseSCIMTokenID(in.ID)
		if err != nil {
			return nil, err
		}

		err = b.State.DeleteSCIMToken(id)
		if err != nil {
			return nil, mapError("deleting scim token", err)
		}

		return &emptyScimTokenOutput{}, nil
	})
}

// parseSCIMTokenID decodes the path id; a non-numeric id is rejected with 400.
func parseSCIMTokenID(s string) (uint64, error) {
	id, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, huma.Error400BadRequest("invalid scim token id", err)
	}

	return id, nil
}

// scimTokenFromState converts a domain SCIM token into the v1 response shape.
func scimTokenFromState(t *types.SCIMToken) ScimToken {
	return ScimToken{
		ID:          formatID(t.ID),
		Prefix:      t.MaskedPrefix(),
		Description: t.Description,
		CreatedAt:   t.CreatedAt,
		Expiration:  t.Expiration,
		LastSeen:    t.LastSeen,
		Revoked:     t.Revoked,
	}
}
