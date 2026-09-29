package apiscim

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/juanfont/headscale/hscontrol/scim"
)

func (a *api) serviceProviderConfig(w http.ResponseWriter, _ *http.Request) {
	_ = scim.WriteJSON(w, http.StatusOK, scim.NewServiceProviderConfig(a.baseURL()))
}

// resourceTypes and schemas answer as list responses (RFC 7644 section 4).
func (a *api) resourceTypes(w http.ResponseWriter, _ *http.Request) {
	types := scim.NewResourceTypes(a.baseURL())

	page := make([]any, 0, len(types))
	for _, t := range types {
		page = append(page, t)
	}

	_ = scim.WriteJSON(w, http.StatusOK, scim.NewListResponse(nil, len(page), page))
}

func (a *api) resourceType(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	for _, t := range scim.NewResourceTypes(a.baseURL()) {
		if strings.EqualFold(t.ID, id) {
			_ = scim.WriteJSON(w, http.StatusOK, t)

			return
		}
	}

	writeError(w, r, scim.NotFound("resource type %q not found", id))
}

func (a *api) schemas(w http.ResponseWriter, _ *http.Request) {
	schemas := scim.NewSchemas(a.baseURL())

	page := make([]any, 0, len(schemas))
	for _, s := range schemas {
		page = append(page, s)
	}

	_ = scim.WriteJSON(w, http.StatusOK, scim.NewListResponse(nil, len(page), page))
}

func (a *api) schema(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	for _, s := range scim.NewSchemas(a.baseURL()) {
		if strings.EqualFold(s.ID, id) {
			_ = scim.WriteJSON(w, http.StatusOK, s)

			return
		}
	}

	writeError(w, r, scim.NotFound("schema %q not found", id))
}
