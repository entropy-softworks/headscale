package apiv1

import (
	"reflect"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/go-chi/chi/v5"
)

// publicOps are the v1 operations that intentionally declare no security and
// so are served without an API key. Every v1 operation currently requires one
// (health included), so the list is empty; adding an entry is a deliberate,
// reviewed decision to expose an operation unauthenticated.
var publicOps = map[string]bool{}

// TestEveryOperationRequiresBearerAuth is the structural guarantee that no v1
// operation ships unauthenticated: authMiddleware only enforces the API key for
// operations that declare security, so an operation registered without
// Security: bearerAuth would be served to anyone.
func TestEveryOperationRequiresBearerAuth(t *testing.T) {
	api := NewAPI(chi.NewMux(), Backend{})

	seen := 0

	for path, item := range api.OpenAPI().Paths {
		for method, op := range map[string]*huma.Operation{
			"GET":    item.Get,
			"POST":   item.Post,
			"PUT":    item.Put,
			"DELETE": item.Delete,
			"PATCH":  item.Patch,
		} {
			if op == nil {
				continue
			}

			seen++

			key := method + " " + path
			if publicOps[key] {
				continue
			}

			if !reflect.DeepEqual(op.Security, bearerAuth) {
				t.Errorf("operation %q (%s) declares security %v, want bearerAuth; "+
					"add Security: bearerAuth, or list it in publicOps if it is "+
					"intentionally public", key, op.OperationID, op.Security)
			}
		}
	}

	if seen == 0 {
		t.Fatal("no operations registered")
	}
}
