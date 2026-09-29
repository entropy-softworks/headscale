package scim

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	errDBDuplicate = errors.New("duplicate key")
	errOther       = errors.New("other")
)

func TestErrorJSONShape(t *testing.T) {
	tests := []struct {
		name string
		err  *Error
		want string
	}{
		{
			name: "uniqueness",
			err:  Uniqueness("user %q already exists", "alice"),
			want: `{"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],` +
				`"scimType":"uniqueness","detail":"user \"alice\" already exists","status":"409"}`,
		},
		{
			name: "not found has no scimType",
			err:  NotFound("user 7 not found"),
			want: `{"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],` +
				`"detail":"user 7 not found","status":"404"}`,
		},
		{
			name: "internal hides cause",
			err:  Internal(errDBDuplicate),
			want: `{"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],` +
				`"detail":"internal server error","status":"500"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := json.Marshal(tt.err)
			require.NoError(t, err)
			assert.JSONEq(t, tt.want, string(got))

			var back Error
			require.NoError(t, json.Unmarshal(got, &back))
			assert.Equal(t, tt.err.Status, back.Status)
			assert.Equal(t, tt.err.ScimType, back.ScimType)
			assert.Equal(t, tt.err.Detail, back.Detail)
		})
	}
}

func TestErrorConstructors(t *testing.T) {
	tests := []struct {
		err      *Error
		status   int
		scimType ScimType
	}{
		{InvalidFilter("x"), 400, ScimTypeInvalidFilter},
		{TooMany("x"), 400, ScimTypeTooMany},
		{Uniqueness("x"), 409, ScimTypeUniqueness},
		{Mutability("x"), 400, ScimTypeMutability},
		{InvalidSyntax("x"), 400, ScimTypeInvalidSyntax},
		{InvalidPath("x"), 400, ScimTypeInvalidPath},
		{NoTarget("x"), 400, ScimTypeNoTarget},
		{InvalidValue("x"), 400, ScimTypeInvalidValue},
		{InvalidVersion("x"), 400, ScimTypeInvalidVers},
		{Sensitive("x"), 400, ScimTypeSensitive},
		{NotFound("x"), 404, ""},
		{Unauthorized("x"), 401, ""},
		{Forbidden("x"), 403, ""},
		{MethodNotAllowed("x"), 405, ""},
		{NotImplemented("x"), 501, ""},
		{PayloadTooLarge("x"), 413, ""},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.status, tt.err.Status, tt.err.Error())
		assert.Equal(t, tt.scimType, tt.err.ScimType, tt.err.Error())
		assert.Equal(t, "x", tt.err.Detail)
	}
}

func TestErrorUnmarshalNumericStatus(t *testing.T) {
	var e Error
	require.NoError(t, json.Unmarshal([]byte(`{"status":409,"scimType":"uniqueness"}`), &e))
	assert.Equal(t, 409, e.Status)

	require.ErrorIs(t, json.Unmarshal([]byte(`{"status":"abc"}`), &e), ErrInvalidSyntax)
	require.Error(t, json.Unmarshal([]byte(`[]`), &e))
}

func TestErrorIsAndAs(t *testing.T) {
	err := fmt.Errorf("creating user: %w", Uniqueness("dup"))

	require.ErrorIs(t, err, ErrUniqueness)
	require.NotErrorIs(t, err, ErrNotFound)
	assert.False(t, Uniqueness("x").Is(errDBDuplicate))

	se := AsError(err)
	assert.Equal(t, 409, se.Status)

	assert.Nil(t, AsError(nil))
	assert.Equal(t, http.StatusInternalServerError, AsError(errDBDuplicate).Status)
	require.ErrorIs(t, AsError(errDBDuplicate), errDBDuplicate)

	assert.Equal(t, "scim: 409 uniqueness: dup", Uniqueness("dup").Error())
	assert.Equal(t, "scim: 500: internal server error: duplicate key", Internal(errDBDuplicate).Error())
}

func TestMapError(t *testing.T) {
	wrapped := fmt.Errorf("db: %w", errDBDuplicate)
	mapping := ErrorMapping{Match: errDBDuplicate, Result: Uniqueness("userName taken")}

	got := MapError(wrapped, mapping)
	assert.Equal(t, 409, got.Status)
	assert.Equal(t, "userName taken", got.Detail)
	require.ErrorIs(t, got, errDBDuplicate)
	// The template is not mutated.
	require.NoError(t, mapping.Result.Err)

	assert.Equal(t, 500, MapError(errOther).Status)
	assert.Nil(t, MapError(nil, mapping))

	// Incomplete entries are skipped instead of panicking.
	got = MapError(wrapped, ErrorMapping{Match: errDBDuplicate}, ErrorMapping{Result: NotFound("x")})
	assert.Equal(t, 500, got.Status)
}

func TestWriteError(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteError(rec, InvalidFilter("bad filter"))

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "application/scim+json", rec.Header().Get("Content-Type"))
	assert.JSONEq(t,
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"scimType":"invalidFilter","detail":"bad filter","status":"400"}`,
		rec.Body.String())

	rec = httptest.NewRecorder()
	WriteError(rec, errDBDuplicate)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.NotContains(t, rec.Body.String(), "duplicate")

	rec = httptest.NewRecorder()
	WriteError(rec, nil)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)

	for _, bad := range []*Error{{}, {Status: 200}, {Status: 99}} {
		rec = httptest.NewRecorder()
		WriteError(rec, bad)
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
		assert.Contains(t, rec.Body.String(), `"status":"500"`)
	}
}

func TestWriteResource(t *testing.T) {
	loc := UserLocation("https://hs/scim/v2", "1")

	rec := httptest.NewRecorder()
	require.NoError(t, WriteResource(rec, http.StatusCreated, loc, &User{ID: "1", UserName: "a"}))
	assert.Equal(t, http.StatusCreated, rec.Code)
	assert.Equal(t, loc, rec.Header().Get("Location"))
	assert.Equal(t, loc, rec.Header().Get("Content-Location"))
	assert.Equal(t, ContentType, rec.Header().Get("Content-Type"))

	rec = httptest.NewRecorder()
	require.NoError(t, WriteResource(rec, http.StatusOK, loc, &User{ID: "1", UserName: "a"}))
	assert.Empty(t, rec.Header().Get("Location"))
	assert.Equal(t, loc, rec.Header().Get("Content-Location"))

	rec = httptest.NewRecorder()
	require.NoError(t, WriteResource(rec, http.StatusOK, "", &User{ID: "1", UserName: "a"}))
	assert.Empty(t, rec.Header().Get("Content-Location"))
}

func TestWriteJSONMarshalFailure(t *testing.T) {
	rec := httptest.NewRecorder()
	err := WriteJSON(rec, http.StatusOK, map[string]any{"x": make(chan int)})

	require.Error(t, err)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Equal(t, ContentType, rec.Header().Get("Content-Type"))
}
