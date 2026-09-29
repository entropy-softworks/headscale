package scim

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// ScimType is the "scimType" detail error keyword of RFC 7644 section 3.12,
// table 9. It is only meaningful together with HTTP status 400 (and 409 for
// uniqueness).
type ScimType string

// The scimType values defined by RFC 7644 section 3.12.
const (
	ScimTypeInvalidFilter ScimType = "invalidFilter"
	ScimTypeTooMany       ScimType = "tooMany"
	ScimTypeUniqueness    ScimType = "uniqueness"
	ScimTypeMutability    ScimType = "mutability"
	ScimTypeInvalidSyntax ScimType = "invalidSyntax"
	ScimTypeInvalidPath   ScimType = "invalidPath"
	ScimTypeNoTarget      ScimType = "noTarget"
	ScimTypeInvalidValue  ScimType = "invalidValue"
	ScimTypeInvalidVers   ScimType = "invalidVers"
	ScimTypeSensitive     ScimType = "sensitive"
)

// Error is a SCIM error response (RFC 7644 section 3.12). It implements
// error so that protocol functions can return it directly and handlers can
// recover it with [AsError] or errors.As.
//
// On the wire the status is a JSON string ("409"), as required by the RFC;
// Entra ID and Okta both parse it that way.
type Error struct {
	// Status is the HTTP status code.
	Status int
	// ScimType is the optional detail keyword; empty for statuses that
	// have none (404, 401, 500, ...).
	ScimType ScimType
	// Detail is a human-readable message returned to the client.
	Detail string
	// Err is an optional underlying cause. It is available through
	// errors.Unwrap for logging but never serialised to the client.
	Err error
}

// Sentinels for errors.Is. [Error.Is] compares Status and ScimType only, so
// errors.Is(err, ErrUniqueness) is true for any 409 uniqueness error
// regardless of its detail.
var (
	ErrNotFound      = &Error{Status: http.StatusNotFound}
	ErrUniqueness    = &Error{Status: http.StatusConflict, ScimType: ScimTypeUniqueness}
	ErrInvalidFilter = &Error{Status: http.StatusBadRequest, ScimType: ScimTypeInvalidFilter}
	ErrInvalidValue  = &Error{Status: http.StatusBadRequest, ScimType: ScimTypeInvalidValue}
	ErrInvalidSyntax = &Error{Status: http.StatusBadRequest, ScimType: ScimTypeInvalidSyntax}
	ErrInvalidPath   = &Error{Status: http.StatusBadRequest, ScimType: ScimTypeInvalidPath}
	ErrNoTarget      = &Error{Status: http.StatusBadRequest, ScimType: ScimTypeNoTarget}
	ErrMutability    = &Error{Status: http.StatusBadRequest, ScimType: ScimTypeMutability}
	ErrTooMany       = &Error{Status: http.StatusBadRequest, ScimType: ScimTypeTooMany}
)

// Error implements the error interface.
func (e *Error) Error() string {
	msg := "scim: " + strconv.Itoa(e.Status)
	if e.ScimType != "" {
		msg += " " + string(e.ScimType)
	}

	if e.Detail != "" {
		msg += ": " + e.Detail
	}

	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}

	return msg
}

// Unwrap returns the underlying cause, if any.
func (e *Error) Unwrap() error {
	return e.Err
}

// Is reports whether target is an *Error with the same status and scimType.
func (e *Error) Is(target error) bool {
	var t *Error
	if !errors.As(target, &t) {
		return false
	}

	return t.Status == e.Status && t.ScimType == e.ScimType
}

type errorBody struct {
	Schemas  []string `json:"schemas"`
	ScimType ScimType `json:"scimType,omitempty"`
	Detail   string   `json:"detail,omitempty"`
	Status   string   `json:"status"`
}

// MarshalJSON renders the RFC 7644 error body. Status is a string.
func (e *Error) MarshalJSON() ([]byte, error) {
	return json.Marshal(errorBody{
		Schemas:  []string{SchemaError},
		ScimType: e.ScimType,
		Detail:   e.Detail,
		Status:   strconv.Itoa(e.Status),
	})
}

// UnmarshalJSON parses an RFC 7644 error body. It accepts status either as a
// string (RFC) or as a number (seen from some implementations).
func (e *Error) UnmarshalJSON(data []byte) error {
	var body struct {
		ScimType ScimType        `json:"scimType"`
		Detail   string          `json:"detail"`
		Status   json.RawMessage `json:"status"`
	}

	err := json.Unmarshal(data, &body)
	if err != nil {
		return err
	}

	raw := strings.Trim(string(body.Status), `"`)

	status, err := strconv.Atoi(raw)
	if err != nil {
		return fmt.Errorf("%w: status %q", ErrInvalidSyntax, raw)
	}

	*e = Error{Status: status, ScimType: body.ScimType, Detail: body.Detail}

	return nil
}

func newError(status int, scimType ScimType, format string, args ...any) *Error {
	return &Error{Status: status, ScimType: scimType, Detail: fmt.Sprintf(format, args...)}
}

// InvalidFilter returns a 400 invalidFilter error.
func InvalidFilter(format string, args ...any) *Error {
	return newError(http.StatusBadRequest, ScimTypeInvalidFilter, format, args...)
}

// TooMany returns a 400 tooMany error.
func TooMany(format string, args ...any) *Error {
	return newError(http.StatusBadRequest, ScimTypeTooMany, format, args...)
}

// Uniqueness returns a 409 uniqueness error. Entra ID, Okta and Authentik
// all rely on 409 to detect an existing resource.
func Uniqueness(format string, args ...any) *Error {
	return newError(http.StatusConflict, ScimTypeUniqueness, format, args...)
}

// Mutability returns a 400 mutability error.
func Mutability(format string, args ...any) *Error {
	return newError(http.StatusBadRequest, ScimTypeMutability, format, args...)
}

// InvalidSyntax returns a 400 invalidSyntax error.
func InvalidSyntax(format string, args ...any) *Error {
	return newError(http.StatusBadRequest, ScimTypeInvalidSyntax, format, args...)
}

// InvalidPath returns a 400 invalidPath error.
func InvalidPath(format string, args ...any) *Error {
	return newError(http.StatusBadRequest, ScimTypeInvalidPath, format, args...)
}

// NoTarget returns a 400 noTarget error.
func NoTarget(format string, args ...any) *Error {
	return newError(http.StatusBadRequest, ScimTypeNoTarget, format, args...)
}

// InvalidValue returns a 400 invalidValue error.
func InvalidValue(format string, args ...any) *Error {
	return newError(http.StatusBadRequest, ScimTypeInvalidValue, format, args...)
}

// InvalidVersion returns a 400 invalidVers error.
func InvalidVersion(format string, args ...any) *Error {
	return newError(http.StatusBadRequest, ScimTypeInvalidVers, format, args...)
}

// Sensitive returns a 400 sensitive error.
func Sensitive(format string, args ...any) *Error {
	return newError(http.StatusBadRequest, ScimTypeSensitive, format, args...)
}

// NotFound returns a 404 error. Entra ID requires the SCIM error body on 404.
func NotFound(format string, args ...any) *Error {
	return newError(http.StatusNotFound, "", format, args...)
}

// Unauthorized returns a 401 error.
func Unauthorized(format string, args ...any) *Error {
	return newError(http.StatusUnauthorized, "", format, args...)
}

// Forbidden returns a 403 error.
func Forbidden(format string, args ...any) *Error {
	return newError(http.StatusForbidden, "", format, args...)
}

// MethodNotAllowed returns a 405 error.
func MethodNotAllowed(format string, args ...any) *Error {
	return newError(http.StatusMethodNotAllowed, "", format, args...)
}

// NotImplemented returns a 501 error, e.g. for /Bulk or sorting.
func NotImplemented(format string, args ...any) *Error {
	return newError(http.StatusNotImplemented, "", format, args...)
}

// PayloadTooLarge returns a 413 error.
func PayloadTooLarge(format string, args ...any) *Error {
	return newError(http.StatusRequestEntityTooLarge, "", format, args...)
}

// Internal returns a 500 error wrapping cause. The cause is kept for logging
// and never sent to the client.
func Internal(cause error) *Error {
	return &Error{
		Status: http.StatusInternalServerError,
		Detail: "internal server error",
		Err:    cause,
	}
}

// AsError converts err into a SCIM error. A *Error anywhere in the chain is
// returned as is; any other non-nil error becomes a 500 via [Internal] so
// that internal details never leak to the client. It returns nil for nil.
func AsError(err error) *Error {
	if err == nil {
		return nil
	}

	if se, ok := errors.AsType[*Error](err); ok {
		return se
	}

	return Internal(err)
}

// MapError is like [AsError] but first consults mapping, a list of
// (match, result) pairs checked in order with errors.Is. It lets a handler
// translate persistence errors without a switch, e.g.
//
//	scim.MapError(err, scim.ErrorMapping{db.ErrUserExists, scim.Uniqueness("user exists")})
//
// The matched cause is attached to the result's Err for logging.
func MapError(err error, mapping ...ErrorMapping) *Error {
	if err == nil {
		return nil
	}

	for _, m := range mapping {
		if m.Match != nil && m.Result != nil && errors.Is(err, m.Match) {
			out := *m.Result
			out.Err = err

			return &out
		}
	}

	return AsError(err)
}

// ErrorMapping pairs an error to match with the SCIM error to return.
// Entries with a nil Match or Result are skipped.
type ErrorMapping struct {
	Match  error
	Result *Error
}

// WriteError writes err as a SCIM error response: status code, the RFC 7644
// error body and Content-Type application/scim+json. Non-SCIM errors are
// written as 500 (see [AsError]).
func WriteError(w http.ResponseWriter, err error) {
	se := AsError(err)
	if se == nil {
		se = Internal(nil)
	}

	if se.Status < 400 || se.Status > 599 {
		// Never WriteHeader(0) or a success status for an error.
		fixed := *se
		fixed.Status = http.StatusInternalServerError
		se = &fixed
	}

	_ = WriteJSON(w, se.Status, se)
}

// WriteResource writes a single resource. For 201 Created it sets Location
// to location, as RFC 7644 section 3.3 requires; for any status it also sets
// Content-Location when location is non-empty. Use [UserLocation] or
// [GroupLocation] to build it (the same value as meta.location).
func WriteResource(w http.ResponseWriter, status int, location string, v any) error {
	if location != "" {
		if status == http.StatusCreated {
			w.Header().Set("Location", location)
		}

		w.Header().Set("Content-Location", location)
	}

	return WriteJSON(w, status, v)
}

// WriteJSON writes v as a SCIM JSON response with the given status and
// Content-Type application/scim+json. It must be used for every SCIM
// response body; Entra ID rejects plain application/json.
func WriteJSON(w http.ResponseWriter, status int, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		body = []byte(`{"schemas":["` + SchemaError + `"],"detail":"internal server error","status":"500"}`)
		status = http.StatusInternalServerError
	}

	w.Header().Set("Content-Type", ContentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	_, werr := w.Write(body)

	if err != nil {
		return err
	}

	return werr
}
