package keycloak

import (
	"github.com/getevo/evo/v2/lib/errors"
	"net/http"
)

var (
	ErrorInvalidClient           = errors.New(http.StatusUnauthorized, "Invalid client")
	ErrorInvalidToken            = errors.New(http.StatusUnauthorized, "Invalid token")
	ErrorInsufficientScope       = errors.New(http.StatusForbidden, "Insufficient scope")
	ErrorInvalidUsernamePassword = errors.New(http.StatusUnauthorized, "Invalid username or password")
	ErrorUserAccountDisabled     = errors.New(http.StatusUnauthorized, "User account is disabled")
	ErrorInvalidRequest          = errors.New(http.StatusBadRequest, "Invalid request")
	ErrorInvalidScope            = errors.New(http.StatusUnauthorized, "Invalid scope")
	ErrorDuplicateUser           = errors.New(http.StatusConflict, "User already exists")
	ErrorUnauthorizedClient      = errors.New(http.StatusUnauthorized, "Unauthorized client")
	ErrorUnsupportedGrantType    = errors.New(http.StatusBadRequest, "Unsupported grant type")
	ErrorServerError             = errors.New(http.StatusInternalServerError, "Server error")
	ErrorTemporarilyUnavailable  = errors.New(http.StatusServiceUnavailable, "Temporarily unavailable")
	ErrorUnknownReason           = errors.New("unknown", 451)
)

func HTTPError(err error) errors.HTTPError {
	var resp errors.HTTPError
	switch err.Error() {
	case "invalid_client":
		resp = ErrorInvalidClient
	case "invalid_grant":
		resp = ErrorInvalidUsernamePassword
	case "invalid_request":
		resp = ErrorInvalidRequest
	case "invalid_scope":
		resp = ErrorInvalidScope
	case "invalid_token":
		resp = ErrorInvalidToken
	case "insufficient_scope":
		resp = ErrorInsufficientScope
	case "duplicate user":
		resp = ErrorDuplicateUser
	case "user account disabled":
		resp = ErrorUserAccountDisabled
	case "unauthorized_client":
		resp = ErrorUnauthorizedClient
	case "unsupported_grant_type":
		resp = ErrorUnsupportedGrantType
	case "server_error":
		resp = ErrorServerError
	case "temporarily_unavailable":
		resp = ErrorTemporarilyUnavailable
	default:
		resp = ErrorUnknownReason
	}
	return resp
}
