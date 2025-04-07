package keycloak

import (
	"fmt"
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
	ErrorUnknownError            = errors.New(http.StatusPreconditionFailed, "Unknown error")
)

func HTTPError(err error) errors.HTTPError {
	var resp errors.HTTPError
	fmt.Println("error:", err.Error())
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
	default:
		resp = ErrorUnknownError
	}
	return resp
}
