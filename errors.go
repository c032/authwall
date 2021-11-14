package authwall

import (
	"net/http"
)

const (
	errTypePrefix = "https://github.com/c032/authwall#errors/"
)

var (
	ErrBackendURLMissing = &RFC7807{
		Type:   errTypePrefix + "backend-url-missing",
		Title:  "Backend URL is missing.",
		Status: http.StatusInternalServerError,
	}
	ErrBackendURLInvalid = &RFC7807{
		Type:   errTypePrefix + "backend-url-invalid",
		Title:  "Backend URL is invalid.",
		Status: http.StatusInternalServerError,
	}
	ErrLoginPathPrefixIsRoot = &RFC7807{
		Type:   errTypePrefix + "login-path-prefix-is-root",
		Title:  "`LoginPathPrefix` cannot be `/`.",
		Status: http.StatusInternalServerError,
	}
	ErrLoginPathPrefixMissingTrailingSlash = &RFC7807{
		Type:   errTypePrefix + "login-path-prefix-missing-trailing-slash",
		Title:  "`LoginPathPrefix` must end with `/`.",
		Status: http.StatusInternalServerError,
	}
	ErrRequestForm = &RFC7807{
		Type:   errTypePrefix + "request-form",
		Title:  "Could not process request form data.",
		Status: http.StatusInternalServerError,
	}
	ErrCredentialsInvalid = &RFC7807{
		Type:   errTypePrefix + "credentials-invalid",
		Title:  "Invalid credentials.",
		Status: http.StatusBadRequest,
	}
	ErrProviderInvalid = &RFC7807{
		Type:   errTypePrefix + "provider-invalid",
		Title:  "Invalid provider.",
		Status: http.StatusBadRequest,
	}
	ErrSessionInvalid = &RFC7807{
		Type:   errTypePrefix + "session-invalid",
		Title:  "Invalid session.",
		Status: http.StatusUnauthorized,
	}
	ErrProviderNone = &RFC7807{
		Type:   errTypePrefix + "provider-none",
		Title:  "No providers defined.",
		Status: http.StatusBadRequest,
	}
	ErrCookieInvalid = &RFC7807{
		Type:   errTypePrefix + "cookie-invalid",
		Title:  "Invalid cookie.",
		Status: http.StatusBadRequest,
	}
)

var (
	ErrUnauthorized = &RFC7807{
		Type:   "https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/401",
		Title:  "Unauthorized.",
		Status: http.StatusUnauthorized,
	}
	ErrMethodNotAllowed = &RFC7807{
		Type:   "https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/405",
		Title:  "Method not allowed.",
		Status: http.StatusMethodNotAllowed,
	}
	ErrInternalServerError = &RFC7807{
		Type:   "https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/500",
		Title:  "Internal server error.",
		Status: http.StatusInternalServerError,
	}
	ErrBadGateway = &RFC7807{
		Type:   "https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/502",
		Title:  "Bad gateway.",
		Status: http.StatusBadGateway,
	}
)
