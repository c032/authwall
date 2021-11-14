package authwall

import (
	"net/http"
	"time"
)

// NewCookie creates a new `*http.Cookie` with the given name and value, plus
// some sane defaults.
func NewCookie(name, value string) *http.Cookie {
	const defaultTTL = 7 * 24 * time.Hour

	c := &http.Cookie{
		Name:  name,
		Value: value,

		Expires:  time.Now().Add(defaultTTL),
		HttpOnly: true,
		Path:     "/",
		SameSite: http.SameSiteStrictMode,
		Secure:   true,
	}

	return c
}

func CookieExpiresSoon(c *http.Cookie) bool {
	// "Expires soon" means the cookie's remaining lifetime is less than this
	// value.
	const minTTL = 3 * 24 * time.Hour

	return time.Now().Add(minTTL).After(c.Expires)
}
