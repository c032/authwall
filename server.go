package authwall

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/c032/go-logger"

	"github.com/c032/authwall/thirdparty"
)

const (
	DefaultSessionCookieName  = "session_id"
	DefaultProviderCookieName = "provider_id"

	DefaultHeaderPrefix = "Authwall-"

	keyRedirectTo = "redirect_to"
)

type Server struct {
	sync.RWMutex

	Title              string
	Logger             logger.Logger
	BackendURL         string
	Providers          []Provider
	SessionCookieName  string
	ProviderCookieName string
	HeaderPrefix       string
	LoginPathPrefix    string
	IsHTTPS            bool

	// CSRFSecret is a slice of random bytes, used for signing and verifying
	// CSRF tokens.
	CSRFSecret []byte

	// VerboseHTTPServerErrors specifies whether HTTP 5xx errors should include
	// details.
	//
	// If false, all responses with HTTP 5xx errors are replaced with a generic
	// message.
	VerboseHTTPServerErrors bool
}

func (s *Server) providerByID(providerID ProviderID) (Provider, bool) {
	for _, provider := range s.Providers {
		if provider.ID() == providerID {
			return provider, true
		}
	}

	return nil, false
}

func (s *Server) Open() error {
	s.Lock()
	defer s.Unlock()

	var err error

	if s.CSRFSecret == nil {
		secret := make([]byte, 64)

		_, err = rand.Read(secret)
		if err != nil {
			return fmt.Errorf("could not read random bytes: %w", err)
		}

		s.CSRFSecret = secret
	}

	return nil
}

func (s *Server) Close() error {
	return nil
}

func (s *Server) sessionCookieName() string {
	name := s.SessionCookieName
	if name == "" {
		return DefaultSessionCookieName
	}

	return name
}

func (s *Server) providerCookieName() string {
	name := s.ProviderCookieName
	if name == "" {
		return DefaultProviderCookieName
	}

	return name
}

func (s *Server) Session(w http.ResponseWriter, req *http.Request) (*Session, error) {
	var (
		err     error
		session *Session

		providerIDCookie *http.Cookie
		sessionIDCookie  *http.Cookie

		sessionID       SessionID
		providerID      ProviderID
		sessionIsValid  bool
		sessionMetadata SessionMetadata
		provider        Provider
		isValidProvider bool
	)

	cookies := req.Cookies()

	sessionCookieName := s.sessionCookieName()
	providerCookieName := s.providerCookieName()

	if n := len(cookies); n > 0 {
		if n != 2 {
			goto RemoveAllCookies
		}

		for _, c := range cookies {
			if c.Name == sessionCookieName {
				sessionIDCookie = c

				break
			}
		}

		for _, c := range cookies {
			if c.Name == providerCookieName {
				providerIDCookie = c

				break
			}
		}
	} else {
		return nil, nil
	}

	if strings.TrimSpace(sessionIDCookie.Value) == "" {
		goto RemoveAllCookies
	}
	if strings.TrimSpace(providerIDCookie.Value) == "" {
		goto RemoveAllCookies
	}

	provider, isValidProvider = s.providerByID(ProviderID(providerIDCookie.Value))
	if !isValidProvider {
		goto RemoveAllCookies
	}

	sessionID = SessionID(sessionIDCookie.Value)

	sessionIsValid, err = provider.SessionIsValid(sessionID)
	if err != nil {
		goto Error
	}
	if !sessionIsValid {
		goto RemoveAllCookies
	}

	sessionMetadata, err = provider.SessionMetadata(sessionID)
	if err != nil {
		// TODO

		return nil, err
	}

	providerID = provider.ID()

	session = &Session{
		ID:         sessionID,
		ProviderID: providerID,
		Metadata:   sessionMetadata,
	}

	return session, nil

RemoveAllCookies:
	for _, c := range cookies {
		s.cookieRemove(w, c.Name)
	}

	err = ErrCookieInvalid

Error:
	return session, err
}

func (s *Server) logger() logger.Logger {
	log := s.Logger

	if log == nil {
		return logger.Discard
	}

	return log
}

func (s *Server) headerPrefix() string {
	log := s.logger()

	headerPrefix := s.HeaderPrefix
	if headerPrefix == "" {
		headerPrefix = DefaultHeaderPrefix

		s.HeaderPrefix = headerPrefix

		log.WithFields(logger.Fields{
			"new_prefix": headerPrefix,
		}).Print("Updated `HeaderPrefix` because it was empty. Using default value.")
	}

	return headerPrefix
}

func (s *Server) pageTitle(title string) string {
	title = strings.TrimSpace(title)
	if title == "" {
		return s.Title
	}
	if s.Title == "" {
		return title
	}

	return fmt.Sprintf("%s | %s", title, s.Title)
}

func (s *Server) writeDefaultHeaders(w http.ResponseWriter) {
	h := w.Header()

	h.Set("referrer-policy", "no-referrer")
	h.Set("x-frame-options", "sameorigin")
	h.Set("x-robots-tag", "noindex, nofollow, noarchive, nosnippet, notranslate, noimageindex")
}

func (s *Server) render(tmpl *template.Template, w http.ResponseWriter, data interface{}) bool {
	l := s.logger()

	s.writeDefaultHeaders(w)

	var err error

	// FIXME: Minification is too roundabout.

	output := &bytes.Buffer{}

	err = tmpl.ExecuteTemplate(output, "layout", data)
	if err != nil {
		l.Print(err)

		return false
	}

	minifiedOutput := thirdparty.MustMinifyHTML(output.String())

	_, err = fmt.Fprint(w, minifiedOutput)
	if err != nil {
		l.Print(err)

		return false
	}

	return true
}

func (s *Server) handleError(w http.ResponseWriter, req *http.Request, err error) {
	var (
		ok         bool
		rfc7807Err *RFC7807
	)

	if rfc7807Err, ok = err.(*RFC7807); ok {
		statusCode := rfc7807Err.Status
		if statusCode == 0 {
			statusCode = http.StatusInternalServerError
		}

		if statusCode >= 500 && statusCode <= 599 && !s.VerboseHTTPServerErrors {
			genericError := &RFC7807{
				Status: http.StatusInternalServerError,
			}

			genericError.ServeHTTP(w, req)

			return
		}

		rfc7807Err.ServeHTTP(w, req)

		return
	}

	if s.VerboseHTTPServerErrors {
		rfc7807Err = ErrInternalServerError.Copy()
		rfc7807Err.Detail = err.Error()
	} else {
		rfc7807Err = ErrInternalServerError
	}

	rfc7807Err.ServeHTTP(w, req)
}

func (s *Server) Forward(w http.ResponseWriter, req *http.Request, session *Session) {
	log := s.logger()

	if s.BackendURL == "" {
		err := ErrBackendURLMissing

		log.WithFields(err.loggerFields()).Print(err.Error())

		s.handleError(w, req, err)

		return
	}

	// TODO: Make this `Forward` method private and acquire the lock in
	// `ServeHTTP`.

	s.Lock()
	headerPrefix := s.headerPrefix()
	s.Unlock()

	var (
		err error

		forwardURL *url.URL
	)

	forwardURL, err = url.Parse(s.BackendURL)
	if err != nil {
		wErr := ErrBackendURLInvalid.Copy()
		wErr.Detail = err.Error()

		s.handleError(w, req, wErr)

		return
	}

	if !strings.HasSuffix(forwardURL.Path, "/") {
		forwardURL.Path += "/"
	}

	if req.URL.Path != "/" {
		forwardURL.Path += req.URL.Path[1:]
	}

	forwardURL.RawQuery = req.URL.RawQuery

	var forwardRequest *http.Request

	forwardRequest, err = http.NewRequest(req.Method, forwardURL.String(), req.Body)
	if err != nil {
		wErr := ErrInternalServerError.Copy()
		wErr.Detail = err.Error()

		s.handleError(w, req, wErr)

		return
	}

	for k, values := range req.Header {
		if strings.HasPrefix(k, headerPrefix) {
			continue
		}

		for _, v := range values {
			forwardRequest.Header.Add(k, v)
		}
	}

	ci := session.Metadata
	if ci != nil {
		for rawKey, v := range ci {
			k := headerPrefix + rawKey
			forwardRequest.Header.Set(k, v)
		}
	}

	// TODO: This should probably be a struct field.
	httpClient := http.DefaultClient

	var resp *http.Response

	resp, err = httpClient.Do(forwardRequest)
	if err != nil {
		wErr := ErrBadGateway.Copy()
		wErr.Detail = err.Error()

		s.handleError(w, req, wErr)

		return
	}
	defer resp.Body.Close()

	wHeaders := w.Header()
	for header, values := range resp.Header {
		wHeaders.Del(header)
		for _, value := range values {
			wHeaders.Add(header, value)
		}
	}

	_, err = io.Copy(w, resp.Body)
	if err != nil {
		wErr := fmt.Errorf("could not write: %w", err)

		log.Print(wErr)

		return
	}

	return
}

func (s *Server) validateLoginPrefix(w http.ResponseWriter, req *http.Request) bool {
	prefix := s.LoginPathPrefix

	if prefix == "/" {
		err := ErrLoginPathPrefixIsRoot

		s.handleError(w, req, err)

		return false
	}

	if !strings.HasSuffix(prefix, "/") {
		err := ErrLoginPathPrefixMissingTrailingSlash

		s.handleError(w, req, err)

		return false
	}

	return true
}

func (s *Server) isLoginPagePath(p string) bool {
	// Has trailing `/`.
	prefix := s.LoginPathPrefix

	if p == prefix {
		return true
	}
	if strings.HasPrefix(p, prefix) {
		return true
	}

	return false
}

func (s *Server) isLoginPage(req *http.Request) bool {
	p := req.URL.Path

	return s.isLoginPagePath(p)
}

func (s *Server) redirectToLoginPage(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "")

	// `redirectAfterLogin` must be relative to "/".
	redirectAfterLogin := req.URL.Path
	if !strings.HasSuffix(redirectAfterLogin, "/") && s.isLoginPagePath(redirectAfterLogin+"/") {
		redirectAfterLogin = "/"
	}

	if req.URL.RawQuery != "" {
		redirectAfterLogin += "?" + req.URL.RawQuery
	}

	if redirectAfterLogin == "/" {
		loginPath := s.LoginPathPrefix

		http.Redirect(w, req, loginPath, http.StatusSeeOther)
	} else {
		q := url.Values{}
		q.Set(keyRedirectTo, redirectAfterLogin)

		loginPath := s.LoginPathPrefix + "?" + q.Encode()

		http.Redirect(w, req, loginPath, http.StatusSeeOther)
	}
}

func (s *Server) redirectAfterLogin(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "")

	q := req.URL.Query()

	redirectTo := q.Get(keyRedirectTo)
	if redirectTo == "" {
		redirectTo = "/"
	} else {
		// TODO: Ensure `redirectTo` is only the path component of a URL.
		//
		// Fully qualified URLs are not allowed.
	}

	http.Redirect(w, req, redirectTo, http.StatusSeeOther)
}

func (s *Server) cookieRemove(w http.ResponseWriter, cookieName string) {
	c := NewCookie(cookieName, "")
	c.Expires = time.Unix(0, 0)
	c.MaxAge = -1
	c.Secure = s.IsHTTPS

	http.SetCookie(w, c)
}

func (s *Server) cookieSet(w http.ResponseWriter, cookieName string, value string) {
	c := NewCookie(cookieName, value)

	c.Secure = s.IsHTTPS

	http.SetCookie(w, c)
}

func (s *Server) sessionCookieSet(w http.ResponseWriter, providerID ProviderID, sessionID SessionID) {
	providerCookieName := s.providerCookieName()
	sessionCookieName := s.sessionCookieName()

	s.cookieSet(w, providerCookieName, string(providerID))
	s.cookieSet(w, sessionCookieName, string(sessionID))
}

func (s *Server) handleCredentials(w http.ResponseWriter, req *http.Request) error {
	formErr := req.ParseForm()
	if formErr != nil {
		err := ErrRequestForm.Copy()
		err.Detail = formErr.Error()

		return err
	}

	formData := req.Form

	// TODO: Move string literal to struct field.
	providerIDStr := formData.Get("authwall_provider_id")

	provider, isValidProvider := s.providerByID(ProviderID(providerIDStr))
	if !isValidProvider {
		return ErrProviderInvalid
	}

	fieldValues := map[ProviderFieldID]ProviderFieldValue{}

	providerFields := provider.Fields()
	for _, pf := range providerFields {
		key := pf.ID
		valueStr := formData.Get(string(pf.ID))

		fieldValues[key] = ProviderFieldValue(valueStr)
	}

	sessionID, err := provider.SessionCreate(fieldValues)
	if err != nil {
		return err
	}

	providerID := provider.ID()

	s.sessionCookieSet(w, providerID, sessionID)

	return nil
}

func (s *Server) HandleLogin(w http.ResponseWriter, req *http.Request) {
	// TODO: Make this `HandleLogin` method private.

	if len(s.Providers) == 0 {
		err := ErrProviderNone

		s.handleError(w, req, err)

		return
	}

	if !s.isLoginPage(req) {
		if req.Method != http.MethodGet {
			err := ErrUnauthorized

			s.handleError(w, req, err)

			return
		}

		s.redirectToLoginPage(w, req)

		return
	}

	q := req.URL.Query()

	var selectedProvider Provider

	// TODO: Move string literal to struct field.
	selectedProviderIDStr := q.Get("provider_id")

	if selectedProviderIDStr == "" {
		selectedProvider = s.Providers[0]
	} else {
		provider, isValidProvider := s.providerByID(ProviderID(selectedProviderIDStr))
		if !isValidProvider {
			err := ErrProviderInvalid

			s.handleError(w, req, err)

			return
		}

		selectedProvider = provider
	}

	page := &PageLogin{
		Page: Page{
			Title: s.pageTitle("Login"),
		},
		Providers:        s.Providers,
		SelectedProvider: selectedProvider,
	}

	if req.Method == http.MethodGet {
		s.render(tmplLogin, w, page)

		return
	} else if req.Method == http.MethodPost {
		err := s.handleCredentials(w, req)
		if err != nil {
			if errors.Is(err, ErrCredentialsInvalid) {
				page.ErrorMessage = err.Error()
			} else {
				page.ErrorMessage = ErrInternalServerError.Error()
			}

			s.render(tmplLogin, w, page)

			return
		}

		s.redirectAfterLogin(w, req)

		return
	} else {
		page.ErrorMessage = ErrMethodNotAllowed.Title

		s.render(tmplLogin, w, page)

		return
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if !s.validateLoginPrefix(w, req) {
		return
	}

	session, err := s.Session(w, req)
	if err != nil {
		if err == ErrCookieInvalid {
			err = nil
			session = nil
		} else {
			wErr := fmt.Errorf("could not get session: %w", err)

			s.handleError(w, req, wErr)

			return
		}
	}

	if session == nil {
		s.HandleLogin(w, req)

		return
	}

	s.Forward(w, req, session)
}
