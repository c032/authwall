package authwall

import (
	"encoding/json"
	"net/http"
	"sync"

	"github.com/c032/go-logger"
)

// RFC7807 is a basic struct containing the fields defined by RFC 7807
// ("Problem Details for HTTP APIs").
type RFC7807 struct {
	Type     string `json:"type,omitempty"`
	Title    string `json:"title,omitempty"`
	Status   int    `json:"status,omitempty"`
	Detail   string `json:"detail,omitempty"`
	Instance string `json:"instance,omitempty"`

	mu     sync.RWMutex  `json:"-"`
	logger logger.Logger `json:"-"`
}

func (e *RFC7807) loggerFields() logger.Fields {
	return logger.Fields{
		"type":     e.Type,
		"title":    e.Title,
		"status":   e.Status,
		"detail":   e.Detail,
		"instance": e.Instance,
	}
}

func (e *RFC7807) Copy() *RFC7807 {
	c := &RFC7807{
		Type:     e.Type,
		Title:    e.Title,
		Status:   e.Status,
		Detail:   e.Detail,
		Instance: e.Instance,

		logger: e.logger,
	}

	return c
}

func (e *RFC7807) Error() string {
	return e.Title
}

func (e *RFC7807) SetLogger(l logger.Logger) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.logger = l
}

func (e *RFC7807) Logger() logger.Logger {
	e.mu.RLock()
	defer e.mu.RUnlock()

	log := e.logger
	if log == nil {
		return logger.Discard
	}

	return log
}

func (e *RFC7807) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	statusCode := e.Status
	if statusCode == 0 {
		statusCode = http.StatusInternalServerError
	}

	h := w.Header()
	h.Set("Content-Type", "application/problem+json; charset=UTF-8")
	h.Set("Content-Language", "en")

	w.WriteHeader(statusCode)

	enc := json.NewEncoder(w)

	err := enc.Encode(e)
	if err != nil {
		log := e.Logger()
		log.Print(err)
	}
}
