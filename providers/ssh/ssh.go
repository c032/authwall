// Package ssh implements authentication with SSH.
package ssh

import (
	"fmt"
	"sync"

	"github.com/c032/authwall"

	"github.com/c032/go-logger"
	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
)

var _ authwall.Provider = (*Provider)(nil)

const (
	ProviderID   = authwall.ProviderID("ssh")
	ProviderName = "SSH"
)

var (
	fieldIDUser     = authwall.ProviderFieldID("user")
	fieldIDPassword = authwall.ProviderFieldID("password")
)

var providerFields = []authwall.ProviderField{
	{
		ID:         fieldIDUser,
		Name:       "User",
		IsRequired: true,
	},
	{
		ID:         fieldIDPassword,
		Name:       "Password",
		IsRequired: true,
		IsSecret:   true,
	},
}

type Provider struct {
	Logger logger.Logger

	Host            string
	HostKeyCallback ssh.HostKeyCallback

	mu       sync.RWMutex
	sessions map[authwall.SessionID]authwall.SessionMetadata
}

func (p *Provider) logger() logger.Logger {
	log := p.Logger

	if log == nil {
		return logger.Discard
	}

	return log
}

func (p *Provider) ID() authwall.ProviderID {
	return ProviderID
}

func (p *Provider) Name() string {
	return ProviderName
}

func (p *Provider) Fields() []authwall.ProviderField {
	return providerFields
}

func (p *Provider) SessionIsValid(id authwall.SessionID) (bool, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	log := p.logger()

	log.WithFields(logger.Fields{
		"id": id.String(),
	}).Print("Checking whether session is valid.")

	if p.sessions == nil {
		log.Print("`sessions` is not initialized.")

		return false, nil
	}

	_, ok := p.sessions[id]
	if !ok {
		log.WithFields(logger.Fields{
			"id": id.String(),
		}).Print("Session not found.")

		return false, nil
	}

	log.WithFields(logger.Fields{
		"id": id.String(),
	}).Print("Session found.")

	return true, nil
}

func (p *Provider) SessionMetadata(id authwall.SessionID) (authwall.SessionMetadata, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.sessions == nil {
		return nil, authwall.ErrSessionInvalid
	}

	sessionMetadata, ok := p.sessions[id]
	if !ok {
		return nil, authwall.ErrSessionInvalid
	}

	return sessionMetadata, nil
}

func (p *Provider) SessionCreate(fields map[authwall.ProviderFieldID]authwall.ProviderFieldValue) (authwall.SessionID, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	log := p.logger()

	var (
		ok bool

		user     authwall.ProviderFieldValue
		password authwall.ProviderFieldValue
	)

	log.WithFields(logger.Fields{
		"field": string(fieldIDUser),
	}).Print("Reading user from form.")

	user, ok = fields[fieldIDUser]
	if !ok {
		return authwall.SessionID(""), authwall.ErrCredentialsInvalid
	}

	log.WithFields(logger.Fields{
		"field": string(fieldIDPassword),
	}).Print("Reading password from form.")

	password, ok = fields[fieldIDPassword]
	if !ok {
		return authwall.SessionID(""), authwall.ErrCredentialsInvalid
	}

	config := &ssh.ClientConfig{
		User: string(user),
		Auth: []ssh.AuthMethod{
			ssh.Password(string(password)),
		},
		HostKeyCallback: p.HostKeyCallback,
	}

	client, err := ssh.Dial("tcp", p.Host, config)
	if err != nil {
		wErr := fmt.Errorf("could not connect: %w", err)

		log.Print(wErr.Error())

		return authwall.SessionID(""), authwall.ErrCredentialsInvalid
	}
	defer client.Close()

	sessionID := p.generateSessionID()
	sessionMetadata := authwall.SessionMetadata{
		"user": string(user),
	}

	if p.sessions == nil {
		p.sessions = map[authwall.SessionID]authwall.SessionMetadata{}
	}

	p.sessions[sessionID] = sessionMetadata

	log.WithFields(logger.Fields{
		"session_id":       sessionID.String(),
		"session_metadata": sessionMetadata,
	}).Print("Created session.")

	return sessionID, nil
}

func (p *Provider) generateSessionID() authwall.SessionID {
	return authwall.SessionID(uuid.New().String())
}
