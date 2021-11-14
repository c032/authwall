package authwall

type SessionID string

func (id SessionID) String() string {
	return string(id)
}

type SessionMetadata map[string]string

type Session struct {
	ID         SessionID
	ProviderID ProviderID
	Metadata   SessionMetadata
}
