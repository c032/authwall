package authwall

type (
	ProviderID string

	ProviderFieldID    string
	ProviderFieldValue string
)

type Provider interface {
	ID() ProviderID
	Name() string
	Fields() []ProviderField

	SessionIsValid(id SessionID) (bool, error)
	SessionMetadata(id SessionID) (SessionMetadata, error)
	SessionCreate(fields map[ProviderFieldID]ProviderFieldValue) (SessionID, error)
}

type ProviderField struct {
	ID          ProviderFieldID
	Name        string
	Description string
	IsRequired  bool
	IsSecret    bool
}
