package keyopts

type KeyData struct {
	PartyID string
	SKI     string
}

type Options interface {
	Set(kVs ...interface{}) (Options, error)
	Get(key string) (interface{}, bool)
}

// KeyOpts manages the storage of key metadata referred to by an ID (MPC KeyID).
type KeyOpts interface {
	// Import imports a key into the repository.
	// ID is the MPC KeyID and key is the key metadata (ex. SKI, PartyID).
	Import(data interface{}, opts Options) error

	// Get returns the key metadata by related to MPC Key ID.
	Get(opts Options) (*KeyData, error)

	// Get returns the all keys' metadata by related to MPC Key ID.
	GetAll(opts Options) (map[string]*KeyData, error)

	// Delete deletes all keys' metadata by related to MPC Key ID.
	DeleteAll(opts Options) error

	Delete(opts Options) error
}
