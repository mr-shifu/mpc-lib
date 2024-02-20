package keyrepository

// KeyRepository manages the storage of key metadata referred to by an ID (MPC KeyID).
type KeyRepository interface {
	// Import imports a key into the repository. 
	// ID is the MPC KeyID and key is the key metadata (ex. SKI, PartyID).
	Import(ID string, key interface{}) error

	// Get returns the all keys' metadata by related to MPC Key ID.
	GetAll(ID string) (map[string]interface{}, error)

	// Delete deletes all keys' metadata by related to MPC Key ID.
	DeleteAll(ID string) error
}