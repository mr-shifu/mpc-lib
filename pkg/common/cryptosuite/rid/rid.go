package rid

type RID interface {
	// Bytes returns the byte representation of the key.
	Bytes() ([]byte, error)

	// SKI returns the serialized key identifier.
	SKI() []byte

	// Private returns true if the key is private.
	Private() bool

	// PublicKey returns the corresponding public key part of RID Key.
	PublicKey() RID

	// Validate ensure that the RID is the correct length and is not identically 0.
	Validate() error
}

type RIDManager interface {
	// GenerateKey generates a new RID key pair.
	GenerateKey() (RID, error)

	// Import imports a RID key from its byte representation.
	ImportKey(data []byte) (RID, error)

	// GetKey returns a RID key by its SKI.
	GetKey(keyID string) (RID, error)

	// modifies the receiver by taking the XOR with the argument.
	XOR(keyID string, message []byte) ([]byte, error)

	// Validate ensure that the RID is the correct length and is not identically 0.
	Validate(keyID string) error
}
