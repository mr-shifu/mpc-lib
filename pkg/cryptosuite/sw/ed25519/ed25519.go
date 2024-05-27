package ed25519

type Ed25519 interface {
	// Bytes returns the byte representation of the key.
	Bytes() ([]byte, error)

	// SKI returns the serialized key identifier.
	SKI() []byte

	// Private returns true if the key is private.
	Private() bool

	// PublicKey returns the corresponding public key part of ECDSA Key.
	PublicKey() Ed25519

	// FromBytes creates a new Ed25519 key from a byte representation.
	FromBytes(data []byte) error
}
