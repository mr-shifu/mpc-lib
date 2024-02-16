package pedersen

import "github.com/cronokirby/saferith"

type PedersenKey interface {
	// Bytes returns the byte representation of the key.
	Bytes() ([]byte, error)

	// SKI returns the serialized key identifier.
	SKI() []byte

	// Private returns true if the key is private.
	Private() bool

	// PublicKey returns the corresponding public key part of Pedersen Key.
	PublicKey() PedersenKey

	// Commit returns the commitment of the given value.
	Commit(x, y *saferith.Int) *saferith.Nat

	// Verify returns true if the given commitment is valid.
	Verify(a, b, e *saferith.Int, S, T *saferith.Nat) bool
}

type PedersenKeyManger interface {
	// GenerateKey generates a new Pedersen key pair.
	GenerateKey() (PedersenKey, error)

	// ImportKey imports a Pedersen key.
	ImportKey(key PedersenKey) error

	// GetKey returns a Pedersen key by its SKI.
	GetKey(ski []byte) (PedersenKey, error)

	// Commit returns the commitment of the given value.
	Commit(ski []byte, x, y *saferith.Int) *saferith.Nat

	// Verify returns true if the given commitment is valid.
	Verify(ski []byte, a, b, e *saferith.Int, S, T *saferith.Nat) bool
}
