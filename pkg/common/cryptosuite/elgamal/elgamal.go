package elgamal

import "github.com/mr-shifu/mpc-lib/core/math/curve"

type ElgamalKey interface {
	// Bytes returns the byte representation of the key.
	Bytes() ([]byte, error)

	// SKI returns the serialized key identifier.
	SKI() []byte

	// Private returns true if the key is private.
	Private() bool

	// PublicKey returns the corresponding public key part of Elgamal Key.
	PublicKey() ElgamalKey

	// Encrypt returns the encryption of `message` as ciphertext and nonce.
	Encrypt(message curve.Scalar) ([]byte, curve.Scalar, error)
}

type ElgamalKeyManger interface {
	// GenerateKey generates a new Elgamal key pair.
	GenerateKey() (ElgamalKey, error)

	// Import imports a Elgamal key from its byte representation.
	ImportKey(data []byte) (ElgamalKey, error)

	// GetKey returns a Elgamal key by its SKI.
	GetKey(ski []byte) (ElgamalKey, error)

	// Encrypt returns the encryption of `message` as ciphertext and nonce.
	Encrypt(ski []byte, message curve.Scalar) ([]byte, curve.Scalar, error)
}
