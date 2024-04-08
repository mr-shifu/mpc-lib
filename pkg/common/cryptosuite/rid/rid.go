package rid

import "github.com/mr-shifu/mpc-lib/pkg/common/keyopts"

type RID interface {
	// Bytes returns the byte representation of the key.
	Bytes() ([]byte, error)

	// SKI returns the serialized key identifier.
	SKI() []byte

	// Private returns true if the key is private.
	Private() bool

	// PublicKey returns the corresponding public key part of RID Key.
	PublicKey() RID

	// Raw returns the byte representation of the key.
	Raw() []byte

	// Validate ensure that the RID is the correct length and is not identically 0.
	Validate() error
}

type RIDManager interface {
	// GenerateKey generates a new RID key pair.
	GenerateKey(opts keyopts.Options) (RID, error)

	// Import imports a RID key from its byte representation.
	ImportKey(data []byte, opts keyopts.Options) (RID, error)

	// GetKey returns a RID key by its SKI.
	GetKey(opts keyopts.Options) (RID, error)

	// modifies the receiver by taking the XOR with the argument.
	XOR(message []byte, opts keyopts.Options) (RID, error)

	// Validate ensure that the RID is the correct length and is not identically 0.
	Validate(opts keyopts.Options) error
}
