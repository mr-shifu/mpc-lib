package rid

import (
	"github.com/mr-shifu/mpc-lib/lib/types"
)

type RIDImpl struct {
	secret types.RID
	// keyID  string
}

// Bytes returns the byte representation of the key.
func (r *RIDImpl) Bytes() ([]byte, error) {
	return r.secret, nil
}

// SKI returns the serialized key identifier.
func (r *RIDImpl) SKI() []byte {
	return nil
}

// Private returns true if the key is private.
func (r *RIDImpl) Private() bool {
	return true
}

// PublicKey returns the corresponding public key part of RID Key.
func (r *RIDImpl) PublicKey() RID {
	return nil
}

// Raw returns the byte representation of the key.
func (r *RIDImpl) Raw() []byte {
	return r.secret
}

// Validate ensure that the RID is the correct length and is not identically 0.
func (r *RIDImpl) Validate() error {
	return r.secret.Validate()
}
