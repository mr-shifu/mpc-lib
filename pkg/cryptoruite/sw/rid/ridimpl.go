package rid

import (
	"github.com/mr-shifu/mpc-lib/lib/types"
)

type RID struct {
	secret types.RID
}

// Bytes returns the byte representation of the key.
func (r *RID) Bytes() ([]byte, error) {
	return r.secret, nil
}

// SKI returns the serialized key identifier.
func (r *RID) SKI() []byte {
	return nil
}

// Private returns true if the key is private.
func (r *RID) Private() bool {
	return true
}

// PublicKey returns the corresponding public key part of RID Key.
func (r *RID) PublicKey() RID {
	return RID{}
}

// Validate ensure that the RID is the correct length and is not identically 0.
func (r *RID) Validate() error {
	return r.secret.Validate()
}
