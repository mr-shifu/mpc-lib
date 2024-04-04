package rid

import (
	"github.com/mr-shifu/mpc-lib/lib/types"
	cs_rid "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/rid"
)

type RID struct {
	secret types.RID
	// keyID  string
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
func (r *RID) PublicKey() cs_rid.RID {
	return nil
}

// Raw returns the byte representation of the key.
func (r *RID) Raw() []byte {
	return r.secret
}

// Validate ensure that the RID is the correct length and is not identically 0.
func (r *RID) Validate() error {
	return r.secret.Validate()
}
