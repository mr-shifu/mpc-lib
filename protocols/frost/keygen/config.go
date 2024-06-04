package keygen

import (
	"filippo.io/edwards25519"
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/party"
)

// Config contains all the information produced after key generation, from the perspective
// of a single participant.
//
// When unmarshalling, EmptyResult needs to be called to set the group, before
// calling cbor.Unmarshal, or equivalent methods.
type Config struct {
	// ID is the identifier for this participant.
	ID party.ID
	// Threshold is the number of accepted corruptions while still being able to sign.
	Threshold int
	// PublicKey is the shared public key for this consortium of signers.
	//
	// This key can be used to verify signatures produced by the consortium.
	PublicKey *edwards25519.Point
}

// EmptyConfig creates an empty Result with a specific group.
//
// This needs to be called before unmarshalling, instead of just using new(Result).
// This is to allow points and scalars to be correctly unmarshalled.
func EmptyConfig() *Config {
	return &Config{
		PublicKey: new(edwards25519.Point),
	}
}

// Curve returns the Elliptic Curve Group associated with this result.
func (r *Config) Curve() curve.Curve {
	return nil
}
