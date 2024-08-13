package pedersen

import (
	"github.com/cronokirby/saferith"
	pedersencore "github.com/mr-shifu/mpc-lib/core/pedersen"
	"github.com/mr-shifu/mpc-lib/core/pool"
	zkprm "github.com/mr-shifu/mpc-lib/core/zk/prm"
	"github.com/mr-shifu/mpc-lib/pkg/common/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/hash"
)

type PedersenKey interface {
	// Bytes returns the byte representation of the key.
	Bytes() ([]byte, error)

	// SKI returns the serialized key identifier.
	SKI() []byte

	// Private returns true if the key is private.
	Private() bool

	// PublicKey returns the corresponding public key part of Pedersen Key.
	PublicKey() PedersenKey

	// PublicKeyRaw returns the corresponding public key part of Pedersen Key.
	PublicKeyRaw() *pedersencore.Parameters

	// Commit returns the commitment of the given value.
	Commit(x, y *saferith.Int) *saferith.Nat

	// Verify returns true if the given commitment is valid.
	Verify(a, b, e *saferith.Int, S, T *saferith.Nat) bool

	// NewProof returns Proof for Pedersen params s, t, lambd.
	NewProof(hash hash.Hash, pl *pool.Pool) *zkprm.Proof

	// VerifyProof returns true if the given proof is valid.
	VerifyProof(hash hash.Hash, pl *pool.Pool, p *zkprm.Proof) bool
}

type PedersenKeyManager interface {
	// GenerateKey generates a new Pedersen key pair.
	GenerateKey(opts keyopts.Options) (PedersenKey, error)

	// ImportKey imports a Pedersen key.
	ImportKey(key interface{}, opts keyopts.Options) (PedersenKey, error)

	// GetKey returns a Pedersen key by its SKI.
	GetKey(opts keyopts.Options) (PedersenKey, error)

	// Commit returns the commitment of the given value.
	Commit(x, y *saferith.Int, opts keyopts.Options) *saferith.Nat

	// Verify returns true if the given commitment is valid.
	Verify(a, b, e *saferith.Int, S, T *saferith.Nat, opts keyopts.Options) bool
}
