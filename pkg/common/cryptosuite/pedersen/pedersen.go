package pedersen

import (
	"github.com/cronokirby/saferith"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/hash"
	pedersencore "github.com/mr-shifu/mpc-lib/core/pedersen"
	"github.com/mr-shifu/mpc-lib/core/pool"
	zkprm "github.com/mr-shifu/mpc-lib/core/zk/prm"
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
	GenerateKey() (PedersenKey, error)

	// ImportKey imports a Pedersen key.
	ImportKey(data []byte) (PedersenKey, error)

	// GetKey returns a Pedersen key by its SKI.
	GetKey(ski []byte) (PedersenKey, error)

	// Commit returns the commitment of the given value.
	Commit(ski []byte, x, y *saferith.Int) *saferith.Nat

	// Verify returns true if the given commitment is valid.
	Verify(ski []byte, a, b, e *saferith.Int, S, T *saferith.Nat) bool
}
