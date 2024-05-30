package ed25519

import (
	"encoding/hex"

	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/hash"
	"github.com/mr-shifu/mpc-lib/pkg/common/keystore"
	vssed25519 "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/vss-ed25519"
	"github.com/mr-shifu/mpc-lib/pkg/keyopts"
	"github.com/pkg/errors"
)

type Ed25519KeyManagerImpl struct {
	keystore keystore.Keystore
	schstore keystore.Keystore
	vssmgr   vssed25519.VssKeyManager
}

func NewEd25519KeyManagerImpl(store, schstore keystore.Keystore, vssmgr vssed25519.VssKeyManager) *Ed25519KeyManagerImpl {
	return &Ed25519KeyManagerImpl{
		keystore: store,
		schstore: schstore,
		vssmgr:   vssmgr,
	}
}

// GenerateKey generates a new Ed25519 key pair.
func (mgr *Ed25519KeyManagerImpl) GenerateKey(opts keyopts.Options) (Ed25519, error) {
	k, err := GenerateKey()
	if err != nil {
		return nil, errors.WithMessage(err, "ed25519: failed to generate key")
	}

	kb, err := k.Bytes()
	if err != nil {
		return nil, errors.WithMessage(err, "ed25519: failed to serialize key")
	}

	keyID := hex.EncodeToString(k.SKI())

	if err := mgr.keystore.Import(keyID, kb, opts); err != nil {
		return nil, errors.WithMessage(err, "ed25519: failed to import key to keystore")
	}

	return k, nil
}

// Import imports a Ed25519 key from its byte representation.
func (mgr *Ed25519KeyManagerImpl) ImportKey(raw interface{}, opts keyopts.Options) (Ed25519, error) {
	k := new(Ed25519Impl)
	switch tt := raw.(type) {
	case []byte:
		if err := k.FromBytes(tt); err != nil {
			return nil, errors.WithMessage(err, "ed25519: failed to import key")
		}
	case Ed25519:
		k = tt.(*Ed25519Impl)
	default:
		return nil, errors.New("ed25519: invalid key type")
	}

	kb, err := k.Bytes()
	if err != nil {
		return nil, errors.WithMessage(err, "ed25519: failed to serialize key")
	}

	keyID := hex.EncodeToString(k.SKI())

	if err := mgr.keystore.Import(keyID, kb, opts); err != nil {
		return nil, errors.WithMessage(err, "ed25519: failed to import key to keystore")
	}

	return k, nil
}

// GetKey returns a Ed25519 key by its SKI.
func (mgr *Ed25519KeyManagerImpl) GetKey(opts keyopts.Options) (Ed25519, error) {
	kb, err := mgr.keystore.Get(opts)
	if err != nil {
		return nil, errors.WithMessage(err, "ed25519: failed to get key from keystore")
	}

	k := new(Ed25519Impl)
	if err := k.FromBytes(kb); err != nil {
		return nil, errors.WithMessage(err, "ed25519: failed to import key")
	}

	return k, nil
}

func (mgr *Ed25519KeyManagerImpl) NewSchnorrProof(h hash.Hash, opts keyopts.Options) (*Proof, error) {
	k, err := mgr.GetKey(opts)
	if err != nil {
		return nil, errors.WithMessage(err, "ed25519: failed to get key from keystore")
	}

	p, err := k.NewScnorrProof(h)
	if err != nil {
		return nil, errors.WithMessage(err, "ed25519: failed to create schnorr proof")
	}

	ski := hex.EncodeToString(k.SKI())

	pb := p.bytes()
	if err := mgr.schstore.Import(ski, pb, opts); err != nil {
		return nil, errors.WithMessage(err, "ed25519: failed to import schnorr proof to keystore")
	}

	return p, nil
}

func (mgr *Ed25519KeyManagerImpl) ImportSchnorrProof(pb []byte, opts keyopts.Options) error {
	k, err := mgr.GetKey(opts)
	if err != nil {
		return errors.WithMessage(err, "ed25519: failed to get key from keystore")
	}

	ski := hex.EncodeToString(k.SKI())

	if err := mgr.schstore.Import(ski, pb, opts); err != nil {
		return errors.WithMessage(err, "ed25519: failed to import schnorr proof to keystore")
	}

	return nil
}

func (mgr *Ed25519KeyManagerImpl) VerifySchnorrProof(h hash.Hash, opts keyopts.Options) (bool, error) {
	k, err := mgr.GetKey(opts)
	if err != nil {
		return false, errors.WithMessage(err, "ed25519: failed to get key from keystore")
	}

	pb, err := mgr.schstore.Get(opts)
	if err != nil {
		return false, errors.WithMessage(err, "ed25519: failed to get schnorr proof from keystore")
	}

	p := new(Proof)
	if err := p.fromBytes(pb); err != nil {
		return false, errors.WithMessage(err, "ed25519: failed to import schnorr proof")
	}

	return k.VerifySchnorrProof(h, p)
}
