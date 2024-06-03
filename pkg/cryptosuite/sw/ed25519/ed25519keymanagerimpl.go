package ed25519

import (
	"encoding/hex"

	ed "filippo.io/edwards25519"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/hash"
	"github.com/mr-shifu/mpc-lib/pkg/common/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/common/keystore"
	vssed25519 "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/vss-ed25519"
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
		key, ok := tt.(*Ed25519Impl)
		if !ok {
			return nil, errors.New("ed25519: invalid key type")
		}
		k = key
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

func (mgr *Ed25519KeyManagerImpl) SumKeys(optsList ...keyopts.Options) (Ed25519, error) {
	s := ed.NewScalar()
	a := new(ed.Point)

	for i := 0; i < len(optsList); i++ {
		opts := optsList[i]
		k, err := mgr.GetKey(opts)
		if err != nil {
			return nil, errors.WithMessage(err, "ed25519: failed to get key from keystore")
		}

		key, ok := k.(*Ed25519Impl)
		if !ok {
			return nil, errors.New("ed25519: invalid key type")
		}

		if i == 0 {
			s = key.s
			a = key.a
			continue
		}

		s.Add(s, key.s)
		a.Add(a, key.a)
	}

	return NewKey(s, a)
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

func (mgr *Ed25519KeyManagerImpl) GenerateVss(degree int, opts keyopts.Options) (vssed25519.VssKey, error) {
	k, err := mgr.GetKey(opts)
	if err != nil {
		return nil, errors.WithMessage(err, "ed25519: failed to get key from keystore")
	}

	key, ok := k.(*Ed25519Impl)
	if !ok {
		return nil, errors.New("ed25519: invalid key type")
	}
	vss, err := mgr.vssmgr.GenerateSecrets(key.s, degree, opts)
	if err != nil {
		return nil, errors.WithMessage(err, "ed25519: failed to generate vss secrets")
	}

	return vss, nil
}

func (mgr *Ed25519KeyManagerImpl) ImportVss(key interface{}, opts keyopts.Options) error {
	_, err := mgr.GetKey(opts)
	if err != nil {
		return errors.WithMessage(err, "ed25519: failed to get key from keystore")
	}

	switch kt := key.(type) {
	case []byte:
		if _, err := mgr.vssmgr.ImportSecrets(kt, opts); err != nil {
			return errors.WithMessage(err, "ed25519: failed to import vss secrets")
		}
	case vssed25519.VssKey:
		kb, err := kt.Bytes()
		if err != nil {
			return errors.WithMessage(err, "ed25519: failed to serialize vss key")
		}

		if _, err := mgr.vssmgr.ImportSecrets(kb, opts); err != nil {
			return errors.WithMessage(err, "ed25519: failed to import vss secrets")
		}
	default:
		return errors.New("ed25519: invalid key type")
	}

	return nil
}

func (mgr *Ed25519KeyManagerImpl) GetVss(opts keyopts.Options) (vssed25519.VssKey, error) {
	_, err := mgr.GetKey(opts)
	if err != nil {
		return nil, errors.WithMessage(err, "ed25519: failed to get key from keystore")
	}

	vss, err := mgr.vssmgr.GetSecrets(opts)
	if err != nil {
		return nil, errors.WithMessage(err, "ed25519: failed to get vss secrets")
	}

	return vss, nil
}
