package pedersen

import (
	"encoding/hex"
	"errors"

	"github.com/cronokirby/saferith"
	"github.com/mr-shifu/mpc-lib/core/pedersen"
	"github.com/mr-shifu/mpc-lib/pkg/common/keystore"
	"github.com/mr-shifu/mpc-lib/pkg/common/keyopts"
)

type PedersenKeyManagerImpl struct {
	ks keystore.Keystore
}

var _ PedersenKeyManager = (*PedersenKeyManagerImpl)(nil)

func NewPedersenKeymanager(ks keystore.Keystore) *PedersenKeyManagerImpl {
	return &PedersenKeyManagerImpl{
		ks: ks,
	}
}

// GenerateKey generates a new Pedersen key pair.
func (mgr *PedersenKeyManagerImpl) GenerateKey(opts keyopts.Options) (PedersenKey, error) {
	return nil, errors.New("not implemented")
}

// ImportKey imports a Pedersen key.
func (mgr *PedersenKeyManagerImpl) ImportKey(raw interface{}, opts keyopts.Options) (PedersenKey, error) {
	var err error
	key := &PedersenKeyImpl{}

	switch raw := raw.(type) {
	case []byte:
		key, err = fromBytes(raw)
		if err != nil {
			return nil, err
		}
	case *PedersenKeyImpl:
		key = raw
	}

	if key.public.N() == nil || key.public.S() == nil || key.public.T() == nil {
		return nil, errors.New("empty parameters in Pedersen key")
	}
	if err := pedersen.ValidateParameters(key.public.N(), key.public.S(), key.public.T()); err != nil {
		return nil, errors.New("invalid Pedersen key")
	}

	// encode key to binary
	kb, err := key.Bytes()
	if err != nil {
		return nil, err
	}

	// get key SKI and hex encode it to string as keyID
	ski := key.SKI()
	keyID := hex.EncodeToString(ski)

	// store key to keystore
	if err := mgr.ks.Import(keyID, kb, opts); err != nil {
		return nil, err
	}

	return key, nil
}

// GetKey returns a Pedersen key by its SKI.
func (mgr *PedersenKeyManagerImpl) GetKey(opts keyopts.Options) (PedersenKey, error) {
	// retreive key from keystore
	kb, err := mgr.ks.Get(opts)
	if err != nil {
		return nil, err
	}

	// decode key from binary
	return fromBytes(kb)
}

// Commit returns the commitment of the given value.
func (mgr *PedersenKeyManagerImpl) Commit(x, y *saferith.Int, opts keyopts.Options) *saferith.Nat {
	key, err := mgr.GetKey(opts)
	if err != nil {
		return nil
	}
	return key.Commit(x, y)
}

// Verify returns true if the given commitment is valid.
func (mgr *PedersenKeyManagerImpl) Verify(a, b, e *saferith.Int, S, T *saferith.Nat, opts keyopts.Options) bool {
	key, err := mgr.GetKey(opts)
	if err != nil {
		return false
	}
	return key.Verify(a, b, e, S, T)
}
