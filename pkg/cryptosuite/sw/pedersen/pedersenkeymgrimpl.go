package pedersen

import (
	"encoding/hex"
	"errors"

	"github.com/cronokirby/saferith"
	"github.com/mr-shifu/mpc-lib/pkg/common/keystore"
	cs_pedersen "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/pedersen"
)

type PedersenKeyManager struct {
	ks keystore.Keystore
}

func NewPedersenKeymanager(ks keystore.Keystore) *PedersenKeyManager {
	return &PedersenKeyManager{
		ks: ks,
	}
}

// GenerateKey generates a new Pedersen key pair.
func (mgr *PedersenKeyManager) GenerateKey() (cs_pedersen.PedersenKey, error) {
	return nil, errors.New("not implemented")
}

// ImportKey imports a Pedersen key.
func (mgr *PedersenKeyManager) ImportKey(key cs_pedersen.PedersenKey) error {
	// encode key to binary
	kb, err := key.Bytes()
	if err != nil {
		return err
	}

	// get key SKI and hex encode it to string as keyID
	ski := key.SKI()
	keyID := hex.EncodeToString(ski)

	// store key to keystore
	return mgr.ks.Import(keyID, kb)
}

// GetKey returns a Pedersen key by its SKI.
func (mgr *PedersenKeyManager) GetKey(ski []byte) (cs_pedersen.PedersenKey, error) {
	// retreive key from keystore
	kb, err := mgr.ks.Get(hex.EncodeToString(ski))
	if err != nil {
		return PedersenKey{}, err
	}

	// decode key from binary
	return fromBytes(kb)
}

// Commit returns the commitment of the given value.
func (mgr *PedersenKeyManager) Commit(ski []byte, x, y *saferith.Int) *saferith.Nat {
	key, err := mgr.GetKey(ski)
	if err != nil {
		return nil
	}
	return key.Commit(x, y)
}

// Verify returns true if the given commitment is valid.
func (mgr *PedersenKeyManager) Verify(ski []byte, a, b, e *saferith.Int, S, T *saferith.Nat) bool {
	key, err := mgr.GetKey(ski)
	if err != nil {
		return false
	}
	return key.Verify(a, b, e, S, T)
}
