package paillierencodedkey

import (
	"github.com/google/uuid"
	pek "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/paillierencodedkey"
	"github.com/mr-shifu/mpc-lib/pkg/common/keystore"
	"github.com/mr-shifu/mpc-lib/pkg/common/keyopts"
)

type PaillierEncodedKeyManager struct {
	store keystore.Keystore
}

func NewPaillierEncodedKeyManager(store keystore.Keystore) *PaillierEncodedKeyManager {
	return &PaillierEncodedKeyManager{
		store: store,
	}
}

func (k *PaillierEncodedKeyManager) Get(opts keyopts.Options) (pek.PaillierEncodedKey, error) {
	b, err := k.store.Get(opts)
	if err != nil {
		return nil, err
	}
	return fromBytes(b)
}

func (k *PaillierEncodedKeyManager) Import(raw interface{}, opts keyopts.Options) (pek.PaillierEncodedKey, error) {
	var err error
	var key PaillierEncodedKey

	switch raw := raw.(type) {
	case []byte:
		key, err = fromBytes(raw)
		if err != nil {
			return PaillierEncodedKey{}, err
		}
	case PaillierEncodedKey:
		key = raw
	case *PaillierEncodedKey:
		key = *raw
	}

	b, err := key.Bytes()
	if err != nil {
		return nil, err
	}

	// get key SKI and encode it to hex string as keyID
	// ski := key.SKI()
	// keyID := hex.EncodeToString(ski)
	keyID := uuid.New().String()

	err = k.store.Import(keyID, b, opts)
	if err != nil {
		return nil, err
	}
	return key, nil
}