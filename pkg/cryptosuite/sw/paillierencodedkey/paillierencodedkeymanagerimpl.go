package paillierencodedkey

import (
	"github.com/google/uuid"
	"github.com/mr-shifu/mpc-lib/pkg/common/keystore"
	"github.com/mr-shifu/mpc-lib/pkg/common/keyopts"
)

type PaillierEncodedKeyManagerImpl struct {
	store keystore.Keystore
}

var _ PaillierEncodedKeyManager = (*PaillierEncodedKeyManagerImpl)(nil)

func NewPaillierEncodedKeyManager(store keystore.Keystore) *PaillierEncodedKeyManagerImpl {
	return &PaillierEncodedKeyManagerImpl{
		store: store,
	}
}

func (k *PaillierEncodedKeyManagerImpl) Get(opts keyopts.Options) (PaillierEncodedKey, error) {
	b, err := k.store.Get(opts)
	if err != nil {
		return nil, err
	}
	return fromBytes(b)
}

func (k *PaillierEncodedKeyManagerImpl) Import(raw interface{}, opts keyopts.Options) (PaillierEncodedKey, error) {
	var err error
	key := &PaillierEncodedKeyImpl{}

	switch raw := raw.(type) {
	case []byte:
		key, err = fromBytes(raw)
		if err != nil {
			return nil, err
		}
	case PaillierEncodedKeyImpl:
		key = &raw
	case *PaillierEncodedKeyImpl:
		key = raw
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