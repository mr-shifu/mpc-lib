package rid

import (
	"crypto/rand"
	"encoding/hex"
	"errors"

	"github.com/google/uuid"
	"github.com/mr-shifu/mpc-lib/lib/types"
	"github.com/mr-shifu/mpc-lib/pkg/common/keystore"
)

type RIDManager struct {
	ks keystore.Keystore
}

func NewRIDManager(ks keystore.Keystore) *RIDManager {
	return &RIDManager{ks}
}

// GenerateKey generates a new RID key pair.
func (mgr *RIDManager) GenerateKey() (*RID, error) {
	r, err := types.NewRID(rand.Reader)
	if err != nil {
		return nil, err
	}
	rid := &RID{r}

	// TODO verify the keyID is unique and secure
	keyID := uuid.New().String()
	if err := mgr.ks.Import(keyID, rid.secret); err != nil {
		return nil, err
	}
	return rid, nil
}

// Import imports a RID key from its byte representation.
func (mgr *RIDManager) ImportKey(data []byte) (*RID, error) {
	rid := &RID{data}
	ski := rid.SKI()
	if ski == nil {
		return nil, errors.New("failed to generate SKI")
	}
	keyID := hex.EncodeToString(ski)
	if err := mgr.ks.Import(keyID, rid.secret); err != nil {
		return nil, err
	}
	return rid, nil
}

// GetKey returns a RID key by its SKI.
func (mgr *RIDManager) GetKey(keyID string) (*RID, error) {
	r, err := mgr.ks.Get(keyID)
	if err != nil {
		return nil, err
	}
	return &RID{r}, nil
}

// modifies the receiver by taking the XOR with the argument.
func (mgr *RIDManager) XOR(keyID string, message []byte) (*RID, error) {
	rid, err := mgr.GetKey(keyID)
	if err != nil {
		return nil, err
	}
	rid.secret.XOR(message)
	mgr.ks.Import(keyID, rid.secret)
	return rid, nil
}

// Validate ensure that the RID is the correct length and is not identically 0.
func (mgr *RIDManager) Validate(keyID string) error {
	rid, err := mgr.GetKey(keyID)
	if err != nil {
		return err
	}
	return rid.Validate()
}
