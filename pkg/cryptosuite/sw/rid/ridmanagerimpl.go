package rid

import (
	"crypto/rand"
	"errors"

	"github.com/google/uuid"
	"github.com/mr-shifu/mpc-lib/lib/types"
	cs_rid "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/rid"
	"github.com/mr-shifu/mpc-lib/pkg/common/keystore"
)

type RIDManager struct {
	ks keystore.Keystore
}

func NewRIDManager(ks keystore.Keystore) *RIDManager {
	return &RIDManager{ks}
}

// GenerateKey generates a new RID key pair.
func (mgr *RIDManager) GenerateKey() (cs_rid.RID, error) {
	r, err := types.NewRID(rand.Reader)
	if err != nil {
		return nil, err
	}

	// generate a unique keyID to be used as SKI
	keyID := uuid.New().String()

	rid := &RID{r, keyID}
	// TODO verify the keyID is unique and secure
	if err := mgr.ks.Import(keyID, rid.secret); err != nil {
		return nil, err
	}
	return rid, nil
}

// Import imports a RID key from its byte representation.
func (mgr *RIDManager) ImportKey(data []byte) (cs_rid.RID, error) {
	// validate data as rid
	if err := types.RID(data).Validate(); err != nil {
		return nil, err
	}
	
	// generate a unique keyID to be used as SKI
	keyID := uuid.New().String()

	rid := &RID{data, keyID}
	if err := mgr.ks.Import(keyID, rid.secret); err != nil {
		return nil, err
	}
	return rid, nil
}

// GetKey returns a RID key by its SKI.
func (mgr *RIDManager) GetKey(keyID string) (cs_rid.RID, error) {
	r, err := mgr.ks.Get(keyID)
	if err != nil {
		return nil, err
	}
	return &RID{r, keyID}, nil
}

// modifies the receiver by taking the XOR with the argument.
func (mgr *RIDManager) XOR(keyID string, message []byte) (cs_rid.RID, error) {
	rid, err := mgr.GetKey(keyID)
	if err != nil {
		return nil, err
	}
	r, ok := rid.(*RID)
	if !ok {
		return nil, errors.New("failed to cast to RID")
	}
	r.secret.XOR(message)
	mgr.ks.Import(keyID, r.secret)
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
