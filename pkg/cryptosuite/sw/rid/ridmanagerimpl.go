package rid

import (
	"crypto/rand"
	"errors"

	"github.com/google/uuid"
	"github.com/mr-shifu/mpc-lib/lib/types"
	cs_rid "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/rid"
	"github.com/mr-shifu/mpc-lib/pkg/common/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/common/keystore"
)

type RIDManager struct {
	ks keystore.Keystore
}

func NewRIDManager(ks keystore.Keystore) *RIDManager {
	return &RIDManager{ks}
}

// GenerateKey generates a new RID key pair.
func (mgr *RIDManager) GenerateKey(opts keyopts.Options) (cs_rid.RID, error) {
	r, err := types.NewRID(rand.Reader)
	if err != nil {
		return nil, err
	}

	// generate a unique keyID to be used as SKI
	keyID := uuid.New().String()

	rid := &RID{r}
	// TODO verify the keyID is unique and secure
	if err := mgr.ks.Import(keyID, rid.secret, opts); err != nil {
		return nil, err
	}
	return rid, nil
}

// Import imports a RID key from its byte representation.
func (mgr *RIDManager) ImportKey(data []byte, opts keyopts.Options) (cs_rid.RID, error) {
	// validate data as rid
	if err := types.RID(data).Validate(); err != nil {
		return nil, err
	}
	
	// generate a unique keyID to be used as SKI
	keyID := uuid.New().String()

	rid := &RID{data}
	if err := mgr.ks.Import(keyID, rid.secret, opts); err != nil {
		return nil, err
	}
	return rid, nil
}

// GetKey returns a RID key by its SKI.
func (mgr *RIDManager) GetKey(opts keyopts.Options) (cs_rid.RID, error) {
	r, err := mgr.ks.Get(opts)
	if err != nil {
		return nil, err
	}
	return &RID{r}, nil
}

func (mgr *RIDManager) DeleteKey(opts keyopts.Options) error {
	return mgr.ks.Delete(opts)
}

func (mgr *RIDManager) DeleteAllKeys(opts keyopts.Options) error {
	return mgr.ks.DeleteAll(opts)
}

// modifies the receiver by taking the XOR with the argument.
func (mgr *RIDManager) XOR(message []byte, opts keyopts.Options) (cs_rid.RID, error) {
	rid, err := mgr.GetKey(opts)
	if err != nil {
		return nil, err
	}
	r, ok := rid.(*RID)
	if !ok {
		return nil, errors.New("failed to cast to RID")
	}
	r.secret.XOR(message)
	if err := mgr.ks.Update(r.secret, opts); err != nil {
		return nil, err
	}
	return rid, nil
}

// Validate ensure that the RID is the correct length and is not identically 0.
func (mgr *RIDManager) Validate(opts keyopts.Options) error {
	rid, err := mgr.GetKey(opts)
	if err != nil {
		return err
	}
	return rid.Validate()
}
