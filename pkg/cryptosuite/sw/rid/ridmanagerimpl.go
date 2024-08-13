package rid

import (
	"crypto/rand"
	"errors"

	"github.com/google/uuid"
	"github.com/mr-shifu/mpc-lib/lib/types"
	"github.com/mr-shifu/mpc-lib/pkg/common/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/common/keystore"
)

type RIDManagerImpl struct {
	ks keystore.Keystore
}

func NewRIDManagerImpl(ks keystore.Keystore) *RIDManagerImpl {
	return &RIDManagerImpl{ks}
}

// GenerateKey generates a new RID key pair.
func (mgr *RIDManagerImpl) GenerateKey(opts keyopts.Options) (RID, error) {
	r, err := types.NewRID(rand.Reader)
	if err != nil {
		return nil, err
	}

	// generate a unique keyID to be used as SKI
	keyID := uuid.New().String()

	rid := &RIDImpl{r}
	// TODO verify the keyID is unique and secure
	if err := mgr.ks.Import(keyID, rid.secret, opts); err != nil {
		return nil, err
	}
	return rid, nil
}

// Import imports a RID key from its byte representation.
func (mgr *RIDManagerImpl) ImportKey(data []byte, opts keyopts.Options) (RID, error) {
	// validate data as rid
	if err := types.RID(data).Validate(); err != nil {
		return nil, err
	}
	
	// generate a unique keyID to be used as SKI
	keyID := uuid.New().String()

	rid := &RIDImpl{data}
	if err := mgr.ks.Import(keyID, rid.secret, opts); err != nil {
		return nil, err
	}
	return rid, nil
}

// GetKey returns a RID key by its SKI.
func (mgr *RIDManagerImpl) GetKey(opts keyopts.Options) (RID, error) {
	r, err := mgr.ks.Get(opts)
	if err != nil {
		return nil, err
	}
	return &RIDImpl{r}, nil
}

func (mgr *RIDManagerImpl) DeleteKey(opts keyopts.Options) error {
	return mgr.ks.Delete(opts)
}

func (mgr *RIDManagerImpl) DeleteAllKeys(opts keyopts.Options) error {
	return mgr.ks.DeleteAll(opts)
}

// modifies the receiver by taking the XOR with the argument.
func (mgr *RIDManagerImpl) XOR(message []byte, opts keyopts.Options) (RID, error) {
	rid, err := mgr.GetKey(opts)
	if err != nil {
		return nil, err
	}
	r, ok := rid.(*RIDImpl)
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
func (mgr *RIDManagerImpl) Validate(opts keyopts.Options) error {
	rid, err := mgr.GetKey(opts)
	if err != nil {
		return err
	}
	return rid.Validate()
}
