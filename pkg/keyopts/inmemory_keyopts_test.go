package keyopts

import (
	"fmt"
	"testing"

	"github.com/mr-shifu/mpc-lib/pkg/common/keyopts"
	"github.com/stretchr/testify/assert"
)

func TestImportKeys(t *testing.T) {
	kr := NewInMemoryKeyOpts()

	keyID := "1"
	keys := []keyopts.KeyData{
		{
			SKI:     "ski",
			PartyID: "Party1",
		},
		{
			SKI:     "ski",
			PartyID: "Party2",
		},
	}
	for _, key := range keys {
		opts, err := NewOptions().Set("id", keyID, "partyid", key.PartyID)
		assert.NoError(t, err)
		err = kr.Import(key.SKI, opts)
		assert.NoError(t, err, "Import should not return an error")
	}

	opts := make(Options)
	opts.Set("id", "1")
	ks, err := kr.GetAll(opts)
	assert.NoError(t, err, "GetAll should not return an error")
	assert.Len(t, ks, len(keys), fmt.Sprintf("GetAll should return %d key", len(keys)))
}
