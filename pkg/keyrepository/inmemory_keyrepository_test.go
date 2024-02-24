package keyrepository

import (
	"fmt"
	"testing"

	"github.com/mr-shifu/mpc-lib/pkg/common/keyrepository"
	"github.com/stretchr/testify/assert"
)

func TestImportKeys(t *testing.T) {
	kr := NewKeyRepository()

	keyID := "1"
	keys := []keyrepository.KeyData{
		{
			SKI:     []byte("ski"),
			PartyID: "Party1",
		},
		{
			SKI:     []byte("ski"),
			PartyID: "Party2",
		},
	}
	for _, key := range keys {
		err := kr.Import(keyID, key)
		assert.NoError(t, err, "Import should not return an error")
	}

	ks, err := kr.GetAll(keyID)
	assert.NoError(t, err, "GetAll should not return an error")
	assert.Len(t, ks, len(keys), fmt.Sprintf("GetAll should return %d key", len(keys)))
}
