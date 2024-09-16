package round_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/party"
	"github.com/mr-shifu/mpc-lib/lib/round"
	"github.com/mr-shifu/mpc-lib/lib/test"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/hash"
	"github.com/mr-shifu/mpc-lib/pkg/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/keystore"
	"github.com/mr-shifu/mpc-lib/pkg/vault"
	"github.com/stretchr/testify/assert"
)

func TestNewSession(t *testing.T) {
	RNumber := round.Number(5)
	T := 20
	N := 26
	partyIDs := test.PartyIDs(N)
	selfID := partyIDs[0]
	tests := []struct {
		name        string
		roundNumber round.Number
		selfID      party.ID
		partyIDs    []party.ID
		threshold   int
		group       curve.Curve
		wantErr     bool
	}{
		{
			"-1 t",
			RNumber,
			selfID,
			partyIDs,
			-1,
			curve.Secp256k1{},
			true,
		},
		{
			"invalid selfID",
			RNumber,
			"",
			partyIDs,
			T,
			curve.Secp256k1{},
			true,
		},
		{
			"duplicate selfID",
			RNumber,
			selfID,
			append(partyIDs, selfID),
			T,
			curve.Secp256k1{},
			true,
		},
		{
			"duplicate second ID",
			RNumber,
			selfID,
			append(partyIDs, partyIDs[1]),
			T,
			curve.Secp256k1{},
			true,
		},
		{
			"duplicate partyIDs",
			RNumber,
			selfID,
			append(partyIDs, partyIDs...),
			T,
			curve.Secp256k1{},
			true,
		},
		{
			"threshold N",
			RNumber,
			selfID,
			partyIDs,
			N,
			curve.Secp256k1{},
			true,
		},
		{
			"threshold T with T parties",
			RNumber,
			selfID,
			partyIDs[:T],
			T,
			curve.Secp256k1{},
			true,
		},
		{
			"no group",
			RNumber,
			selfID,
			partyIDs,
			T,
			curve.Secp256k1{},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyID := uuid.New().String()

			hahs_keyopts := keyopts.NewInMemoryKeyOpts()
			hahs_vault := vault.NewInMemoryVault()
			hash_ks := keystore.NewInMemoryKeystore(hahs_vault, hahs_keyopts)
			hash_mgr := hash.NewHashManager(hash_ks)

			opts, err := keyopts.NewOptions().Set("id", keyID, "partyid", "a")
			assert.NoError(t, err)
			h := hash_mgr.NewHasher("test", opts)

			info := round.Info{
				ProtocolID:       "TEST",
				FinalRoundNumber: tt.roundNumber,
				SelfID:           tt.selfID,
				PartyIDs:         tt.partyIDs,
				Threshold:        tt.threshold,
				Group:            tt.group,
			}
			_, err = round.NewSession(keyID, info, nil, nil, h)
			if tt.wantErr == (err == nil) {
				t.Error(err)
			}
		})
	}
}
