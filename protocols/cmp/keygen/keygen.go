package keygen

import (
	"fmt"

	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/party"
	"github.com/mr-shifu/mpc-lib/core/pool"
	"github.com/mr-shifu/mpc-lib/core/protocol"
	"github.com/mr-shifu/mpc-lib/lib/round"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/hash"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/commitment"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/ecdsa"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/elgamal"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/mpckey"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/paillier"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/pedersen"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/rid"
	"github.com/mr-shifu/mpc-lib/protocols/cmp/config"
)

const Rounds round.Number = 5

type MPCKeygen struct {
	elgamal_km  elgamal.ElgamalKeyManager
	paillier_km paillier.PaillierKeyManager
	pedersen_km pedersen.PedersenKeyManager
	ecdsa_km    ecdsa.ECDSAKeyManager
	ec_vss_km   ecdsa.ECDSAKeyManager
	rid_km      rid.RIDKeyManager
	chainKey_km rid.RIDKeyManager
	hash_mgr    hash.HashManager
	mpc_ks      mpckey.MPCKeystore
	commit_mgr  commitment.CommitmentManager
	// keys              map[string]round.Info
	// roundStates       map[string]int
}

func NewMPCKeygen(
	elgamal elgamal.ElgamalKeyManager,
	paillier paillier.PaillierKeyManager,
	pedersen pedersen.PedersenKeyManager,
	ecdsa ecdsa.ECDSAKeyManager,
	ec_vss ecdsa.ECDSAKeyManager,
	rid rid.RIDKeyManager,
	chainKey rid.RIDKeyManager,
	hash_mgr hash.HashManager,
	mpc_ks mpckey.MPCKeystore,
	commit_mgr commitment.CommitmentManager,
	pl *pool.Pool,
) *MPCKeygen {
	return &MPCKeygen{
		mpc_ks:      mpc_ks,
		elgamal_km:  elgamal,
		paillier_km: paillier,
		pedersen_km: pedersen,
		ecdsa_km:    ecdsa,
		ec_vss_km:   ec_vss,
		rid_km:      rid,
		chainKey_km: chainKey,
		hash_mgr:    hash_mgr,
		commit_mgr:  commit_mgr,
	}
}

func (m *MPCKeygen) Start(keyID string, info round.Info, pl *pool.Pool, c *config.Config) protocol.StartFunc {
	return func(sessionID []byte) (_ round.Session, err error) {
		// m.keys[keyID] = info
		h := m.hash_mgr.NewHasher(keyID)

		var helper *round.Helper
		if c == nil {
			helper, err = round.NewSession(keyID, info, sessionID, pl, h)
		} else {
			helper, err = round.NewSession(keyID, info, sessionID, pl, h, c)
		}
		if err != nil {
			return nil, fmt.Errorf("keygen: %w", err)
		}

		group := helper.Group()

		if c != nil {
			PublicSharesECDSA := make(map[party.ID]curve.Point, len(c.Public))
			for id, public := range c.Public {
				PublicSharesECDSA[id] = public.ECDSA
			}
			return &round1{
				Helper:                    helper,
				elgamal_km:                m.elgamal_km,
				paillier_km:               m.paillier_km,
				pedersen_km:               m.pedersen_km,
				ecdsa_km:                  m.ecdsa_km,
				ec_vss_km:                 m.ec_vss_km,
				rid_km:                    m.rid_km,
				chainKey_km:               m.chainKey_km,
				PreviousSecretECDSA:       c.ECDSA,
				PreviousPublicSharesECDSA: PublicSharesECDSA,
				PreviousChainKey:          c.ChainKey,
			}, nil
		}

		// sample fᵢ(X) deg(fᵢ) = t, fᵢ(0) = secretᵢ
		key, err := m.ecdsa_km.GenerateKey(keyID, string(helper.SelfID()))
		if err != nil {
			return nil, fmt.Errorf("keygen: %w", err)
		}
		if err := key.GenerateVSSSecrets(helper.Threshold()); err != nil {
			return nil, fmt.Errorf("keygen: %w", err)
		}

		mpckey := mpckey.MPCKey{
			ID:        keyID,
			Group:     group,
			Threshold: helper.Threshold(),
			SelfID:    helper.SelfID(),
			PartyIDs:  helper.PartyIDs(),
			RID:       nil,
			ChainKey:  nil,
		}
		if err := m.mpc_ks.Import(mpckey); err != nil {
			return nil, fmt.Errorf("keygen: %w", err)
		}

		// set key round number
		// m.roundStates[keyID] = 1

		return &round1{
			Helper:      helper,
			mpc_ks:      m.mpc_ks,
			elgamal_km:  m.elgamal_km,
			paillier_km: m.paillier_km,
			pedersen_km: m.pedersen_km,
			ecdsa_km:    m.ecdsa_km,
			ec_vss_km:   m.ec_vss_km,
			rid_km:      m.rid_km,
			chainKey_km: m.chainKey_km,
			commit_mgr:  m.commit_mgr,
		}, nil

	}
}
