package keygen

import (
	"fmt"

	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/party"
	"github.com/mr-shifu/mpc-lib/core/pool"
	"github.com/mr-shifu/mpc-lib/core/protocol"
	"github.com/mr-shifu/mpc-lib/lib/round"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/ecdsa"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/elgamal"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/hash"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/paillier"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/pedersen"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/rid"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/vss"
	"github.com/mr-shifu/mpc-lib/pkg/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/commitment"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/mpckey"
	"github.com/mr-shifu/mpc-lib/protocols/cmp/config"
)

const Rounds round.Number = 5

type MPCKeygen struct {
	elgamal_km  elgamal.ElgamalKeyManager
	paillier_km paillier.PaillierKeyManager
	pedersen_km pedersen.PedersenKeyManager
	ecdsa_km    ecdsa.ECDSAKeyManager
	ec_vss_km   ecdsa.ECDSAKeyManager
	vss_mgr     vss.VssKeyManager
	rid_km      rid.RIDManager
	chainKey_km rid.RIDManager
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
	ec_vss_km ecdsa.ECDSAKeyManager,
	vss_mgr vss.VssKeyManager,
	rid rid.RIDManager,
	chainKey rid.RIDManager,
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
		ec_vss_km:   ec_vss_km,
		vss_mgr:     vss_mgr,
		rid_km:      rid,
		chainKey_km: chainKey,
		hash_mgr:    hash_mgr,
		commit_mgr:  commit_mgr,
	}
}

func (m *MPCKeygen) Start(keyID string, info round.Info, pl *pool.Pool, c *config.Config) protocol.StartFunc {
	return func(sessionID []byte) (_ round.Session, err error) {
		// m.keys[keyID] = info
		opts := keyopts.Options{}
		opts.Set("id", keyID, "partyid", string(info.SelfID))
		h := m.hash_mgr.NewHasher(keyID, opts)

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
				vss_mgr:                   m.vss_mgr,
				rid_km:                    m.rid_km,
				chainKey_km:               m.chainKey_km,
				PreviousSecretECDSA:       c.ECDSA,
				PreviousPublicSharesECDSA: PublicSharesECDSA,
				PreviousChainKey:          c.ChainKey,
			}, nil
		}

		// sample fᵢ(X) deg(fᵢ) = t, fᵢ(0) = secretᵢ
		key, err := m.ecdsa_km.GenerateKey(opts)
		if err != nil {
			return nil, fmt.Errorf("keygen: %w", err)
		}
		if err := key.GenerateVSSSecrets(helper.Threshold(), opts); err != nil {
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
			vss_mgr:     m.vss_mgr,
			rid_km:      m.rid_km,
			chainKey_km: m.chainKey_km,
			commit_mgr:  m.commit_mgr,
		}, nil

	}
}
