package keygen

import (
	"fmt"

	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/party"
	"github.com/mr-shifu/mpc-lib/core/pool"
	"github.com/mr-shifu/mpc-lib/core/protocol"
	"github.com/mr-shifu/mpc-lib/lib/round"

	sw_elgamal "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/elgamal"
	comm_elgamal "github.com/mr-shifu/mpc-lib/pkg/mpc/common/elgamal"
	mpc_elgamal "github.com/mr-shifu/mpc-lib/pkg/mpc/elgamal"

	sw_paillier "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/paillier"
	comm_paillier "github.com/mr-shifu/mpc-lib/pkg/mpc/common/paillier"
	mpc_paillier "github.com/mr-shifu/mpc-lib/pkg/mpc/paillier"

	sw_pedersen "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/pedersen"
	comm_pedersen "github.com/mr-shifu/mpc-lib/pkg/mpc/common/pedersen"
	mpc_pedersen "github.com/mr-shifu/mpc-lib/pkg/mpc/pedersen"

	sw_rid "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/rid"
	comm_rid "github.com/mr-shifu/mpc-lib/pkg/mpc/common/rid"
	mpc_rid "github.com/mr-shifu/mpc-lib/pkg/mpc/rid"

	sw_vss "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/vss"

	sw_ecdsa "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/ecdsa"
	comm_ecdsa "github.com/mr-shifu/mpc-lib/pkg/mpc/common/ecdsa"
	mpc_ecdsa "github.com/mr-shifu/mpc-lib/pkg/mpc/ecdsa"

	comm_hash "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/hash"
	sw_hash "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/hash"

	comm_mpckey "github.com/mr-shifu/mpc-lib/pkg/mpc/common/mpckey"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/mpckey"

	inmem_keyrepo "github.com/mr-shifu/mpc-lib/pkg/keyrepository"
	"github.com/mr-shifu/mpc-lib/pkg/keystore"
	"github.com/mr-shifu/mpc-lib/protocols/cmp/config"
)

const Rounds round.Number = 5

type MPCKeygen struct {
	elgamal_km  comm_elgamal.ElgamalKeyManager
	paillier_km comm_paillier.PaillierKeyManager
	pedersen_km comm_pedersen.PedersenKeyManager
	ecdsa_km    comm_ecdsa.ECDSAKeyManager
	rid_km      comm_rid.RIDKeyManager
	chainKey_km comm_rid.RIDKeyManager
	hash_mgr    comm_hash.HashManager
	mpc_ks      comm_mpckey.MPCKeystore
	// keys              map[string]round.Info
	// roundStates       map[string]int
}

func NewMPCKeygen() *MPCKeygen {
	pl := pool.NewPool(2)

	mpc_ks := mpckey.NewInMemoryMPCKeystore()

	elgamal_kr := inmem_keyrepo.NewKeyRepository()
	elgamal_ks := keystore.NewInMemoryKeystore()
	elgamal_km := sw_elgamal.NewElgamalKeyManager(elgamal_ks, &sw_elgamal.Config{Group: curve.Secp256k1{}})
	elgamal := mpc_elgamal.NewElgamal(elgamal_km, elgamal_kr)

	paillier_kr := inmem_keyrepo.NewKeyRepository()
	paillier_ks := keystore.NewInMemoryKeystore()
	paillier_km := sw_paillier.NewPaillierKeyManager(paillier_ks, pl)
	paillier := mpc_paillier.NewPaillierKeyManager(paillier_km, paillier_kr)

	pedersen_kr := inmem_keyrepo.NewKeyRepository()
	pedersen_ks := keystore.NewInMemoryKeystore()
	pedersen_km := sw_pedersen.NewPedersenKeymanager(pedersen_ks)
	pedersen := mpc_pedersen.NewPedersenKeyManager(pedersen_km, pedersen_kr)

	vss_kr := inmem_keyrepo.NewKeyRepository()
	vss_ks := keystore.NewInMemoryKeystore()
	vss_ss := sw_vss.NewInMemoryVSSShareStore()
	vss_km := sw_vss.NewVssKeyManager(vss_ks, vss_ss, curve.Secp256k1{})

	ecdsa_ks := keystore.NewInMemoryKeystore()
	schstore := keystore.NewInMemoryKeystore()
	ecdsa_km := sw_ecdsa.NewECDSAKeyManager(ecdsa_ks, schstore, vss_km, &sw_ecdsa.Config{Group: curve.Secp256k1{}})
	ecdsa_kr := inmem_keyrepo.NewKeyRepository()
	ecdsa := mpc_ecdsa.NewECDSA(ecdsa_km, ecdsa_kr, vss_km, vss_kr)

	rid_kr := inmem_keyrepo.NewKeyRepository()
	rid_ks := keystore.NewInMemoryKeystore()
	rid_km := sw_rid.NewRIDManager(rid_ks)
	rid := mpc_rid.NewRIDKeyManager(rid_km, rid_kr)

	chainKey_kr := inmem_keyrepo.NewKeyRepository()
	chainKey_ks := keystore.NewInMemoryKeystore()
	chainKey_km := sw_rid.NewRIDManager(chainKey_ks)
	chainKey := mpc_rid.NewRIDKeyManager(chainKey_km, chainKey_kr)

	hash_ks := keystore.NewInMemoryKeystore()
	hash_mgr := sw_hash.NewHashManager(hash_ks)

	return &MPCKeygen{
		mpc_ks:      mpc_ks,
		elgamal_km:  elgamal,
		paillier_km: paillier,
		pedersen_km: pedersen,
		ecdsa_km:    ecdsa,
		rid_km:      rid,
		chainKey_km: chainKey,
		hash_mgr:    hash_mgr,
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

		mpckey := comm_mpckey.MPCKey{
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
			rid_km:      m.rid_km,
			chainKey_km: m.chainKey_km,
		}, nil

	}
}
