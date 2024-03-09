package sign

import (
	"errors"
	"fmt"

	"github.com/mr-shifu/mpc-lib/core/math/polynomial"
	"github.com/mr-shifu/mpc-lib/core/party"
	"github.com/mr-shifu/mpc-lib/core/pool"
	"github.com/mr-shifu/mpc-lib/core/protocol"
	"github.com/mr-shifu/mpc-lib/lib/round"
	"github.com/mr-shifu/mpc-lib/lib/types"
	"github.com/mr-shifu/mpc-lib/protocols/cmp/config"

	cs_ecdsa "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/ecdsa"
	comm_hash "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/hash"
	sw_mta "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/mta"
	inmem_keyrepo "github.com/mr-shifu/mpc-lib/pkg/keyrepository"
	"github.com/mr-shifu/mpc-lib/pkg/keystore"
	inmem_keystore "github.com/mr-shifu/mpc-lib/pkg/keystore"
	comm_config "github.com/mr-shifu/mpc-lib/pkg/mpc/common/config"
	comm_ecdsa "github.com/mr-shifu/mpc-lib/pkg/mpc/common/ecdsa"
	comm_mta "github.com/mr-shifu/mpc-lib/pkg/mpc/common/mta"
	comm_paillier "github.com/mr-shifu/mpc-lib/pkg/mpc/common/paillier"
	comm_pedersen "github.com/mr-shifu/mpc-lib/pkg/mpc/common/pedersen"
	comm_result "github.com/mr-shifu/mpc-lib/pkg/mpc/common/result"
	comm_vss "github.com/mr-shifu/mpc-lib/pkg/mpc/common/vss"
	mpc_config "github.com/mr-shifu/mpc-lib/pkg/mpc/config"
	mpc_ecdsa "github.com/mr-shifu/mpc-lib/pkg/mpc/ecdsa"
	mpc_mta "github.com/mr-shifu/mpc-lib/pkg/mpc/mta"
	mpc_result "github.com/mr-shifu/mpc-lib/pkg/mpc/result"
)

// protocolSignID for the "3 round" variant using echo broadcast.
const (
	protocolSignID                  = "cmp/sign"
	protocolSignRounds round.Number = 5
)

type MPCSign struct {
	cfgmgr comm_config.SignConfigManager

	hash_mgr comm_hash.HashManager

	paillier_km comm_paillier.PaillierKeyManager

	pedersen_km comm_pedersen.PedersenKeyManager

	ec       comm_ecdsa.ECDSAKeyManager
	gamma    comm_ecdsa.ECDSAKeyManager
	signK    comm_ecdsa.ECDSAKeyManager
	delta    comm_ecdsa.ECDSAKeyManager
	chi      comm_ecdsa.ECDSAKeyManager
	bigDelta comm_ecdsa.ECDSAKeyManager

	delta_mta comm_mta.MtAManager
	chi_mta   comm_mta.MtAManager

	sigma     comm_result.SigmaStore
	signature comm_result.Signature
}

func NewMPCSign(
	hash_mgr comm_hash.HashManager,
	paillier_km comm_paillier.PaillierKeyManager,
	pedersen_km comm_pedersen.PedersenKeyManager,
	ec_mgr comm_ecdsa.ECDSAKeyManager,
	ecdsa_km cs_ecdsa.ECDSAKeyManager,
	vss_km comm_vss.VssKeyManager,
) *MPCSign {
	cfg_mgr := mpc_config.NewSignConfigManager()

	sigma_kr := inmem_keyrepo.NewKeyRepository()
	sigma_ks := inmem_keystore.NewInMemoryKeystore()
	sigma := mpc_result.NewSigmaStore(sigma_ks, sigma_kr)

	signature := mpc_result.NewSignStore()

	gamma_kr := inmem_keyrepo.NewKeyRepository()
	gamma_mgr := mpc_ecdsa.NewECDSA(ecdsa_km, gamma_kr, nil, nil)

	signK_kr := inmem_keyrepo.NewKeyRepository()
	signK_mgr := mpc_ecdsa.NewECDSA(ecdsa_km, signK_kr, nil, nil)

	delta_kr := inmem_keyrepo.NewKeyRepository()
	delta_mgr := mpc_ecdsa.NewECDSA(ecdsa_km, delta_kr, nil, nil)

	chi_kr := inmem_keyrepo.NewKeyRepository()
	chi_mgr := mpc_ecdsa.NewECDSA(ecdsa_km, chi_kr, nil, nil)

	bigDelta_kr := inmem_keyrepo.NewKeyRepository()
	bigDelta_mgr := mpc_ecdsa.NewECDSA(ecdsa_km, bigDelta_kr, nil, nil)

	mta_ks := keystore.NewInMemoryKeystore()
	mta_km := sw_mta.NewMtAManager(mta_ks)
	delta_mta_kr := inmem_keyrepo.NewKeyRepository()
	delta_mta := mpc_mta.NewPaillierKeyManager(mta_km, delta_mta_kr)

	chi_mta_kr := inmem_keyrepo.NewKeyRepository()
	chi_mta := mpc_mta.NewPaillierKeyManager(mta_km, chi_mta_kr)

	return &MPCSign{
		cfgmgr:      cfg_mgr,
		hash_mgr:    hash_mgr,
		paillier_km: paillier_km,
		pedersen_km: pedersen_km,
		ec:          ec_mgr,
		gamma:       gamma_mgr,
		signK:       signK_mgr,
		delta:       delta_mgr,
		chi:         chi_mgr,
		bigDelta:    bigDelta_mgr,
		delta_mta:   delta_mta,
		chi_mta:     chi_mta,
		sigma:       sigma,
		signature:   signature,
	}
}

func (m *MPCSign) StartSign(signID string, keyID string, config *config.Config, signers []party.ID, message []byte, pl *pool.Pool) protocol.StartFunc {
	return func(sessionID []byte) (round.Session, error) {
		group := config.Group

		h := m.hash_mgr.NewHasher(signID)

		// this could be used to indicate a pre-signature later on
		if len(message) == 0 {
			return nil, errors.New("sign.Create: message is nil")
		}

		info := round.Info{
			ProtocolID:       protocolSignID,
			FinalRoundNumber: protocolSignRounds,
			SelfID:           config.ID,
			PartyIDs:         signers,
			Threshold:        config.Threshold,
			Group:            config.Group,
		}

		helper, err := round.NewSession(signID, info, sessionID, pl, h, config, types.SigningMessage(message))
		if err != nil {
			return nil, fmt.Errorf("sign.Create: %w", err)
		}

		if !config.CanSign(helper.PartyIDs()) {
			return nil, errors.New("sign.Create: signers is not a valid signing subset")
		}

		// Scale public data
		lagrange := polynomial.Lagrange(group, signers)
		for _, j := range helper.PartyIDs() {
			ecKey, err := m.ec.GetKey(keyID, string(j))
			if err != nil {
				return nil, err
			}
			cloned := ecKey.CloneByMultiplier(lagrange[j])
			if err := m.ec.ImportKey(signID, string(j), cloned); err != nil {
				return nil, err
			}
		}

		mpcsign := mpc_config.NewSignConfig(
			signID,
			keyID,
			group,
			helper.Threshold(),
			helper.SelfID(),
			helper.PartyIDs(),
		)
		if err := m.cfgmgr.ImportConfig(mpcsign); err != nil {
			return nil, fmt.Errorf("keygen: %w", err)
		}

		return &round1{
			Helper:      helper,
			cfg:         m.cfgmgr.GetConfig(signID),
			hash_mgr:    m.hash_mgr,
			paillier_km: m.paillier_km,
			pedersen_km: m.pedersen_km,
			ec:          m.ec,
			gamma:       m.gamma,
			signK:       m.signK,
			delta:       m.delta,
			chi:         m.chi,
			bigDelta:    m.bigDelta,
			sigma:       m.sigma,
			signature:   m.signature,
			Message:     message,
		}, nil
	}
}
