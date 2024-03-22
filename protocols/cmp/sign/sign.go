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

	comm_hash "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/hash"
	sw_ecdsa "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/ecdsa"
	comm_config "github.com/mr-shifu/mpc-lib/pkg/mpc/common/config"
	comm_ecdsa "github.com/mr-shifu/mpc-lib/pkg/mpc/common/ecdsa"
	comm_mta "github.com/mr-shifu/mpc-lib/pkg/mpc/common/mta"
	comm_paillier "github.com/mr-shifu/mpc-lib/pkg/mpc/common/paillier"
	comm_pedersen "github.com/mr-shifu/mpc-lib/pkg/mpc/common/pedersen"
	comm_pek "github.com/mr-shifu/mpc-lib/pkg/mpc/common/pek"
	comm_result "github.com/mr-shifu/mpc-lib/pkg/mpc/common/result"
	comm_vss "github.com/mr-shifu/mpc-lib/pkg/mpc/common/vss"
	mpc_config "github.com/mr-shifu/mpc-lib/pkg/mpc/config"
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

	ec comm_ecdsa.ECDSAKeyManager
	// ec_vss   comm_ecdsa.ECDSAKeyManager
	gamma    comm_ecdsa.ECDSAKeyManager
	signK    comm_ecdsa.ECDSAKeyManager
	delta    comm_ecdsa.ECDSAKeyManager
	chi      comm_ecdsa.ECDSAKeyManager
	bigDelta comm_ecdsa.ECDSAKeyManager

	vss_mgr comm_vss.VssKeyManager

	gamma_pek comm_pek.PaillierEncodedKeyManager
	signK_pek comm_pek.PaillierEncodedKeyManager

	delta_mta comm_mta.MtAManager
	chi_mta   comm_mta.MtAManager

	sigma     comm_result.SigmaStore
	signature comm_result.Signature
}

func NewMPCSign(
	cfgmgr comm_config.SignConfigManager,
	hash_mgr comm_hash.HashManager,
	paillier_km comm_paillier.PaillierKeyManager,
	pedersen_km comm_pedersen.PedersenKeyManager,
	ec comm_ecdsa.ECDSAKeyManager,
	// ec_vss comm_ecdsa.ECDSAKeyManager,
	vss_mgr comm_vss.VssKeyManager,
	gamma comm_ecdsa.ECDSAKeyManager,
	signK comm_ecdsa.ECDSAKeyManager,
	delta comm_ecdsa.ECDSAKeyManager,
	chi comm_ecdsa.ECDSAKeyManager,
	bigDelta comm_ecdsa.ECDSAKeyManager,
	gamma_pek comm_pek.PaillierEncodedKeyManager,
	signK_pek comm_pek.PaillierEncodedKeyManager,
	delta_mta comm_mta.MtAManager,
	chi_mta comm_mta.MtAManager,
	sigma comm_result.SigmaStore,
	signature comm_result.Signature,
) *MPCSign {
	return &MPCSign{
		cfgmgr:      cfgmgr,
		hash_mgr:    hash_mgr,
		paillier_km: paillier_km,
		pedersen_km: pedersen_km,
		ec:          ec,
		// ec_vss:      ec_vss,
		vss_mgr:   vss_mgr,
		gamma:     gamma,
		signK:     signK,
		delta:     delta,
		chi:       chi,
		bigDelta:  bigDelta,
		gamma_pek: gamma_pek,
		signK_pek: signK_pek,
		delta_mta: delta_mta,
		chi_mta:   chi_mta,
		sigma:     sigma,
		signature: signature,
	}
}

func (m *MPCSign) StartSign(signID string, keyID string, info round.Info, signers []party.ID, message []byte, pl *pool.Pool) protocol.StartFunc {
	return func(sessionID []byte) (round.Session, error) {
		group := info.Group

		h := m.hash_mgr.NewHasher(signID)

		// this could be used to indicate a pre-signature later on
		if len(message) == 0 {
			return nil, errors.New("sign.Create: message is nil")
		}

		helper, err := round.NewSession(signID, info, sessionID, pl, h, types.SigningMessage(message))
		if err != nil {
			return nil, fmt.Errorf("sign.Create: %w", err)
		}

		// if !config.CanSign(helper.PartyIDs()) {
		// 	return nil, errors.New("sign.Create: signers is not a valid signing subset")
		// }

		// Scale public data
		lagrange := polynomial.Lagrange(group, signers)
		clonedPubKey := info.Group.NewPoint()
		for _, j := range helper.PartyIDs() {
			vssKey, err := m.vss_mgr.GetShare(keyID, "ROOT", j)
			if err != nil {
				return nil, err
			}
			clonedj := vssKey.CloneByMultiplier(lagrange[j])
			if err := m.ec.ImportKey(signID, string(j), clonedj); err != nil {
				return nil, err
			}
			fmt.Printf("Party: %s, clonedj: %v\n", j, clonedj.PublicKeyRaw())
			clonedPubKey = clonedPubKey.Add(clonedj.PublicKeyRaw())
		}
		fmt.Printf("Roto cloned: %v\n", clonedPubKey)
		cloned := sw_ecdsa.NewECDSAKey(nil, clonedPubKey, info.Group)
		if err := m.ec.ImportKey(signID, "ROOT", cloned); err != nil {
			return nil, err
		}

		cfg := mpc_config.NewSignConfig(
			signID,
			keyID,
			group,
			helper.Threshold(),
			helper.SelfID(),
			helper.PartyIDs(),
		)
		if err := m.cfgmgr.ImportConfig(cfg); err != nil {
			return nil, fmt.Errorf("keygen: %w", err)
		}

		return &round1{
			Helper:      helper,
			cfg:         m.cfgmgr.GetConfig(signID),
			hash_mgr:    m.hash_mgr,
			paillier_km: m.paillier_km,
			pedersen_km: m.pedersen_km,
			ec:          m.ec,
			vss_mgr:     m.vss_mgr,
			gamma:       m.gamma,
			signK:       m.signK,
			delta:       m.delta,
			chi:         m.chi,
			bigDelta:    m.bigDelta,
			gamma_pek:   m.gamma_pek,
			signK_pek:   m.signK_pek,
			delta_mta:   m.delta_mta,
			chi_mta:     m.chi_mta,
			sigma:       m.sigma,
			signature:   m.signature,
			Message:     message,
		}, nil
	}
}
