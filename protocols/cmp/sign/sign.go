package sign

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/mr-shifu/mpc-lib/core/math/polynomial"
	"github.com/mr-shifu/mpc-lib/core/party"
	"github.com/mr-shifu/mpc-lib/core/pool"
	"github.com/mr-shifu/mpc-lib/core/protocol"
	"github.com/mr-shifu/mpc-lib/lib/round"
	"github.com/mr-shifu/mpc-lib/lib/types"

	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/ecdsa"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/hash"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/mta"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/paillier"
	pek "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/paillierencodedkey"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/pedersen"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/vss"
	sw_ecdsa "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/ecdsa"
	"github.com/mr-shifu/mpc-lib/pkg/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/config"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/result"
	mpc_config "github.com/mr-shifu/mpc-lib/pkg/mpc/config"
)

// protocolSignID for the "3 round" variant using echo broadcast.
const (
	protocolSignID                  = "cmp/sign"
	protocolSignRounds round.Number = 5
)

type MPCSign struct {
	signcfgmgr config.SignConfigManager

	hash_mgr hash.HashManager

	paillier_km paillier.PaillierKeyManager

	pedersen_km pedersen.PedersenKeyManager

	ec       ecdsa.ECDSAKeyManager
	ec_vss   ecdsa.ECDSAKeyManager
	gamma    ecdsa.ECDSAKeyManager
	signK    ecdsa.ECDSAKeyManager
	delta    ecdsa.ECDSAKeyManager
	chi      ecdsa.ECDSAKeyManager
	bigDelta ecdsa.ECDSAKeyManager

	vss_mgr vss.VssKeyManager

	gamma_pek pek.PaillierEncodedKeyManager
	signK_pek pek.PaillierEncodedKeyManager

	delta_mta mta.MtAManager
	chi_mta   mta.MtAManager

	sigma     result.SigmaStore
	signature result.Signature
}

func NewMPCSign(
	signcfgmgr config.SignConfigManager,
	hash_mgr hash.HashManager,
	paillier_km paillier.PaillierKeyManager,
	pedersen_km pedersen.PedersenKeyManager,
	ec ecdsa.ECDSAKeyManager,
	ec_vss ecdsa.ECDSAKeyManager,
	vss_mgr vss.VssKeyManager,
	gamma ecdsa.ECDSAKeyManager,
	signK ecdsa.ECDSAKeyManager,
	delta ecdsa.ECDSAKeyManager,
	chi ecdsa.ECDSAKeyManager,
	bigDelta ecdsa.ECDSAKeyManager,
	gamma_pek pek.PaillierEncodedKeyManager,
	signK_pek pek.PaillierEncodedKeyManager,
	delta_mta mta.MtAManager,
	chi_mta mta.MtAManager,
	sigma result.SigmaStore,
	signature result.Signature,
) *MPCSign {
	return &MPCSign{
		signcfgmgr:  signcfgmgr,
		hash_mgr:    hash_mgr,
		paillier_km: paillier_km,
		pedersen_km: pedersen_km,
		ec:          ec,
		ec_vss:      ec_vss,
		vss_mgr:     vss_mgr,
		gamma:       gamma,
		signK:       signK,
		delta:       delta,
		chi:         chi,
		bigDelta:    bigDelta,
		gamma_pek:   gamma_pek,
		signK_pek:   signK_pek,
		delta_mta:   delta_mta,
		chi_mta:     chi_mta,
		sigma:       sigma,
		signature:   signature,
	}
}

func (m *MPCSign) StartSign(signID string, keyID string, info round.Info, signers []party.ID, message []byte, pl *pool.Pool) protocol.StartFunc {
	return func(sessionID []byte) (round.Session, error) {
		group := info.Group

		opts := keyopts.Options{}
		opts.Set("id", signID, "partyid", info.SelfID)

		h := m.hash_mgr.NewHasher(signID, opts)

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
			vssOpts := keyopts.Options{}
			vssOpts.Set("id", keyID, "partyid", "ROOT")
			vss, err := m.vss_mgr.GetSecrets(vssOpts)
			if err != nil {
				return nil, err
			}

			partyVSSOpts := keyopts.Options{}
			partyVSSOpts.Set("id", hex.EncodeToString(vss.SKI()), "partyid", string(j))

			vssShareKey, err := m.ec_vss.GetKey(partyVSSOpts)
			if err != nil {
				return nil, err
			}

			partyOpts := keyopts.Options{}
			partyOpts.Set("id", signID, "partyid", string(j))
			clonedj := vssShareKey.CloneByMultiplier(lagrange[j])
			if _, err := m.ec.ImportKey(clonedj, partyOpts); err != nil {
				return nil, err
			}
			clonedPubKey = clonedPubKey.Add(clonedj.PublicKeyRaw())
		}
		rootECOpts := keyopts.Options{}
		rootECOpts.Set("id", signID, "partyid", "ROOT")
		cloned := sw_ecdsa.NewECDSAKey(nil, clonedPubKey, info.Group)
		if _, err := m.ec.ImportKey(cloned, rootECOpts); err != nil {
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
		if err := m.signcfgmgr.ImportConfig(cfg); err != nil {
			return nil, fmt.Errorf("keygen: %w", err)
		}

		return &round1{
			Helper:      helper,
			cfg:         cfg,
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
