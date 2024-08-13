package cmp

import (
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/pool"
	"github.com/mr-shifu/mpc-lib/core/protocol"

	comm_ecdsa "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/ecdsa"
	comm_hash "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/hash"
	comm_mta "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/mta"
	comm_pek "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/paillierencodedkey"
	comm_rid "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/rid"
	comm_vss "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/vss"
	"github.com/mr-shifu/mpc-lib/pkg/common/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/common/keystore"
	"github.com/mr-shifu/mpc-lib/pkg/common/vault"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/commitment"
	sw_ecdsa "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/ecdsa"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/elgamal"
	sw_hash "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/hash"
	sw_mta "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/mta"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/paillier"
	sw_paillier "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/paillier"
	sw_pek "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/paillierencodedkey"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/pedersen"
	sw_pedersen "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/pedersen"
	sw_rid "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/rid"
	sw_vss "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/vss"
	comm_config "github.com/mr-shifu/mpc-lib/pkg/mpc/common/config"
	comm_message "github.com/mr-shifu/mpc-lib/pkg/mpc/common/message"
	comm_result "github.com/mr-shifu/mpc-lib/pkg/mpc/common/result"
	comm_state "github.com/mr-shifu/mpc-lib/pkg/mpc/common/state"
	mpc_config "github.com/mr-shifu/mpc-lib/pkg/mpc/config"
	mpc_message "github.com/mr-shifu/mpc-lib/pkg/mpc/message"
	mpc_result "github.com/mr-shifu/mpc-lib/pkg/mpc/result"
	mpc_state "github.com/mr-shifu/mpc-lib/pkg/mpc/state"
	"github.com/mr-shifu/mpc-lib/protocols/cmp/config"
	"github.com/mr-shifu/mpc-lib/protocols/cmp/keygen"
	"github.com/mr-shifu/mpc-lib/protocols/cmp/sign"
)

type MPC struct {
	keycfgmgr  comm_config.KeyConfigManager
	signcfgmgr comm_config.SignConfigManager
	msgmgr     comm_message.MessageManager
	bcstmgr    comm_message.MessageManager

	keystatmgr  comm_state.MPCStateManager
	signstatmgr comm_state.MPCStateManager

	elgamal    elgamal.ElgamalKeyManager
	paillier   paillier.PaillierKeyManager
	pedersen   pedersen.PedersenKeyManager
	ec         comm_ecdsa.ECDSAKeyManager
	ec_vss     comm_ecdsa.ECDSAKeyManager
	rid        comm_rid.RIDManager
	chainKey   comm_rid.RIDManager
	hash_mgr   comm_hash.HashManager
	commit_mgr commitment.CommitmentManager

	vss_mgr comm_vss.VssKeyManager

	gamma    comm_ecdsa.ECDSAKeyManager
	signK    comm_ecdsa.ECDSAKeyManager
	delta    comm_ecdsa.ECDSAKeyManager
	chi      comm_ecdsa.ECDSAKeyManager
	bigDelta comm_ecdsa.ECDSAKeyManager

	gamma_pek comm_pek.PaillierEncodedKeyManager
	signK_pek comm_pek.PaillierEncodedKeyManager

	delta_mta comm_mta.MtAManager
	chi_mta   comm_mta.MtAManager

	sigma     comm_result.SigmaStore
	signature comm_result.Signature

	pl *pool.Pool
}

func NewMPC(
	ksf keystore.KeystoreFactory,
	krf keyopts.KeyOptsFactory,
	vf vault.VaultFactory,
	keycfgstore comm_config.ConfigStore,
	signcfgstore comm_config.ConfigStore,
	keystatstore comm_state.MPCStateStore,
	signstatstore comm_state.MPCStateStore,
	msgstore comm_message.MessageStore,
	bcststore comm_message.MessageStore,
	pl *pool.Pool,
) *MPC {
	elgamal_kr := krf.NewKeyOpts(nil)
	elgamal_vault := vf.NewVault(nil)
	elgamal_ks := ksf.NewKeystore(elgamal_vault, elgamal_kr, nil)
	elgamal_km := elgamal.NewElgamalKeyManager(elgamal_ks, &elgamal.Config{Group: curve.Secp256k1{}})

	paillier_kr := krf.NewKeyOpts(nil)
	paillier_vault := vf.NewVault(nil)
	paillier_ks := ksf.NewKeystore(paillier_vault, paillier_kr, nil)
	paillier_km := sw_paillier.NewPaillierKeyManager(paillier_ks, pl)

	pedersen_kr := krf.NewKeyOpts(nil)
	pedersen_vault := vf.NewVault(nil)
	pedersen_ks := ksf.NewKeystore(pedersen_vault, pedersen_kr, nil)
	pedersen_km := sw_pedersen.NewPedersenKeymanager(pedersen_ks)

	vss_kr := krf.NewKeyOpts(nil)
	vss_vault := vf.NewVault(nil)
	vss_ks := ksf.NewKeystore(vss_vault, vss_kr, nil)
	vss_km := sw_vss.NewVssKeyManager(vss_ks, curve.Secp256k1{})

	ec_kr := krf.NewKeyOpts(nil)
	ec_vault := vf.NewVault(nil)
	ec_ks := ksf.NewKeystore(ec_vault, ec_kr, nil)
	sch_kr := krf.NewKeyOpts(nil)
	sch_vault := vf.NewVault(nil)
	sch_ks := ksf.NewKeystore(sch_vault, sch_kr, nil)
	ecdsa_km := sw_ecdsa.NewECDSAKeyManager(ec_ks, sch_ks, vss_km, &sw_ecdsa.Config{Group: curve.Secp256k1{}})

	ec_vss_kr := krf.NewKeyOpts(nil)
	ec_vss_ks := ksf.NewKeystore(ec_vault, ec_vss_kr, nil)
	ec_vss_km := sw_ecdsa.NewECDSAKeyManager(ec_vss_ks, sch_ks, vss_km, &sw_ecdsa.Config{Group: curve.Secp256k1{}})

	rid_kr := krf.NewKeyOpts(nil)
	rid_vault := vf.NewVault(nil)
	rid_ks := ksf.NewKeystore(rid_vault, rid_kr, nil)
	rid_km := sw_rid.NewRIDManager(rid_ks)

	chainKey_kr := krf.NewKeyOpts(nil)
	chainKey_vault := vf.NewVault(nil)
	chainKey_ks := ksf.NewKeystore(chainKey_vault, chainKey_kr, nil)
	chainKey_km := sw_rid.NewRIDManager(chainKey_ks)

	hash_kr := krf.NewKeyOpts(nil)
	hash_vault := vf.NewVault(nil)
	hash_ks := ksf.NewKeystore(hash_vault, hash_kr, nil)
	hash_mgr := sw_hash.NewHashManager(hash_ks)

	commit_keyopts := krf.NewKeyOpts(nil)
	commit_vault := vf.NewVault(nil)
	commit_ks := ksf.NewKeystore(commit_vault, commit_keyopts, nil)
	commit_mgr := commitment.NewCommitmentManagerImpl(commit_ks)

	sigma_kr := krf.NewKeyOpts(nil)
	sigma_vault := vf.NewVault(nil)
	sigma_ks := ksf.NewKeystore(sigma_vault, sigma_kr, nil)
	sigma := mpc_result.NewSigmaStore(sigma_ks)

	keycfgmgr := mpc_config.NewKeyConfigManager(keycfgstore)
	signcfgmgr := mpc_config.NewSignConfigManager(signcfgstore)

	keystatmgr := mpc_state.NewMPCStateManager(keystatstore)
	signstatmgr := mpc_state.NewMPCStateManager(signstatstore)

	msgmgr := mpc_message.NewMessageManager(msgstore)
	bcstmgr := mpc_message.NewMessageManager(bcststore)

	signature := mpc_result.NewSignStore()

	gamma_kr := krf.NewKeyOpts(nil)
	gamma_ks := ksf.NewKeystore(ec_vault, gamma_kr, nil)
	gamma_km := sw_ecdsa.NewECDSAKeyManager(gamma_ks, sch_ks, vss_km, &sw_ecdsa.Config{Group: curve.Secp256k1{}})

	signK_kr := krf.NewKeyOpts(nil)
	signK_ks := ksf.NewKeystore(ec_vault, signK_kr, nil)
	signK_km := sw_ecdsa.NewECDSAKeyManager(signK_ks, sch_ks, vss_km, &sw_ecdsa.Config{Group: curve.Secp256k1{}})

	delta_kr := krf.NewKeyOpts(nil)
	delta_ks := ksf.NewKeystore(ec_vault, delta_kr, nil)
	delta_km := sw_ecdsa.NewECDSAKeyManager(delta_ks, sch_ks, vss_km, &sw_ecdsa.Config{Group: curve.Secp256k1{}})

	chi_kr := krf.NewKeyOpts(nil)
	chi_ks := ksf.NewKeystore(ec_vault, chi_kr, nil)
	chi_km := sw_ecdsa.NewECDSAKeyManager(chi_ks, sch_ks, vss_km, &sw_ecdsa.Config{Group: curve.Secp256k1{}})

	bigDelta_kr := krf.NewKeyOpts(nil)
	bigDelta_ks := ksf.NewKeystore(ec_vault, bigDelta_kr, nil)
	bigDelta_km := sw_ecdsa.NewECDSAKeyManager(bigDelta_ks, sch_ks, vss_km, &sw_ecdsa.Config{Group: curve.Secp256k1{}})

	gamma_pek_vault := vf.NewVault(nil)
	gamma_pek_kr := krf.NewKeyOpts(nil)
	gamma_pek_ks := ksf.NewKeystore(gamma_pek_vault, gamma_pek_kr, nil)
	gamma_pek_mgr := sw_pek.NewPaillierEncodedKeyManager(gamma_pek_ks)

	signK_pek_vault := vf.NewVault(nil)
	signK_pek_kr := krf.NewKeyOpts(nil)
	signK_pek_ks := ksf.NewKeystore(signK_pek_vault, signK_pek_kr, nil)
	signK_pek_mgr := sw_pek.NewPaillierEncodedKeyManager(signK_pek_ks)

	delta_mta_vault := vf.NewVault(nil)
	delta_mta_kr := krf.NewKeyOpts(nil)
	delta_mta_ks := ksf.NewKeystore(delta_mta_vault, delta_mta_kr, nil)
	delta_mta_km := sw_mta.NewMtAManager(delta_mta_ks)

	chi_mta_vault := vf.NewVault(nil)
	chi_mta_kr := krf.NewKeyOpts(nil)
	chi_mta_ks := ksf.NewKeystore(chi_mta_vault, chi_mta_kr, nil)
	chi_mta_km := sw_mta.NewMtAManager(chi_mta_ks)

	return &MPC{
		keycfgmgr:   keycfgmgr,
		signcfgmgr:  signcfgmgr,
		keystatmgr:  keystatmgr,
		signstatmgr: signstatmgr,
		msgmgr:      msgmgr,
		bcstmgr:     bcstmgr,
		elgamal:     elgamal_km,
		paillier:    paillier_km,
		pedersen:    pedersen_km,
		ec:          ecdsa_km,
		ec_vss:      ec_vss_km,
		vss_mgr:     vss_km,
		rid:         rid_km,
		chainKey:    chainKey_km,
		hash_mgr:    hash_mgr,
		commit_mgr:  commit_mgr,
		gamma:       gamma_km,
		signK:       signK_km,
		delta:       delta_km,
		chi:         chi_km,
		bigDelta:    bigDelta_km,
		gamma_pek:   gamma_pek_mgr,
		signK_pek:   signK_pek_mgr,
		delta_mta:   delta_mta_km,
		chi_mta:     chi_mta_km,
		sigma:       sigma,
		signature:   signature,
		pl:          pl,
	}
}

func (mpc *MPC) NewMPCKeygenManager() *keygen.MPCKeygen {
	return keygen.NewMPCKeygen(
		mpc.keycfgmgr,
		mpc.keystatmgr,
		mpc.msgmgr,
		mpc.bcstmgr,
		mpc.elgamal,
		mpc.paillier,
		mpc.pedersen,
		mpc.ec,
		mpc.ec_vss,
		mpc.vss_mgr,
		mpc.rid,
		mpc.chainKey,
		mpc.hash_mgr,
		mpc.commit_mgr,
		mpc.pl,
	)
}

func (mpc *MPC) NewMPCSignManager() *sign.MPCSign {
	return sign.NewMPCSign(
		mpc.signcfgmgr,
		mpc.signstatmgr,
		mpc.msgmgr,
		mpc.bcstmgr,
		mpc.hash_mgr,
		mpc.paillier,
		mpc.pedersen,
		mpc.ec,
		mpc.ec_vss,
		mpc.vss_mgr,
		mpc.gamma,
		mpc.signK,
		mpc.delta,
		mpc.chi,
		mpc.bigDelta,
		mpc.gamma_pek,
		mpc.signK_pek,
		mpc.delta_mta,
		mpc.chi_mta,
		mpc.sigma,
		mpc.signature,
	)
}

// Config represents the stored state of a party who participated in a successful `Keygen` protocol.
// It contains secret key material and should be safely stored.
type Config = config.Config

// EmptyConfig creates an empty Config with a fixed group, ready for unmarshalling.
//
// This needs to be used for unmarshalling, otherwise the points on the curve can't
// be decoded.
func EmptyConfig(group curve.Curve) *Config {
	return &Config{
		Group: group,
	}
}

// Keygen generates a new shared ECDSA key over the curve defined by `group`. After a successful execution,
// all participants posses a unique share of this key, as well as auxiliary parameters required during signing.
//
// For better performance, a `pool.Pool` can be provided in order to parallelize certain steps of the protocol.
// Returns *cmp.Config if successful.
func (mpc *MPC) Keygen(cfg comm_config.KeyConfig, pl *pool.Pool) protocol.StartFunc {
	mpckg := mpc.NewMPCKeygenManager()
	return mpckg.Start(cfg, pl)
}

// Sign generates an ECDSA signature for `messageHash` among the given `signers`.
// Returns *ecdsa.Signature if successful.
func (mpc *MPC) Sign(cfg comm_config.SignConfig, pl *pool.Pool) protocol.StartFunc {
	mpcsign := mpc.NewMPCSignManager()
	return mpcsign.StartSign(cfg, pl)
}
