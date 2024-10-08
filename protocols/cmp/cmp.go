package cmp

import (
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/pool"
	"github.com/mr-shifu/mpc-lib/core/protocol"

	"github.com/mr-shifu/mpc-lib/pkg/common/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/common/keystore"
	"github.com/mr-shifu/mpc-lib/pkg/common/vault"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/commitment"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/ecdsa"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/elgamal"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/hash"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/mta"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/paillier"
	pek "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/paillierencodedkey"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/pedersen"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/rid"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/vss"
	comm_config "github.com/mr-shifu/mpc-lib/pkg/mpc/common/config"
	comm_message "github.com/mr-shifu/mpc-lib/pkg/mpc/common/message"
	comm_result "github.com/mr-shifu/mpc-lib/pkg/mpc/common/result"
	comm_state "github.com/mr-shifu/mpc-lib/pkg/mpc/common/state"
	mpc_config "github.com/mr-shifu/mpc-lib/pkg/mpc/config"
	mpc_message "github.com/mr-shifu/mpc-lib/pkg/mpc/message"
	ecsig "github.com/mr-shifu/mpc-lib/pkg/mpc/result/ecdsa"
	mpc_state "github.com/mr-shifu/mpc-lib/pkg/mpc/state"
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
	ec_key     ecdsa.ECDSAKeyManager
	ec_vss     ecdsa.ECDSAKeyManager
	rid        rid.RIDManager
	chainKey   rid.RIDManager
	hash_mgr   hash.HashManager
	commit_mgr commitment.CommitmentManager

	vss_mgr vss.VssKeyManager

	ec_sig   ecdsa.ECDSAKeyManager
	gamma    ecdsa.ECDSAKeyManager
	signK    ecdsa.ECDSAKeyManager
	delta    ecdsa.ECDSAKeyManager
	chi      ecdsa.ECDSAKeyManager
	bigDelta ecdsa.ECDSAKeyManager

	gamma_pek pek.PaillierEncodedKeyManager
	signK_pek pek.PaillierEncodedKeyManager

	delta_mta mta.MtAManager
	chi_mta   mta.MtAManager

	sigmgr comm_result.EcdsaSignatureManager

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
	paillier_km := paillier.NewPaillierKeyManager(paillier_ks, pl)

	pedersen_kr := krf.NewKeyOpts(nil)
	pedersen_vault := vf.NewVault(nil)
	pedersen_ks := ksf.NewKeystore(pedersen_vault, pedersen_kr, nil)
	pedersen_km := pedersen.NewPedersenKeymanager(pedersen_ks)

	vss_kr := krf.NewKeyOpts(nil)
	vss_vault := vf.NewVault(nil)
	vss_ks := ksf.NewKeystore(vss_vault, vss_kr, nil)
	vss_km := vss.NewVssKeyManager(vss_ks, curve.Secp256k1{})

	ec_kr := krf.NewKeyOpts(nil)
	ec_vault := vf.NewVault(nil)
	ec_ks := ksf.NewKeystore(ec_vault, ec_kr, nil)
	sch_kr := krf.NewKeyOpts(nil)
	sch_vault := vf.NewVault(nil)
	sch_ks := ksf.NewKeystore(sch_vault, sch_kr, nil)
	ecdsa_km := ecdsa.NewECDSAKeyManager(ec_ks, sch_ks, vss_km, &ecdsa.Config{Group: curve.Secp256k1{}})

	ec_vss_kr := krf.NewKeyOpts(nil)
	ec_vss_ks := ksf.NewKeystore(ec_vault, ec_vss_kr, nil)
	ec_vss_km := ecdsa.NewECDSAKeyManager(ec_vss_ks, sch_ks, vss_km, &ecdsa.Config{Group: curve.Secp256k1{}})

	rid_kr := krf.NewKeyOpts(nil)
	rid_vault := vf.NewVault(nil)
	rid_ks := ksf.NewKeystore(rid_vault, rid_kr, nil)
	rid_km := rid.NewRIDManagerImpl(rid_ks)

	chainKey_kr := krf.NewKeyOpts(nil)
	chainKey_vault := vf.NewVault(nil)
	chainKey_ks := ksf.NewKeystore(chainKey_vault, chainKey_kr, nil)
	chainKey_km := rid.NewRIDManagerImpl(chainKey_ks)

	hash_kr := krf.NewKeyOpts(nil)
	hash_vault := vf.NewVault(nil)
	hash_ks := ksf.NewKeystore(hash_vault, hash_kr, nil)
	hash_mgr := hash.NewHashManager(hash_ks)

	commit_keyopts := krf.NewKeyOpts(nil)
	commit_vault := vf.NewVault(nil)
	commit_ks := ksf.NewKeystore(commit_vault, commit_keyopts, nil)
	commit_mgr := commitment.NewCommitmentManagerImpl(commit_ks)

	keycfgmgr := mpc_config.NewKeyConfigManager(keycfgstore)
	signcfgmgr := mpc_config.NewSignConfigManager(signcfgstore)

	keystatmgr := mpc_state.NewMPCStateManager(keystatstore)
	signstatmgr := mpc_state.NewMPCStateManager(signstatstore)

	msgmgr := mpc_message.NewMessageManager(msgstore)
	bcstmgr := mpc_message.NewMessageManager(bcststore)

	ecsig_keyopts := krf.NewKeyOpts(nil)
	ecsigstore := ecsig.NewInMemoryEcdsaSignature(ecsig_keyopts)
	ecsigmgr := ecsig.NewEcdsaSignatureManager(ecsigstore)

	ec_sig_kr := krf.NewKeyOpts(nil)
	ec_sig_ks := ksf.NewKeystore(ec_vault, ec_sig_kr, nil)
	ec_sig_km := ecdsa.NewECDSAKeyManager(ec_sig_ks, sch_ks, vss_km, &ecdsa.Config{Group: curve.Secp256k1{}})

	gamma_kr := krf.NewKeyOpts(nil)
	gamma_ks := ksf.NewKeystore(ec_vault, gamma_kr, nil)
	gamma_km := ecdsa.NewECDSAKeyManager(gamma_ks, sch_ks, vss_km, &ecdsa.Config{Group: curve.Secp256k1{}})

	signK_kr := krf.NewKeyOpts(nil)
	signK_ks := ksf.NewKeystore(ec_vault, signK_kr, nil)
	signK_km := ecdsa.NewECDSAKeyManager(signK_ks, sch_ks, vss_km, &ecdsa.Config{Group: curve.Secp256k1{}})

	delta_kr := krf.NewKeyOpts(nil)
	delta_ks := ksf.NewKeystore(ec_vault, delta_kr, nil)
	delta_km := ecdsa.NewECDSAKeyManager(delta_ks, sch_ks, vss_km, &ecdsa.Config{Group: curve.Secp256k1{}})

	chi_kr := krf.NewKeyOpts(nil)
	chi_ks := ksf.NewKeystore(ec_vault, chi_kr, nil)
	chi_km := ecdsa.NewECDSAKeyManager(chi_ks, sch_ks, vss_km, &ecdsa.Config{Group: curve.Secp256k1{}})

	bigDelta_kr := krf.NewKeyOpts(nil)
	bigDelta_ks := ksf.NewKeystore(ec_vault, bigDelta_kr, nil)
	bigDelta_km := ecdsa.NewECDSAKeyManager(bigDelta_ks, sch_ks, vss_km, &ecdsa.Config{Group: curve.Secp256k1{}})

	gamma_pek_vault := vf.NewVault(nil)
	gamma_pek_kr := krf.NewKeyOpts(nil)
	gamma_pek_ks := ksf.NewKeystore(gamma_pek_vault, gamma_pek_kr, nil)
	gamma_pek_mgr := pek.NewPaillierEncodedKeyManager(gamma_pek_ks)

	signK_pek_vault := vf.NewVault(nil)
	signK_pek_kr := krf.NewKeyOpts(nil)
	signK_pek_ks := ksf.NewKeystore(signK_pek_vault, signK_pek_kr, nil)
	signK_pek_mgr := pek.NewPaillierEncodedKeyManager(signK_pek_ks)

	delta_mta_vault := vf.NewVault(nil)
	delta_mta_kr := krf.NewKeyOpts(nil)
	delta_mta_ks := ksf.NewKeystore(delta_mta_vault, delta_mta_kr, nil)
	delta_mta_km := mta.NewMtAManager(delta_mta_ks)

	chi_mta_vault := vf.NewVault(nil)
	chi_mta_kr := krf.NewKeyOpts(nil)
	chi_mta_ks := ksf.NewKeystore(chi_mta_vault, chi_mta_kr, nil)
	chi_mta_km := mta.NewMtAManager(chi_mta_ks)

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
		ec_key:      ecdsa_km,
		ec_vss:      ec_vss_km,
		vss_mgr:     vss_km,
		rid:         rid_km,
		chainKey:    chainKey_km,
		hash_mgr:    hash_mgr,
		commit_mgr:  commit_mgr,
		ec_sig:      ec_sig_km,
		gamma:       gamma_km,
		signK:       signK_km,
		delta:       delta_km,
		chi:         chi_km,
		bigDelta:    bigDelta_km,
		gamma_pek:   gamma_pek_mgr,
		signK_pek:   signK_pek_mgr,
		delta_mta:   delta_mta_km,
		chi_mta:     chi_mta_km,
		sigmgr:      ecsigmgr,
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
		mpc.ec_key,
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
		mpc.ec_key,
		mpc.ec_sig,
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
		mpc.sigmgr,
		mpc.pl,
	)
}

// Config represents the stored state of a party who participated in a successful `Keygen` protocol.
// It contains secret key material and should be safely stored.
type Config = keygen.Config

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
func (mpc *MPC) Keygen(cfg comm_config.KeyConfig) protocol.StartFunc {
	mpckg := mpc.NewMPCKeygenManager()
	return mpckg.Start(cfg)
}

// Sign generates an ECDSA signature for `messageHash` among the given `signers`.
// Returns *ecdsa.Signature if successful.
func (mpc *MPC) Sign(cfg comm_config.SignConfig) protocol.StartFunc {
	mpcsign := mpc.NewMPCSignManager()
	return mpcsign.Start(cfg)
}
