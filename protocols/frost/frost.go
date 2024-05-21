package frost

import (
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/pool"
	"github.com/mr-shifu/mpc-lib/core/protocol"

	comm_commitment "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/commitment"
	comm_ecdsa "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/ecdsa"
	comm_hash "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/hash"
	comm_rid "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/rid"
	comm_vss "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/vss"
	"github.com/mr-shifu/mpc-lib/pkg/common/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/common/keystore"
	"github.com/mr-shifu/mpc-lib/pkg/common/vault"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/commitment"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/ecdsa"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/hash"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/rid"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/vss"
	comm_config "github.com/mr-shifu/mpc-lib/pkg/mpc/common/config"
	comm_msg "github.com/mr-shifu/mpc-lib/pkg/mpc/common/message"
	comm_result "github.com/mr-shifu/mpc-lib/pkg/mpc/common/result"
	comm_state "github.com/mr-shifu/mpc-lib/pkg/mpc/common/state"
	mpc_config "github.com/mr-shifu/mpc-lib/pkg/mpc/config"
	mpc_msg "github.com/mr-shifu/mpc-lib/pkg/mpc/message"
	edsig "github.com/mr-shifu/mpc-lib/pkg/mpc/result/eddsa"
	mpc_state "github.com/mr-shifu/mpc-lib/pkg/mpc/state"
	"github.com/mr-shifu/mpc-lib/protocols/frost/keygen"
	"github.com/mr-shifu/mpc-lib/protocols/frost/sign"
)

type FROST struct {
	keyconfigmgr comm_config.KeyConfigManager
	signcfgmgr   comm_config.SignConfigManager

	keystatemgr  comm_state.MPCStateManager
	signstatemgr comm_state.MPCStateManager
	msgmgr       comm_msg.MessageManager
	bcstmgr      comm_msg.MessageManager
	ecdsa_km     comm_ecdsa.ECDSAKeyManager
	ec_vss_km    comm_ecdsa.ECDSAKeyManager
	vss_mgr      comm_vss.VssKeyManager
	chainKey_km  comm_rid.RIDManager
	hash_mgr     comm_hash.HashManager
	commit_mgr   comm_commitment.CommitmentManager

	sigmgr     comm_result.EddsaSignatureManager
	ec_sign_km comm_ecdsa.ECDSAKeyManager
	sign_d     comm_ecdsa.ECDSAKeyManager
	sign_e     comm_ecdsa.ECDSAKeyManager

	pl *pool.Pool
}

func NewFROST(
	ksf keystore.KeystoreFactory,
	krf keyopts.KeyOptsFactory,
	vf vault.VaultFactory,
	keycfgstore comm_config.ConfigStore,
	signcfgstore comm_config.ConfigStore,
	keystatstore comm_state.MPCStateStore,
	signstatstore comm_state.MPCStateStore,
	msgstore comm_msg.MessageStore,
	bcststore comm_msg.MessageStore,
	pl *pool.Pool,
) *FROST {
	keycfgmr := mpc_config.NewKeyConfigManager(keycfgstore)

	keystatestore := mpc_state.NewInMemoryStateStore()
	keystatemgr := mpc_state.NewMPCStateManager(keystatestore)

	signstatestore := mpc_state.NewInMemoryStateStore()
	signstatemgr := mpc_state.NewMPCStateManager(signstatestore)

	msgmgr := mpc_msg.NewMessageManager(msgstore)
	bcstmgr := mpc_msg.NewMessageManager(bcststore)

	vss_keyopts := krf.NewKeyOpts(nil)
	vss_vault := vf.NewVault(nil)
	vss_ks := ksf.NewKeystore(vss_vault, vss_keyopts, nil)
	vss_km := vss.NewVssKeyManager(vss_ks, curve.Secp256k1{})

	ec_keyopts := krf.NewKeyOpts(nil)
	ec_vault := vf.NewVault(nil)
	ec_ks := ksf.NewKeystore(ec_vault, ec_keyopts, nil)
	sch_keyopts := krf.NewKeyOpts(nil)
	sch_vault := vf.NewVault(nil)
	sch_ks := ksf.NewKeystore(sch_vault, sch_keyopts, nil)
	ecdsa_km := ecdsa.NewECDSAKeyManager(ec_ks, sch_ks, vss_km, &ecdsa.Config{Group: curve.Secp256k1{}})

	ec_vss_keyopts := krf.NewKeyOpts(nil)
	ec_vss_ks := ksf.NewKeystore(ec_vault, ec_vss_keyopts, nil)
	ec_vss_km := ecdsa.NewECDSAKeyManager(ec_vss_ks, sch_ks, vss_km, &ecdsa.Config{Group: curve.Secp256k1{}})

	chainKey_keyopts := krf.NewKeyOpts(nil)
	chainKey_vault := vf.NewVault(nil)
	chainKey_ks := ksf.NewKeystore(chainKey_vault, chainKey_keyopts, nil)
	chainKey_km := rid.NewRIDManager(chainKey_ks)

	hahs_keyopts := krf.NewKeyOpts(nil)
	hahs_vault := vf.NewVault(nil)
	hash_ks := ksf.NewKeystore(hahs_vault, hahs_keyopts, nil)
	hash_mgr := hash.NewHashManager(hash_ks)

	commit_keyopts := krf.NewKeyOpts(nil)
	commit_vault := vf.NewVault(nil)
	commit_ks := ksf.NewKeystore(commit_vault, commit_keyopts, nil)
	commit_mgr := commitment.NewCommitmentManager(commit_ks)

	signcfgmgr := mpc_config.NewSignConfigManager(signcfgstore)

	edsig_keyopts := krf.NewKeyOpts(nil)
	edsigstore := edsig.NewInMemoryEddsaSignature(edsig_keyopts)
	edsigmgr := edsig.NewEddsaSignatureManager(edsigstore)

	ec_sign_keyopts := krf.NewKeyOpts(nil)
	ec_sign_ks := ksf.NewKeystore(ec_vault, ec_sign_keyopts, nil)
	ec_sign_km := ecdsa.NewECDSAKeyManager(ec_sign_ks, sch_ks, vss_km, &ecdsa.Config{Group: curve.Secp256k1{}})

	sign_d_keyopts := krf.NewKeyOpts(nil)
	sign_d_ks := ksf.NewKeystore(ec_vault, sign_d_keyopts, nil)
	sign_d_km := ecdsa.NewECDSAKeyManager(sign_d_ks, sch_ks, vss_km, &ecdsa.Config{Group: curve.Secp256k1{}})

	sign_e_keyopts := krf.NewKeyOpts(nil)
	sign_e_ks := ksf.NewKeystore(ec_vault, sign_e_keyopts, nil)
	sign_e_km := ecdsa.NewECDSAKeyManager(sign_e_ks, sch_ks, vss_km, &ecdsa.Config{Group: curve.Secp256k1{}})

	return &FROST{
		keyconfigmgr: keycfgmr,
		keystatemgr:  keystatemgr,
		msgmgr:       msgmgr,
		bcstmgr:      bcstmgr,
		ecdsa_km:     ecdsa_km,
		vss_mgr:      vss_km,
		ec_vss_km:    ec_vss_km,
		chainKey_km:  chainKey_km,
		hash_mgr:     hash_mgr,
		commit_mgr:   commit_mgr,

		signcfgmgr:   signcfgmgr,
		signstatemgr: signstatemgr,
		sigmgr:       edsigmgr,
		ec_sign_km:   ec_sign_km,
		sign_d:       sign_d_km,
		sign_e:       sign_e_km,
	}
}

func (frost *FROST) NewMPCKeygenManager() *keygen.FROSTKeygen {
	return keygen.NewFROSTKeygen(
		frost.keyconfigmgr,
		frost.keystatemgr,
		frost.msgmgr,
		frost.bcstmgr,
		frost.ecdsa_km,
		frost.ec_vss_km,
		frost.vss_mgr,
		frost.chainKey_km,
		frost.hash_mgr,
		frost.commit_mgr,
		frost.pl,
	)
}

func (frost *FROST) NewMPCSignManager() *sign.FROSTSign {
	return sign.NewFROSTSign(
		frost.signcfgmgr,
		frost.signstatemgr,
		frost.sigmgr,
		frost.msgmgr,
		frost.bcstmgr,
		frost.ecdsa_km,
		frost.ec_vss_km,
		frost.ec_sign_km,
		frost.vss_mgr,
		frost.sign_d,
		frost.sign_e,
		frost.hash_mgr,
		frost.pl,
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
		PublicKey: group.NewPoint(),
	}
}

// Keygen generates a new shared ECDSA key over the curve defined by `group`. After a successful execution,
// all participants posses a unique share of this key, as well as auxiliary parameters required during signing.
//
// For better performance, a `pool.Pool` can be provided in order to parallelize certain steps of the protocol.
// Returns *cmp.Config if successful.
func (frost *FROST) Keygen(cfg comm_config.KeyConfig, pl *pool.Pool) protocol.StartFunc {
	kg := frost.NewMPCKeygenManager()
	return kg.Start(cfg)
}

// Sign generates an ECDSA signature for `messageHash` among the given `signers`.
// Returns *ecdsa.Signature if successful.
func (frost *FROST) Sign(cfg comm_config.SignConfig, pl *pool.Pool) protocol.StartFunc {
	sign := frost.NewMPCSignManager()
	return sign.Start(cfg)
}
