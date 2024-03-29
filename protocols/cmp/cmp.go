package cmp

import (
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

	sw_pek "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/paillierencodedkey"
	comm_pek "github.com/mr-shifu/mpc-lib/pkg/mpc/common/pek"
	mpc_pek "github.com/mr-shifu/mpc-lib/pkg/mpc/pekmanager"

	"github.com/mr-shifu/mpc-lib/pkg/common/commitstore"
	comm_hash "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/hash"
	"github.com/mr-shifu/mpc-lib/pkg/common/keyrepository"
	sw_hash "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/hash"

	comm_mpckey "github.com/mr-shifu/mpc-lib/pkg/mpc/common/mpckey"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/mpckey"

	"github.com/mr-shifu/mpc-lib/pkg/common/keystore"
	sw_mta "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/mta"
	inmem_keyrepo "github.com/mr-shifu/mpc-lib/pkg/keyrepository"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/commitment"
	comm_commitment "github.com/mr-shifu/mpc-lib/pkg/mpc/common/commitment"
	comm_config "github.com/mr-shifu/mpc-lib/pkg/mpc/common/config"
	comm_mta "github.com/mr-shifu/mpc-lib/pkg/mpc/common/mta"
	comm_result "github.com/mr-shifu/mpc-lib/pkg/mpc/common/result"
	comm_vss "github.com/mr-shifu/mpc-lib/pkg/mpc/common/vss"
	mpc_vss "github.com/mr-shifu/mpc-lib/pkg/mpc/vss"
	mpc_config "github.com/mr-shifu/mpc-lib/pkg/mpc/config"
	mpc_mta "github.com/mr-shifu/mpc-lib/pkg/mpc/mta"
	mpc_result "github.com/mr-shifu/mpc-lib/pkg/mpc/result"
	"github.com/mr-shifu/mpc-lib/protocols/cmp/config"
	"github.com/mr-shifu/mpc-lib/protocols/cmp/sign"

	"github.com/mr-shifu/mpc-lib/protocols/cmp/keygen"
)

type MPC struct {
	signcfg comm_config.SignConfigManager

	elgamal    comm_elgamal.ElgamalKeyManager
	paillier   comm_paillier.PaillierKeyManager
	pedersen   comm_pedersen.PedersenKeyManager
	ec         comm_ecdsa.ECDSAKeyManager
	rid        comm_rid.RIDKeyManager
	chainKey   comm_rid.RIDKeyManager
	hash_mgr   comm_hash.HashManager
	mpc_ks     comm_mpckey.MPCKeystore
	commit_mgr comm_commitment.CommitmentManager

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
	krf keyrepository.KeyRepositoryFactory,
	commit_ks commitstore.CommitStore,
	pl *pool.Pool,
) *MPC {
	mpc_ks := mpckey.NewInMemoryMPCKeystore()

	elgamal_ks := ksf.NewKeystore(nil)
	elgamal_kr := krf.NewKeyRepository(nil)
	elgamal_km := sw_elgamal.NewElgamalKeyManager(elgamal_ks, &sw_elgamal.Config{Group: curve.Secp256k1{}})
	elgamal := mpc_elgamal.NewElgamal(elgamal_km, elgamal_kr)

	paillier_ks := ksf.NewKeystore(nil)
	paillier_kr := krf.NewKeyRepository(nil)
	paillier_km := sw_paillier.NewPaillierKeyManager(paillier_ks, pl)
	paillier := mpc_paillier.NewPaillierKeyManager(paillier_km, paillier_kr)

	pedersen_ks := ksf.NewKeystore(nil)
	pedersen_kr := krf.NewKeyRepository(nil)
	pedersen_km := sw_pedersen.NewPedersenKeymanager(pedersen_ks)
	pedersen := mpc_pedersen.NewPedersenKeyManager(pedersen_km, pedersen_kr)

	vss_ks := ksf.NewKeystore(nil)
	vss_kr := krf.NewKeyRepository(nil)
	vss_km := sw_vss.NewVssKeyManager(vss_ks, curve.Secp256k1{})

	ecdsa_ks := ksf.NewKeystore(nil)
	ecdsa_kr := krf.NewKeyRepository(nil)
	sch_ks := ksf.NewKeystore(nil)
	ecdsa_km := sw_ecdsa.NewECDSAKeyManager(ecdsa_ks, sch_ks, vss_km, &sw_ecdsa.Config{Group: curve.Secp256k1{}})
	ecdsa := mpc_ecdsa.NewECDSA(ecdsa_km, ecdsa_kr, vss_km, vss_kr)

	ec_vss_kr := krf.NewKeyRepository(nil)
	vss_mgr := mpc_vss.NewVSS(vss_km, vss_kr, ecdsa_km, ec_vss_kr)

	rid_ks := ksf.NewKeystore(nil)
	rid_kr := krf.NewKeyRepository(nil)
	rid_km := sw_rid.NewRIDManager(rid_ks)
	rid := mpc_rid.NewRIDKeyManager(rid_km, rid_kr)

	chainKey_ks := ksf.NewKeystore(nil)
	chainKey_kr := krf.NewKeyRepository(nil)
	chainKey_km := sw_rid.NewRIDManager(chainKey_ks)
	chainKey := mpc_rid.NewRIDKeyManager(chainKey_km, chainKey_kr)

	hash_ks := ksf.NewKeystore(nil)
	hash_mgr := sw_hash.NewHashManager(hash_ks)

	commit_kr := krf.NewKeyRepository(nil)
	commit_mgr := commitment.NewCommitmentManager(commit_ks, commit_kr)

	sigma_ks := ksf.NewKeystore(nil)
	sigma_kr := krf.NewKeyRepository(nil)
	sigma := mpc_result.NewSigmaStore(sigma_ks, sigma_kr)

	sign_cfg := mpc_config.NewSignConfigManager()

	signature := mpc_result.NewSignStore()

	gamma_kr := krf.NewKeyRepository(nil)
	gamma_mgr := mpc_ecdsa.NewECDSA(ecdsa_km, gamma_kr, nil, nil)

	signK_kr := inmem_keyrepo.NewKeyRepository()
	signK_mgr := mpc_ecdsa.NewECDSA(ecdsa_km, signK_kr, nil, nil)

	delta_kr := inmem_keyrepo.NewKeyRepository()
	delta_mgr := mpc_ecdsa.NewECDSA(ecdsa_km, delta_kr, nil, nil)

	chi_kr := inmem_keyrepo.NewKeyRepository()
	chi_mgr := mpc_ecdsa.NewECDSA(ecdsa_km, chi_kr, nil, nil)

	bigDelta_kr := inmem_keyrepo.NewKeyRepository()
	bigDelta_mgr := mpc_ecdsa.NewECDSA(ecdsa_km, bigDelta_kr, nil, nil)

	pek_ks := ksf.NewKeystore(nil)
	pek_mgr := sw_pek.NewPaillierEncodedKeyManager(pek_ks)

	gamma_pek_kr := krf.NewKeyRepository(nil)
	gamma_pek := mpc_pek.NewPaillierKeyManager(pek_mgr, gamma_pek_kr)

	signK_pek_kr := krf.NewKeyRepository(nil)
	signK_pek := mpc_pek.NewPaillierKeyManager(pek_mgr, signK_pek_kr)

	mta_ks := ksf.NewKeystore(nil)
	delta_mta_kr := krf.NewKeyRepository(nil)
	mta_km := sw_mta.NewMtAManager(mta_ks)
	delta_mta := mpc_mta.NewPaillierKeyManager(mta_km, delta_mta_kr)

	chi_mta_kr := krf.NewKeyRepository(nil)
	chi_mta := mpc_mta.NewPaillierKeyManager(mta_km, chi_mta_kr)

	return &MPC{
		signcfg:    sign_cfg,
		mpc_ks:     mpc_ks,
		elgamal:    elgamal,
		paillier:   paillier,
		pedersen:   pedersen,
		ec:         ecdsa,
		vss_mgr:    vss_mgr,
		rid:        rid,
		chainKey:   chainKey,
		hash_mgr:   hash_mgr,
		commit_mgr: commit_mgr,
		gamma:      gamma_mgr,
		signK:      signK_mgr,
		delta:      delta_mgr,
		chi:        chi_mgr,
		bigDelta:   bigDelta_mgr,
		gamma_pek:  gamma_pek,
		signK_pek:  signK_pek,
		delta_mta:  delta_mta,
		chi_mta:    chi_mta,
		sigma:      sigma,
		signature:  signature,
		pl:         pl,
	}
}

func (mpc *MPC) NewMPCKeygenManager() *keygen.MPCKeygen {
	return keygen.NewMPCKeygen(
		mpc.elgamal,
		mpc.paillier,
		mpc.pedersen,
		mpc.ec,
		mpc.vss_mgr,
		mpc.rid,
		mpc.chainKey,
		mpc.hash_mgr,
		mpc.mpc_ks,
		mpc.commit_mgr,
		mpc.pl,
	)
}

func (mpc *MPC) NewMPCSignManager() *sign.MPCSign {
	return sign.NewMPCSign(
		mpc.signcfg,
		mpc.hash_mgr,
		mpc.paillier,
		mpc.pedersen,
		mpc.ec,
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
func (mpc *MPC) Keygen(keyID string, group curve.Curve, selfID party.ID, participants []party.ID, threshold int, pl *pool.Pool) protocol.StartFunc {
	info := round.Info{
		ProtocolID:       "cmp/keygen-threshold",
		FinalRoundNumber: keygen.Rounds,
		SelfID:           selfID,
		PartyIDs:         participants,
		Threshold:        threshold,
		Group:            group,
	}
	mpckg := keygen.NewMPCKeygen(
		mpc.elgamal,
		mpc.paillier,
		mpc.pedersen,
		mpc.ec,
		mpc.vss_mgr,
		mpc.rid,
		mpc.chainKey,
		mpc.hash_mgr,
		mpc.mpc_ks,
		mpc.commit_mgr,
		pl,
	)
	return mpckg.Start(keyID, info, pl, nil)
}

// Sign generates an ECDSA signature for `messageHash` among the given `signers`.
// Returns *ecdsa.Signature if successful.
func (mpc *MPC) Sign(signID string, keyID string, info round.Info, signers []party.ID, messageHash []byte, pl *pool.Pool) protocol.StartFunc {
	mpcsign := sign.NewMPCSign(
		mpc.signcfg,
		mpc.hash_mgr,
		mpc.paillier,
		mpc.pedersen,
		mpc.ec,
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

	return mpcsign.StartSign(signID, keyID, info, signers, messageHash, pl)
}
