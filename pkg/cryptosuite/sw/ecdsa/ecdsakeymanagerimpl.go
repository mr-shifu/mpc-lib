package ecdsa

import (
	"encoding/hex"

	"github.com/cronokirby/saferith"
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	core_paillier "github.com/mr-shifu/mpc-lib/core/paillier"
	zkaffg "github.com/mr-shifu/mpc-lib/core/zk/affg"
	zkenc "github.com/mr-shifu/mpc-lib/core/zk/enc"
	zklogstar "github.com/mr-shifu/mpc-lib/core/zk/logstar"
	"github.com/mr-shifu/mpc-lib/lib/mta"
	"github.com/mr-shifu/mpc-lib/pkg/common/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/common/keystore"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/hash"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/paillier"
	cs_paillier "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/paillier"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/paillierencodedkey"
	pek "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/paillierencodedkey"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/pedersen"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/vss"
	"github.com/pkg/errors"
)

type Config struct {
	Group curve.Curve
}

type ECDSAKeyManagerImpl struct {
	keystore keystore.Keystore
	schstore keystore.Keystore
	vssmgr   vss.VssKeyManager
	cfg      *Config
}

func NewECDSAKeyManager(
	store keystore.Keystore,
	schstore keystore.Keystore,
	vssmgr vss.VssKeyManager,
	cfg *Config) *ECDSAKeyManagerImpl {
	return &ECDSAKeyManagerImpl{
		keystore: store,
		schstore: schstore,
		vssmgr:   vssmgr,
		cfg:      cfg,
	}
}

func (mgr *ECDSAKeyManagerImpl) GenerateKey(opts keyopts.Options) (ECDSAKey, error) {
	key, err := GenerateKey(mgr.cfg.Group)
	if err != nil {
		return nil, err
	}

	decoded, err := key.Bytes()
	if err != nil {
		return nil, err
	}

	// get key SKI and encode it to hex string as keyID
	ski := key.SKI()
	keyID := hex.EncodeToString(ski)

	// import the decoded key to the keystore with keyID
	if err := mgr.keystore.Import(keyID, decoded, opts); err != nil {
		return nil, err
	}

	// return the key pair
	return key.withVSSKeyMgr(mgr.vssmgr), nil
}

func (mgr *ECDSAKeyManagerImpl) ImportKey(raw interface{}, opts keyopts.Options) (ECDSAKey, error) {
	var err error
	key := &ECDSAKeyImpl{}

	switch raw := raw.(type) {
	case []byte:
		key, err = fromBytes(raw)
		if err != nil {
			return nil, err
		}
	case *ECDSAKeyImpl:
		key = raw
	}

	// decode the key
	kb, err := key.Bytes()
	if err != nil {
		return nil, err
	}

	// get key SKI and encode it to hex string as keyID
	ski := key.SKI()
	keyID := hex.EncodeToString(ski)

	// import the decoded key to the keystore with keyID
	if err := mgr.keystore.Import(keyID, kb, opts); err != nil {
		return nil, err
	}

	return key.withVSSKeyMgr(mgr.vssmgr), nil
}

func (mgr *ECDSAKeyManagerImpl) GetKey(opts keyopts.Options) (ECDSAKey, error) {
	// get the key from the keystore
	// keyID := hex.EncodeToString(ski)
	decoded, err := mgr.keystore.Get(opts)
	if err != nil {
		return nil, err
	}

	// decode the key
	k, err := fromBytes(decoded)
	if err != nil {
		return nil, err
	}

	return k.withVSSKeyMgr(mgr.vssmgr), nil
}

func (mgr *ECDSAKeyManagerImpl) SumKeys(optsList ...keyopts.Options) (ECDSAKey, error) {
	group := curve.Secp256k1{}
	priv := group.NewScalar()
	pub := group.NewPoint()

	for i := 0; i < len(optsList); i++ {
		opts := optsList[i]
		k, err := mgr.GetKey(opts)
		if err != nil {
			return nil, errors.WithMessage(err, "ecdsa: failed to get key from keystore")
		}

		key, ok := k.(*ECDSAKeyImpl)
		if !ok {
			return nil, errors.New("ecdsa: invalid key type")
		}

		if i == 0 {
			priv = key.priv
			pub = key.pub
			continue
		}

		priv = priv.Add(key.priv)
		pub = pub.Add(key.pub)
	}

	priv = group.NewScalar().SetNat(curve.MakeInt(priv).Mod(group.Order()))

	return NewKey(priv, pub, group), nil
}

func (mgr *ECDSAKeyManagerImpl) GenerateSchnorrCommitment(h hash.Hash, opts keyopts.Options) (*Proof, error) {
	k, err := mgr.GetKey(opts)
	if err != nil {
		return nil, errors.WithMessage(err, "ecdsa: failed to get key from keystore")
	}

	p := new(Proof)
	_, err = p.GenerateCommitment(h)
	if err != nil {
		return nil, errors.WithMessage(err, "ecdsa: failed to generate schnorr commitment")
	}
	pb, err := p.Bytes()
	if err != nil {
		return nil, errors.WithMessage(err, "ecdsa: failed to marshal schnorr commitment")
	}

	ski := hex.EncodeToString(k.SKI())
	if err := mgr.schstore.Import(ski, pb, opts); err != nil {
		return nil, errors.WithMessage(err, "ecdsa: failed to import schnorr proof to keystore")
	}

	return p, nil
}

func (mgr *ECDSAKeyManagerImpl) GenerateSchnorrResponse(h hash.Hash, opts keyopts.Options) (*Proof, error) {
	k, err := mgr.GetKey(opts)
	if err != nil {
		return nil, errors.WithMessage(err, "ecdsa: failed to get key from keystore")
	}

	key, ok := k.(*ECDSAKeyImpl)
	if !ok {
		return nil, errors.New("ecdsa: invalid key type")
	}

	p, err := mgr.GetSchnorrProof(opts)
	if err != nil {
		return nil, errors.WithMessage(err, "ecdsa: failed to get schnorr proof from keystore")
	}

	_, err = p.GenerateResponse(h, key.priv)
	if err != nil {
		return nil, errors.WithMessage(err, "ecdsa: failed to generate schnorr response")
	}

	return p, nil
}

func (mgr *ECDSAKeyManagerImpl) VerifySchnorrProof(h hash.Hash, opts keyopts.Options) (bool, error) {
	k, err := mgr.GetKey(opts)
	if err != nil {
		return false, errors.WithMessage(err, "ecdsa: failed to get key from keystore")
	}

	pb, err := mgr.schstore.Get(opts)
	if err != nil {
		return false, errors.WithMessage(err, "ecdsa: failed to get schnorr proof from keystore")
	}

	p := new(Proof)
	if err := p.FromBytes(pb); err != nil {
		return false, errors.WithMessage(err, "ecdsa: failed to import schnorr proof")
	}

	return verifySchnorrProof(h, p, k.PublicKeyRaw())
}

func (mgr *ECDSAKeyManagerImpl) ImportSchnorrCommitment(cmt_byte []byte, opts keyopts.Options) error {
	cmt := new(Commitment)
	if err := cmt.FromBytes(cmt_byte); err != nil {
		return errors.WithMessage(err, "ecdsa: failed to import schnorr commitment")
	}

	p := NewProof(cmt, nil)
	pb, err := p.Bytes()
	if err != nil {
		return errors.WithMessage(err, "ecdsa: failed to marshal schnorr commitment")
	}

	k, err := mgr.GetKey(opts)
	if err != nil {
		return errors.WithMessage(err, "ecdsa: failed to get key from keystore")
	}

	ski := hex.EncodeToString(k.SKI())

	if err := mgr.schstore.Import(ski, pb, opts); err != nil {
		return errors.WithMessage(err, "ecdsa: failed to import schnorr proof to keystore")
	}

	return nil
}

func (mgr *ECDSAKeyManagerImpl) ImportSchnorrProofResponse(zb []byte, opts keyopts.Options) error {
	k, err := mgr.GetKey(opts)
	if err != nil {
		return errors.WithMessage(err, "ecdsa: failed to get key from keystore")
	}

	p, err := mgr.GetSchnorrProof(opts)
	if err != nil {
		return errors.WithMessage(err, "ecdsa: failed to import schnorr proof")
	}

	rsp := new(Response)
	if err := rsp.FromBytes(zb); err != nil {
		return errors.WithMessage(err, "ecdsa: failed to import schnorr response")
	}

	p.SetResponse(rsp)

	pb, err := p.Bytes()
	if err != nil {
		return errors.WithMessage(err, "ecdsa: failed to marshal schnorr proof")
	}

	ski := hex.EncodeToString(k.SKI())
	if err := mgr.schstore.Import(ski, pb, opts); err != nil {
		return errors.WithMessage(err, "ecdsa: failed to import schnorr proof to keystore")
	}

	return nil
}

func (mgr *ECDSAKeyManagerImpl) GetSchnorrProof(opts keyopts.Options) (*Proof, error) {
	pb, err := mgr.schstore.Get(opts)
	if err != nil {
		return nil, errors.WithMessage(err, "ecdsa: failed to get schnorr proof from keystore")
	}

	proof := new(Proof)
	if err := proof.FromBytes(pb); err != nil {
		return nil, errors.WithMessage(err, "ecdsa: failed to import schnorr proof")
	}

	return proof, nil
}

func (mgr *ECDSAKeyManagerImpl) NewZKEncProof(
	h hash.Hash,
	pek pek.PaillierEncodedKey,
	pk paillier.PaillierKey,
	ped pedersen.PedersenKey,
	opts keyopts.Options) (*zkenc.Proof, error) {
	k, err := mgr.GetKey(opts)
	if err != nil {
		return nil, errors.WithMessage(err, "ecdsa: failed to get key from keystore")
	}
	key, ok := k.(*ECDSAKeyImpl)
	if !ok {
		return nil, errors.New("ecdsa: invalid key type")
	}

	proof := zkenc.NewProof(
		k.Group(),
		h,
		zkenc.Public{
			K:      pek.Encoded(),
			Prover: pk.PublicKeyRaw(),
			Aux:    ped.PublicKeyRaw(),
		}, zkenc.Private{
			K:   curve.MakeInt(key.priv),
			Rho: pek.Nonce(),
		},
	)

	return proof, nil
}

func (mgr *ECDSAKeyManagerImpl) NewZKLogstarProof(
	h hash.Hash,
	pek pek.PaillierEncodedKey,
	C *core_paillier.Ciphertext,
	X curve.Point,
	G curve.Point,
	prover paillier.PaillierKey,
	ped pedersen.PedersenKey,
	opts keyopts.Options) (*zklogstar.Proof, error) {
	k, err := mgr.GetKey(opts)
	if err != nil {
		return nil, errors.WithMessage(err, "ecdsa: failed to get key from keystore")
	}

	key, ok := k.(*ECDSAKeyImpl)
	if !ok {
		return nil, errors.New("ed25519: invalid key type")
	}

	proof := zklogstar.NewProof(
		k.Group(),
		h,
		zklogstar.Public{
			C:      C,
			X:      X,
			G:      G,
			Prover: prover.PublicKeyRaw(),
			Aux:    ped.PublicKeyRaw(),
		}, zklogstar.Private{
			X:   curve.MakeInt(key.priv),
			Rho: pek.Nonce(),
		},
	)

	return proof, nil
}

func (mgr *ECDSAKeyManagerImpl) NewMtAAffgProof(
	h hash.Hash,
	encoded *core_paillier.Ciphertext,
	selfPaillier cs_paillier.PaillierKey,
	partyPaillier cs_paillier.PaillierKey,
	ped pedersen.PedersenKey,
	opts keyopts.Options) (*saferith.Int, *core_paillier.Ciphertext, *core_paillier.Ciphertext, *zkaffg.Proof, error) {
	k, err := mgr.GetKey(opts)
	if err != nil {
		return nil, nil, nil, nil, errors.WithMessage(err, "ecdsa: failed to get key from keystore")
	}

	key, ok := k.(*ECDSAKeyImpl)
	if !ok {
		return nil, nil, nil, nil, errors.New("ecdsa: invalid key type")
	}
	if k.Private() {
		beta, D, F, proof := mta.ProveAffG(
			k.Group(),
			h,
			curve.MakeInt(key.priv),
			k.PublicKeyRaw(),
			encoded,
			selfPaillier.PublicKeyRaw(),
			partyPaillier.PublicKeyRaw(),
			ped.PublicKeyRaw(),
		)
		return beta, D, F, proof, nil
	}
	return nil, nil, nil, nil, errors.WithMessage(err, "ecdsa: key must be private")
}

func (mgr *ECDSAKeyManagerImpl) EncodeByPaillier(pk paillier.PaillierKey, opts keyopts.Options) (paillierencodedkey.PaillierEncodedKey, error) {
	k, err := mgr.GetKey(opts)
	if err != nil {
		return nil, errors.WithMessage(err, "ecdsa: failed to get key from keystore")
	}

	key, ok := k.(*ECDSAKeyImpl)
	if !ok {
		return nil, errors.New("ecdsa: invalid key type")
	}

	if key.Private() {
		encoded, nonce := pk.Encode(curve.MakeInt(key.priv))
		pek := paillierencodedkey.NewPaillierEncodedKeyImpl(nil, encoded, nonce, key.group)
		return pek, nil
	}
	return nil, nil
}

func (mgr *ECDSAKeyManagerImpl) GenerateVss(degree int, opts keyopts.Options) (vss.VssKey, error) {
	k, err := mgr.GetKey(opts)
	if err != nil {
		return nil, errors.WithMessage(err, "ecdsa: failed to get key from keystore")
	}

	key, ok := k.(*ECDSAKeyImpl)
	if !ok {
		return nil, errors.New("ecdsa: invalid key type")
	}
	vss, err := mgr.vssmgr.GenerateSecrets(key.priv, degree, opts)
	if err != nil {
		return nil, errors.WithMessage(err, "ed25519: failed to generate vss secrets")
	}

	return vss, nil
}

func (mgr *ECDSAKeyManagerImpl) ImportVss(key interface{}, opts keyopts.Options) error {
	_, err := mgr.GetKey(opts)
	if err != nil {
		return errors.WithMessage(err, "ecdsa: failed to get key from keystore")
	}

	switch kt := key.(type) {
	case []byte:
		if _, err := mgr.vssmgr.ImportSecrets(kt, opts); err != nil {
			return errors.WithMessage(err, "ed25519: failed to import vss secrets")
		}
	case vss.VssKey:
		kb, err := kt.Bytes()
		if err != nil {
			return errors.WithMessage(err, "ed25519: failed to serialize vss key")
		}

		if _, err := mgr.vssmgr.ImportSecrets(kb, opts); err != nil {
			return errors.WithMessage(err, "ed25519: failed to import vss secrets")
		}
	default:
		return errors.New("ed25519: invalid key type")
	}

	return nil
}

func (mgr *ECDSAKeyManagerImpl) GetVss(opts keyopts.Options) (vss.VssKey, error) {
	_, err := mgr.GetKey(opts)
	if err != nil {
		return nil, errors.WithMessage(err, "ecdsa: failed to get key from keystore")
	}

	vss, err := mgr.vssmgr.GetSecrets(opts)
	if err != nil {
		return nil, errors.WithMessage(err, "ed25519: failed to get vss secrets")
	}

	return vss, nil
}
