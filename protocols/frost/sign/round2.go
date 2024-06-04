package sign

import (
	"crypto/sha512"

	"filippo.io/edwards25519"
	"github.com/mr-shifu/mpc-lib/core/math/sample"
	"github.com/mr-shifu/mpc-lib/core/party"
	"github.com/mr-shifu/mpc-lib/lib/round"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/hash"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/ed25519"
	sw_hash "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/hash"
	vssed25519 "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/vss-ed25519"
	"github.com/mr-shifu/mpc-lib/pkg/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/config"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/message"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/result"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/state"
	"github.com/pkg/errors"
)

// This round roughly corresponds with steps 3-6 of Figure 3 in the Frost paper:
//
//	https://eprint.iacr.org/2020/852.pdf
//
// The main differences stem from the lack of a signature authority.
//
// This means that instead of receiving a bundle of all the commitments, instead
// each participant sends us their commitment directly.
//
// Then, instead of sending our scalar response to the authority, we broadcast it
// to everyone instead.
type round2 struct {
	*round.Helper
	cfg        config.SignConfig
	statemgr   state.MPCStateManager
	sigmgr     result.EddsaSignatureManager
	msgmgr     message.MessageManager
	bcstmgr    message.MessageManager
	eddsa_km   ed25519.Ed25519KeyManager
	ed_vss_km  ed25519.Ed25519KeyManager
	ed_sign_km ed25519.Ed25519KeyManager
	vss_mgr    vssed25519.VssKeyManager
	sign_d     ed25519.Ed25519KeyManager
	sign_e     ed25519.Ed25519KeyManager
	hash_mgr   hash.HashManager
}

type broadcast2 struct {
	round.ReliableBroadcastContent
	// D_i is the first commitment produced by the sender of this message.
	D *edwards25519.Point
	// E_i is the second commitment produced by the sender of this message.
	E *edwards25519.Point
}

// StoreBroadcastMessage implements round.BroadcastRound.
func (r *round2) StoreBroadcastMessage(msg round.Message) error {
	body, ok := msg.Content.(*broadcast2)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	if body.D.Equal(edwards25519.NewIdentityPoint()) == 1 || body.E.Equal(edwards25519.NewIdentityPoint()) == 1 {
		return errors.New("nonce commitment is the identity point")
	}

	opts := keyopts.Options{}
	opts.Set("id", r.ID, "partyid", string(msg.From))

	// store D params as EC Key into EC keystore
	dk, err := ed25519.NewKey(nil, body.D)
	if err != nil {
		return err
	}
	if _, err := r.sign_d.ImportKey(dk, opts); err != nil {
		return err
	}

	// store E params as EC Key into EC keystore
	ek, err := ed25519.NewKey(nil, body.E)
	if err != nil {
		return err
	}
	if _, err := r.sign_e.ImportKey(ek, opts); err != nil {
		return err
	}

	// Mark the message as received
	if err := r.bcstmgr.Import(
		r.bcstmgr.NewMessage(r.ID, int(r.Number()), string(msg.From), true),
	); err != nil {
		return err
	}

	return nil
}

// VerifyMessage implements round.Round.
func (round2) VerifyMessage(round.Message) error { return nil }

// StoreMessage implements round.Round.
func (round2) StoreMessage(round.Message) error { return nil }

// Finalize implements round.Round.
func (r *round2) Finalize(out chan<- *round.Message) (round.Session, error) {
	rho := make(map[party.ID]*edwards25519.Scalar)

	// 0. fetch Dᵢ and Eᵢ from the keystore
	Ds := make(map[party.ID]*edwards25519.Point)
	Es := make(map[party.ID]*edwards25519.Point)
	for _, l := range r.PartyIDs() {
		opts := keyopts.Options{}
		opts.Set("id", r.ID, "partyid", string(l))
		dk, err := r.sign_d.GetKey(opts)
		if err != nil {
			return r, err
		}

		ek, err := r.sign_e.GetKey(opts)
		if err != nil {
			return r, err
		}

		Ds[l] = dk.PublickeyPoint()
		Es[l] = ek.PublickeyPoint()
	}

	// ToDo replace with hash manager
	// 1. generate random ρᵢ for each party i
	rhoPreHash := sw_hash.New(nil)
	_ = rhoPreHash.WriteAny(r.cfg.Message())
	for _, l := range r.PartyIDs() {
		_ = rhoPreHash.WriteAny(Ds[l], Es[l])
	}
	for _, l := range r.PartyIDs() {
		rhoHash := rhoPreHash.Clone()
		_ = rhoHash.WriteAny(l)
		rl, err := sample.Ed25519Scalar(rhoHash.Digest())
		if err != nil {
			return nil, err
		}
		rho[l] = rl
	}

	// 2. Compute Rᵢ = (ρᵢ Eᵢ + Dᵢ) && R = Σᵢ Rᵢ
	R := new(edwards25519.Point)
	RShares := make(map[party.ID]*edwards25519.Point)
	for itr, l := range r.PartyIDs() {
		RShares[l] = new(edwards25519.Point).ScalarMult(rho[l], Es[l])
		RShares[l].Add(RShares[l], Ds[l])

		opts_l := keyopts.Options{}
		opts_l.Set("id", r.ID, "partyid", string(l))
		if err := r.sigmgr.Import(r.sigmgr.NewEddsaSignature(RShares[l], nil), opts_l); err != nil {
			return r, nil
		}

		if itr == 0 {
			R.Set(RShares[l])
			continue
		}
		R.Add(R, RShares[l])
	}
	rootOpts := keyopts.Options{}
	rootOpts.Set("id", r.ID, "partyid", "ROOT")
	if err := r.sigmgr.Import(r.sigmgr.NewEddsaSignature(R, nil), rootOpts); err != nil {
		return r, nil
	}

	// 3. Generate a random number as commitment to the nonce
	kopts := keyopts.Options{}
	kopts.Set("id", r.cfg.KeyID(), "partyid", "ROOT")
	edKey, err := r.eddsa_km.GetKey(kopts)
	if err != nil {
		return r, err
	}
	kh := sha512.New()
	kh.Write(R.Bytes())
	kh.Write(edKey.PublickeyPoint().Bytes())
	kh.Write(r.cfg.Message())
	hramDigest := make([]byte, 0, sha512.Size)
	hramDigest = kh.Sum(hramDigest)
	c, err := edwards25519.NewScalar().SetUniformBytes(hramDigest)
	if err != nil {
		panic("ed25519: internal error: setting scalar failed")
	}

	// 4. Compute zᵢ = dᵢ + (eᵢ ρᵢ) + λᵢ sᵢ c
	sopts := keyopts.Options{}
	sopts.Set("id", r.cfg.ID(), "partyid", string(r.SelfID()))
	ek, err := r.sign_e.GetKey(sopts)
	if err != nil {
		return r, err
	}
	dk, err := r.sign_d.GetKey(sopts)
	if err != nil {
		return r, err
	}
	edk := ek.MultiplyAdd(rho[r.SelfID()], dk)

	signKey, err := r.ed_sign_km.GetKey(sopts)
	if err != nil {
		return r, err
	}
	z := signKey.MultiplyAdd(c, edk)
	if err := r.sigmgr.SetZ(z, sopts); err != nil {
		return r, nil
	}

	// 5. Broadcast z
	if err := r.BroadcastMessage(out, &broadcast3{Z: z}); err != nil {
		return r, err
	}

	// update last round processed in StateManager
	if err := r.statemgr.SetLastRound(r.ID, int(r.Number())); err != nil {
		return r, err
	}

	return &round3{
		cfg:        r.cfg,
		statemgr:   r.statemgr,
		sigmgr:     r.sigmgr,
		msgmgr:     r.msgmgr,
		bcstmgr:    r.bcstmgr,
		eddsa_km:   r.eddsa_km,
		ed_vss_km:  r.ed_vss_km,
		ed_sign_km: r.ed_sign_km,
		vss_mgr:    r.vss_mgr,
		sign_d:     r.sign_d,
		sign_e:     r.sign_e,
		hash_mgr:   r.hash_mgr,
		Helper:     r.Helper,
	}, nil
}

func (r *round2) CanFinalize() bool {
	// Verify if all parties commitments are received
	var parties []string
	for _, p := range r.OtherPartyIDs() {
		parties = append(parties, string(p))
	}
	rcvd, err := r.bcstmgr.HasAll(r.ID, int(r.Number()), parties)
	if err != nil {
		return false
	}
	return rcvd
}

// MessageContent implements round.Round.
func (round2) MessageContent() round.Content { return nil }

// RoundNumber implements round.Content.
func (broadcast2) RoundNumber() round.Number { return 2 }

func (msg broadcast2) MarshalBinary() ([]byte, error) {
	dbytes := msg.D.Bytes()
	ebytes := msg.E.Bytes()
	return append(dbytes, ebytes...), nil
}

func (msg *broadcast2) UnmarshalBinary(b []byte) error {
	if len(b) != 64 {
		return round.ErrInvalidContent
	}

	if _, err := msg.D.SetBytes(b[:32]); err != nil {
		return err
	}
	if _, err := msg.E.SetBytes(b[32:]); err != nil {
		return err
	}

	return nil
}

// BroadcastContent implements round.BroadcastRound.
func (r *round2) BroadcastContent() round.BroadcastContent {
	return &broadcast2{
		D: new(edwards25519.Point),
		E: new(edwards25519.Point),
	}
}

// Number implements round.Round.
func (round2) Number() round.Number { return 2 }
