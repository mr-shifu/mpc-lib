package sign

import (
	"crypto/sha512"
	"fmt"

	"filippo.io/edwards25519"
	"github.com/mr-shifu/mpc-lib/core/eddsa"
	"github.com/pkg/errors"

	"github.com/mr-shifu/mpc-lib/lib/round"
	"github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/hash"
	"github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/ed25519"
	vssed25519 "github.com/mr-shifu/mpc-lib/pkg/cryptosuite/sw/vss-ed25519"
	"github.com/mr-shifu/mpc-lib/pkg/keyopts"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/config"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/message"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/result"
	"github.com/mr-shifu/mpc-lib/pkg/mpc/common/state"
)

type broadcast3 struct {
	round.NormalBroadcastContent
	// Z_i is the response scalar computed by the sender of this message.
	Z *edwards25519.Scalar
}

type round3 struct {
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

// StoreBroadcastMessage implements round.BroadcastRound.
func (r *round3) StoreBroadcastMessage(msg round.Message) error {
	from := msg.From
	body, ok := msg.Content.(*broadcast3)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	// check nil
	if body.Z == nil {
		return round.ErrNilFields
	}

	kopts, err := keyopts.NewOptions().Set("id", r.cfg.KeyID(), "partyid", "ROOT")
	if err != nil {
		return errors.New("forst.sign.Round3: failed to set options")
	}

	sopts, err := keyopts.NewOptions().Set("id", r.ID, "partyid", string(msg.From))
	if err != nil {
		return errors.New("forst.sign.Round3: failed to set options")
	}

	rootOpts, err := keyopts.NewOptions().Set("id", r.ID, "partyid", "ROOT")
	if err != nil {
		return errors.New("forst.sign.Round3: failed to set options")
	}

	// 1. Reproduce c random number as commitment to the nonce
	rootSig, err := r.sigmgr.Get(rootOpts)
	if err != nil {
		return err
	}
	edKey, err := r.eddsa_km.GetKey(kopts)
	if err != nil {
		return err
	}
	kh := sha512.New()
	kh.Write(rootSig.R().Bytes())
	kh.Write(edKey.PublickeyPoint().Bytes())
	kh.Write(r.cfg.Message())
	hramDigest := make([]byte, 0, sha512.Size)
	hramDigest = kh.Sum(hramDigest)
	c, err := edwards25519.NewScalar().SetUniformBytes(hramDigest)
	if err != nil {
		panic("ed25519: internal error: setting scalar failed")
	}

	// 2. Verify the z_i response
	signKey, err := r.ed_sign_km.GetKey(sopts)
	if err != nil {
		return err
	}
	fromSig, err := r.sigmgr.Get(sopts)
	if err != nil {
		return err
	}

	expected := new(edwards25519.Point)
	expected.ScalarMult(c, signKey.PublickeyPoint()).Add(expected, fromSig.R())
	actual := new(edwards25519.Point).ScalarBaseMult(body.Z)
	if actual.Equal(expected) != 1 {
		return fmt.Errorf("failed to verify response from %v", from)
	}

	// Import z_i into the signature reposnse share
	if err := r.sigmgr.SetZ(body.Z, sopts); err != nil {
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
func (round3) VerifyMessage(round.Message) error { return nil }

// StoreMessage implements round.Round.
func (round3) StoreMessage(round.Message) error { return nil }

// Finalize implements round.Round.
func (r *round3) Finalize(chan<- *round.Message) (round.Session, error) {
	// 1. Compute the group's response z = ∑ᵢ zᵢ
	z := edwards25519.NewScalar()
	for _, l := range r.PartyIDs() {
		opts, err := keyopts.NewOptions().Set("id", r.ID, "partyid", string(l))
		if err != nil {
			return nil, errors.New("forst.sign.Round3: failed to set options")
		}
		sig, err := r.sigmgr.Get(opts)
		if err != nil {
			return r.AbortRound(err), nil
		}
		z.Add(z, sig.Z())
	}
	rootOpts, err := keyopts.NewOptions().Set("id", r.ID, "partyid", "ROOT")
	if err != nil {
		return nil, errors.New("forst.sign.Round3: failed to set options")
	}
	if err := r.sigmgr.SetZ(z, rootOpts); err != nil {
		return r, nil
	}

	// 2. Verify the signature
	ecKey, err := r.eddsa_km.GetKey(keyopts.Options{"id": r.cfg.KeyID(), "partyid": "ROOT"})
	if err != nil {
		return r.AbortRound(err), nil
	}
	s, err := r.sigmgr.Get(rootOpts)
	if err != nil {
		return r.AbortRound(err), nil
	}
	sig := eddsa.Signature{
		R: s.R(),
		Z: s.Z(),
	}
	verified := eddsa.Verify(ecKey.PublickeyPoint(), sig, r.cfg.Message())
	if !verified {
		return r.AbortRound(fmt.Errorf("generated signature failed to verify")), nil
	}

	// update last round processed in StateManager
	if err := r.statemgr.SetLastRound(r.ID, int(r.Number())); err != nil {
		return r, err
	}

	return r.ResultRound(s), nil
}

func (r *round3) CanFinalize() bool {
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
func (round3) MessageContent() round.Content { return nil }

// RoundNumber implements round.Content.
func (broadcast3) RoundNumber() round.Number { return 3 }

func (msg *broadcast3) MarshalBinary() ([]byte, error) {
	zbytes := msg.Z.Bytes()
	return zbytes[:], nil
}

func (msg *broadcast3) UnmarshalBinary(data []byte) error {
	if len(data) != 32 {
		return errors.New("invalid data length")
	}

	z, err := edwards25519.NewScalar().SetCanonicalBytes(data)
	if err != nil {
		return err
	}

	msg.Z = z

	return nil
}

// BroadcastContent implements round.BroadcastRound.
func (r *round3) BroadcastContent() round.BroadcastContent {
	return &broadcast3{
		Z: edwards25519.NewScalar(),
	}
}

// Number implements round.Round.
func (round3) Number() round.Number { return 3 }
