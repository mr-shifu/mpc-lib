package cmp

import (
	"github.com/mr-shifu/mpc-lib/core/ecdsa"
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/party"
	"github.com/mr-shifu/mpc-lib/core/pool"
	"github.com/mr-shifu/mpc-lib/core/protocol"
	"github.com/mr-shifu/mpc-lib/lib/round"
	"github.com/mr-shifu/mpc-lib/protocols/cmp/config"
	"github.com/mr-shifu/mpc-lib/protocols/cmp/keygen"
	"github.com/mr-shifu/mpc-lib/protocols/cmp/presign"
	"github.com/mr-shifu/mpc-lib/protocols/cmp/sign"
)

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
func Keygen(keyID string, group curve.Curve, selfID party.ID, participants []party.ID, threshold int, pl *pool.Pool) protocol.StartFunc {
	info := round.Info{
		ProtocolID:       "cmp/keygen-threshold",
		FinalRoundNumber: keygen.Rounds,
		SelfID:           selfID,
		PartyIDs:         participants,
		Threshold:        threshold,
		Group:            group,
	}
	mpckg := keygen.NewMPCKeygen()
	return mpckg.Start(keyID, info, pl, nil)
}

// Refresh allows the parties to refresh all existing cryptographic keys from a previously generated Config.
// The group's ECDSA public key remains the same, but any previous shares are rendered useless.
// Returns *cmp.Config if successful.
func Refresh(keyID string, config *Config, pl *pool.Pool) protocol.StartFunc {
	info := round.Info{
		ProtocolID:       "cmp/refresh-threshold",
		FinalRoundNumber: keygen.Rounds,
		SelfID:           config.ID,
		PartyIDs:         config.PartyIDs(),
		Threshold:        config.Threshold,
		Group:            config.Group,
	}
	mpckg := keygen.NewMPCKeygen()
	return mpckg.Start(keyID, info, pl, config)
}

// Sign generates an ECDSA signature for `messageHash` among the given `signers`.
// Returns *ecdsa.Signature if successful.
func Sign(config *Config, signers []party.ID, messageHash []byte, pl *pool.Pool) protocol.StartFunc {
	return sign.StartSign(config, signers, messageHash, pl)
}

// Presign generates a preprocessed signature that does not depend on the message being signed.
// When the message becomes available, the same participants can efficiently combine their shares
// to produce a full signature with the PresignOnline protocol.
// Note: the PreSignatures should be treated as secret key material.
// Returns *ecdsa.PreSignature if successful.
func Presign(config *Config, signers []party.ID, pl *pool.Pool) protocol.StartFunc {
	return presign.StartPresign(config, signers, nil, pl)
}

// PresignOnline efficiently generates an ECDSA signature for `messageHash` given a preprocessed `PreSignature`.
// Returns *ecdsa.Signature if successful.
func PresignOnline(config *Config, preSignature *ecdsa.PreSignature, messageHash []byte, pl *pool.Pool) protocol.StartFunc {
	return presign.StartPresignOnline(config, preSignature, messageHash, pl)
}
