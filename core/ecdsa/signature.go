package ecdsa

import (
	"github.com/mr-shifu/mpc-lib/core/math/curve"
)

type Signature struct {
	R curve.Point
	S curve.Scalar
}

// EmptySignature returns a new signature with a given curve, ready to be unmarshalled.
func EmptySignature(group curve.Curve) Signature {
	return Signature{R: group.NewPoint(), S: group.NewScalar()}
}

// Verify is a custom signature format using curve data.
func (sig Signature) Verify(X curve.Point, hash []byte) bool {
	group := X.Curve()

	r := sig.R.XScalar()
	if r.IsZero() || sig.S.IsZero() {
		return false
	}

	m := curve.FromHash(group, hash)
	sInv := group.NewScalar().Set(sig.S).Invert()
	mG := m.ActOnBase()
	rX := r.Act(X)
	R2 := mG.Add(rX)
	R2 = sInv.Act(R2)
	return R2.Equal(sig.R)
}

// get a signature in ethereum format
func (sig Signature) SigEthereum() ([]byte, error) {
	IsOverHalfOrder := sig.S.IsOverHalfOrder() // s-values greater than secp256k1n/2 are considered invalid

	if IsOverHalfOrder {
		sig.S.Negate()
	}

	r, err := sig.R.MarshalBinary()
	if err != nil {
		return nil, err
	}
	s, err := sig.S.MarshalBinary()
	if err != nil {
		return nil, err
	}

	rs := make([]byte, 0, 65)
	rs = append(rs, r...)
	rs = append(rs, s...)

	if IsOverHalfOrder {
		v := rs[0] - 2 // Convert to Ethereum signature format with 'recovery id' v at the end.
		copy(rs, rs[1:])
		rs[64] = v ^ 1
	} else {
		v := rs[0] - 2
		copy(rs, rs[1:])
		rs[64] = v
	}

	r[0] = rs[64] + 2
	if err := sig.R.UnmarshalBinary(r); err != nil {
		return nil, err
	}

	return rs, nil
}

func SignatureFromEth(sig [65]byte) (*Signature, error) {
	r := make([]byte, 33)
	copy(r[1:], sig[:33])
	r[0] = sig[64] + 2

	s := make([]byte, 32)
	copy(s, sig[32:64])

	signature := EmptySignature(curve.Secp256k1{})
	if err := signature.S.UnmarshalBinary(s); err != nil {
		return nil, err
	}

	if signature.S.IsOverHalfOrder() {
		r[0] = r[0] ^ 1
	}
	if err := signature.R.UnmarshalBinary(r); err != nil {
		return nil, err
	}

	return &signature, nil
}
