package mta

import (
	"github.com/cronokirby/saferith"
	"github.com/fxamacker/cbor/v2"
)

type MtA struct {
	alpha *saferith.Int
	beta  *saferith.Int
}

type rawMtA struct {
	Alpha []byte
	Beta  []byte
}

func NewMtA(alpha, beta *saferith.Int) *MtA {
	return &MtA{
		alpha: alpha,
		beta:  beta,
	}
}

func (m *MtA) Bytes() ([]byte, error) {
	raw := rawMtA{}
	if m.alpha != nil {
		alphaBytes, err := m.alpha.MarshalBinary()
		if err != nil {
			return nil, err
		}
		raw.Alpha = alphaBytes
	}
	if m.beta != nil {
		betaBytes, err := m.beta.MarshalBinary()
		if err != nil {
			return nil, err
		}
		raw.Beta = betaBytes
	}
	return cbor.Marshal(raw)
}

func (m *MtA) Alpha() (alpha *saferith.Int) {
	return m.alpha
}
func (m *MtA) Beta() *saferith.Int {
	return m.beta
}
func (m *MtA) SetAlpha(alpha *saferith.Int) {
	m.alpha = alpha
}
func (m *MtA) SetBeta(beta *saferith.Int) {
	m.beta = beta
}

func fromBytes(b []byte) (*MtA, error) {
	var raw rawMtA
	err := cbor.Unmarshal(b, &raw)
	if err != nil {
		return nil, err
	}
	if err != nil {
		return nil, err
	}

	
	alpha := new(saferith.Int)
	if raw.Alpha != nil {
		err = alpha.UnmarshalBinary(raw.Alpha)
		if err != nil {
			return nil, err
		}
	}
	beta := new(saferith.Int)
	if raw.Beta != nil {
		err = beta.UnmarshalBinary(raw.Beta)
		if err != nil {
			return nil, err
		}
	}
	return NewMtA(alpha, beta), nil
}
