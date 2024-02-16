package pedersen

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"github.com/cronokirby/saferith"
	pedersencore "github.com/mr-shifu/mpc-lib/core/pedersen"
)

var (
	ErrEmptyEncodedData = errors.New("encoded secret has empty data")
)

type PedersenKey struct {
	secretKey *saferith.Nat            // lambda
	publicKey *pedersencore.Parameters // n, s, t
}

func NewPedersenKey(s *saferith.Nat, p *pedersencore.Parameters) PedersenKey {
	return PedersenKey{
		secretKey: s,
		publicKey: p,
	}
}

// Bytes returns the byte representation of the key.
func (k *PedersenKey) Bytes() ([]byte, error) {
	skb, err := k.secretKey.MarshalBinary()
	if err != nil {
		return nil, err
	}

	pkb, err := k.publicKey.MarshalBiinary()
	if err != nil {
		return nil, err
	}

	slb := make([]byte, 2)
	binary.LittleEndian.PutUint16(slb, uint16(len(skb)))

	plb := make([]byte, 2)
	binary.LittleEndian.PutUint16(plb, uint16(len(pkb)))

	buf := make([]byte, 0)
	buf = append(buf, plb...)
	buf = append(buf, pkb...)
	buf = append(buf, slb...)
	buf = append(buf, skb...)

	return buf, nil
}

// SKI returns the serialized key identifier.
func (k *PedersenKey) SKI() []byte {
	pbs, err := k.publicKey.MarshalBiinary()
	if err != nil {
		return nil
	}
	hash := sha256.New()
	hash.Write(pbs)
	return hash.Sum(nil)
}

// Private returns true if the key is private.
func (k *PedersenKey) Private() bool {
	return k.secretKey != nil
}

// PublicKey returns the corresponding public key part of Pedersen Key.
func (k *PedersenKey) PublicKey() PedersenKey {
	return PedersenKey{
		secretKey: nil,
		publicKey: k.publicKey,
	}
}

// Commit returns the commitment of the given value.
func (k *PedersenKey) Commit(x, y *saferith.Int) *saferith.Nat {
	return k.publicKey.Commit(x, y)
}

// Verify returns true if the given commitment is valid.
func (k *PedersenKey) Verify(a, b, e *saferith.Int, S, T *saferith.Nat) bool {
	return k.publicKey.Verify(a, b, e, S, T)
}

func fromBytes(data []byte) (PedersenKey, error) {
	if len(data) == 0 {
		return PedersenKey{}, ErrEmptyEncodedData
	}

	plb := data[:2]
	pLen := binary.LittleEndian.Uint16(plb)
	if pLen == 0 {
		return PedersenKey{}, ErrEmptyEncodedData
	}
	p := new(pedersencore.Parameters)
	if err := p.UnmarshalBiinary(data[2 : pLen+2]); err != nil {
		return PedersenKey{}, err
	}

	slb := data[pLen+2 : pLen+4]
	sLen := binary.LittleEndian.Uint16(slb)
	if sLen == 0 {
		return PedersenKey{}, ErrEmptyEncodedData
	}
	s := new(saferith.Nat)
	if err := s.UnmarshalBinary(data[pLen+4 : pLen+4+sLen]); err != nil {
		return PedersenKey{}, err
	}

	return PedersenKey{
		secretKey: s,
		publicKey: p,
	}, nil
}
