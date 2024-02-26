package pedersen

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"github.com/cronokirby/saferith"
	pedersencore "github.com/mr-shifu/mpc-lib/core/pedersen"
	cs_pedersen "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/pedersen"
)

var (
	ErrEmptyEncodedData = errors.New("encoded secret has empty data")
)

type PedersenKey struct {
	secret *saferith.Nat            // lambda
	public *pedersencore.Parameters // n, s, t
}

func NewPedersenKey(s *saferith.Nat, p *pedersencore.Parameters) PedersenKey {
	return PedersenKey{
		secret: s,
		public: p,
	}
}

// Bytes returns the byte representation of the key.
func (k PedersenKey) Bytes() ([]byte, error) {
	pkb, err := k.public.MarshalBiinary()
	if err != nil {
		return nil, err
	}
	plb := make([]byte, 2)
	binary.LittleEndian.PutUint16(plb, uint16(len(pkb)))

	buf := make([]byte, 0)
	buf = append(buf, plb...)
	buf = append(buf, pkb...)

	if k.Private() {
		skb, err := k.secret.MarshalBinary()
		if err != nil {
			return nil, err
		}
		slb := make([]byte, 2)
		binary.LittleEndian.PutUint16(slb, uint16(len(skb)))
		buf = append(buf, slb...)
		buf = append(buf, skb...)
	}

	return buf, nil
}

// SKI returns the serialized key identifier.
func (k PedersenKey) SKI() []byte {
	pbs, err := k.public.MarshalBiinary()
	if err != nil {
		return nil
	}
	hash := sha256.New()
	hash.Write(pbs)
	return hash.Sum(nil)
}

// Private returns true if the key is private.
func (k PedersenKey) Private() bool {
	return k.secret != nil
}

// Public returns the corresponding public key part of Pedersen Key.
func (k PedersenKey) PublicKey() cs_pedersen.PedersenKey {
	return PedersenKey{
		secret: nil,
		public: k.public,
	}
}

func (k PedersenKey) PublicKeyRaw() *pedersencore.Parameters {
	return k.public
}

// Commit returns the commitment of the given value.
func (k PedersenKey) Commit(x, y *saferith.Int) *saferith.Nat {
	return k.public.Commit(x, y)
}

// Verify returns true if the given commitment is valid.
func (k PedersenKey) Verify(a, b, e *saferith.Int, S, T *saferith.Nat) bool {
	return k.public.Verify(a, b, e, S, T)
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
		return PedersenKey{
			secret: nil,
			public: p,
		}, nil
	}
	s := new(saferith.Nat)
	if err := s.UnmarshalBinary(data[pLen+4 : pLen+4+sLen]); err != nil {
		return PedersenKey{}, err
	}

	return PedersenKey{
		secret: s,
		public: p,
	}, nil
}
