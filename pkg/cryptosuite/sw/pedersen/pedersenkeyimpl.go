package pedersen

import (
	"crypto/sha256"
	"errors"

	"github.com/cronokirby/saferith"
	"github.com/fxamacker/cbor/v2"
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

type rawPedersenKey struct {
	Secret []byte
	Public []byte
}

func NewPedersenKey(s *saferith.Nat, p *pedersencore.Parameters) PedersenKey {
	return PedersenKey{
		secret: s,
		public: p,
	}
}

// Bytes returns the byte representation of the key.
func (k PedersenKey) Bytes() ([]byte, error) {
	// pkb, err := k.public.MarshalBiinary()
	// if err != nil {
	// 	return nil, err
	// }
	// plb := make([]byte, 2)
	// binary.LittleEndian.PutUint16(plb, uint16(len(pkb)))

	// buf := make([]byte, 0)
	// buf = append(buf, plb...)
	// buf = append(buf, pkb...)

	// if k.Private() {
	// 	skb, err := k.secret.MarshalBinary()
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	slb := make([]byte, 2)
	// 	binary.LittleEndian.PutUint16(slb, uint16(len(skb)))
	// 	buf = append(buf, slb...)
	// 	buf = append(buf, skb...)
	// }
	raw := &rawPedersenKey{}

	if k.Private() {
		skb, err := k.secret.MarshalBinary()
		if err != nil {
			return nil, err
		}
		raw.Secret = skb
	}

	pkb, err := k.public.MarshalBiinary()
	if err != nil {
		return nil, err
	}
	raw.Public = pkb

	return cbor.Marshal(raw)
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
	raw := &rawPedersenKey{}
	if err := cbor.Unmarshal(data, raw); err != nil {
		return PedersenKey{}, err
	}

	key := PedersenKey{}

	if len(raw.Secret) != 0 {
		s := new(saferith.Nat)
		if err := s.UnmarshalBinary(raw.Secret); err != nil {
			return PedersenKey{}, err
		}
		key.secret = s
	}

	p := new(pedersencore.Parameters)
	if err := p.UnmarshalBiinary(raw.Public); err != nil {
		return PedersenKey{}, err
	}
	key.public = p

	return key, nil
}
