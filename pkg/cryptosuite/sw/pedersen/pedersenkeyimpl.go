package pedersen

import (
	"crypto/sha256"
	"errors"

	"github.com/cronokirby/saferith"
	"github.com/fxamacker/cbor/v2"
	pedersencore "github.com/mr-shifu/mpc-lib/core/pedersen"
)

var (
	ErrEmptyEncodedData = errors.New("encoded secret has empty data")
)

type PedersenKeyImpl struct {
	secret *saferith.Nat            // lambda
	public *pedersencore.Parameters // n, s, t
}

type rawPedersenKey struct {
	Secret []byte
	Public []byte
}

var _ PedersenKey = (*PedersenKeyImpl)(nil)

func NewPedersenKey(s *saferith.Nat, p *pedersencore.Parameters) *PedersenKeyImpl {
	return &PedersenKeyImpl{
		secret: s,
		public: p,
	}
}

// Bytes returns the byte representation of the key.
func (k *PedersenKeyImpl) Bytes() ([]byte, error) {
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
func (k *PedersenKeyImpl) SKI() []byte {
	pbs, err := k.public.MarshalBiinary()
	if err != nil {
		return nil
	}
	hash := sha256.New()
	hash.Write(pbs)
	return hash.Sum(nil)
}

// Private returns true if the key is private.
func (k *PedersenKeyImpl) Private() bool {
	return k.secret != nil
}

// Public returns the corresponding public key part of Pedersen Key.
func (k *PedersenKeyImpl) PublicKey() PedersenKey {
	return &PedersenKeyImpl{
		secret: nil,
		public: k.public,
	}
}

func (k *PedersenKeyImpl) PublicKeyRaw() *pedersencore.Parameters {
	return k.public
}

// Commit returns the commitment of the given value.
func (k *PedersenKeyImpl) Commit(x, y *saferith.Int) *saferith.Nat {
	return k.public.Commit(x, y)
}

// Verify returns true if the given commitment is valid.
func (k *PedersenKeyImpl) Verify(a, b, e *saferith.Int, S, T *saferith.Nat) bool {
	return k.public.Verify(a, b, e, S, T)
}

func fromBytes(data []byte) (*PedersenKeyImpl, error) {
	raw := &rawPedersenKey{}
	if err := cbor.Unmarshal(data, raw); err != nil {
		return nil, err
	}

	key := PedersenKeyImpl{}

	if len(raw.Secret) != 0 {
		s := new(saferith.Nat)
		if err := s.UnmarshalBinary(raw.Secret); err != nil {
			return nil, err
		}
		key.secret = s
	}

	p := new(pedersencore.Parameters)
	if err := p.UnmarshalBiinary(raw.Public); err != nil {
		return nil, err
	}
	key.public = p

	return &key, nil
}
