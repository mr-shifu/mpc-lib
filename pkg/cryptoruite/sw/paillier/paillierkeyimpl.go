package paillier

import (
	"crypto/sha256"

	"github.com/cronokirby/saferith"
	"github.com/mr-shifu/mpc-lib/core/math/arith"
	pailliercore "github.com/mr-shifu/mpc-lib/core/paillier"
)

type PaillierKey struct {
	secretKey *pailliercore.SecretKey
	publicKey *pailliercore.PublicKey
}

// Bytes returns the binary encoded of N param of public key secret key params (P, Q) if exists.
// The encoded data is structured as follows:
// | N length | N | SecretKey Length | P Length | P | Q length | Q |
func (k *PaillierKey) Bytes() ([]byte, error) {
	// encode public key Modulus N
	nb, err := k.publicKey.Modulus().MarshalBinary()
	if err != nil {
		return nil, err
	}

	// write public key encoded into buffer
	buf := make([]byte, 0)
	buf = append(buf, uint8(len(nb)))
	buf = append(buf, nb...)

	// if secret key exists then encode secret key params (P, Q)
	if k.secretKey == nil {
		return buf, nil
	}
	skb, err := k.secretKey.MarshalBinary()
	if err != nil {
		return nil, err
	}

	// write secret key encoded into buffer
	buf = append(buf, uint8(len(skb)))
	buf = append(buf, skb...)

	return buf, nil
}

// SKI returns the Subject Key Identifier of the key derived from N param of public key.
func (k *PaillierKey) SKI() []byte {
	// TODO: we should make sure that N param is unique for each key to derive SKI from it.
	pbs := k.ParamN().Bytes()
	if pbs == nil {
		return nil
	}
	hash := sha256.New()
	hash.Write(pbs)
	return hash.Sum(nil)
}

// Private returns true if the key contains secret key.
func (k *PaillierKey) Private() bool {
	return k.secretKey != nil
}

// PublicKey returns the public key part of the key.
func (k *PaillierKey) PublicKey() PaillierKey {
	return PaillierKey{nil, k.publicKey}
}

// Modulus returns the modulus of the key.
func (k *PaillierKey) Modulus() *arith.Modulus {
	return k.publicKey.Modulus()
}

// ParamN returns the N param of the key.
func (k *PaillierKey) ParamN() *saferith.Modulus {
	return k.publicKey.N()
}

// fromBytes returns a Paillier key from its binary encoded data.
func fromBytes(data []byte) (PaillierKey, error) {
	nl := int(data[0])
	nb := data[1 : nl+1]

	// decode public key Modulus N
	n := new(saferith.Modulus)
	if err := n.UnmarshalBinary(nb); err != nil {
		return PaillierKey{}, err
	}

	// if secret key exists then decode secret key params (P, Q)
	sl := int(data[nl+1])
	if sl == 0 {
		return PaillierKey{publicKey: pailliercore.NewPublicKey(n)}, nil
	}

	// decode secret key params (P, Q)
	sb := data[nl+2 : nl+2+sl]
	sk := new(pailliercore.SecretKey)
	if err := sk.UnmarshalBinary(sb); err != nil {
		return PaillierKey{}, err
	}

	return PaillierKey{sk, pailliercore.NewPublicKey(n)}, nil
}