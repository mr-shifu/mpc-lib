package hash

import (
	"bytes"
	"crypto/rand"
	"encoding"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"reflect"

	"github.com/fxamacker/cbor/v2"
	core_hash "github.com/mr-shifu/mpc-lib/core/hash"
	"github.com/mr-shifu/mpc-lib/lib/params"
	comm_hash "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/hash"
	"github.com/mr-shifu/mpc-lib/pkg/common/keystore"
	"github.com/zeebo/blake3"
)

type Hash struct {
	h     *blake3.Hasher
	state []core_hash.BytesWithDomain
	store keystore.KeyAccessor
}

func New(store keystore.KeyAccessor, initialData ...core_hash.WriterToWithDomain) comm_hash.Hash {
	hash := &Hash{h: blake3.New(), store: store}
	_, _ = hash.h.WriteString("CMP-BLAKE")
	for _, d := range initialData {
		_ = hash.WriteAny(d)
	}
	return hash
}

func Restore(store keystore.KeyAccessor) (comm_hash.Hash, error) {
	hash := &Hash{h: blake3.New(), store: store}

	ss, err := hash.store.Get()
	if err != nil {
		return nil, err
	}
	if err := cbor.Unmarshal(ss, &hash.state); err != nil {
		return nil, err
	}

	for _, d := range hash.state {
		hash.writeBytesWithDomain(d)
	}

	return hash, nil
}

func (hash *Hash) Digest() io.Reader {
	return hash.h.Digest()
}

func (hash *Hash) Sum() []byte {
	out := make([]byte, core_hash.DigestLengthBytes)
	if _, err := io.ReadFull(hash.Digest(), out); err != nil {
		panic(fmt.Sprintf("hash.ReadBytes: internal hash failure: %v", err))
	}
	return out
}

func (hash *Hash) WriteAny(data ...interface{}) error {
	var toBeWritten core_hash.BytesWithDomain
	for _, d := range data {
		switch t := d.(type) {
		case []byte:
			if t == nil {
				return errors.New("hash.WriteAny: nil []byte")
			}
			toBeWritten = core_hash.BytesWithDomain{"[]byte", t}
		case *big.Int:
			if t == nil {
				return fmt.Errorf("hash.WriteAny: write *big.Int: nil")
			}
			bytes, _ := t.GobEncode()
			toBeWritten = core_hash.BytesWithDomain{"big.Int", bytes}
		case core_hash.WriterToWithDomain:
			var buf = new(bytes.Buffer)
			_, err := t.WriteTo(buf)
			if err != nil {
				name := reflect.TypeOf(t)
				return fmt.Errorf("hash.WriteAny: %s: %w", name.String(), err)
			}
			toBeWritten = core_hash.BytesWithDomain{t.Domain(), buf.Bytes()}
		case encoding.BinaryMarshaler:
			name := reflect.TypeOf(t)
			bytes, err := t.MarshalBinary()
			if err != nil {
				return fmt.Errorf("hash.WriteAny: %s: %w", name.String(), err)
			}
			toBeWritten = core_hash.BytesWithDomain{
				TheDomain: name.String(),
				Bytes:     bytes,
			}
		case encoding.KeyMarshaler:
			name := reflect.TypeOf(t)
			bytes, err := t.Bytes()
			if err != nil {
				return fmt.Errorf("hash.WriteAny: %s: %w", name.String(), err)
			}
			toBeWritten = core_hash.BytesWithDomain{
				TheDomain: name.String(),
				Bytes:     bytes,
			}
		default:
			// This should panic or something
			return fmt.Errorf("hash.WriteAny: invalid type provided as input")
		}

		hash.updateState(toBeWritten)

		hash.writeBytesWithDomain(toBeWritten)
	}
	return nil
}

func (hash *Hash) writeBytesWithDomain(toBeWritten core_hash.BytesWithDomain) {
	var sizeBuf [8]byte

	// Write out `(<domain_size><domain><data_size><data>)`, so that each domain separated piece of data
	// is distinguished from others.

	_, _ = hash.h.WriteString("(")
	// <domain_size>
	binary.BigEndian.PutUint64(sizeBuf[:], uint64(len(toBeWritten.TheDomain)))
	_, _ = hash.h.Write(sizeBuf[:])
	// <domain>
	_, _ = hash.h.WriteString(toBeWritten.TheDomain)
	// <data_size>
	binary.BigEndian.PutUint64(sizeBuf[:], uint64(len(toBeWritten.Bytes)))
	_, _ = hash.h.Write(sizeBuf[:])
	// <data>
	_, _ = hash.h.Write(toBeWritten.Bytes)
	// )
	_, _ = hash.h.WriteString(")")
}

func (hash *Hash) updateState(toBeWritten core_hash.BytesWithDomain) error {
	hash.state = append(hash.state, toBeWritten)
	ss, err := cbor.Marshal(hash.state)
	if err != nil {
		return err
	}
	if hash.store != nil {
		return hash.store.Import(ss)
	}
	return nil
}

func (hash *Hash) Clone() comm_hash.Hash {
	return &Hash{
		h:     hash.h.Clone(),
		state: hash.state,
		store: nil,
	}
}

// Commit creates a commitment to data, and returns a commitment hash, and a decommitment string such that
// commitment = h(data, decommitment).
func (hash *Hash) Commit(data ...interface{}) (core_hash.Commitment, core_hash.Decommitment, error) {
	var err error
	decommitment := core_hash.Decommitment(make([]byte, params.SecBytes))

	if _, err = rand.Read(decommitment); err != nil {
		return nil, nil, fmt.Errorf("hash.Commit: failed to generate decommitment: %w", err)
	}

	h := hash.Clone()

	for _, item := range data {
		if err = h.WriteAny(item); err != nil {
			return nil, nil, fmt.Errorf("hash.Commit: failed to write data: %w", err)
		}
	}

	_ = h.WriteAny(decommitment)

	commitment := h.Sum()

	return commitment, decommitment, nil
}

// Decommit verifies that the commitment corresponds to the data and decommitment such that
// commitment = h(data, decommitment).
func (hash *Hash) Decommit(c core_hash.Commitment, d core_hash.Decommitment, data ...interface{}) bool {
	var err error
	if err = c.Validate(); err != nil {
		return false
	}
	if err = d.Validate(); err != nil {
		return false
	}

	h := hash.Clone()

	for _, item := range data {
		if err = h.WriteAny(item); err != nil {
			return false
		}
	}

	_ = h.WriteAny(d)

	computedCommitment := h.Sum()

	return bytes.Equal(computedCommitment, c)
}
