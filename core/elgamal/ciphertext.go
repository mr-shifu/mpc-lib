package elgamal

import (
	"io"

	"github.com/mr-shifu/mpc-lib/core/math/curve"
)

type Ciphertext struct {
	// L = nonce⋅G
	L curve.Point
	// M = message⋅G + nonce⋅public
	M curve.Point
}

func NewCiphertext(group curve.Curve) *Ciphertext {
	return &Ciphertext{
		L: group.NewPoint(),
		M: group.NewPoint(),
	}
}

// Valid returns true if the ciphertext passes basic validation.
func (c *Ciphertext) Valid() bool {
	if c == nil || c.L == nil || c.L.IsIdentity() ||
		c.M == nil || c.M.IsIdentity() {
		return false
	}
	return true
}

func (c *Ciphertext) MarshalBinary() ([]byte, error) {
	buf, err := c.L.MarshalBinary()
	if err != nil {
		return nil, err
	}
	buf2, err := c.M.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return append(buf, buf2...), nil
}

func (c *Ciphertext) UnmarshalBinary(data []byte) error {
	if len(data) == 0 {
		return io.ErrShortBuffer
	}
	c.L = c.L.Curve().NewPoint()
	if err := c.L.UnmarshalBinary(data[:33]); err != nil {
		return err
	}
	c.M = c.M.Curve().NewPoint()
	return c.M.UnmarshalBinary(data[33:])
}

func (c *Ciphertext) WriteTo(w io.Writer) (int64, error) {
	var total int64
	var n int

	buf, err := c.L.MarshalBinary()
	if err != nil {
		return 0, err
	}
	n, err = w.Write(buf)
	total += int64(n)
	if err != nil {
		return total, err
	}

	buf, err = c.M.MarshalBinary()
	if err != nil {
		return 0, err
	}
	n, err = w.Write(buf)
	total += int64(n)
	if err != nil {
		return total, err
	}

	return total, nil
}
