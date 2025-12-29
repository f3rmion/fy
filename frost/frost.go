package frost

import (
	"errors"

	"github.com/f3rmion/fy/group"
)

// FROST holds the group and threshold parameters.
type FROST struct {
	group     group.Group
	threshold int // t - minimum signers needed
	total     int // n - total participants
}

// KeyShare represents a participant's share of the secret key.
type KeyShare struct {
	ID        group.Scalar // participant identifier
	SecretKey group.Scalar // secret key share
	PublicKey group.Point  // public key share
	GroupKey  group.Point  // combined group public key
}

// Signature is a Schnorr signature.
type Signature struct {
	R group.Point
	Z group.Scalar
}

// New creates a FROST instance with the given group and threshold parameters.
// threshold is the minimum number of signers required (t).
// total is the total number of participants (n).
func New(g group.Group, threshold, total int) (*FROST, error) {
	if threshold < 2 {
		return nil, errors.New("threshold must be at least 2")
	}
	if total < threshold {
		return nil, errors.New("total must be >= threshold")
	}

	return &FROST{
		group:     g,
		threshold: threshold,
		total:     total,
	}, nil
}

func (f *FROST) scalarFromInt(n int) group.Scalar {
	s := f.group.NewScalar()
	buf := make([]byte, 32)
	buf[31] = byte(n) // big-endian: value goes at the end
	s.SetBytes(buf)
	return s
}

func (f *FROST) evalPolynomial(coeffs []group.Scalar, x group.Scalar) group.Scalar {
	result := f.group.NewScalar().Set(coeffs[len(coeffs)-1])
	for i := len(coeffs) - 2; i >= 0; i-- {
		result = f.group.NewScalar().Mul(result, x)
		result = f.group.NewScalar().Add(result, coeffs[i])
	}
	return result
}
