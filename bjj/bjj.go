package bjj

import (
	"crypto/sha256"
	"errors"
	"io"
	"math/big"

	"github.com/f3rmion/fy/group"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
)

// curveOrder is the Baby Jubjub subgroup order.
// This is distinct from the BN254 scalar field order (Fr).
var curveOrder *big.Int

func init() {
	curve := twistededwards.GetEdwardsCurve()
	curveOrder = new(big.Int).Set(&curve.Order)
}

// Scalar represents an element of the Baby Jubjub scalar field.
// It implements [group.Scalar] using big.Int with modular arithmetic
// over the curve's subgroup order.
//
// All arithmetic operations automatically reduce results modulo the
// curve order to maintain valid scalar values.
type Scalar struct {
	inner *big.Int
}

// newScalar creates a new scalar initialized to zero.
func newScalar() *Scalar {
	return &Scalar{inner: new(big.Int)}
}

// reduce ensures the scalar is in the range [0, curveOrder).
func (s *Scalar) reduce() {
	s.inner.Mod(s.inner, curveOrder)
}

// Add sets s to a + b (mod curveOrder) and returns s.
func (s *Scalar) Add(a, b group.Scalar) group.Scalar {
	aScalar := a.(*Scalar)
	bScalar := b.(*Scalar)
	s.inner.Add(aScalar.inner, bScalar.inner)
	s.reduce()
	return s
}

// Sub sets s to a - b (mod curveOrder) and returns s.
func (s *Scalar) Sub(a, b group.Scalar) group.Scalar {
	aScalar := a.(*Scalar)
	bScalar := b.(*Scalar)
	s.inner.Sub(aScalar.inner, bScalar.inner)
	s.reduce()
	return s
}

// Mul sets s to a * b (mod curveOrder) and returns s.
func (s *Scalar) Mul(a, b group.Scalar) group.Scalar {
	aScalar := a.(*Scalar)
	bScalar := b.(*Scalar)
	s.inner.Mul(aScalar.inner, bScalar.inner)
	s.reduce()
	return s
}

// Negate sets s to -a (mod curveOrder) and returns s.
func (s *Scalar) Negate(a group.Scalar) group.Scalar {
	aScalar := a.(*Scalar)
	s.inner.Neg(aScalar.inner)
	s.reduce()
	return s
}

// Invert sets s to a^(-1) (mod curveOrder) and returns s.
// Returns an error if a is zero, as zero has no multiplicative inverse.
func (s *Scalar) Invert(a group.Scalar) (group.Scalar, error) {
	aScalar := a.(*Scalar)
	if aScalar.IsZero() {
		return nil, errors.New("cannot invert zero scalar")
	}
	s.inner.ModInverse(aScalar.inner, curveOrder)
	return s, nil
}

// Set copies the value of a into s and returns s.
func (s *Scalar) Set(a group.Scalar) group.Scalar {
	aScalar := a.(*Scalar)
	s.inner.Set(aScalar.inner)
	return s
}

// Bytes returns the scalar as a 32-byte big-endian representation.
func (s *Scalar) Bytes() []byte {
	bytes := s.inner.Bytes()
	if len(bytes) >= 32 {
		return bytes[:32]
	}
	// Pad with leading zeros
	padded := make([]byte, 32)
	copy(padded[32-len(bytes):], bytes)
	return padded
}

// SetBytes sets s from a big-endian byte slice and returns s.
// The value is reduced modulo the curve order.
func (s *Scalar) SetBytes(data []byte) (group.Scalar, error) {
	s.inner.SetBytes(data)
	s.reduce()
	return s, nil
}

// Equal reports whether s and b represent the same scalar value.
func (s *Scalar) Equal(b group.Scalar) bool {
	bScalar := b.(*Scalar)
	return s.inner.Cmp(bScalar.inner) == 0
}

// IsZero reports whether s is the zero scalar.
func (s *Scalar) IsZero() bool {
	return s.inner.Sign() == 0
}

// Point represents a point on the Baby Jubjub curve.
// It implements [group.Point] by wrapping gnark-crypto's PointAffine.
//
// Points are represented in affine coordinates (x, y) on the twisted
// Edwards curve. The identity element is (0, 1).
type Point struct {
	inner twistededwards.PointAffine
}

// Add sets p to a + b and returns p.
func (p *Point) Add(a, b group.Point) group.Point {
	aPoint := a.(*Point)
	bPoint := b.(*Point)
	p.inner.Add(&aPoint.inner, &bPoint.inner)
	return p
}

// Sub sets p to a - b and returns p.
func (p *Point) Sub(a, b group.Point) group.Point {
	aPoint := a.(*Point)
	bPoint := b.(*Point)
	var negB twistededwards.PointAffine
	negB.Neg(&bPoint.inner)
	p.inner.Add(&aPoint.inner, &negB)
	return p
}

// Negate sets p to -a and returns p.
func (p *Point) Negate(a group.Point) group.Point {
	aPoint := a.(*Point)
	p.inner.Neg(&aPoint.inner)
	return p
}

// ScalarMult sets p to s * q and returns p.
func (p *Point) ScalarMult(s group.Scalar, q group.Point) group.Point {
	scalar := s.(*Scalar)
	qPoint := q.(*Point)
	p.inner.ScalarMultiplication(&qPoint.inner, scalar.inner)
	return p
}

// Set copies the value of a into p and returns p.
func (p *Point) Set(a group.Point) group.Point {
	aPoint := a.(*Point)
	p.inner.Set(&aPoint.inner)
	return p
}

// Bytes returns the compressed point encoding as a byte slice.
func (p *Point) Bytes() []byte {
	bytes := p.inner.Bytes()
	return bytes[:]
}

// SetBytes sets p from a compressed point encoding and returns p.
// Returns an error if the data does not represent a valid curve point.
func (p *Point) SetBytes(data []byte) (group.Point, error) {
	if err := p.inner.Unmarshal(data); err != nil {
		return nil, err
	}
	return p, nil
}

// Equal reports whether p and b represent the same curve point.
func (p *Point) Equal(b group.Point) bool {
	bPoint := b.(*Point)
	return p.inner.Equal(&bPoint.inner)
}

// IsIdentity reports whether p is the identity element (0, 1).
func (p *Point) IsIdentity() bool {
	return p.inner.IsZero()
}

// BJJ implements [group.Group] for the Baby Jubjub curve.
//
// BJJ is a zero-sized type that provides access to Baby Jubjub curve
// operations. Create an instance with &BJJ{} or new(BJJ).
type BJJ struct{}

// NewScalar returns a new scalar initialized to zero.
func (g *BJJ) NewScalar() group.Scalar {
	return newScalar()
}

// NewPoint returns a new point initialized to the identity element (0, 1).
func (g *BJJ) NewPoint() group.Point {
	var p Point
	p.inner.X.SetZero()
	p.inner.Y.SetOne()
	return &p
}

// Generator returns the standard base point for the Baby Jubjub curve.
func (g *BJJ) Generator() group.Point {
	var p Point
	p.inner = twistededwards.GetEdwardsCurve().Base
	return &p
}

// RandomScalar generates a cryptographically random scalar using the
// provided random source. The result is uniformly distributed in
// [0, curveOrder).
func (g *BJJ) RandomScalar(r io.Reader) (group.Scalar, error) {
	var buf [32]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return nil, err
	}
	s := newScalar()
	s.inner.SetBytes(buf[:])
	s.reduce()
	return s, nil
}

// HashToScalar hashes the provided data to a scalar using SHA-256.
// Multiple byte slices are concatenated before hashing.
func (g *BJJ) HashToScalar(data ...[]byte) (group.Scalar, error) {
	h := sha256.New()
	for _, d := range data {
		h.Write(d)
	}
	hash := h.Sum(nil)

	s := newScalar()
	s.inner.SetBytes(hash)
	s.reduce()
	return s, nil
}

// Order returns the order of the Baby Jubjub curve's prime-order subgroup
// as a big-endian byte slice.
func (g *BJJ) Order() []byte {
	return curveOrder.Bytes()
}
