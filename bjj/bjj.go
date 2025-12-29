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
var curveOrder *big.Int

func init() {
	curve := twistededwards.GetEdwardsCurve()
	curveOrder = new(big.Int).Set(&curve.Order)
}

// Scalar implements group.Scalar using big.Int with modular arithmetic
// over the Baby Jubjub curve order.
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

// Add implements group.Scalar.Add.
func (s *Scalar) Add(a, b group.Scalar) group.Scalar {
	aScalar := a.(*Scalar)
	bScalar := b.(*Scalar)
	s.inner.Add(aScalar.inner, bScalar.inner)
	s.reduce()
	return s
}

// Sub implements group.Scalar.Sub.
func (s *Scalar) Sub(a, b group.Scalar) group.Scalar {
	aScalar := a.(*Scalar)
	bScalar := b.(*Scalar)
	s.inner.Sub(aScalar.inner, bScalar.inner)
	s.reduce()
	return s
}

// Mul implements group.Scalar.Mul.
func (s *Scalar) Mul(a, b group.Scalar) group.Scalar {
	aScalar := a.(*Scalar)
	bScalar := b.(*Scalar)
	s.inner.Mul(aScalar.inner, bScalar.inner)
	s.reduce()
	return s
}

// Negate implements group.Scalar.Negate.
func (s *Scalar) Negate(a group.Scalar) group.Scalar {
	aScalar := a.(*Scalar)
	s.inner.Neg(aScalar.inner)
	s.reduce()
	return s
}

// Invert implements group.Scalar.Invert.
func (s *Scalar) Invert(a group.Scalar) (group.Scalar, error) {
	aScalar := a.(*Scalar)
	if aScalar.IsZero() {
		return nil, errors.New("cannot invert zero scalar")
	}
	// ModInverse computes the modular multiplicative inverse
	s.inner.ModInverse(aScalar.inner, curveOrder)
	return s, nil
}

// Set implements group.Scalar.Set.
func (s *Scalar) Set(a group.Scalar) group.Scalar {
	aScalar := a.(*Scalar)
	s.inner.Set(aScalar.inner)
	return s
}

// Bytes implements group.Scalar.Bytes.
func (s *Scalar) Bytes() []byte {
	// Pad to 32 bytes, big-endian
	bytes := s.inner.Bytes()
	if len(bytes) >= 32 {
		return bytes[:32]
	}
	// Pad with leading zeros
	padded := make([]byte, 32)
	copy(padded[32-len(bytes):], bytes)
	return padded
}

// SetBytes implements group.Scalar.SetBytes.
func (s *Scalar) SetBytes(data []byte) (group.Scalar, error) {
	s.inner.SetBytes(data)
	s.reduce()
	return s, nil
}

// Equal implements group.Scalar.Equal.
func (s *Scalar) Equal(b group.Scalar) bool {
	bScalar := b.(*Scalar)
	return s.inner.Cmp(bScalar.inner) == 0
}

// IsZero implements group.Scalar.IsZero.
func (s *Scalar) IsZero() bool {
	return s.inner.Sign() == 0
}

// Point wraps gnark-crypto's PointAffine to implement group.Point.
type Point struct {
	inner twistededwards.PointAffine
}

// Add implements group.Point.Add. 
func (p *Point) Add(a, b group.Point) group.Point {
	aPoint := a.(*Point)
	bPoint := b.(*Point)
	p.inner.Add(&aPoint.inner, &bPoint.inner)
	return p
}

// Sub implements group.Point.Sub. 
func (p *Point) Sub(a, b group.Point) group.Point {
	aPoint := a.(*Point)
	bPoint := b.(*Point)
	var negB twistededwards.PointAffine
	negB.Neg(&bPoint.inner)
	p.inner.Add(&aPoint.inner, &negB)
	return p
}

// Negate implements group.Point.Negate.
func (p *Point) Negate(a group.Point) group.Point {
	aPoint := a.(*Point)
	p.inner.Neg(&aPoint.inner)
	return p
}

// ScalarMult implements group.Point.ScalarMult.
func (p *Point) ScalarMult(s group.Scalar, q group.Point) group.Point {
	scalar := s.(*Scalar)
	qPoint := q.(*Point)
	p.inner.ScalarMultiplication(&qPoint.inner, scalar.inner)
	return p
}

// Set implements group.Point.Set.
func (p *Point) Set(a group.Point) group.Point {
	aPoint := a.(*Point)
	p.inner.Set(&aPoint.inner)
	return p
}

// Bytes implements group.Point.Bytes.
func (p *Point) Bytes() []byte {
	bytes := p.inner.Bytes()
	return bytes[:]
}

// SetBytes implements group.Point.SetBytes.
func (p *Point) SetBytes(data []byte) (group.Point, error) {
	if err := p.inner.Unmarshal(data); err != nil {
		return nil, err
	}
	return p, nil
}
	
// Equal implements group.Point.Equal.
func (p *Point) Equal(b group.Point) bool {
	bPoint := b.(*Point)
	return p.inner.Equal(&bPoint.inner)
}

// IsIdentity implements group.Point.IsIdentity.
func (p *Point) IsIdentity() bool {
	return p.inner.IsZero()
}

// BJJ implements group.Group for the BabyJubJub curve.
type BJJ struct{}

// NewScalar implements group.Group.NewScalar.
func (g *BJJ) NewScalar() group.Scalar {
	return newScalar()
}

// NewPoint implements group.Group.NewPoint.
func (g *BJJ) NewPoint() group.Point {
	var p Point
	p.inner.X.SetZero()
	p.inner.Y.SetOne()
	return &p
}

// Generator implements group.Group.Generator.
func (g *BJJ) Generator() group.Point {
	var p Point
	// Get BJJ generator from gnark-crypto
	p.inner = twistededwards.GetEdwardsCurve().Base
	return &p
}

// RandomScalar implements group.Group.RandomScalar.
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

// HashToScalar implements group.Group.HashToScalar.
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

// Order implements group.Group.Order.
func (g *BJJ) Order() []byte {
	return curveOrder.Bytes()
}
