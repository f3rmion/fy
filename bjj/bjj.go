package bjj

import (
	"crypto/sha256"
	"errors"
	"io"
	"math/big"

	"github.com/f3rmion/fy/group"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// Scalar wraps gnark-crypto's fr.Element to implement group.Scalar.
type Scalar struct {
	inner fr.Element
}

// Add implements group.Scalar.Add.
func (s *Scalar) Add(a, b group.Scalar) group.Scalar {
	aScalar := a.(*Scalar)
	bScalar := b.(*Scalar)
	s.inner.Add(&aScalar.inner, &bScalar.inner)
	return s
}

// Sub implements group.Scalar.Sub. 
func (s *Scalar) Sub(a, b group.Scalar) group.Scalar {
	aScalar := a.(*Scalar)
	bScalar := b.(*Scalar)
	s.inner.Sub(&aScalar.inner, &bScalar.inner)
	return s
}

// Mul implements group.Scalar.Mul. 
func (s *Scalar) Mul(a, b group.Scalar) group.Scalar {
	aScalar := a.(*Scalar)
	bScalar := b.(*Scalar)
	s.inner.Mul(&aScalar.inner, &bScalar.inner)
	return s
}

// Negate implements group.Scalar.Negate. 
func (s *Scalar) Negate(a group.Scalar) group.Scalar {
	aScalar := a.(*Scalar)
	s.inner.Neg(&aScalar.inner)
	return s
}

// Invert implements group.Scalar.Invert. 
func (s *Scalar) Invert(a group.Scalar) (group.Scalar, error) {
	aScalar := a.(*Scalar)
	if aScalar.IsZero() {
		return nil, errors.New("cannot invert zero scalar")
	}
	s.inner.Inverse(&aScalar.inner)
	return s, nil
}

// Set implements group.Scalar.Set. 
func (s *Scalar) Set(a group.Scalar) group.Scalar {
	aScalar := a.(*Scalar)
	s.inner.Set(&aScalar.inner)
	return s
}

// Bytes implements group.Scalar.Bytes. 
func (s *Scalar) Bytes() []byte {
	bytes := s.inner.Bytes()
	// fr.Element.Bytes() returns [32]byte, so we slice it to []byte
	return bytes[:]
}

// SetBytes implements group.Scalar.SetBytes. 
func (s *Scalar) SetBytes(data []byte) (group.Scalar, error) {
	s.inner.SetBytes(data)
	return s, nil
}

// Equal implements group.Scalar.Equal. 
func (s *Scalar) Equal(b group.Scalar) bool {
	bScalar := b.(*Scalar)
	return s.inner.Equal(&bScalar.inner)
}

// IsZero implements group.Scalar.IsZero. 
func (s *Scalar) IsZero() bool {
	return s.inner.IsZero()
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
	var sBigInt big.Int
	scalar.inner.BigInt(&sBigInt)
	p.inner.ScalarMultiplication(&qPoint.inner, &sBigInt)
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
type BJJ struct {}

// NewScalar implements group.Group.NewScalar.
func (g *BJJ) NewScalar() group.Scalar {
	return &Scalar{}
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
	var s Scalar
	s.inner.SetBytes(buf[:])
	return &s, nil
}

// HashToScalar implements group.Group.HashToScalar.
func (g *BJJ) HashToScalar(data ...[]byte) (group.Scalar, error) {
	h := sha256.New()
	for _, d := range data {
		h.Write(d)
	}
	hash := h.Sum(nil)

	var s Scalar
	s.inner.SetBytes(hash)
	return &s, nil
}

// Order implements group.Group.Order.
func (g *BJJ) Order() []byte {
	order := fr.Modulus()
	return order.Bytes()
}
