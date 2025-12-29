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

type Scalar struct {
	inner fr.Element
}

func (s *Scalar) Add(a, b group.Scalar) group.Scalar {
	aScalar := a.(*Scalar)
	bScalar := b.(*Scalar)
	s.inner.Add(&aScalar.inner, &bScalar.inner)
	return s
}

func (s *Scalar) Sub(a, b group.Scalar) group.Scalar {
	aScalar := a.(*Scalar)
	bScalar := b.(*Scalar)
	s.inner.Sub(&aScalar.inner, &bScalar.inner)
	return s
}

func (s *Scalar) Mul(a, b group.Scalar) group.Scalar {
	aScalar := a.(*Scalar)
	bScalar := b.(*Scalar)
	s.inner.Mul(&aScalar.inner, &bScalar.inner)
	return s
}

func (s *Scalar) Negate(a group.Scalar) group.Scalar {
	aScalar := a.(*Scalar)
	s.inner.Neg(&aScalar.inner)
	return s
}

func (s *Scalar) Invert(a group.Scalar) (group.Scalar, error) {
	aScalar := a.(*Scalar)
	if aScalar.IsZero() {
		return nil, errors.New("cannot invert zero scalar")
	}
	s.inner.Inverse(&aScalar.inner)
	return s, nil
}

func (s *Scalar) Set(a group.Scalar) group.Scalar {
	aScalar := a.(*Scalar)
	s.inner.Set(&aScalar.inner)
	return s
}

func (s *Scalar) Bytes() []byte {
	bytes := s.inner.Bytes()
	// fr.Element.Bytes() returns [32]byte, so we slice it to []byte
	return bytes[:]
}

func (s *Scalar) SetBytes(data []byte) (group.Scalar, error) {
	s.inner.SetBytes(data)
	return s, nil
}

func (s *Scalar) Equal(b group.Scalar) bool {
	bScalar := b.(*Scalar)
	return s.inner.Equal(&bScalar.inner)
}

func (s *Scalar) IsZero() bool {
	return s.inner.IsZero()
}

type Point struct {
	inner twistededwards.PointAffine
}

func (p *Point) Add(a, b group.Point) group.Point {
	aPoint := a.(*Point)
	bPoint := b.(*Point)
	p.inner.Add(&aPoint.inner, &bPoint.inner)
	return p
}

func (p *Point) Sub(a, b group.Point) group.Point {
	aPoint := a.(*Point)
	bPoint := b.(*Point)
	var negB twistededwards.PointAffine
	negB.Neg(&bPoint.inner)
	p.inner.Add(&aPoint.inner, &negB)
	return p
}

func (p *Point) Negate(a group.Point) group.Point {
	aPoint := a.(*Point)
	p.inner.Neg(&aPoint.inner)
	return p
}

func (p *Point) ScalarMult(s group.Scalar, q group.Point) group.Point {
	scalar := s.(*Scalar)
	qPoint := q.(*Point)
	var sBigInt big.Int
	scalar.inner.BigInt(&sBigInt)
	p.inner.ScalarMultiplication(&qPoint.inner, &sBigInt)
	return p
}

func (p *Point) Set(a group.Point) group.Point {
	aPoint := a.(*Point)
	p.inner.Set(&aPoint.inner)
	return p
}

func (p *Point) Bytes() []byte {
	bytes := p.inner.Bytes()
	return bytes[:]
}

func (p *Point) SetBytes(data []byte) (group.Point, error) {
	if err := p.inner.Unmarshal(data); err != nil {
		return nil, err
	}
	return p, nil
}
	
func (p *Point) Equal(b group.Point) bool {
	bPoint := b.(*Point)
	return p.inner.Equal(&bPoint.inner)
}

func (p *Point) IsIdentity() bool {
	return p.inner.IsZero()
}

type BJJ struct {}

func (g *BJJ) NewScalar() group.Scalar {
	return &Scalar{}
}

func (g *BJJ) NewPoint() group.Point {
	return &Point{} // zero value identity
}

func (g *BJJ) Generator() group.Point {
	var p Point
	// Get BJJ generator from gnark-crypto
	p.inner = twistededwards.GetEdwardsCurve().Base
	return &p
}

func (g *BJJ) RandomScalar(r io.Reader) (group.Scalar, error) {
	var buf [32]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return nil, err
	}
	var s Scalar
	s.inner.SetBytes(buf[:])
	return &s, nil
}

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

func (g *BJJ) Order() []byte {
	order := fr.Modulus()
	return order.Bytes()
}
