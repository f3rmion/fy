package group

import (
	"io"
)

type Scalar interface {
	Add(a, b Scalar) Scalar
	Sub(a, b Scalar) Scalar
	Mul(a, b Scalar) Scalar
	Negate(a Scalar) Scalar
	Invert(a Scalar) (Scalar, error)
	Set(a Scalar) Scalar
	Bytes() []byte
	SetBytes(data []byte) (Scalar, error)
	Equal(b Scalar) bool
	IsZero() bool
}

type Point interface {
	Add(a, b Point) Point
	Sub(a, b Point) Point
	Negate(a Point) Point
	ScalarMult(s Scalar, p Point) Point
	Set(a Point) Point
	Bytes() []byte
	SetBytes(data []byte) (Point, error)
	Equal(b Point) bool
	IsIdentity() bool
}

type Group interface {
	NewScalar() Scalar
	NewPoint() Point
	Generator() Point
	RandomScalar(r io.Reader) (Scalar, error)
	HashToScalar(data ...[]byte) (Scalar, error)
	Order() []byte
}
