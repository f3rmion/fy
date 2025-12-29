package group

import (
	"io"
)

// Scalar represents an element of the scalar field.
type Scalar interface {
	// Add sets the receiver to a+b and returns it. 
	Add(a, b Scalar) Scalar
	// Sub sets the receiver to a-b and returns it.
	Sub(a, b Scalar) Scalar
	// Mul sets the receiver to a*b and returns it.
	Mul(a, b Scalar) Scalar
	// Negate sets the receiver to -a and returns it.
	Negate(a Scalar) Scalar
	// Invert sets the receiver to a^{-1} and returns it.
	// Returns an error if a is zero.
	Invert(a Scalar) (Scalar, error)
	// Set sets the receiver to a and returns it.
	Set(a Scalar) Scalar
	// Bytes returns the canonical byte representation of the scalar.
	Bytes() []byte
	// SetBytes sets the receiver from a byte slice and returns it.
	// Returns an error if the data is invalid or out of range.
	SetBytes(data []byte) (Scalar, error)
	// Equal reports whether the receiver equals b.
	Equal(b Scalar) bool
	// IsZero reports whether the receiver is zero.
	IsZero() bool
}

// Point represents an element of the group.
type Point interface {
	// Add sets the receiver to a+b and returns it.
	Add(a, b Point) Point
	// Sub sets the receiver to a-b and returns it.
	Sub(a, b Point) Point
	// Negate sets the receiver to -a and returns it.
	Negate(a Point) Point
	// ScalarMult sets the receiver to s*p and returns it.
	ScalarMult(s Scalar, p Point) Point
	// Set sets the receiver to a and returns it.
	Set(a Point) Point
	// Bytes returns the canonical byte representation of the point.
	Bytes() []byte
	// SetBytes sets the receiver from a byte slice and returns it.
	// Returns an error if the data is invalid or out of range.
	SetBytes(data []byte) (Point, error)
	// Equal reports whether the receiver equals b.
	Equal(b Point) bool
	// IsIdentity reports whether the receiver is the identity element.
	IsIdentity() bool
}

// Group defines a cryptographic group for use with FROST.
type Group interface {
	// NewScalar returns a new zero scalar.
	NewScalar() Scalar
	// NewPoint returns a new identity point.
	NewPoint() Point
	// Generator returns the group's base point.
	Generator() Point
	// RandomScalar returns a cryptographically random scalar.
	RandomScalar(r io.Reader) (Scalar, error)
	// HashToScalar hashes the input data to a scalar.
	HashToScalar(data ...[]byte) (Scalar, error)
	// Order returns the group order as a byte slice.
	Order() []byte
}
