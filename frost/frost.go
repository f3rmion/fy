package frost

import (
	"github.com/f3rmion/fy/group"
)

// FROST holds the group and threshold parameters.
type FROST struct {
	group group.Group
	threshold int // t - minimum signers needed
	total int     // n - total participants
}

// KeyShare represents a participant's share of the secret key
type KeyShare struct {
	ID group.Scalar // participant identifier
	SecretKey group.Scalar // secret key share
	PublicKey group.Point // public key share
	GroupKey group.Point // combined group public key
}

// Signature is a Schnorr signature.
type Signature struct {
	R group.Point
	Z group.Scalar
}
