package frost

import (
	"io"

	"github.com/f3rmion/fy/group"
)

// SigningNonce holds a participant's nonce pair for signing.
type SigningNonce struct {
	ID group.Scalar
	D  group.Scalar // hiding nonce
	E  group.Scalar // binding nonce
}

// SigningCommitment is broadcast in round 1 of signing.
type SigningCommitment struct {
	ID           group.Scalar
	HidingPoint  group.Point // D * G
	BindingPoint group.Point // E * G
}

// SignatureShare is a participant's share of the signature.
type SignatureShare struct {
	ID group.Scalar
	Z  group.Scalar
}

// SignRound1 generates nonces and commitment for signing.
func (f *FROST) SignRound1(r io.Reader, share *KeyShare) (*SigningNonce, *SigningCommitment, error) {
	d, err := f.group.RandomScalar(r)
	if err != nil {
		return nil, nil, err
	}
	e, err := f.group.RandomScalar(r)
	if err != nil {
		return nil, nil, err
	}

	nonce := &SigningNonce{
		ID: share.ID,
		D:  d,
		E:  e,
	}

	commitment := &SigningCommitment{
		ID:           share.ID,
		HidingPoint:  f.group.NewPoint().ScalarMult(d, f.group.Generator()),
		BindingPoint: f.group.NewPoint().ScalarMult(e, f.group.Generator()),
	}

	return nonce, commitment, nil
}

// SignRound2 generates a signature share.
func (f *FROST) SignRound2(
	share *KeyShare,
	nonce *SigningNonce,
	message []byte,
	commitments []*SigningCommitment,
) (*SignatureShare, error) {
	// Compute binding factors for each signer
	bindingFactors := f.computeBindingFactors(message, commitments)

	// Compute group commitment R = sum(D_i + rho_i * E_i)
	R := f.group.NewPoint()
	for _, comm := range commitments {
		rho := bindingFactors[string(comm.ID.Bytes())]
		rhoE := f.group.NewPoint().ScalarMult(rho, comm.BindingPoint)
		term := f.group.NewPoint().Add(comm.HidingPoint, rhoE)
		R = f.group.NewPoint().Add(R, term)
	}

	// Compute challenge c = H(R, GroupKey, message)
	c, err := f.group.HashToScalar(R.Bytes(), share.GroupKey.Bytes(), message)
	if err != nil {
		return nil, err
	}

	// Compute Lagrange coefficient for this signer
	lambda := f.lagrangeCoefficient(share.ID, commitments)

	// Compute signature share: z_i = d + rho * e + lambda * s * c
	myRho := bindingFactors[string(share.ID.Bytes())]

	z := f.group.NewScalar().Mul(myRho, nonce.E)              // rho * e
	z = f.group.NewScalar().Add(nonce.D, z)                   // d + rho * e
	lambdaS := f.group.NewScalar().Mul(lambda, share.SecretKey) // lambda * s
	lambdaSC := f.group.NewScalar().Mul(lambdaS, c)           // lambda * s * c
	z = f.group.NewScalar().Add(z, lambdaSC)                  // d + rho*e + lambda*s*c

	return &SignatureShare{
		ID: share.ID,
		Z:  z,
	}, nil
}

// Aggregate combines signature shares into a final signature.
func (f *FROST) Aggregate(
	message []byte,
	commitments []*SigningCommitment,
	shares []*SignatureShare,
) (*Signature, error) {
	// Recompute R
	bindingFactors := f.computeBindingFactors(message, commitments)
	R := f.group.NewPoint()
	for _, comm := range commitments {
		rho := bindingFactors[string(comm.ID.Bytes())]
		rhoE := f.group.NewPoint().ScalarMult(rho, comm.BindingPoint)
		term := f.group.NewPoint().Add(comm.HidingPoint, rhoE)
		R = f.group.NewPoint().Add(R, term)
	}

	// Sum all z shares
	z := f.group.NewScalar()
	for _, s := range shares {
		z = f.group.NewScalar().Add(z, s.Z)
	}

	return &Signature{R: R, Z: z}, nil
}

// Verify checks a FROST signature.
func (f *FROST) Verify(message []byte, sig *Signature, groupKey group.Point) bool {
	// c = H(R, GroupKey, message)
	c, err := f.group.HashToScalar(sig.R.Bytes(), groupKey.Bytes(), message)
	if err != nil {
		return false
	}

	// Check: z*G == R + c*Y
	lhs := f.group.NewPoint().ScalarMult(sig.Z, f.group.Generator())

	cY := f.group.NewPoint().ScalarMult(c, groupKey)
	rhs := f.group.NewPoint().Add(sig.R, cY)

	return lhs.Equal(rhs)
}

func (f *FROST) computeBindingFactors(message []byte, commitments []*SigningCommitment) map[string]group.Scalar {
	factors := make(map[string]group.Scalar)

	// Build commitment list bytes for hashing
	var commBytes []byte
	for _, c := range commitments {
		commBytes = append(commBytes, c.ID.Bytes()...)
		commBytes = append(commBytes, c.HidingPoint.Bytes()...)
		commBytes = append(commBytes, c.BindingPoint.Bytes()...)
	}

	for _, c := range commitments {
		rho, _ := f.group.HashToScalar(message, commBytes, c.ID.Bytes())
		factors[string(c.ID.Bytes())] = rho
	}

	return factors
}

func (f *FROST) lagrangeCoefficient(id group.Scalar, commitments []*SigningCommitment) group.Scalar {
	num := f.scalarFromInt(1)
	den := f.scalarFromInt(1)

	for _, c := range commitments {
		if c.ID.Equal(id) {
			continue
		}
		// num *= c.ID
		num = f.group.NewScalar().Mul(num, c.ID)
		// den *= (c.ID - id)
		diff := f.group.NewScalar().Sub(c.ID, id)
		den = f.group.NewScalar().Mul(den, diff)
	}

	denInv, _ := f.group.NewScalar().Invert(den)
	return f.group.NewScalar().Mul(num, denInv)
}
