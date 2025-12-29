// Package bjj provides a Baby Jubjub elliptic curve implementation of the
// [group.Group] interface for use with FROST threshold signatures.
//
// Baby Jubjub is a twisted Edwards curve defined over the scalar field of
// BN254 (also known as alt_bn128). It is commonly used in zero-knowledge
// proof systems and privacy-preserving applications.
//
// This package wraps the Baby Jubjub implementation from gnark-crypto,
// providing a clean interface that satisfies [group.Group], [group.Scalar],
// and [group.Point].
//
// # Curve Parameters
//
// Baby Jubjub is defined by the equation:
//
//	a*x^2 + y^2 = 1 + d*x^2*y^2
//
// where a = 168700 and d = 168696 over the BN254 scalar field.
//
// The curve has a prime-order subgroup of size:
//
//	2736030358979909402780800718157159386076813972158567259200215660948447373041
//
// # Usage
//
// Create a BJJ group and use it with FROST:
//
//	g := &bjj.BJJ{}
//	f, err := frost.New(g, threshold, total)
//
// The BJJ type implements [group.Group] and can be used anywhere a Group
// is required.
//
// # Security
//
// This implementation relies on gnark-crypto for the underlying curve
// arithmetic. All scalar operations are performed modulo the curve's
// subgroup order to ensure correctness.
package bjj
