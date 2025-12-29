// Package group defines abstract interfaces for cryptographic groups
// used by the FROST threshold signature scheme.
//
// This package provides three core interfaces that abstract over the
// mathematical operations needed for threshold Schnorr signatures:
//
//   - [Scalar]: Elements of the scalar field (integers modulo the group order)
//   - [Point]: Elements of the group (points on an elliptic curve)
//   - [Group]: Factory and utility methods for creating scalars and points
//
// # Design Philosophy
//
// The interfaces use a mutable receiver pattern for efficiency. Operations
// like Add, Mul, and ScalarMult set the receiver to the result and return it,
// allowing method chaining while minimizing allocations:
//
//	// Compute a + b*c
//	result := g.NewScalar().Mul(b, c)
//	result = g.NewScalar().Add(a, result)
//
// All operations that can fail return errors rather than panicking, making
// error handling explicit and predictable.
//
// # Implementing a Group
//
// To implement these interfaces for a new elliptic curve:
//
//  1. Create a Scalar type that wraps your field element and implements [Scalar]
//  2. Create a Point type that wraps your curve point and implements [Point]
//  3. Create a Group type that implements [Group] as a factory
//
// See the bjj package for a complete implementation using Baby Jubjub.
//
// # Security Considerations
//
// Implementations must ensure:
//
//   - Scalar arithmetic is performed modulo the group order
//   - Point operations are constant-time where possible
//   - Random scalars are generated from cryptographically secure sources
//   - Invalid curve points are rejected in SetBytes
package group
