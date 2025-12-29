package bjj

import (
	"crypto/rand"
	"testing"

	"github.com/f3rmion/fy/group"
)

func TestScalar(t *testing.T) {
	g := &BJJ{}

	t.Run("AddSub", func(t *testing.T) {
		a, _ := g.RandomScalar(rand.Reader)
		b, _ := g.RandomScalar(rand.Reader)

		sum := g.NewScalar().Add(a, b)
		diff := g.NewScalar().Sub(sum, b)

		if !diff.Equal(a) {
			t.Error("(a+b)-b != a")
		}
	})

	t.Run("MulInvert", func(t *testing.T) {
		a, _ := g.RandomScalar(rand.Reader)
		aInv, err := g.NewScalar().Invert(a)
		if err != nil {
			t.Fatal(err)
		}

		product := g.NewScalar().Mul(a, aInv)

		// a * a^-1 = 1 => product
		// check if product equals one
		// if product = 1, then product * b = b for any b
		b, _ := g.RandomScalar(rand.Reader)
		result := g.NewScalar().Mul(product, b)

		if !result.Equal(b) {
			t.Error("a*a^-1 != 1")
		}
	})

	t.Run("InvertZeroFails", func(t *testing.T) {
		zero := g.NewScalar()
		_, err := g.NewScalar().Invert(zero)
		if err == nil {
			t.Error("expected error inverting zero")
		}
	})

	t.Run("Negate", func(t *testing.T) {
		zero := g.NewScalar()
		a, _ := g.RandomScalar(rand.Reader)
		negA := g.NewScalar().Negate(a)

		result := g.NewScalar().Add(a, negA)

		if !result.Equal(zero) {
			t.Error("negating scalar failed")
		}
	})

	t.Run("BytesRoundtrip", func(t *testing.T) {
		a, _ := g.RandomScalar(rand.Reader)

		bytes := a.Bytes()
		restored, err := g.NewScalar().SetBytes(bytes)
		if err != nil {
			t.Fatal(err)
		}

		if !restored.Equal(a) {
			t.Error("scalar bytes roundtrip failed")
		}
	})

	t.Run("NewScalarIsZero", func(t *testing.T) {
		zero := g.NewScalar()
		if !zero.IsZero() {
			t.Error("new scalar should be zero")
		}
	})

	t.Run("Equal", func(t *testing.T) {
		var a group.Scalar
		for {
			// edge case is a==0 where -a==a
			// for assertion below, so we exclude a==0
			a, _ = g.RandomScalar(rand.Reader)
			if !a.IsZero(){
				break
			}
		}
		b := g.NewScalar().Set(a)
		if !a.Equal(b) {
			t.Error("copied scalar should equal original")
		}

		b = g.NewScalar().Negate(a)
		if a.Equal(b) {
			t.Error("a should not equal -a")
		}
	})
}

func TestPoint(t *testing.T) {
	g := &BJJ{}

	t.Run("AddSub", func(t *testing.T) {
		s1, _ := g.RandomScalar(rand.Reader)
		s2, _ := g.RandomScalar(rand.Reader)
		P := g.NewPoint().ScalarMult(s1, g.Generator())
		Q := g.NewPoint().ScalarMult(s2, g.Generator())

		sum := g.NewPoint().Add(P, Q)
		diff := g.NewPoint().Sub(sum, Q)

		if !diff.Equal(P) {
			t.Error("(P+Q)-Q != P")
		}
	})

	t.Run("Negate", func(t *testing.T) {
		s, _ := g.RandomScalar(rand.Reader)
		P := g.NewPoint().ScalarMult(s, g.Generator())
		negP := g.NewPoint().Negate(P)

		result := g.NewPoint().Add(P, negP)

		if !result.IsIdentity() {
			t.Error("P + (-P) != identity")
		}
	})

	t.Run("BytesRoundtrip", func(t *testing.T) {
		s, _ := g.RandomScalar(rand.Reader)
		P := g.NewPoint().ScalarMult(s, g.Generator())

		bytes := P.Bytes()
		restored, err := g.NewPoint().SetBytes(bytes)
		if err != nil {
			t.Fatal(err)
		}

		if !restored.Equal(P) {
			t.Error("point bytes roundtrip failed")
		}
	})

	t.Run("IsIdentity", func(t *testing.T) {
		identity := g.NewPoint()
		if !identity.IsIdentity() {
			t.Error("new point should be identity")
		}

		gen := g.Generator()
		if gen.IsIdentity() {
			t.Error("generator should not be identity")
		}
	})
}
