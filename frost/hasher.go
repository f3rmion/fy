package frost

import (
	"crypto/sha256"

	"github.com/f3rmion/fy/group"
	"golang.org/x/crypto/blake2b"
)

// Hasher defines the hash operations required by FROST.
// Different implementations can provide different hash functions
// and domain separation schemes.
type Hasher interface {
	// H1 computes the binding factor for a signer.
	// Inputs: message, encoded commitment list, signer ID.
	H1(g group.Group, msg, encCommitList, signerID []byte) group.Scalar

	// H2 computes the Schnorr challenge.
	// Inputs: R point, public key Y, message.
	H2(g group.Group, R, Y, msg []byte) group.Scalar

	// H3 computes a nonce from seed and additional data.
	// Inputs: seed, rho (binding factor), message.
	H3(g group.Group, seed, rho, msg []byte) group.Scalar

	// H4 hashes a message for signing.
	H4(g group.Group, msg []byte) []byte

	// H5 hashes the commitment list.
	H5(g group.Group, encCommitList []byte) []byte
}

// SHA256Hasher implements Hasher using SHA-256.
// This is the default hasher for general use.
type SHA256Hasher struct{}

func (h *SHA256Hasher) hash(data ...[]byte) []byte {
	hasher := sha256.New()
	for _, d := range data {
		hasher.Write(d)
	}
	return hasher.Sum(nil)
}

func (h *SHA256Hasher) hashToScalar(g group.Group, data ...[]byte) group.Scalar {
	hash := h.hash(data...)
	s := g.NewScalar()
	s.SetBytes(hash)
	return s
}

// H1 implements Hasher.H1.
func (h *SHA256Hasher) H1(g group.Group, msg, encCommitList, signerID []byte) group.Scalar {
	return h.hashToScalar(g, []byte("rho"), msg, encCommitList, signerID)
}

// H2 implements Hasher.H2.
func (h *SHA256Hasher) H2(g group.Group, R, Y, msg []byte) group.Scalar {
	return h.hashToScalar(g, R, Y, msg)
}

// H3 implements Hasher.H3.
func (h *SHA256Hasher) H3(g group.Group, seed, rho, msg []byte) group.Scalar {
	return h.hashToScalar(g, []byte("nonce"), seed, rho, msg)
}

// H4 implements Hasher.H4.
func (h *SHA256Hasher) H4(g group.Group, msg []byte) []byte {
	return h.hash([]byte("msg"), msg)
}

// H5 implements Hasher.H5.
func (h *SHA256Hasher) H5(g group.Group, encCommitList []byte) []byte {
	return h.hash([]byte("com"), encCommitList)
}

// Blake2bHasher implements Hasher using Blake2b-512 with domain separation.
// This is compatible with Ledger/iden3 FROST implementations.
//
// Domain separation format: prefix + tag + input
// Output is interpreted as little-endian before reducing mod curve order.
type Blake2bHasher struct {
	// Prefix is the domain separation prefix.
	// Default: "FROST-EDBABYJUJUB-BLAKE512-v1"
	Prefix string
}

// NewBlake2bHasher creates a Blake2bHasher with the Ledger-compatible prefix.
func NewBlake2bHasher() *Blake2bHasher {
	return &Blake2bHasher{
		Prefix: "FROST-EDBABYJUJUB-BLAKE512-v1",
	}
}

func (h *Blake2bHasher) hash(tag string, data ...[]byte) []byte {
	hasher, _ := blake2b.New512(nil)
	hasher.Write([]byte(h.Prefix))
	hasher.Write([]byte(tag))
	for _, d := range data {
		hasher.Write(d)
	}
	return hasher.Sum(nil)
}

// hashToScalar hashes data and converts to a scalar.
// The 64-byte output is interpreted as little-endian before reducing mod order.
func (h *Blake2bHasher) hashToScalar(g group.Group, tag string, data ...[]byte) group.Scalar {
	hash := h.hash(tag, data...)

	// Reverse bytes for little-endian interpretation
	reversed := make([]byte, len(hash))
	for i := 0; i < len(hash); i++ {
		reversed[i] = hash[len(hash)-1-i]
	}

	s := g.NewScalar()
	s.SetBytes(reversed)
	return s
}

// H1 implements Hasher.H1 (binding factor computation).
func (h *Blake2bHasher) H1(g group.Group, msg, encCommitList, signerID []byte) group.Scalar {
	return h.hashToScalar(g, "rho", msg, encCommitList, signerID)
}

// H2 implements Hasher.H2 (Schnorr challenge).
func (h *Blake2bHasher) H2(g group.Group, R, Y, msg []byte) group.Scalar {
	return h.hashToScalar(g, "chal", R, Y, msg)
}

// H3 implements Hasher.H3 (nonce generation).
func (h *Blake2bHasher) H3(g group.Group, seed, rho, msg []byte) group.Scalar {
	return h.hashToScalar(g, "nonce", seed, rho, msg)
}

// H4 implements Hasher.H4 (message hashing).
func (h *Blake2bHasher) H4(g group.Group, msg []byte) []byte {
	return h.hash("msg", msg)
}

// H5 implements Hasher.H5 (commitment list hashing).
func (h *Blake2bHasher) H5(g group.Group, encCommitList []byte) []byte {
	return h.hash("com", encCommitList)
}
