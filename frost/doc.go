// Package frost implements the FROST (Flexible Round-Optimized Schnorr Threshold)
// signature scheme over an arbitrary elliptic curve group.
//
// FROST is a threshold signature scheme that allows t-of-n participants to
// collaboratively generate a Schnorr signature without any single participant
// knowing the full private key. The scheme consists of two main phases:
//
// # Distributed Key Generation (DKG)
//
// Before signing, participants must run a distributed key generation protocol
// to establish their key shares. The DKG proceeds in rounds:
//
//  1. Each participant generates a random polynomial and broadcasts commitments
//     to its coefficients using [Participant.Round1Broadcast].
//  2. Each participant sends private shares to all other participants using
//     [FROST.Round1PrivateSend].
//  3. Each participant verifies received shares against the broadcasted
//     commitments using [FROST.Round2ReceiveShare].
//  4. Each participant computes their final key share using [FROST.Finalize].
//
// # Threshold Signing
//
// Once key shares are established, any t participants can collaboratively
// sign a message:
//
//  1. Each signer generates nonces and commitments using [FROST.SignRound1].
//  2. Each signer computes their signature share using [FROST.SignRound2].
//  3. Signature shares are aggregated into a final signature using [FROST.Aggregate].
//  4. Anyone can verify the signature using [FROST.Verify].
//
// # Example
//
// Basic usage with 2-of-3 threshold:
//
//	// Create FROST instance
//	f, _ := frost.New(group, 2, 3)
//
//	// Run DKG (simplified - see tests for full example)
//	participants := make([]*frost.Participant, 3)
//	for i := range participants {
//	    participants[i], _ = f.NewParticipant(rand.Reader, i+1)
//	}
//	// ... exchange broadcasts and shares ...
//	keyShares := make([]*frost.KeyShare, 3)
//	for i, p := range participants {
//	    keyShares[i], _ = f.Finalize(p, broadcasts)
//	}
//
//	// Sign with 2 participants
//	message := []byte("hello")
//	nonce1, commit1, _ := f.SignRound1(rand.Reader, keyShares[0])
//	nonce2, commit2, _ := f.SignRound1(rand.Reader, keyShares[1])
//	commitments := []*frost.SigningCommitment{commit1, commit2}
//
//	share1, _ := f.SignRound2(keyShares[0], nonce1, message, commitments)
//	share2, _ := f.SignRound2(keyShares[1], nonce2, message, commitments)
//
//	sig, _ := f.Aggregate(message, commitments, []*frost.SignatureShare{share1, share2})
//
//	// Verify
//	valid := f.Verify(message, sig, keyShares[0].GroupKey)
//
// # Security Considerations
//
// This implementation assumes a trusted dealer-free setup where all participants
// are honest during DKG. The scheme provides security against a passive adversary
// controlling up to t-1 participants during signing.
//
// Nonces generated in [FROST.SignRound1] must never be reused. Each signing
// session requires fresh nonces.
package frost
