# fy

A Go library implementing the FROST (Flexible Round-Optimized Schnorr Threshold) signature scheme with a curve-agnostic design.

FROST enables t-of-n threshold signatures where any t participants can collaboratively sign a message without reconstructing the private key. This implementation includes a Baby Jubjub elliptic curve adapter, making it suitable for use in zero-knowledge proof systems and privacy-preserving applications.


## Installation

```
go get github.com/f3rmion/fy
```


## Usage

### Distributed Key Generation

Before signing, participants run a distributed key generation (DKG) protocol to establish their key shares:

```go
package main

import (
    "crypto/rand"
    "github.com/f3rmion/fy/bjj"
    "github.com/f3rmion/fy/frost"
)

func main() {
    // Create a 2-of-3 threshold scheme on Baby Jubjub
    g := &bjj.BJJ{}
    f, _ := frost.New(g, 2, 3)

    // Each participant creates their state
    participants := make([]*frost.Participant, 3)
    for i := range participants {
        participants[i], _ = f.NewParticipant(rand.Reader, i+1)
    }

    // Round 1: Broadcast commitments
    broadcasts := make([]*frost.Round1Data, 3)
    for i, p := range participants {
        broadcasts[i] = p.Round1Broadcast()
    }

    // Round 1: Send private shares to each other participant
    for i, sender := range participants {
        for j := 0; j < 3; j++ {
            if i == j {
                continue
            }
            privateData := f.Round1PrivateSend(sender, j+1)
            f.Round2ReceiveShare(participants[j], privateData, broadcasts[i].Commitments)
        }
    }

    // Finalize: Each participant computes their key share
    keyShares := make([]*frost.KeyShare, 3)
    for i, p := range participants {
        keyShares[i], _ = f.Finalize(p, broadcasts)
    }

    // All participants now have the same group public key
    groupKey := keyShares[0].GroupKey
}
```

### Threshold Signing

Once key shares are established, any t participants can sign a message:

```go
// Any 2 participants can sign
message := []byte("hello FROST")
signers := []*frost.KeyShare{keyShares[0], keyShares[1]}

// Round 1: Generate nonces and commitments
nonces := make([]*frost.SigningNonce, 2)
commitments := make([]*frost.SigningCommitment, 2)
for i, ks := range signers {
    nonces[i], commitments[i], _ = f.SignRound1(rand.Reader, ks)
}

// Round 2: Generate signature shares
sigShares := make([]*frost.SignatureShare, 2)
for i, ks := range signers {
    sigShares[i], _ = f.SignRound2(ks, nonces[i], message, commitments)
}

// Aggregate into final signature
sig, _ := f.Aggregate(message, commitments, sigShares)

// Anyone can verify with the group public key
valid := f.Verify(message, sig, groupKey)
```


## Package Structure

```
fy/
├── group/    # Abstract interfaces for cryptographic groups
├── bjj/      # Baby Jubjub curve implementation
├── frost/    # FROST threshold signature protocol
├── go.mod
└── go.sum
```

### group

Defines the core interfaces that abstract over elliptic curve operations:

- Group: Factory for scalars and points, provides the generator and random scalar generation
- Scalar: Field element arithmetic (add, subtract, multiply, invert)
- Point: Group element operations (add, subtract, scalar multiplication)

### bjj

Implements the group interfaces for the Baby Jubjub twisted Edwards curve. Baby Jubjub is defined over the BN254 scalar field and is commonly used in zero-knowledge proof systems like those in Ethereum.

This package wraps gnark-crypto's Baby Jubjub implementation.

### frost

Implements the FROST protocol with two main phases:

- Distributed Key Generation (DKG): Participants jointly generate key shares without a trusted dealer
- Threshold Signing: Any t-of-n participants can collaboratively produce a valid Schnorr signature

The implementation is curve-agnostic and accepts any group.Group implementation.


## Adding a New Curve

To use FROST with a different elliptic curve:

1. Implement group.Scalar for your field elements
2. Implement group.Point for your curve points
3. Implement group.Group as a factory

See the bjj package for a reference implementation.


## References

- FROST: Flexible Round-Optimized Schnorr Threshold Signatures
  https://eprint.iacr.org/2020/852

- Baby Jubjub Elliptic Curve
  https://eips.ethereum.org/EIPS/eip-2494


## License

MIT
