package frost

import (
	"crypto/rand"
	"testing"

	"github.com/f3rmion/fy/bjj"
)

func TestDKGAndSign(t *testing.T) {
	g := &bjj.BJJ{}
	threshold := 2
	total := 3

	f, err := New(g, threshold, total)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("DKG", func(t *testing.T) {
		// Create participants
		participants := make([]*Participant, total)
		for i := 0; i < total; i++ {
			p, err := f.NewParticipant(rand.Reader, i+1)
			if err != nil {
				t.Fatalf("failed to create participant %d: %v", i+1, err)
			}
			participants[i] = p
		}

		// Round 1: Each participant broadcasts commitments
		broadcasts := make([]*Round1Data, total)
		for i, p := range participants {
			broadcasts[i] = p.Round1Broadcast()
		}

		// Round 1: Each participant sends private shares to others
		for i, sender := range participants {
			for j := 0; j < total; j++ {
				if i == j {
					continue // don't send to self
				}
				privateData := f.Round1PrivateSend(sender, j+1)

				t.Logf("Sender %d -> Recipient %d", i+1, j+1)
				t.Logf("  Share: %x", privateData.Share.Bytes())
				t.Logf("  ToID: %x", privateData.ToID.Bytes())
				t.Logf("  Recipient p.id: %x", participants[j].id.Bytes())

				// Recipient receives and verifies
				err := f.Round2ReceiveShare(participants[j], privateData, broadcasts[i].Commitments)
				if err != nil {
					t.Fatalf("participant %d failed to verify share from %d: %v", j+1, i+1, err)
				}
			}
		}

		// Finalize: Each participant computes their key share
		keyShares := make([]*KeyShare, total)
		for i, p := range participants {
			ks, err := f.Finalize(p, broadcasts)
			if err != nil {
				t.Fatalf("participant %d failed to finalize: %v", i+1, err)
			}
			keyShares[i] = ks
		}

		// Verify all participants have the same group key
		for i := 1; i < total; i++ {
			if !keyShares[i].GroupKey.Equal(keyShares[0].GroupKey) {
				t.Error("participants have different group keys")
			}
		}

		t.Run("Sign", func(t *testing.T) {
			message := []byte("hello FROST")

			// Use first 'threshold' participants to sign
			signers := keyShares[:threshold]

			// Round 1: Generate nonces and commitments
			nonces := make([]*SigningNonce, threshold)
			commitments := make([]*SigningCommitment, threshold)
			for i, ks := range signers {
				n, c, err := f.SignRound1(rand.Reader, ks)
				if err != nil {
					t.Fatalf("signer %d failed round 1: %v", i+1, err)
				}
				nonces[i] = n
				commitments[i] = c
			}

			// Round 2: Generate signature shares
			sigShares := make([]*SignatureShare, threshold)
			for i, ks := range signers {
				ss, err := f.SignRound2(ks, nonces[i], message, commitments)
				if err != nil {
					t.Fatalf("signer %d failed round 2: %v", i+1, err)
				}
				sigShares[i] = ss
			}

			// Aggregate signature
			sig, err := f.Aggregate(message, commitments, sigShares)
			if err != nil {
				t.Fatalf("failed to aggregate signature: %v", err)
			}

			// Verify signature
			if !f.Verify(message, sig, keyShares[0].GroupKey) {
				t.Error("signature verification failed")
			}

			// Verify with wrong message fails
			if f.Verify([]byte("wrong message"), sig, keyShares[0].GroupKey) {
				t.Error("signature should not verify with wrong message")
			}
		})
	})
}

func TestThresholdValidation(t *testing.T) {
	g := &bjj.BJJ{}

	t.Run("ThresholdTooLow", func(t *testing.T) {
		_, err := New(g, 1, 3)
		if err == nil {
			t.Error("expected error for threshold < 2")
		}
	})

	t.Run("TotalLessThanThreshold", func(t *testing.T) {
		_, err := New(g, 3, 2)
		if err == nil {
			t.Error("expected error for total < threshold")
		}
	})
}
