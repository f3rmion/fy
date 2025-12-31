// Package session provides a high-level API for FROST threshold signature
// ceremonies. It wraps the low-level primitives in the [frost] package with
// a simpler interface that handles round management and prevents common
// mistakes like nonce reuse.
//
// The session package is designed for application developers who want to
// integrate FROST without understanding every protocol detail. For full
// control over the protocol, use the [frost] package directly.
//
// # DKG Ceremony
//
// A distributed key generation (DKG) ceremony creates key shares for all
// participants. Each participant runs the same code independently:
//
//	// Create participant state
//	p, err := session.NewParticipant(group, threshold, total, myID)
//	if err != nil {
//		return err
//	}
//
//	// Generate round 1 messages
//	r1, err := p.GenerateRound1(rand.Reader)
//	if err != nil {
//		return err
//	}
//
//	// Broadcast r1.Broadcast to all participants
//	// Send r1.PrivateShares[id] to each participant over secure channel
//
//	// After receiving messages from all other participants:
//	result, err := p.ProcessRound1(&session.Round1Input{
//		Broadcasts:    receivedBroadcasts,
//		PrivateShares: receivedShares,
//	})
//
//	// Store result.KeyShare securely
//
// # Signing
//
// Signing uses a session-based API that ensures nonces are never reused:
//
//	// Create a signing session (generates nonces internally)
//	sess, err := p.NewSigningSession(rand.Reader, message)
//	if err != nil {
//		return err
//	}
//
//	// Broadcast sess.Commitment() to other signers
//	// Collect commitments from other signers
//
//	// Produce signature share (consumes the session)
//	share, err := sess.Sign(allCommitments)
//	if err != nil {
//		return err
//	}
//
//	// Coordinator aggregates shares
//	sig, err := session.Aggregate(frost, message, allCommitments, allShares)
//
// The SigningSession is designed to be used exactly once. Calling Sign a
// second time returns an error, preventing accidental nonce reuse which
// would compromise security.
//
// # Transport Agnostic
//
// This package does not handle network communication. You are responsible
// for distributing messages between participants using your preferred
// transport (TCP, HTTP, libp2p, etc.). The package only manages protocol
// state and message generation.
package session
