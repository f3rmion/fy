package frost

import (
	"errors"
	"io"

	"github.com/f3rmion/fy/group"
)

// Round1Data is broadcast by each participant in round 1.
type Round1Data struct {
	ID          group.Scalar  // participant identifier
	Commitments []group.Point // commitments to polynomial coefficients
}

// Round1PrivateData is sent privately to each participant.
type Round1PrivateData struct {
	FromID group.Scalar // sender's ID
	ToID   group.Scalar // recipient's ID
	Share  group.Scalar // polynomial evaluation for recipient
}

// Participant holds state during DKG.
type Participant struct {
	id             group.Scalar
	coefficients   []group.Scalar          // our secret polynomial
	commitments    []group.Point           // public commitments
	receivedShares map[string]group.Scalar // shares from others
}

// NewParticipant creates a participant for DKG.
func (f *FROST) NewParticipant(r io.Reader, id int) (*Participant, error) {
	// Generate random polynomial of degree t-1
	coeffs := make([]group.Scalar, f.threshold)
	for i := 0; i < f.threshold; i++ {
		c, err := f.group.RandomScalar(r)
		if err != nil {
			return nil, err
		}
		coeffs[i] = c
	}

	// Compute commitments: C_i = coeffs[i] * G
	commits := make([]group.Point, f.threshold)
	for i, c := range coeffs {
		commits[i] = f.group.NewPoint().ScalarMult(c, f.group.Generator())
	}

	return &Participant{
		id:             f.scalarFromInt(id),
		coefficients:   coeffs,
		commitments:    commits,
		receivedShares: make(map[string]group.Scalar),
	}, nil
}

// Round1Broadcast returns data to broadcast to all participants.
func (p *Participant) Round1Broadcast() *Round1Data {
	return &Round1Data{
		ID:          p.id,
		Commitments: p.commitments,
	}
}

// Round1PrivateSend returns the share to send privately to recipient.
func (f *FROST) Round1PrivateSend(p *Participant, recipientID int) *Round1PrivateData {
	toID := f.scalarFromInt(recipientID)
	share := f.evalPolynomial(p.coefficients, toID)

	return &Round1PrivateData{
		FromID: p.id,
		ToID:   toID,
		Share:  share,
	}
}

// Round2ReceiveShare verifies and stores a received share.
func (f *FROST) Round2ReceiveShare(p *Participant, data *Round1PrivateData, senderCommitments []group.Point) error {
	// Verify: share * G == sum(commitments[i] * recipientID^i)
	lhs := f.group.NewPoint().ScalarMult(data.Share, f.group.Generator())

	rhs := f.group.NewPoint()
	xPower := f.scalarFromInt(1)

	for _, commit := range senderCommitments {
		term := f.group.NewPoint().ScalarMult(xPower, commit)
		rhs = f.group.NewPoint().Add(rhs, term)
		xPower = f.group.NewScalar().Mul(xPower, data.ToID)
	}

	if !lhs.Equal(rhs) {
		return errors.New("invalid share from participant")
	}

	// Store the share
	key := string(data.FromID.Bytes())
	p.receivedShares[key] = data.Share
	return nil
}

// Finalize computes the final key share after receiving all shares.
func (f *FROST) Finalize(p *Participant, allBroadcasts []*Round1Data) (*KeyShare, error) {
	// Sum all received shares (including our own)
	secretKey := f.evalPolynomial(p.coefficients, p.id)
	for _, share := range p.receivedShares {
		secretKey = f.group.NewScalar().Add(secretKey, share)
	}

	// Compute public key share
	publicKey := f.group.NewPoint().ScalarMult(secretKey, f.group.Generator())

	// Compute group public key: sum of all constant term commitments
	groupKey := f.group.NewPoint()
	for _, broadcast := range allBroadcasts {
		groupKey = f.group.NewPoint().Add(groupKey, broadcast.Commitments[0])
	}

	return &KeyShare{
		ID:        p.id,
		SecretKey: secretKey,
		PublicKey: publicKey,
		GroupKey:  groupKey,
	}, nil
}
