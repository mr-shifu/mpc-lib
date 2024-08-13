package commitment

import "github.com/fxamacker/cbor/v2"

type CommitmentImpl struct {
	cmt  []byte
	dcmt []byte
}

type rawCommitment struct {
	Commitment   []byte
	Decommitment []byte
}

func (cmt *CommitmentImpl) Bytes() ([]byte, error) {
	raw := rawCommitment{
		Commitment:   cmt.cmt,
		Decommitment: cmt.dcmt,
	}
	return cbor.Marshal(raw)
}

func (cmt *CommitmentImpl) Commitment() []byte {
	return cmt.cmt
}

func (cmt *CommitmentImpl) Decommitment() []byte {
	return cmt.dcmt
}

func fromBytes(data []byte) (*CommitmentImpl, error) {
	raw := &rawCommitment{}
	if err := cbor.Unmarshal(data, raw); err != nil {
		return nil, err
	}
	cmt := &CommitmentImpl{
		cmt:  raw.Commitment,
		dcmt: raw.Decommitment,
	}
	return cmt, nil
}
