package commitment

import "github.com/fxamacker/cbor/v2"

type Commitment struct {
	cmt  []byte
	dcmt []byte
}

type rawCommitment struct {
	Commitment   []byte
	Decommitment []byte
}

func (cmt *Commitment) Bytes() ([]byte, error) {
	raw := rawCommitment{
		Commitment:   cmt.cmt,
		Decommitment: cmt.dcmt,
	}
	return cbor.Marshal(raw)
}

func (cmt *Commitment) Commitment() []byte {
	return cmt.cmt
}

func (cmt *Commitment) Decommitment() []byte {
	return cmt.dcmt
}

func fromBytes(data []byte) (*Commitment, error) {
	raw := &rawCommitment{}
	if err := cbor.Unmarshal(data, raw); err != nil {
		return nil, err
	}
	cmt := &Commitment{
		cmt:  raw.Commitment,
		dcmt: raw.Decommitment,
	}
	return cmt, nil
}
