package commitstore

type Commitment struct {
	Commitment []byte
	Decommitment []byte
}

type CommitStore interface {
	Get(ID string) (*Commitment, error)
	Import(ID string, commitment *Commitment) error
	Delete(ID string) error
}