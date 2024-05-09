package encoding

type KeyMarshaler interface {
	Bytes() ([]byte, error)
}