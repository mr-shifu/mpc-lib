package round

import "errors"

var (
	ErrNilFields         = errors.New("message contained empty fields")
	ErrInvalidContent    = errors.New("content is not the right type")
	ErrNotEnoughMessages = errors.New("not enough messages")
	ErrOutChanFull       = errors.New("content is not the right type")
)
