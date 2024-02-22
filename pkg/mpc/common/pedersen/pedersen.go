package pedersen
import (
	comm_pedersen "github.com/mr-shifu/mpc-lib/pkg/common/cryptosuite/pedersen"
)
type PedersenKeyManager interface {
	ImportKey(keyID string, partyID string, data []byte) (comm_pedersen.PedersenKey, error)
	GetKey(keyID string, partyID string) (comm_pedersen.PedersenKey, error)
}
