package keygen

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/mr-shifu/mpc-lib/core/ecdsa"
	"github.com/mr-shifu/mpc-lib/core/math/curve"
	"github.com/mr-shifu/mpc-lib/core/party"
	"github.com/mr-shifu/mpc-lib/core/pool"
	"github.com/mr-shifu/mpc-lib/lib/round"
	"github.com/mr-shifu/mpc-lib/lib/test"
	"github.com/mr-shifu/mpc-lib/protocols/cmp/config"
	"github.com/mr-shifu/mpc-lib/protocols/cmp/sign"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
	"golang.org/x/sync/errgroup"
)

type Task struct {
	round round.Session
}

type Key struct {
	round round.Session
}

type Sign struct {
	keyID     string
	message   []byte
	signature []byte
	round     round.Session
}

type Party struct {
	PartyID party.ID
	Others  []party.ID
	tasks   map[string]*Task
	keys    map[string]*Key
	signs   map[string]*Sign
}

type Parties map[party.ID]*Party

var parties map[party.ID]*Party

func NewParties(N int) map[party.ID]*Party {
	parties = make(map[party.ID]*Party)
	partyIDs := test.PartyIDs(N)
	for _, partyID := range partyIDs {
		others := make([]party.ID, 0, N-1)
		for _, other := range partyIDs {
			if other != partyID {
				others = append(others, other)
			}
		}
		parties[partyID] = &Party{
			PartyID: partyID,
			Others:  others,
			tasks:   make(map[string]*Task),
			keys:    make(map[string]*Key),
			signs:   make(map[string]*Sign),
		}
	}
	return parties
}

func (p *Party) NewTask(uuid string) {
	p.tasks[uuid] = &Task{}
}

func (p *Party) NewKey(uuid string) {
	p.keys[uuid] = &Key{}
	p.NewTask(uuid)
}

func (p *Party) NewSign(uuid string, keyID string, message []byte, r round.Session) {
	p.signs[uuid] = &Sign{
		keyID:   keyID,
		message: message,
		round:   r,
	}
	p.NewTask(uuid)
	p.tasks[uuid].round = r
}

func (p *Party) BroadcastMsg(msgBytes []byte, keyID string) error {
	m := round.Message{
		From:      p.PartyID,
		Broadcast: true,
	}

	others := p.Others
	for _, other := range others {
		fmt.Printf("Message Broadcasted %s -> %s\n", p.PartyID, other)
		r := parties[other].tasks[keyID].round

		b, ok := r.(round.BroadcastRound)
		if !ok {
			return errors.New("broadcast message but not broadcast round")
		}
		m.Content = b.BroadcastContent()
		if err := cbor.Unmarshal(msgBytes, m.Content); err != nil {
			return err
		}

		if err := b.StoreBroadcastMessage(m); err != nil {
			return err
		}
	}
	return nil
}

func (p *Party) SendMsgTo(msgBytes []byte, to party.ID, keyID string) error {
	fmt.Printf("Message Sent %s -> %s\n", p.PartyID, to)

	r := parties[to].tasks[keyID].round
	m := round.Message{
		From:      p.PartyID,
		To:        to,
		Broadcast: false,
	}
	m.Content = r.MessageContent()
	if err := cbor.Unmarshal(msgBytes, m.Content); err != nil {
		return err
	}

	var errGroup errgroup.Group

	if m.To == "" || m.To == r.SelfID() {
		errGroup.Go(func() error {
			if err := r.VerifyMessage(m); err != nil {
				return err
			}
			fmt.Printf("StoreMessage Sent %s -> %s\n", p.PartyID, to)
			if err := r.StoreMessage(m); err != nil {
				return err
			}
			return nil
		})
	}
	if err := errGroup.Wait(); err != nil {
		return err
	}

	return nil
}

func CheckOutput(t *testing.T, parties Parties, partyIDs []party.ID, taskID string) {
	rounds := make([]round.Session, 0, len(partyIDs))
	for id := range partyIDs {
		idx := id
		partyID := partyIDs[idx]
		party := parties[partyID]
		rounds = append(rounds, party.tasks[taskID].round)
	}
	checkOutput(t, rounds)
}

var pl *pool.Pool

func TestP2PKeygen(t *testing.T) {

	pl = pool.NewPool(0)
	defer pl.TearDown()

	N := 2
	parties := NewParties(N)

	var partyIDs []party.ID
	for _, partyID := range parties {
		partyIDs = append(partyIDs, partyID.PartyID)
	}

	keyID := uuid.New().String()
	for _, partyID := range partyIDs {
		party := parties[partyID]
		party.NewKey(keyID)
	}

	for id := range partyIDs {
		idx := id
		partyID := partyIDs[idx]
		party := parties[partyID]

		info := round.Info{
			ProtocolID:       "cmp/keygen-test",
			FinalRoundNumber: Rounds,
			SelfID:           party.PartyID,
			PartyIDs:         partyIDs,
			Threshold:        N - 1,
			Group:            group,
		}
		r, err := Start(info, pl, nil)(nil)
		fmt.Printf("r: %v\n", r)
		require.NoError(t, err, "round creation should not result in an error")
		task := party.tasks[keyID]
		task.round = r
	}

	for {
		err, done := Run(partyIDs, keyID)
		if err != nil {
			fmt.Printf("err: %v\n", err)
		}
		if done {
			fmt.Printf("done: %v\n", done)
			break
		}
	}

	CheckOutput(t, parties, partyIDs, keyID)

	for id := range partyIDs {
		idx := id
		partyID := partyIDs[idx]
		party := parties[partyID]
		party.keys[keyID].round = party.tasks[keyID].round
	}

	/// Start Signing
	messageToSign := []byte("hello")
	messageHash := make([]byte, 64)
	sha3.ShakeSum128(messageHash, messageToSign)
	signID := uuid.New().String()
	for idx := range partyIDs {
		partyID := partyIDs[idx]
		party := parties[partyID]

		config := party.keys[keyID].round.(*round.Output).Result.(*config.Config)
		r, err := sign.StartSign(config, partyIDs, messageHash, pl)(nil)
		if err != nil {
			fmt.Printf("err: %v\n", err)
			panic(err)
		}
		party.NewSign(signID, keyID, messageHash, r)
		fmt.Printf("sf: %v\n", r)
	}

	for {
		err, done := Run(partyIDs, signID)
		if err != nil {
			fmt.Printf("err: %v\n", err)
		}
		if done {
			fmt.Printf("done: %v\n", done)
			break
		}
	}

	// CheckOutput(t, parties, partyIDs, signID)

	for id := range partyIDs {
		idx := id
		partyID := partyIDs[idx]
		party := parties[partyID]
		party.signs[signID].round = party.tasks[signID].round
		signature := party.signs[signID].round.(*round.Output).Result.(*ecdsa.Signature)

		r, _ := signature.R.MarshalBinary()
		s, _ := signature.S.MarshalBinary()
		fmt.Printf("signature: %x, %x\n", r, s)

		sigEth, _ := signature.SigEthereum()
		fmt.Printf("signature: %x\n", sigEth)

		k := party.keys[keyID].round.(*round.Output).Result.(*config.Config).PublicPoint()
		verified := signature.Verify(k, messageHash)
		fmt.Printf("verified: %v\n", verified)

		sig_ret, _ := ecdsa.SignatureFromEth([65]byte(sigEth))
		sig_ret_bytes, _ := sig_ret.SigEthereum()
		fmt.Printf("signature: %x\n", sig_ret_bytes)

		verified = sig_ret.Verify(k, messageHash)
		fmt.Printf("verified: %v\n", verified)
	}
}

func Run(partyIDs []party.ID, taskID string) (error, bool) {
	N := len(partyIDs)
	out := make(chan *round.Message, N*(N+1))

	var errGroup errgroup.Group
	for id := range partyIDs {
		idx := id
		partyID := partyIDs[idx]
		party := parties[partyID]

		errGroup.Go(func() error {
			fmt.Printf("Party %s Running Round\n", party.PartyID)

			rNew, err := party.tasks[taskID].round.Finalize(out)
			if err != nil {
				return err
			}

			fmt.Printf("Round: %d, Party: %s\n", rNew.Number(), rNew.SelfID())
			rs, err := rNew.Serialize()
			if err != nil {
				return err
			}
			var rr round.Session
			switch rNew.Number() {
			case 0:
				rr = round.NewEmptyKeyResult(group, pl)
				if err := rr.Deserialize(rs); err != nil {
					return err
				}
			case 1:
				rr = NewEmptyRound1(group, pl)
				if err := rr.Deserialize(rs); err != nil {
					return err
				}
			case 2:
				rr = NewEmptyRound2(group, pl)
				if err := rr.Deserialize(rs); err != nil {
					return err
				}
			case 3:
				rr = NewEmptyRound3(group, pl)
				if err := rr.Deserialize(rs); err != nil {
					return err
				}
			case 4:
				rr = NewEmptyRound4(group, pl)
				if err := rr.Deserialize(rs); err != nil {
					return err
				}
			case 5:
				rr = NewEmptyRound5(group, pl)
				if err := rr.Deserialize(rs); err != nil {
					return err
				}
			}

			if !rNew.Equal(rr) {
				return fmt.Errorf("rounds not equal")
			}

			rNew = rr

			task := party.tasks[taskID]
			task.round = rNew

			return err
		})
	}
	err := errGroup.Wait()
	if err != nil {
		return err, false
	}

	close(out)

	roundType, err := checkRounds(partyIDs, taskID)
	if err != nil {
		return err, false
	}
	if roundType.String() == reflect.TypeOf(&round.Output{}).String() {
		return nil, true
	}
	if roundType.String() == reflect.TypeOf(&round.Abort{}).String() {
		return nil, true
	}

	for msg := range out {
		msgBytes, err := cbor.Marshal(msg.Content)
		if err != nil {
			fmt.Printf("err: %v\n", err)
		}
		party := parties[msg.From]

		m := *msg
		errGroup.Go(func() error {
			if m.Broadcast {
				err = party.BroadcastMsg(msgBytes, taskID)
			} else {
				err = party.SendMsgTo(msgBytes, msg.To, taskID)
			}
			return nil
		})
		if err = errGroup.Wait(); err != nil {
			fmt.Printf("err: %v\n", err)
		}
	}

	return nil, false
}

func checkRounds(partyIDs []party.ID, keyID string) (reflect.Type, error) {
	var t reflect.Type
	for id := range partyIDs {
		idx := id
		partyID := partyIDs[idx]
		party := parties[partyID]
		rReal := party.tasks[keyID].round
		t2 := reflect.TypeOf(rReal)
		if t == nil {
			t = t2
		} else if t != t2 {
			return t, fmt.Errorf("two different rounds: %s %s", t, t2)
		}
	}
	return t, nil
}

func TestRoundWasm(t *testing.T) {
	pl := pool.NewPool(0)

	N := 2
	group := curve.Secp256k1{}

	partyIDs := test.PartyIDs(N)

	info := round.Info{
		ProtocolID:       "cmp/keygen-test",
		FinalRoundNumber: Rounds,
		SelfID:           partyIDs[0],
		PartyIDs:         partyIDs,
		Threshold:        N - 1,
		Group:            group,
	}

	r, err := Start(info, pl, nil)(nil)
	if err != nil {
		t.Fatal(err)
	}

	rs, err := r.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("rBytes: %s\n", rs)

	rr := NewEmptyRound1(group, pl)
	if err := rr.Deserialize(rs); err != nil {
		t.Fatal(err)
	}
	fmt.Printf("rr: %v\n", rr)

	out := make(chan *round.Message, N*(N+1))
	r2, err := rr.Finalize(out)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("newR: %v\n", r2)

	r2s, err := r2.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("r2Bytes: %s\n", r2s)

	r2r := NewEmptyRound2(group, pl)
	if err := r2r.Deserialize(r2s); err != nil {
		t.Fatal(err)
	}
	fmt.Printf("r2r: %v\n", r2r)
}

func Serialize(a any) map[string]interface{} {
	return getFields(reflect.ValueOf(a))
}

func getFields(val reflect.Value) map[string]interface{} {
	v := make(map[string]any)

	var ival reflect.Value
	if val.Kind() == reflect.Pointer {
		ival = reflect.Indirect(val)
	} else {
		ival = reflect.Indirect(val)
	}

	for i := 0; i < ival.NumField(); i++ {
		fn := ival.Type().Field(i).Name
		fv := ival.Field(i)
		fk := ival.Field(i).Kind()

		switch fk {
		case reflect.String:
			v[fn] = fv.String()
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			v[fn] = fv.Int()
		case reflect.Bool:
			v[fn] = fv.Bool()
		case reflect.Slice:
			v[fn] = getSlice(fv)
		case reflect.Array:
			v[fn] = getSlice(fv)
		case reflect.Pointer:
			v[fn] = getFields(fv.Elem())
		case reflect.Struct:
			v[fn] = getFields(fv)
		}
	}
	return v
}

func getSlice(val reflect.Value) []interface{} {
	v := make([]interface{}, val.Len())

	for i := 0; i < val.Len(); i++ {
		switch val.Index(i).Kind() {
		case reflect.String:
			v[i] = val.Index(i).String()
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			v[i] = val.Index(i).Int()
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			v[i] = val.Index(i).Uint()
		case reflect.Bool:
			v[i] = val.Index(i).Bool()
		case reflect.Pointer:
			v[i] = getFields(val.Index(i).Elem())
		case reflect.Interface:
			v[i] = getFields(val.Index(i).Elem())
		case reflect.Struct:
			v[i] = getFields(val.Index(i))
		}
	}
	return v
}

func getKeys(v map[string]any) {
	fmt.Printf("Number of Keys: %d\n", len(v))
	for k := range v {
		fmt.Printf("key: %v\n", k)
		newMap, ok := v[k].(map[string]any)
		if ok && len(newMap) > 0 {
			getKeys(newMap)
		}
	}
}
