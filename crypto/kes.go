package crypto

import (
	"fmt"

	"github.com/echovl/ed25519"
	"golang.org/x/crypto/blake2b"
)

const (
	PublicKeyLength = 32
	SecretKeyLength = 32
)

type KesKey struct {
	pubKey PubKey
	prvKey PrvKey
}

func NewKesKey(seed []byte) (KesKey, error) {
	if len(seed) != 32 {
		return KesKey{}, fmt.Errorf("seed has to be 32 bytes")
	}

	prvKey, pubKey, err := kesKeygen(seed, 6) // A 2^6 period KES
	if err != nil {
		return KesKey{}, err
	}
	return KesKey{pubKey: pubKey, prvKey: prvKey}, nil
}

func (k KesKey) PrvKey() PrvKey {
	return k.prvKey
}

func (k KesKey) PubKey() PubKey {
	return k.pubKey
}

func kesKeyLen(depth int) int {
	return SecretKeyLength + depth*32 + depth*(PublicKeyLength*2)
}

func kesKeygen(seed []byte, depth int) (PrvKey, PubKey, error) {
	if depth > 7 {
		return nil, nil, fmt.Errorf("Sum7KesKey is maximum")
	}
	if depth == 0 {
		pkey := ed25519.NewKeyFromSeed(seed)
		_, pubKey := pkey[:32], pkey[32:]
		return PrvKey(pkey[:32]), PubKey(pubKey), nil
	}

	data := make([]byte, kesKeyLen(depth)+4)

	pk, err := kesKeygenSlice(data, seed, depth)
	if err != nil {
		return nil, nil, err
	}
	return data, pk, nil
}

func kesKeygenSlice(in_slice []byte, in_seed []byte, depth int) (PubKey, error) {
	if depth == 0 {
		pkey := ed25519.NewKeyFromSeed(in_seed)
		_, pubKey := pkey[:32], pkey[32:]
		copy(in_slice[:kesKeyLen(0)], pkey)
		return PubKey(pubKey), nil
	}

	r0, seed, err := splitSlice(in_seed)
	if err != nil {
		return nil, err
	}

	copy(in_slice[kesKeyLen(depth-1):kesKeyLen(depth-1)+32], seed)

	pk0, err := kesKeygenSlice(in_slice, r0, depth-1)
	if err != nil {
		return nil, err
	}
	_, pk1, err := kesKeygen(seed, depth-1)
	if err != nil {
		return nil, err
	}

	pubKey, err := hashPair(pk0, pk1)
	if err != nil {
		return nil, err
	}

	copy(in_slice[kesKeyLen(depth-1)+32:kesKeyLen(depth-1)+64], pk0)
	copy(in_slice[kesKeyLen(depth-1)+64:kesKeyLen(depth-1)+96], pk1)

	return pubKey, nil
}

func hashPair(a []byte, b []byte) ([]byte, error) {
	h, err := blake2b.New256(nil)
	if err != nil {
		return nil, err
	}

	_, errA := h.Write(a)
	if errA != nil {
		return nil, err
	}
	_, errB := h.Write(b)
	if errB != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func splitSlice(bytes []byte) ([]byte, []byte, error) {
	hLeft, err := blake2b.New256(nil) // 32
	if err != nil {
		return nil, nil, err
	}
	hRight, err := blake2b.New256(nil)
	if err != nil {
		return nil, nil, err
	}

	_, err = hLeft.Write([]byte{1})
	if err != nil {
		return nil, nil, err
	}
	_, err = hLeft.Write(bytes)
	if err != nil {
		return nil, nil, err
	}
	leftSeed := hLeft.Sum(nil)

	_, err = hRight.Write([]byte{2})
	if err != nil {
		return nil, nil, err
	}
	_, err = hRight.Write(bytes)
	if err != nil {
		return nil, nil, err
	}
	rightSeed := hRight.Sum(nil)

	return leftSeed, rightSeed, nil
}
