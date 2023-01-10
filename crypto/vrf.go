package crypto

import (
	"fmt"

	"github.com/echovl/ed25519"
)

type VrfKey PrvKey

func NewVrfKey(seed []byte) (VrfKey, error) {
	if len(seed) != 32 {
		return VrfKey{}, fmt.Errorf("seed has to be 32 bytes")
	}
	return VrfKey(ed25519.NewKeyFromSeed(seed)), nil
}

func (v VrfKey) PrvKey() PrvKey {
	return PrvKey(v)
}

func (v VrfKey) PubKey() PubKey {
	return PrvKey(v[:32]).PubKey()
}
