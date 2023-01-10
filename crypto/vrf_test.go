package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tyler-smith/go-bip39"
)

const (
	vrfMnemonic = "math pair canoe wolf donor moon luggage brain proof merge arrive snack exact face pipe salad chapter imitate fiber audit around copper climb deliver"
)

func TestNewVrfKey(t *testing.T) {
	entropy, err := bip39.EntropyFromMnemonic(vrfMnemonic) // 32 bytes
	assert.NoError(t, err)

	vrfKey, err := NewVrfKey(entropy)
	assert.NoError(t, err)

	expectedVrfSKey := "8913e0867e64151f2130d7ac516c326684e4a32955f2266e2d568780c25fcac1bd1cb0e86e7f9c00cc6f3c710c35552f120f241bb935c599ca69433b72410eff"
	expectedVrfVKey := "bd1cb0e86e7f9c00cc6f3c710c35552f120f241bb935c599ca69433b72410eff"
	assert.Equal(t, expectedVrfSKey, vrfKey.PrvKey().String())
	assert.Equal(t, expectedVrfVKey, vrfKey.PubKey().String())
}

func TestNewVrfKeyWithDerivation(t *testing.T) {
	entropy, err := bip39.EntropyFromMnemonic(vrfMnemonic) // 32 bytes

	accountIndex := uint32(1)
	rootKey := NewXPrvKeyFromEntropy(entropy, "")
	stakePoolColdKey := rootKey.Derive(1852 + 0x80000000).Derive(1815 + 0x80000000).Derive(0x80000000).Derive(accountIndex + 0x80000000)
	stakePoolVrfKey := stakePoolColdKey.Derive(0)

	vrfKey, err := NewVrfKey(stakePoolVrfKey.PrvKey()[:32])
	assert.NoError(t, err)

	expectedVrfSKey := "481308297c3df2ad4a7999350e2f8cb740080552dc975d89a49f0fa624788c474567cb76b95a2a05bbda04ebd7ec3bcdd4a470e6020e4fabfe70007ede03d7a7"
	expectedVrfVKey := "4567cb76b95a2a05bbda04ebd7ec3bcdd4a470e6020e4fabfe70007ede03d7a7"
	assert.Equal(t, expectedVrfSKey, vrfKey.PrvKey().String())
	assert.Equal(t, expectedVrfVKey, vrfKey.PubKey().String())
}
