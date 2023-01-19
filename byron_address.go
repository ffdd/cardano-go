package cardano

import (
	"github.com/Bitrue-exchange/libada-go"
	"github.com/cosmos/btcutil/base58"
)

type ByronAddress struct {
	libada.LegacyAddress
}

func NewByronAddress(b58 string) (*ByronAddress, error) {
	ba := &ByronAddress{}
	err := ba.UnmarshalCBOR(base58.Decode(b58))
	if err != nil {
		return nil, err
	}
	return ba, nil
}
func (ba *ByronAddress) Bech32() string {
	return ""
}
