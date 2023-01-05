package cardano

import (
	"encoding/hex"
	"github.com/echovl/cardano-go/crypto"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewOperationalCertificate(t *testing.T) {
	kesVKey := "69ffc95dc8f843d79033f86eb81e61785517e56e8e9b3854b43c5fc567440023"
	kesBytes, err := hex.DecodeString(kesVKey)
	assert.NoError(t, err)

	coldSKey := "288fe53f497bd3e6e9f1a1849d75fcf164b77c5a41786d1e2c3f9e001d788c47"
	coldSKeyBytes, err := hex.DecodeString(coldSKey)
	assert.NoError(t, err)

	coldSKeyPrv := crypto.PrvKey(coldSKeyBytes)
	signPayload := kesVKey + "0000000000000006" + "0000000000000001"
	signPayloadBytes, err := hex.DecodeString(signPayload)
	assert.NoError(t, err)

	signatureBytes := coldSKeyPrv.Sign(signPayloadBytes)
	signature := hex.EncodeToString(signatureBytes)
	assert.Equal(t, "4ea5a83a14ccd15955dbee08c500922bded3624752439bd33dc1f9500e40a4cba63bd6a9dba3770b91a47659da5385c15b7f9d0f75a3fe6f1a150f15a041f003", signature)

	coldVKey := "c5749cc4f1c635f025090816af6eb6043659785e837abbd1f154444fc5033b58"
	coldVKeyBytes, err := hex.DecodeString(coldVKey)
	assert.NoError(t, err)

	opCert := OperationalCertificate{
		KesVKey:   kesBytes,
		Counter:   6,
		KesPeriod: 1,
		Signature: signatureBytes,
		ColdVKey:  coldVKeyBytes,
	}
	opCertCborHexBytes, err := opCert.MarshalCBOR()
	assert.NoError(t, err)

	opCertCborHex := hex.EncodeToString(opCertCborHexBytes)
	assert.Equal(t, "8284582069ffc95dc8f843d79033f86eb81e61785517e56e8e9b3854b43c5fc567440023060158404ea5a83a14ccd15955dbee08c500922bded3624752439bd33dc1f9500e40a4cba63bd6a9dba3770b91a47659da5385c15b7f9d0f75a3fe6f1a150f15a041f0035820c5749cc4f1c635f025090816af6eb6043659785e837abbd1f154444fc5033b58", opCertCborHex)

	// reverse
	newOpCert := OperationalCertificate{}
	errCert := newOpCert.UnmarshalCBOR(opCertCborHexBytes)
	assert.NoError(t, errCert)

	assert.Equal(t, opCert, newOpCert)
}
