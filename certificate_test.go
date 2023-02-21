package cardano

import (
	"encoding/hex"
	"github.com/echovl/cardano-go/crypto"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestOperationalCertificate(t *testing.T) {
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

func TestNewOperationalCertificate_1(t *testing.T) {
	kesVKey := "69ffc95dc8f843d79033f86eb81e61785517e56e8e9b3854b43c5fc567440023"
	kesBytes, err := hex.DecodeString(kesVKey)
	assert.NoError(t, err)

	coldSKey := "288fe53f497bd3e6e9f1a1849d75fcf164b77c5a41786d1e2c3f9e001d788c47"
	coldSKeyBytes, err := hex.DecodeString(coldSKey)
	assert.NoError(t, err)

	coldVKey := crypto.PrvKey(coldSKeyBytes).PubKey().String()
	assert.Equal(t, "c5749cc4f1c635f025090816af6eb6043659785e837abbd1f154444fc5033b58", coldVKey)

	opCert, err := NewOperationalCertificate(kesBytes, 6, 1, coldSKeyBytes)
	assert.NoError(t, err)

	opCertCborHexBytes, err := opCert.MarshalCBOR()
	assert.NoError(t, err)

	opCertCborHex := hex.EncodeToString(opCertCborHexBytes)
	expectedOpCertCborHex := "8284582069ffc95dc8f843d79033f86eb81e61785517e56e8e9b3854b43c5fc567440023060158404ea5a83a14ccd15955dbee08c500922bded3624752439bd33dc1f9500e40a4cba63bd6a9dba3770b91a47659da5385c15b7f9d0f75a3fe6f1a150f15a041f0035820c5749cc4f1c635f025090816af6eb6043659785e837abbd1f154444fc5033b58"
	assert.Equal(t, expectedOpCertCborHex, opCertCborHex)
}

func TestNewOperationalCertificate_2(t *testing.T) {
	kesVKey := "0bfce00d2a23f8a36f2bdc6cd53b706724eea78b834f6b256f986596849a2910"
	kesBytes, err := hex.DecodeString(kesVKey)
	assert.NoError(t, err)

	coldSKey := "705a3bed15e8c4c8cdb179545ef5f6fbb6a587c691333666150c073677b1eb48"
	coldSKeyBytes, err := hex.DecodeString(coldSKey)
	assert.NoError(t, err)

	coldVKey := crypto.PrvKey(coldSKeyBytes).PubKey().String()
	assert.Equal(t, "95d7698b66ca242e1d52cb7ceda6073fe61fe896010e5c2ef626834e07b65d8a", coldVKey)

	opCert, err := NewOperationalCertificate(kesBytes, 0, 21, coldSKeyBytes)
	assert.NoError(t, err)

	expectedSignature := "acd0bca3165802b7e0401b63a1376850230c6f8c488e27d24524dcf3f22750cf03963548cdead29f6283d2d86b894ffb6bf8c22e64579c5978d1fa18ec748a0a"
	assert.Equal(t, expectedSignature, hex.EncodeToString(opCert.Signature))

	opCertCborHexBytes, err := opCert.MarshalCBOR()
	assert.NoError(t, err)

	opCertCborHex := hex.EncodeToString(opCertCborHexBytes)
	expectedOpCertCborHex := "828458200bfce00d2a23f8a36f2bdc6cd53b706724eea78b834f6b256f986596849a291000155840acd0bca3165802b7e0401b63a1376850230c6f8c488e27d24524dcf3f22750cf03963548cdead29f6283d2d86b894ffb6bf8c22e64579c5978d1fa18ec748a0a582095d7698b66ca242e1d52cb7ceda6073fe61fe896010e5c2ef626834e07b65d8a"
	assert.Equal(t, expectedOpCertCborHex, opCertCborHex)
}
