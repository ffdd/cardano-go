package cardano

import (
	"encoding/hex"
	"fmt"

	"github.com/echovl/cardano-go/crypto"
)

// https://github.com/IntersectMBO/cardano-ledger/blob/adb63e0c899109d89b5e99cc0d5b6a2e97fa3d2d/eras/conway/impl/testlib/Test/Cardano/Ledger/Conway/CDDL.hs#L281-L375
type CertificateType uint

const (
	StakeRegistration CertificateType = iota
	StakeDeregistration
	StakeDelegation
	PoolRegistration
	PoolRetirement
	GenesisKeyDelegation
	MoveInstantaneousRewards
	// conway
	Registration
	Deregistration
	VoteDelegation
	StakeVoteDelegation
	StakeRegistrationDelegation
	VoteRegistrationDelegation
	StakeVoteRegistrationDelegation
	AuthCommiteeHot
	ResignCommiteeCold
	RegistrationDrep
	DeregistrationDrep
	UpdateDrep
)

// https://github.com/IntersectMBO/cardano-ledger/blob/adb63e0c899109d89b5e99cc0d5b6a2e97fa3d2d/eras/conway/impl/testlib/Test/Cardano/Ledger/Conway/CDDL.hs#L384-L390
type Drep uint

const (
	AddressKeyHash Drep = iota
	ScriptHash
	AlwaysAbstain
	NoConfidence
)

type stakeRegistration struct {
	_               struct{} `cbor:",toarray"`
	Type            CertificateType
	StakeCredential StakeCredential
}

type stakeDeregistration struct {
	_               struct{} `cbor:",toarray"`
	Type            CertificateType
	StakeCredential StakeCredential
}

type stakeDelegation struct {
	_               struct{} `cbor:",toarray"`
	Type            CertificateType
	StakeCredential StakeCredential
	PoolKeyHash     PoolKeyHash
}

type poolRegistration struct {
	_             struct{} `cbor:",toarray"`
	Type          CertificateType
	Operator      PoolKeyHash
	VrfKeyHash    Hash32
	Pledge        Coin
	PoolCost      Coin
	Margin        UnitInterval
	RewardAccount Address
	Owners        []AddrKeyHash
	Relays        []Relay
	PoolMetadata  *PoolMetadata // or null
}

type poolRetirement struct {
	_           struct{} `cbor:",toarray"`
	Type        CertificateType
	PoolKeyHash PoolKeyHash
	Epoch       uint64
}

type genesisKeyDelegation struct {
	_                   struct{} `cbor:",toarray"`
	Type                CertificateType
	GenesisHash         Hash28
	GenesisDelegateHash Hash28
	VrfKeyHash          Hash32
}

type voteDelegation struct {
	_               struct{} `cbor:",toarray"`
	Type            CertificateType
	StakeCredential StakeCredential
	Drep            []Drep
}

// Certificate is a Cardano certificate.
type Certificate struct {
	Type CertificateType

	// Common fields
	StakeCredential StakeCredential
	PoolKeyHash     PoolKeyHash
	VrfKeyHash      Hash32

	// Pool related fields
	Operator      PoolKeyHash
	Pledge        Coin
	PoolCost      Coin
	Margin        UnitInterval
	RewardAccount Address
	Owners        []AddrKeyHash
	Relays        []Relay
	PoolMetadata  *PoolMetadata // or null
	Epoch         uint64

	// Genesis fields
	GenesisHash         Hash28
	GenesisDelegateHash Hash28

	// Conway fields
	Drep []Drep
}

// MarshalCBOR implements cbor.Marshaler.
func (c *Certificate) MarshalCBOR() ([]byte, error) {
	var cert interface{}
	switch c.Type {
	case StakeRegistration:
		cert = stakeRegistration{
			Type:            c.Type,
			StakeCredential: c.StakeCredential,
		}
	case StakeDeregistration:
		cert = stakeDeregistration{
			Type:            c.Type,
			StakeCredential: c.StakeCredential,
		}
	case StakeDelegation:
		cert = stakeDelegation{
			Type:            c.Type,
			StakeCredential: c.StakeCredential,
			PoolKeyHash:     c.PoolKeyHash,
		}
	case PoolRegistration:
		cert = poolRegistration{
			Type:          c.Type,
			Operator:      c.Operator,
			VrfKeyHash:    c.VrfKeyHash,
			Pledge:        c.Pledge,
			PoolCost:      c.PoolCost,
			Margin:        c.Margin,
			RewardAccount: c.RewardAccount,
			Owners:        c.Owners,
			Relays:        c.Relays,
			PoolMetadata:  c.PoolMetadata,
		}
	case PoolRetirement:
		cert = poolRetirement{
			Type:        c.Type,
			PoolKeyHash: c.PoolKeyHash,
			Epoch:       c.Epoch,
		}
	case GenesisKeyDelegation:
		cert = genesisKeyDelegation{
			Type:                c.Type,
			GenesisHash:         c.GenesisHash,
			GenesisDelegateHash: c.GenesisDelegateHash,
			VrfKeyHash:          c.VrfKeyHash,
		}
	case VoteDelegation:
		cert = voteDelegation{
			Type:            c.Type,
			StakeCredential: c.StakeCredential,
			Drep:            c.Drep,
		}
	}

	return cborEnc.Marshal(cert)
}

// NewStakeRegistrationCertificate creates a Stake Registration Certificate.
func NewStakeRegistrationCertificate(stakeKey crypto.PubKey) (Certificate, error) {
	cred, err := NewKeyCredential(stakeKey)
	if err != nil {
		return Certificate{}, err
	}

	return Certificate{
		Type:            StakeRegistration,
		StakeCredential: cred,
	}, nil
}

// NewStakeDeregistrationCertificate creates a Stake Deregistration Certificate.
func NewStakeDeregistrationCertificate(stakeKey crypto.PubKey) (Certificate, error) {
	cred, err := NewKeyCredential(stakeKey)
	if err != nil {
		return Certificate{}, err
	}

	return Certificate{
		Type:            StakeDeregistration,
		StakeCredential: cred,
	}, nil
}

// NewStakeDelegationCertificate creates a Stake Delegation Certificate.
func NewStakeDelegationCertificate(stakeKey crypto.PubKey, poolKeyHash Hash28) (Certificate, error) {
	cred, err := NewKeyCredential(stakeKey)
	if err != nil {
		return Certificate{}, err
	}

	return Certificate{
		Type:            StakeDelegation,
		StakeCredential: cred,
		PoolKeyHash:     poolKeyHash,
	}, nil
}

// UnmarshalCBOR implements cbor.Unmarshaler.
func (c *Certificate) UnmarshalCBOR(data []byte) error {
	certType, err := getTypeFromCBORArray(data)
	if err != nil {
		return fmt.Errorf("cbor: cannot unmarshal CBOR array into StakeCredential (%v)", err)
	}

	switch CertificateType(certType) {
	case StakeRegistration:
		cert := &stakeRegistration{}
		if err := cborDec.Unmarshal(data, cert); err != nil {
			return err
		}
		c.Type = StakeRegistration
		c.StakeCredential = cert.StakeCredential
	case StakeDeregistration:
		cert := &stakeDeregistration{}
		if err := cborDec.Unmarshal(data, cert); err != nil {
			return err
		}
		c.Type = StakeDeregistration
		c.StakeCredential = cert.StakeCredential
	case StakeDelegation:
		cert := &stakeDelegation{}
		if err := cborDec.Unmarshal(data, cert); err != nil {
			return err
		}
		c.Type = StakeDelegation
		c.StakeCredential = cert.StakeCredential
		c.PoolKeyHash = cert.PoolKeyHash
	case PoolRegistration:
		cert := &poolRegistration{}
		if err := cborDec.Unmarshal(data, cert); err != nil {
			return err
		}
		c.Type = PoolRegistration
		c.Operator = cert.Operator
		c.VrfKeyHash = cert.VrfKeyHash
		c.Pledge = cert.Pledge
		c.PoolCost = cert.PoolCost
		c.Margin = cert.Margin
		c.RewardAccount = cert.RewardAccount
		c.Owners = cert.Owners
		c.Relays = cert.Relays
		c.PoolMetadata = cert.PoolMetadata
	case PoolRetirement:
		cert := &poolRetirement{}
		if err := cborDec.Unmarshal(data, cert); err != nil {
			return err
		}
		c.Type = PoolRetirement
		c.PoolKeyHash = cert.PoolKeyHash
		c.Epoch = cert.Epoch
	case GenesisKeyDelegation:
		cert := &genesisKeyDelegation{}
		if err := cborDec.Unmarshal(data, cert); err != nil {
			return err
		}
		c.Type = GenesisKeyDelegation
		c.GenesisHash = cert.GenesisHash
		c.GenesisDelegateHash = cert.GenesisDelegateHash
		c.VrfKeyHash = cert.VrfKeyHash
	case VoteDelegation:
		cert := &voteDelegation{}
		if err := cborDec.Unmarshal(data, cert); err != nil {
			return err
		}
		c.Type = VoteDelegation
		c.StakeCredential = cert.StakeCredential
		c.Drep = cert.Drep
	}

	return nil
}

// PoolMetadata represents the metadata used for a pool registration.
type PoolMetadata struct {
	_    struct{} `cbor:",toarray"`
	URL  string
	Hash Hash32
}

type RelayType uint64

const (
	SingleHostAddr RelayType = 0
	SingleHostName           = 1
	MultiHostName            = 2
)

type singleHostAddr struct {
	_    struct{} `cbor:",toarray"`
	Type RelayType
	Port Uint64
	Ipv4 []byte
	Ipv6 []byte
}

type singleHostName struct {
	_       struct{} `cbor:",toarray"`
	Type    RelayType
	Port    Uint64
	DNSName string
}

type multiHostName struct {
	_       struct{} `cbor:",toarray"`
	Type    RelayType
	DNSName string
}

type Relay struct {
	Type    RelayType
	Port    Uint64
	Ipv4    []byte
	Ipv6    []byte
	DNSName string
}

// MarshalCBOR implements cbor.Marshaler.
func (r *Relay) MarshalCBOR() ([]byte, error) {
	var relay interface{}
	switch r.Type {
	case SingleHostAddr:
		relay = singleHostAddr{
			Type: r.Type,
			Port: r.Port,
			Ipv4: r.Ipv4,
			Ipv6: r.Ipv6,
		}
	case SingleHostName:
		relay = singleHostName{
			Type:    r.Type,
			Port:    r.Port,
			DNSName: r.DNSName,
		}
	case MultiHostName:
		relay = multiHostName{
			Type:    r.Type,
			DNSName: r.DNSName,
		}
	}

	return cborEnc.Marshal(relay)
}

// UnmarshalCBOR implements cbor.Unmarshaler.
func (r *Relay) UnmarshalCBOR(data []byte) error {
	relayType, err := getTypeFromCBORArray(data)
	if err != nil {
		return fmt.Errorf("cbor: cannot unmarshal CBOR array into Relay (%v)", err)
	}

	switch RelayType(relayType) {
	case SingleHostAddr:
		rl := &singleHostAddr{}
		if err := cborDec.Unmarshal(data, rl); err != nil {
			return err
		}
		r.Type = SingleHostAddr
		r.Port = rl.Port
		r.Ipv4 = rl.Ipv4
		r.Ipv6 = rl.Ipv6
	case SingleHostName:
		rl := &singleHostName{}
		if err := cborDec.Unmarshal(data, rl); err != nil {
			return err
		}
		r.Type = SingleHostName
		r.Port = rl.Port
		r.DNSName = rl.DNSName
	case MultiHostName:
		rl := &multiHostName{}
		if err := cborDec.Unmarshal(data, rl); err != nil {
			return err
		}
		r.Type = MultiHostName
		r.DNSName = rl.DNSName
	}

	return nil
}

type OCertBody struct {
	_         struct{} `cbor:",toarray"`
	KesVKey   []byte
	Counter   uint
	KesPeriod uint
	Signature []byte
}

type operationalCertificate struct {
	_        struct{} `cbor:",toarray"`
	Body     OCertBody
	ColdVKey []byte
}

// OperationalCertificate is a Cardano operational certificate
type OperationalCertificate struct {
	KesVKey   []byte
	Counter   uint
	KesPeriod uint
	Signature []byte
	ColdVKey  []byte
}

func NewOperationalCertificate(kesVKey []byte, counter uint, kesPeriod uint, coldSKey crypto.PrvKey) (OperationalCertificate, error) {
	signPayload := hex.EncodeToString(kesVKey) + fmt.Sprintf("%0*x", 16, counter) + fmt.Sprintf("%0*x", 16, kesPeriod)
	signPayloadBytes, err := hex.DecodeString(signPayload)
	if err != nil {
		return OperationalCertificate{}, err
	}
	signatureBytes := coldSKey.Sign(signPayloadBytes)

	opCert := OperationalCertificate{
		KesVKey:   kesVKey,
		Counter:   counter,
		KesPeriod: kesPeriod,
		Signature: signatureBytes,
		ColdVKey:  coldSKey.PubKey(),
	}
	return opCert, nil
}

func (oc *OperationalCertificate) MarshalCBOR() ([]byte, error) {
	var cert interface{}
	cert = operationalCertificate{
		Body: OCertBody{
			KesVKey:   oc.KesVKey,
			Counter:   oc.Counter,
			KesPeriod: oc.KesPeriod,
			Signature: oc.Signature,
		},
		ColdVKey: oc.ColdVKey,
	}
	return cborEnc.Marshal(cert)
}

func (oc *OperationalCertificate) UnmarshalCBOR(data []byte) error {
	ocl := &operationalCertificate{}
	if err := cborDec.Unmarshal(data, ocl); err != nil {
		return err
	}
	oc.KesVKey = ocl.Body.KesVKey
	oc.Counter = ocl.Body.Counter
	oc.KesPeriod = ocl.Body.KesPeriod
	oc.Signature = ocl.Body.Signature
	oc.ColdVKey = ocl.ColdVKey
	return nil
}
