package mock

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil/bech32"

	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/netann"
)

// DummySignature is a dummy Signature implementation.
type DummySignature struct{}

// Serialize returns an empty byte slice.
func (d *DummySignature) Serialize() []byte {
	return []byte{}
}

// Verify always returns true.
func (d *DummySignature) Verify(_ []byte, _ *btcec.PublicKey) bool {
	return true
}

// DummySigner is an implementation of the Signer interface that returns
// dummy values when called.
type DummySigner struct{}

// SignOutputRaw returns a dummy signature.
func (d *DummySigner) SignOutputRaw(tx *wire.MsgTx,
	signDesc *input.SignDescriptor) (input.Signature, error) {

	return &DummySignature{}, nil
}

// ComputeInputScript returns nil for both values.
func (d *DummySigner) ComputeInputScript(tx *wire.MsgTx,
	signDesc *input.SignDescriptor) (*input.Script, error) {

	return &input.Script{}, nil
}

// SingleNodeContextSigner is an implementation of the NodeContextSigner
// interface that signs everything with a single private key.
type SingleNodeContextSigner struct {
	nodeKeyECDH *keychain.PrivKeyECDH
	nodeSigner  *netann.NodeSigner
}

func NewSingleNodeContextSigner(
	privKey *btcec.PrivateKey) *SingleNodeContextSigner {
	privKeySigner := &keychain.PrivKeyDigestSigner{PrivKey: privKey}
	return &SingleNodeContextSigner{
		nodeKeyECDH: &keychain.PrivKeyECDH{PrivKey: privKey},
		nodeSigner:  netann.NewNodeSigner(privKeySigner),
	}
}

func (cs *SingleNodeContextSigner) PubKey() *btcec.PublicKey {
	return cs.nodeKeyECDH.PubKey()
}

func (cs *SingleNodeContextSigner) ECDH(pubKey *btcec.PublicKey) ([32]byte, error) {
	return cs.nodeKeyECDH.ECDH(pubKey)
}

func (cs *SingleNodeContextSigner) SignNodeAnnouncement(
	dataToSign []byte) (input.Signature, error) {
	return cs.nodeSigner.SignMessage(cs.PubKey(), dataToSign)
}

func (cs *SingleNodeContextSigner) SignChannelUpdate(
	dataToSign []byte) (input.Signature, error) {
	return cs.nodeSigner.SignMessage(cs.PubKey(), dataToSign)
}

func (cs *SingleNodeContextSigner) SignInvoice(
	hrp string, fieldsData []byte) ([]byte, []byte, error) {
	// The signature is over the single SHA-256 hash of the hrp + the
	// tagged fields encoded in base256.
	taggedFieldsBytes, err := bech32.ConvertBits(fieldsData, 5, 8, true)
	if err != nil {
		return nil, nil, err
	}
	toSign := append([]byte(hrp), taggedFieldsBytes...)
	hash := chainhash.HashB(toSign)

	sign, err := cs.nodeSigner.SignDigestCompact(hash)
	return hash, sign, err
}

func (cs *SingleNodeContextSigner) SignMessage(
	dataToSign []byte) ([]byte, error) {
	return cs.nodeSigner.SignCompact(dataToSign)
}

// SingleSigner is an implementation of the Signer interface that signs
// everything with a single private key.
type SingleSigner struct {
	Privkey *btcec.PrivateKey
}

// SignOutputRaw generates a signature for the passed transaction using the
// stored private key.
func (s *SingleSigner) SignOutputRaw(tx *wire.MsgTx,
	signDesc *input.SignDescriptor) (input.Signature, error) {

	amt := signDesc.Output.Value
	witnessScript := signDesc.WitnessScript
	privKey := s.Privkey

	if !privKey.PubKey().IsEqual(signDesc.KeyDesc.PubKey) {
		return nil, fmt.Errorf("incorrect key passed")
	}

	switch {
	case signDesc.SingleTweak != nil:
		privKey = input.TweakPrivKey(privKey,
			signDesc.SingleTweak)
	case signDesc.DoubleTweak != nil:
		privKey = input.DeriveRevocationPrivKey(privKey,
			signDesc.DoubleTweak)
	}

	sig, err := txscript.RawTxInWitnessSignature(tx, signDesc.SigHashes,
		signDesc.InputIndex, amt, witnessScript, signDesc.HashType,
		privKey)
	if err != nil {
		return nil, err
	}

	return btcec.ParseDERSignature(sig[:len(sig)-1], btcec.S256())
}

// ComputeInputScript computes an input script with the stored private key
// given a transaction and a SignDescriptor.
func (s *SingleSigner) ComputeInputScript(tx *wire.MsgTx,
	signDesc *input.SignDescriptor) (*input.Script, error) {

	privKey := s.Privkey

	switch {
	case signDesc.SingleTweak != nil:
		privKey = input.TweakPrivKey(privKey,
			signDesc.SingleTweak)
	case signDesc.DoubleTweak != nil:
		privKey = input.DeriveRevocationPrivKey(privKey,
			signDesc.DoubleTweak)
	}

	witnessScript, err := txscript.WitnessSignature(tx, signDesc.SigHashes,
		signDesc.InputIndex, signDesc.Output.Value, signDesc.Output.PkScript,
		signDesc.HashType, privKey, true)
	if err != nil {
		return nil, err
	}

	return &input.Script{
		Witness: witnessScript,
	}, nil
}

// SignMessage takes a public key and a message and only signs the message
// with the stored private key if the public key matches the private key.
func (s *SingleSigner) SignMessage(pubKey *btcec.PublicKey,
	msg []byte) (input.Signature, error) {

	if !pubKey.IsEqual(s.Privkey.PubKey()) {
		return nil, fmt.Errorf("unknown public key")
	}

	digest := chainhash.DoubleHashB(msg)
	sign, err := s.Privkey.Sign(digest)
	if err != nil {
		return nil, fmt.Errorf("can't sign the message: %v", err)
	}

	return sign, nil
}
