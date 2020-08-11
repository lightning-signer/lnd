package netann

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwallet"
)

type NodeSigner interface {
	lnwallet.MessageSigner
	SignDigestCompact(digest []byte) ([]byte, error)
	SignCompact(msg []byte) ([]byte, error)
}

// NodeSignerImpl is an implementation of the MessageSigner interface
// backed by the identity private key of running lnd node.
type NodeSignerImpl struct {
	keySigner keychain.SingleKeyDigestSigner
}

// NewNodeSignerImpl creates a new instance of the NodeSignerImpl
// backed by the target private key.
func NewNodeSignerImpl(keySigner keychain.SingleKeyDigestSigner) *NodeSignerImpl {
	return &NodeSignerImpl{
		keySigner: keySigner,
	}
}

// SignMessage signs a double-sha256 digest of the passed msg under the
// resident node's private key. If the target public key is _not_ the node's
// private key, then an error will be returned.
func (n *NodeSignerImpl) SignMessage(pubKey *btcec.PublicKey,
	msg []byte) (input.Signature, error) {

	// If this isn't our identity public key, then we'll exit early with an
	// error as we can't sign with this key.
	if !pubKey.IsEqual(n.keySigner.PubKey()) {
		return nil, fmt.Errorf("unknown public key")
	}

	// Otherwise, we'll sign the dsha256 of the target message.
	var digest [32]byte
	copy(digest[:], chainhash.DoubleHashB(msg))
	sig, err := n.keySigner.SignDigest(digest)
	if err != nil {
		return nil, fmt.Errorf("can't sign the message: %v", err)
	}

	return sig, nil
}

// SignCompact signs a double-sha256 digest of the msg parameter under the
// resident node's private key. The returned signature is a pubkey-recoverable
// signature.
func (n *NodeSignerImpl) SignCompact(msg []byte) ([]byte, error) {
	// We'll sign the dsha256 of the target message.
	digest := chainhash.DoubleHashB(msg)

	return n.SignDigestCompact(digest)
}

// SignDigestCompact signs the provided message digest under the resident
// node's private key. The returned signature is a pubkey-recoverable signature.
func (n *NodeSignerImpl) SignDigestCompact(hash []byte) ([]byte, error) {
	var digest [32]byte
	copy(digest[:], hash)

	// keychain.SignDigestCompact returns a pubkey-recoverable signature.
	sig, err := n.keySigner.SignDigestCompact(digest)
	if err != nil {
		return nil, fmt.Errorf("can't sign the hash: %v", err)
	}

	return sig, nil
}

// A compile time check to ensure that NodeSignerImpl implements the
// MessageSigner interface.
var _ lnwallet.MessageSigner = (*NodeSignerImpl)(nil)
