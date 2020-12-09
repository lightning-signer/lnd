package contextsigner

import (
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/zpay32"
)

type ContextSigner interface {
	// NodeContextSigner is used to sign in node-specific contexts.
	NodeContextSigner

	// ChannelContextSigner is used to sign in channel-specific contexts.
	ChannelContextSigner
}

type NodeContextSigner interface {
	// PubKey returns the node identity public key.
	PubKey() *btcec.PublicKey

	// ECDH performs an ECDH operation between pub and priv. The
	// returned value is the sha256 of the compressed shared point.
	ECDH(pubKey *btcec.PublicKey) ([32]byte, error)

	// Generate the node signature for the node announcement.
	SignNodeAnnouncement(dataToSign []byte) (input.Signature, error)

	// Generate the node signature for the channel update.
	SignChannelUpdate(dataToSign []byte) (input.Signature, error)

	// Generate a signature for an invoice.
	zpay32.InvoiceSigner

	// Generate a signature for an ad-hoc message.
	SignMessage(dataToSign []byte) ([]byte, error)
}

type ChannelContextSigner interface {
	// TODO - Hack for unconverted code; Remove this when we're done
	// converting!
	Hack() input.Signer

	// Update signer with shim for external funding flow.
	ShimKeyRing(keyRing keychain.KeyRing) error

	// Inform the validating signer that a new channel is being created.
	NewChannel(
		peerNode *btcec.PublicKey,
		pendingChanID [32]byte,
	) (*ChannelBasepoints, error)

	// Provide the signer with needed information to validate
	// subsequent signature requests.
	ReadyChannel(
		peerNode *btcec.PublicKey,
		pendingChanID [32]byte,
		isOutbound bool,
		channelValueSat uint64,
		pushValueMsat uint64,
		fundingOutpoint *wire.OutPoint,
		localToSelfDelay uint16,
		localShutdownScript []byte,
		remoteRevocationBasepoint *btcec.PublicKey,
		remotePaymentBasepoint *btcec.PublicKey,
		remoteHtlcBasepoint *btcec.PublicKey,
		remoteDelayedPaymentBasepoint *btcec.PublicKey,
		remoteFundingPubkey *btcec.PublicKey,
		remoteToSelfDelay uint16,
		remoteShutdownScript []byte,
		hasAnchors bool,
		isTweakless bool,
	) error

	// Generate our signatures for the funding transaction.
	SignFundingTx(
		signDescs []*input.SignDescriptor,
		fundingTx *wire.MsgTx,
	) ([]*input.Script, error)

	// Generate our signature for the peer's commitment transaction.
	SignRemoteCommitmentTx(
		chanID lnwire.ChannelID,
		localMultiSigKey keychain.KeyDescriptor,
		remoteMultiSigKey keychain.KeyDescriptor,
		channelValueSat int64,
		remotePerCommitPoint *btcec.PublicKey,
		theirCommitTx *wire.MsgTx,
		theirRedeemScriptMap input.RedeemScriptMap,
	) (input.Signature, error)

	// Sign the local commitment at force-close time.
	SignLocalCommitmentTx(
		chanID lnwire.ChannelID,
		signDesc *input.SignDescriptor,
		ourCommitTx *wire.MsgTx,
	) (input.Signature, error)

	// Generate our signature for the peer's htlc transactions.
	SignRemoteHTLCTx(
		chanID lnwire.ChannelID,
		signDesc *input.SignDescriptor,
		commitPoint *btcec.PublicKey,
		theirTx *wire.MsgTx,
		witnessScript []byte,
	) (input.Signature, error)

	// Generate the both the node signature and the bitcoin (funding)
	// signature for the channel announcement.
	SignChannelAnnouncement(
		chanID lnwire.ChannelID,
		localFundingKey *btcec.PublicKey,
		dataToSign []byte,
	) (input.Signature, input.Signature, error)
}

type ChannelBasepoints struct {
	MultiSigKey         keychain.KeyDescriptor
	RevocationBasePoint keychain.KeyDescriptor
	HtlcBasePoint       keychain.KeyDescriptor
	PaymentBasePoint    keychain.KeyDescriptor
	DelayBasePoint      keychain.KeyDescriptor
}

// Compile time check to make sure ContextSigners implement the
// requisite interfaces.
var _ keychain.SingleKeyECDH = (NodeContextSigner)(nil)
