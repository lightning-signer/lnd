package lnwallet

import (
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwallet/chanfunding"
	"github.com/lightningnetwork/lnd/lnwire"
)

type ChannelBasepoints struct {
	MultiSigKey         keychain.KeyDescriptor
	RevocationBasePoint keychain.KeyDescriptor
	HtlcBasePoint       keychain.KeyDescriptor
	PaymentBasePoint    keychain.KeyDescriptor
	DelayBasePoint      keychain.KeyDescriptor
}

type NodeContextSigner interface {
	// ECDH performs an ECDH operation between pub and priv. The
	// returned value is the sha256 of the compressed shared point.
	ECDH(pubKey *btcec.PublicKey) ([32]byte, error)

	// Generate the node signature for the node announcement.
	SignNodeAnnouncement(dataToSign []byte) (input.Signature, error)

	// Generate the node signature for the channel update.
	SignChannelUpdate(dataToSign []byte) (input.Signature, error)
}

type ChannelContextSigner interface {
	// Update signer with shim for external funding flow.
	ShimKeyRing(keyRing keychain.SecretKeyRing) error

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
		chanType channeldb.ChannelType,
	) error

	// Generate our signature for the peer's commitment transaction.
	SignRemoteCommitment(
		ourContribution *ChannelContribution,
		theirContribution *ChannelContribution,
		partialState *channeldb.OpenChannel,
		fundingIntent chanfunding.Intent,
		theirCommitTx *wire.MsgTx,
	) (input.Signature, error)

	// Generate the both the node signature and the bitcoin (funding)
	// signature for the channel announcement.
	SignChannelAnnouncement(
		chanID lnwire.ChannelID,
		localFundingKey *btcec.PublicKey,
		dataToSign []byte,
	) (input.Signature, input.Signature, error)
}
