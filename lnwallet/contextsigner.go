package lnwallet

import (
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwallet/chanfunding"
)

type ChannelBasepoints struct {
	MultiSigKey         keychain.KeyDescriptor
	RevocationBasePoint keychain.KeyDescriptor
	HtlcBasePoint       keychain.KeyDescriptor
	PaymentBasePoint    keychain.KeyDescriptor
	DelayBasePoint      keychain.KeyDescriptor
}

type ChannelContextSigner interface {
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
}
