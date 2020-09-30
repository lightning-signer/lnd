package lnwallet

import (
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lnwire"
)

type NodeContextSigner interface {
	PubKey() *btcec.PublicKey

	ECDH(
		pubKey *btcec.PublicKey,
	) ([32]byte, error)

	// SignAnnouncement(
	// 	pubKey *btcec.PublicKey,
	// 	msg lnwire.Message,
	// ) (input.Signature, error)
}

type ChannelBasepoints struct {
	Revocation     *btcec.PublicKey
	Payment        *btcec.PublicKey
	Htlc           *btcec.PublicKey
	DelayedPayment *btcec.PublicKey
	FundingPubkey  *btcec.PublicKey
}

type ChannelContextSigner interface {
	NewChannel(
		peerNode *btcec.PublicKey,
		pendingChanID [32]byte,
	) error

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

	GetChannelBasepoints(
		peerNode *btcec.PublicKey,
		pendingChanID [32]byte,
	) (*ChannelBasepoints, error)

	SignAnnouncement(
		pubKey *btcec.PublicKey,
		msg lnwire.Message,
	) (input.Signature, error)

	SignRemoteCommitment(
		fundingOutpoint *wire.OutPoint,
		channelValueSat uint64,
		remotePerCommitPoint *btcec.PublicKey,
		theirCommitTx *wire.MsgTx,
		witscripts [][]byte,
	) (input.Signature, error)
}
