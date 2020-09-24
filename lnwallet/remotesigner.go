package lnwallet

import (
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/wire"
	"github.com/go-errors/errors"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwire"
)

type ChannelBasepoints struct {
	Revocation     *btcec.PublicKey
	Payment        *btcec.PublicKey
	Htlc           *btcec.PublicKey
	DelayedPayment *btcec.PublicKey
	FundingPubkey  *btcec.PublicKey
}

type RemoteSigner interface {
	InitNode(
		networkName string,
		seed0 []byte, // SHADOW mode only
		debugCaller string,
	) ([]byte, error)

	SetShadowECDH(*keychain.PubKeyECDH) error // SHADOW mode only

	PubKey() *btcec.PublicKey

	ECDH(
		pubKey *btcec.PublicKey,
	) ([32]byte, error)

	SignAnnouncement(
		pubKey *btcec.PublicKey,
		msg lnwire.Message,
	) (input.Signature, error)

	NewChannel(
		peerNode *btcec.PublicKey,
		pendingChanID [32]byte,
	) error

	GetChannelBasepoints(
		peerNode *btcec.PublicKey,
		pendingChanID [32]byte,
	) (*ChannelBasepoints, error)

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

	SignRemoteCommitment(
		fundingOutpoint *wire.OutPoint,
		channelValueSat uint64,
		remotePerCommitPoint *btcec.PublicKey,
		theirCommitTx *wire.MsgTx,
		witscripts [][]byte,
	) (input.Signature, error)
}

var (
	ErrRemoteSignerNodeIDNotSet = errors.New("remotesigner nodeid not set")
	remoteSignerInstance        RemoteSigner
)

func SetRemoteSigner(remoteSigner RemoteSigner) {
	remoteSignerInstance = remoteSigner
}

func GetRemoteSigner() RemoteSigner {
	return remoteSignerInstance
}
