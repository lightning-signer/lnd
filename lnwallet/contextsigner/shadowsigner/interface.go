package shadowsigner

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwallet/chanfunding"
)

// TEMPORARY - The ShadowSigner is used to validate the remotesigner
// during development.  The ShadowSigner is a ChannelContextSigner
// which contains an internal ChannelContextSigner and a remote
// ChannelContextSigner. It delegates all calls to both of the other
// signers and compares the results.

type shadowSigner struct {
	internalSigner lnwallet.ChannelContextSigner
	remoteSigner   lnwallet.ChannelContextSigner
}

func NewShadowSigner(
	internalSigner lnwallet.ChannelContextSigner,
	remoteSigner lnwallet.ChannelContextSigner,
) lnwallet.ChannelContextSigner {
	return &shadowSigner{
		internalSigner: internalSigner,
		remoteSigner:   remoteSigner,
	}
}

func (ss *shadowSigner) NewChannel(
	peerNode *btcec.PublicKey,
	pendingChanID [32]byte,
) (*lnwallet.ChannelBasepoints, error) {
	var err error
	bps0, err := ss.internalSigner.NewChannel(peerNode, pendingChanID)
	if err != nil {
		return nil, err
	}
	bps1, err := ss.remoteSigner.NewChannel(peerNode, pendingChanID)
	if err != nil {
		return nil, err
	}
	if bps0 != bps1 {
		return nil, fmt.Errorf("ShadowSigner.NewChannel mismatch: "+
			"internal=%v remote=%v", bps0, bps1)
	}
	return bps1, nil
}

func (ss *shadowSigner) ReadyChannel(
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
) error {
	var err error
	err = ss.internalSigner.ReadyChannel(
		peerNode,
		pendingChanID,
		isOutbound,
		channelValueSat,
		pushValueMsat,
		fundingOutpoint,
		localToSelfDelay,
		localShutdownScript,
		remoteRevocationBasepoint,
		remotePaymentBasepoint,
		remoteHtlcBasepoint,
		remoteDelayedPaymentBasepoint,
		remoteFundingPubkey,
		remoteToSelfDelay,
		remoteShutdownScript,
		chanType,
	)
	if err != nil {
		return err
	}
	err = ss.remoteSigner.ReadyChannel(
		peerNode,
		pendingChanID,
		isOutbound,
		channelValueSat,
		pushValueMsat,
		fundingOutpoint,
		localToSelfDelay,
		localShutdownScript,
		remoteRevocationBasepoint,
		remotePaymentBasepoint,
		remoteHtlcBasepoint,
		remoteDelayedPaymentBasepoint,
		remoteFundingPubkey,
		remoteToSelfDelay,
		remoteShutdownScript,
		chanType,
	)
	if err != nil {
		return err
	}
	return nil
}

func (ss *shadowSigner) SignRemoteCommitment(
	ourContribution *lnwallet.ChannelContribution,
	theirContribution *lnwallet.ChannelContribution,
	partialState *channeldb.OpenChannel,
	fundingIntent chanfunding.Intent,
	theirCommitTx *wire.MsgTx,
) (input.Signature, error) {
	var err error
	sig0, err := ss.internalSigner.SignRemoteCommitment(
		ourContribution,
		theirContribution,
		partialState,
		fundingIntent,
		theirCommitTx,
	)
	if err != nil {
		return nil, err
	}
	sig1, err := ss.remoteSigner.SignRemoteCommitment(
		ourContribution,
		theirContribution,
		partialState,
		fundingIntent,
		theirCommitTx,
	)
	if err != nil {
		return nil, err
	}
	if sig0 != sig1 {
		return nil, fmt.Errorf("ShadowSigner.SignRemoteCommitment mismatch: "+
			"internal=%v remote=%v", sig0, sig1)
	}
	return sig1, nil
}

// Compile time check to make sure shadowSigner implements the
// requisite interfaces.
var _ lnwallet.ChannelContextSigner = (*shadowSigner)(nil)
