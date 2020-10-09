package internalsigner

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwallet/chanfunding"
)

type internalSigner struct {
	signer  input.Signer
	keyRing keychain.KeyRing
}

func NewInternalSigner(
	signer input.Signer,
	keyRing keychain.KeyRing,
) lnwallet.ChannelContextSigner {
	return &internalSigner{
		signer:  signer,
		keyRing: keyRing,
	}
}

func (is *internalSigner) ShimKeyRing(keyRing keychain.KeyRing) error {
	is.keyRing = keyRing
	return nil
}

func (is *internalSigner) NewChannel(
	peerNode *btcec.PublicKey,
	pendingChanID [32]byte,
) (*lnwallet.ChannelBasepoints, error) {
	var err error
	var bps lnwallet.ChannelBasepoints
	bps.MultiSigKey, err = is.keyRing.DeriveNextKey(
		keychain.KeyFamilyMultiSig,
	)
	if err != nil {
		return nil, err
	}
	bps.RevocationBasePoint, err = is.keyRing.DeriveNextKey(
		keychain.KeyFamilyRevocationBase,
	)
	if err != nil {
		return nil, err
	}
	bps.HtlcBasePoint, err = is.keyRing.DeriveNextKey(
		keychain.KeyFamilyHtlcBase,
	)
	if err != nil {
		return nil, err
	}
	bps.PaymentBasePoint, err = is.keyRing.DeriveNextKey(
		keychain.KeyFamilyPaymentBase,
	)
	if err != nil {
		return nil, err
	}
	bps.DelayBasePoint, err = is.keyRing.DeriveNextKey(
		keychain.KeyFamilyDelayBase,
	)
	if err != nil {
		return nil, err
	}
	return &bps, nil
}

func (is *internalSigner) ReadyChannel(
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
	// The internal signer doesn't need this call, but validating
	// signers using the ChannelContextSigner interface will.
	return nil
}

func (is *internalSigner) SignRemoteCommitment(
	ourContribution *lnwallet.ChannelContribution,
	theirContribution *lnwallet.ChannelContribution,
	partialState *channeldb.OpenChannel,
	fundingIntent chanfunding.Intent,
	theirCommitTx *wire.MsgTx,
) (input.Signature, error) {
	// We'll obtain the funding witness script, and the funding
	// output itself so we can generate a valid signature for the remote
	// party.
	fundingWitnessScript, fundingOutput, err := fundingIntent.FundingOutput()
	if err != nil {
		return nil, fmt.Errorf("unable to obtain funding output")
	}

	// Generate our signature for their version of the initial commitment
	// transaction to hand back to the counterparty.
	ourKey := ourContribution.MultiSigKey
	signDesc := input.SignDescriptor{
		WitnessScript: fundingWitnessScript,
		KeyDesc:       ourKey,
		Output:        fundingOutput,
		HashType:      txscript.SigHashAll,
		SigHashes:     txscript.NewTxSigHashes(theirCommitTx),
		InputIndex:    0,
	}
	return is.signer.SignOutputRaw(theirCommitTx, &signDesc)
}

// Compile time check to make sure internalSigner implements the
// requisite interfaces.
var _ lnwallet.ChannelContextSigner = (*internalSigner)(nil)
