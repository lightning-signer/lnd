package internalsigner

import (
	"fmt"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwallet/chanfunding"
)

type internalSigner struct {
	signer input.Signer
}

func NewInternalSigner(signer input.Signer) lnwallet.ChannelContextSigner {
	return &internalSigner{
		signer: signer,
	}
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

	// Generate a signature for their version of the initial commitment
	// transaction.
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
