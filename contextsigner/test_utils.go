package contextsigner

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwire"
)

// MockChannelContextSigner is an implementation of the ChannelContextSigner
// interface that signs everything with a provided input.Signer
type MockChannelContextSigner struct {
	signer input.Signer
}

func NewMockChannelContextSigner(
	signer input.Signer) *MockChannelContextSigner {
	return &MockChannelContextSigner{signer: signer}
}

// TODO - Remove this hack.
func (ms *MockChannelContextSigner) Hack() input.Signer {
	return ms.signer
}

func (ms *MockChannelContextSigner) ShimKeyRing(
	publicKeyRing keychain.KeyRing) error {
	return fmt.Errorf("MockChannelContextSigner unimplemented " +
		"ShimKeyRing")
}

func (ms *MockChannelContextSigner) NewChannel(
	peerNode *btcec.PublicKey,
	pendingChanID [32]byte,
) (*ChannelBasepoints, error) {
	return nil, fmt.Errorf("MockChannelContextSigner unimplemented " +
		"NewChannel")
}

func (ms *MockChannelContextSigner) ReadyChannel(
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
) error {
	return fmt.Errorf("MockChannelContextSigner unimplemented " +
		"ReadyChannel")
}

func (ms *MockChannelContextSigner) SignRemoteCommitment(
	chanID lnwire.ChannelID,
	localMultiSigKey keychain.KeyDescriptor,
	remoteMultiSigKey keychain.KeyDescriptor,
	channelValueSat int64,
	remotePerCommitPoint *btcec.PublicKey,
	theirCommitTx *wire.MsgTx,
	theirWitscriptMap map[[32]byte][]byte,
) (input.Signature, error) {
	fundingWitnessScript, fundingOutput, err := input.GenFundingPkScript(
		localMultiSigKey.PubKey.SerializeCompressed(),
		remoteMultiSigKey.PubKey.SerializeCompressed(),
		channelValueSat,
	)
	if err != nil {
		return nil, err
	}

	// Generate our signature for their version of the initial commitment
	// transaction to hand back to the counterparty.
	signDesc := input.SignDescriptor{
		WitnessScript: fundingWitnessScript,
		KeyDesc:       localMultiSigKey,
		Output:        fundingOutput,
		HashType:      txscript.SigHashAll,
		SigHashes:     txscript.NewTxSigHashes(theirCommitTx),
		InputIndex:    0,
	}
	return ms.signer.SignOutputRaw(theirCommitTx, &signDesc)
}

func (ms *MockChannelContextSigner) SignFundingTx(
	signDescs []*input.SignDescriptor,
	fundingTx *wire.MsgTx,
) ([]*input.Script, error) {
	return nil, fmt.Errorf("MockChannelContextSigner unimplemented " +
		"SignFundingTx")
}

func (ms *MockChannelContextSigner) SignChannelAnnouncement(
	chanID lnwire.ChannelID,
	localFundingKey *btcec.PublicKey,
	dataToSign []byte,
) (input.Signature, input.Signature, error) {
	return nil, nil, fmt.Errorf("MockChannelContextSigner unimplemented " +
		"SignChannelAnnouncement")
}

// Compile time check to make sure MockChannelContextSigner implements the
// requisite interfaces.
var _ ChannelContextSigner = (*MockChannelContextSigner)(nil)
