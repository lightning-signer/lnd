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
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/netann"
)

type InternalSigner struct {
	signer        input.Signer
	secretKeyRing keychain.SecretKeyRing
	keyRing       keychain.KeyRing // separate for shimming
	signMessage   func(
		pubKey *btcec.PublicKey, msg []byte) (input.Signature, error)
	idKeyDesc     keychain.KeyDescriptor
	nodeKeyECDH   *keychain.PubKeyECDH
	nodeKeySigner *keychain.PubKeyDigestSigner
	nodeSigner    *netann.NodeSigner
}

func NewInternalSigner(
	signer input.Signer,
	keyRing keychain.SecretKeyRing,
	signMessage func(
		pubKey *btcec.PublicKey, msg []byte) (input.Signature, error),
) (*InternalSigner, error) {
	// We can't initialize the signers yet because the keyring is still
	// locked. Record the arguments for later..
	return &InternalSigner{
		signer:        signer,
		secretKeyRing: keyRing,
		keyRing:       keyRing, // separate for shimming
		signMessage:   signMessage,
	}, nil
}

func (is *InternalSigner) Initialize() error {
	// Once the keyring is unlocked we can setup the signers.
	var err error
	is.idKeyDesc, err = is.keyRing.DeriveKey(
		keychain.KeyLocator{
			Family: keychain.KeyFamilyNodeKey,
			Index:  0,
		},
	)
	if err != nil {
		return err
	}
	is.nodeKeyECDH = keychain.NewPubKeyECDH(is.idKeyDesc, is.secretKeyRing)
	is.nodeKeySigner = keychain.NewPubKeyDigestSigner(is.idKeyDesc, is.secretKeyRing)
	is.nodeSigner = netann.NewNodeSigner(is.nodeKeySigner)
	return nil
}

func (is *InternalSigner) ShimKeyRing(keyRing keychain.KeyRing) error {
	// Replace the non-secret keyring w/ shimmed version.
	is.keyRing = keyRing
	return nil
}

func (is *InternalSigner) NewChannel(
	peerNode *btcec.PublicKey,
	pendingChanID [32]byte,
) (*lnwallet.ChannelBasepoints, error) {
	// Use the non-secret keyring, it may have been shimmed.
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

func (is *InternalSigner) ReadyChannel(
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

func (is *InternalSigner) SignRemoteCommitment(
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

func (is *InternalSigner) SignChannelAnnouncement(
	chanID lnwire.ChannelID,
	localFundingKey *btcec.PublicKey,
	dataToSign []byte,
) (input.Signature, input.Signature, error) {
	nodeSig, err := is.nodeSigner.SignMessage(
		is.nodeKeyECDH.PubKey(), dataToSign)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to generate node "+
			"signature for channel announcement: %v", err)
	}
	bitcoinSig, err := is.signMessage(localFundingKey, dataToSign)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to generate bitcoin "+
			"signature for channel announcement: %v", err)
	}
	return nodeSig, bitcoinSig, nil
}

// Compile time check to make sure InternalSigner implements the
// requisite interfaces.
var _ lnwallet.ChannelContextSigner = (*InternalSigner)(nil)
