package internalsigner

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
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
	secretKeyRing keychain.SecretKeyRing
	publicKeyRing keychain.KeyRing // separate for shimming
	nodeKeyECDH   *keychain.PubKeyECDH
	nodeSigner    *netann.NodeSigner
	signer        input.Signer
	signMessage   func(
		pubKey *btcec.PublicKey, msg []byte) (input.Signature, error)
}

func NewInternalSigner(
	keyRing keychain.SecretKeyRing,
	signer input.Signer,
	signMessage func(
		pubKey *btcec.PublicKey, msg []byte) (input.Signature, error),
) *InternalSigner {
	// We can't initialize the signers yet because the keyring is still
	// locked. Record the arguments for later..
	return &InternalSigner{
		secretKeyRing: keyRing,
		publicKeyRing: keyRing, // separate for shimming
		signer:        signer,
		signMessage:   signMessage,
	}
}

// This constructor can be used in testing contexts where only
// the lnwallet.MessageSigner subset of methods is needed (testing).
func NewNodeSignerOnly(nodeSigner *netann.NodeSigner) *InternalSigner {
	return &InternalSigner{
		nodeSigner: nodeSigner,
	}
}

func (is *InternalSigner) Initialize() error {
	// Once the keyring is unlocked we can setup the signers.
	idKeyDesc, err := is.publicKeyRing.DeriveKey(
		keychain.KeyLocator{
			Family: keychain.KeyFamilyNodeKey,
			Index:  0,
		},
	)
	if err != nil {
		return err
	}
	is.nodeKeyECDH = keychain.NewPubKeyECDH(idKeyDesc, is.secretKeyRing)
	is.nodeSigner = netann.NewNodeSigner(
		keychain.NewPubKeyDigestSigner(idKeyDesc, is.secretKeyRing),
	)
	return nil
}

func (is *InternalSigner) PubKey() *btcec.PublicKey {
	return is.nodeKeyECDH.PubKey()
}

func (is *InternalSigner) ECDH(pubKey *btcec.PublicKey) ([32]byte, error) {
	return is.nodeKeyECDH.ECDH(pubKey)
}

func (is *InternalSigner) SignNodeAnnouncement(
	dataToSign []byte) (input.Signature, error) {
	return is.nodeSigner.SignMessage(is.PubKey(), dataToSign)
}

func (is *InternalSigner) SignChannelUpdate(
	dataToSign []byte) (input.Signature, error) {
	return is.nodeSigner.SignMessage(is.PubKey(), dataToSign)
}

func (is *InternalSigner) SignInvoice(
	hrp string, taggedFieldsBytes []byte) ([]byte, []byte, error) {

	toSign := append([]byte(hrp), taggedFieldsBytes...)
	hash := chainhash.HashB(toSign)

	// We use compact signature format, and also encoded the recovery ID
	// such that a reader of the invoice can recover our pubkey from the
	// signature.
	sign, err := is.nodeSigner.SignCompact(hash)

	return hash, sign, err
}

func (is *InternalSigner) SignMessage(
	dataToSign []byte) ([]byte, error) {
	return is.nodeSigner.SignCompact(dataToSign)
}

func (is *InternalSigner) ShimKeyRing(publicKeyRing keychain.KeyRing) error {
	// Replace the non-secret keyring w/ shimmed version.
	is.publicKeyRing = publicKeyRing
	return nil
}

func (is *InternalSigner) NewChannel(
	peerNode *btcec.PublicKey,
	pendingChanID [32]byte,
) (*lnwallet.ChannelBasepoints, error) {
	// Use the non-secret keyring, it may have been shimmed.
	var err error
	var bps lnwallet.ChannelBasepoints
	bps.MultiSigKey, err = is.publicKeyRing.DeriveNextKey(
		keychain.KeyFamilyMultiSig,
	)
	if err != nil {
		return nil, err
	}
	bps.RevocationBasePoint, err = is.publicKeyRing.DeriveNextKey(
		keychain.KeyFamilyRevocationBase,
	)
	if err != nil {
		return nil, err
	}
	bps.HtlcBasePoint, err = is.publicKeyRing.DeriveNextKey(
		keychain.KeyFamilyHtlcBase,
	)
	if err != nil {
		return nil, err
	}
	bps.PaymentBasePoint, err = is.publicKeyRing.DeriveNextKey(
		keychain.KeyFamilyPaymentBase,
	)
	if err != nil {
		return nil, err
	}
	bps.DelayBasePoint, err = is.publicKeyRing.DeriveNextKey(
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
var _ lnwallet.ContextSigner = (*InternalSigner)(nil)
