package shadowsigner

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"reflect"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/davecgh/go-spew/spew"
	"github.com/lightningnetwork/lnd/contextsigner"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwire"
)

// TEMPORARY - The ShadowSigner is used to validate the remotesigner
// during development.  The ShadowSigner is a ContextSigner
// which contains an internal ContextSigner and a remote
// ContextSigner. It delegates all calls to both of the other
// signers and compares the results.

type shadowSigner struct {
	internalSigner contextsigner.ContextSigner
	remoteSigner   contextsigner.ContextSigner
}

// We need to capture the same seed that the internal wallet uses for
// the remote signer.  These routines are removed once we are done
// with the shadowing phase of remotesigner development.
var (
	shadowSeed []byte
)

// The argument to EstablishShadowSeed is sometimes empty, in which
// case we will generate the seed here and return the generated seed.
func EstablishShadowSeed(seed []byte, debugCaller string) ([]byte, error) {
	// Was entropy supplied?
	if seed != nil {
		// Yes, use the supplied entropy..
		shadowSeed = seed
		log.Infof("EstablishShadowSeed: using supplied seed %s, called from %s",
			hex.EncodeToString(shadowSeed), debugCaller)
	} else {
		// No, generate some entropy and return it.
		var err error
		shadowSeed, err = hdkeychain.GenerateSeed(
			hdkeychain.RecommendedSeedLen)
		if err != nil {
			return nil, err
		}
		log.Infof("EstablishShadowSeed: generated seed %s, called from %s",
			hex.EncodeToString(shadowSeed), debugCaller)
	}
	return shadowSeed, nil
}

func GetShadowSeed() []byte {
	return shadowSeed
}

func NewShadowSigner(
	internalSigner contextsigner.ContextSigner,
	remoteSigner contextsigner.ContextSigner,
) contextsigner.ContextSigner {
	return &shadowSigner{
		internalSigner: internalSigner,
		remoteSigner:   remoteSigner,
	}
}

func (ss *shadowSigner) PubKey() *btcec.PublicKey {
	pubkey0 := ss.internalSigner.PubKey()
	pubkey1 := ss.remoteSigner.PubKey()
	if !reflect.DeepEqual(pubkey0, pubkey1) {
		panic(fmt.Sprintf("ShadowSigner.PubKey mismatch: %v != %v",
			pubkey0, pubkey1))
	}
	return pubkey1
}

func (ss *shadowSigner) ECDH(pubKey *btcec.PublicKey) ([32]byte, error) {
	ecdh0, err := ss.internalSigner.ECDH(pubKey)
	if err != nil {
		return [32]byte{}, err
	}
	ecdh1, err := ss.remoteSigner.ECDH(pubKey)
	if err != nil {
		return [32]byte{}, err
	}
	if ecdh0 != ecdh1 {
		return [32]byte{}, fmt.Errorf("ShadowSigner.ECDH mismatch: %s != %s",
			hex.EncodeToString(ecdh0[:]), hex.EncodeToString(ecdh1[:]))
	}
	return ecdh1, nil
}

func (ss *shadowSigner) SignNodeAnnouncement(
	dataToSign []byte) (input.Signature, error) {
	sig0, err := ss.internalSigner.SignNodeAnnouncement(dataToSign)
	if err != nil {
		return nil, err
	}
	sig1, err := ss.remoteSigner.SignNodeAnnouncement(dataToSign)
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(sig0, sig1) {
		return nil, fmt.Errorf("ShadowSigner.SignNodeAnnouncement mismatch: "+
			"internal=%v remote=%v", sig0, sig1)
	}
	return sig1, nil
}

func (ss *shadowSigner) SignChannelUpdate(
	dataToSign []byte) (input.Signature, error) {
	sig0, err := ss.internalSigner.SignChannelUpdate(dataToSign)
	if err != nil {
		return nil, err
	}
	sig1, err := ss.remoteSigner.SignChannelUpdate(dataToSign)
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(sig0, sig1) {
		return nil, fmt.Errorf("ShadowSigner.SignChannelUpdate mismatch: "+
			"internal=%v remote=%v", sig0, sig1)
	}
	return sig1, nil
}

func (ss *shadowSigner) SignInvoice(
	hrp string, base32Bytes []byte) ([]byte, []byte, error) {
	hash0, sig0, err := ss.internalSigner.SignInvoice(hrp, base32Bytes)
	if err != nil {
		return nil, nil, err
	}
	hash1, sig1, err := ss.remoteSigner.SignInvoice(hrp, base32Bytes)
	if err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(hash0, hash1) {
		return nil, nil, fmt.Errorf("ShadowSigner.SignInvoice hash mismatch: "+
			"internal=%s remote=%s",
			hex.EncodeToString(hash0),
			hex.EncodeToString(hash1))
	}
	if !reflect.DeepEqual(sig0, sig1) {
		return nil, nil, fmt.Errorf("ShadowSigner.SignInvoice mismatch: "+
			"internal=%s remote=%s",
			hex.EncodeToString(sig0),
			hex.EncodeToString(sig1))
	}
	return hash1, sig1, nil
}

// TODO - Remove this hack.
func (ss *shadowSigner) Hack() input.Signer {
	return ss.internalSigner.Hack()
}

func (ss *shadowSigner) SignMessage(
	dataToSign []byte) ([]byte, error) {
	sig0, err := ss.internalSigner.SignMessage(dataToSign)
	if err != nil {
		return nil, err
	}
	sig1, err := ss.remoteSigner.SignMessage(dataToSign)
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(sig0, sig1) {
		return nil, fmt.Errorf("ShadowSigner.SignMessage mismatch: "+
			"internal=%s remote=%s",
			hex.EncodeToString(sig0),
			hex.EncodeToString(sig1))
	}
	return sig1, nil
}

func (ss *shadowSigner) ShimKeyRing(keyRing keychain.KeyRing) error {
	var err error
	err = ss.internalSigner.ShimKeyRing(keyRing)
	if err != nil {
		return nil
	}
	err = ss.remoteSigner.ShimKeyRing(keyRing)
	if err != nil {
		return nil
	}
	return nil
}

func (ss *shadowSigner) NewChannel(
	peerNode *btcec.PublicKey,
	pendingChanID [32]byte,
) (*contextsigner.ChannelBasepoints, error) {
	var err error
	bps0, err := ss.internalSigner.NewChannel(peerNode, pendingChanID)
	if err != nil {
		return nil, err
	}
	bps1, err := ss.remoteSigner.NewChannel(peerNode, pendingChanID)
	if err != nil {
		return nil, err
	}
	// FIXME - the remotesigner gets the index wrong after a restart
	// with an existing wallet (it's index starts over).  For now we
	// only compare the pubkeys ...
	if !bytes.Equal(
		bps0.MultiSigKey.PubKey.SerializeCompressed(),
		bps1.MultiSigKey.PubKey.SerializeCompressed()) ||
		!bytes.Equal(
			bps0.RevocationBasePoint.PubKey.SerializeCompressed(),
			bps1.RevocationBasePoint.PubKey.SerializeCompressed()) ||
		!bytes.Equal(
			bps0.HtlcBasePoint.PubKey.SerializeCompressed(),
			bps1.HtlcBasePoint.PubKey.SerializeCompressed()) ||
		!bytes.Equal(
			bps0.PaymentBasePoint.PubKey.SerializeCompressed(),
			bps1.PaymentBasePoint.PubKey.SerializeCompressed()) ||
		!bytes.Equal(
			bps0.DelayBasePoint.PubKey.SerializeCompressed(),
			bps1.DelayBasePoint.PubKey.SerializeCompressed()) {
		logBasepoints("INT", bps0)
		logBasepoints("RMT", bps1)
		return nil, fmt.Errorf(
			"ShadowSigner.NewChannel mismatch: "+
				"internal=%v remote=%v", bps0, bps1)
	}

	// Return the internally generated KeyDescriptors while shadowing
	// since they have the correct Index values.
	return bps0, nil
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
	hasAnchors bool,
	isTweakless bool,
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
		hasAnchors,
		isTweakless,
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
		hasAnchors,
		isTweakless,
	)
	if err != nil {
		return err
	}
	return nil
}

func (ss *shadowSigner) SignRemoteCommitment(
	chanID lnwire.ChannelID,
	localMultiSigKey keychain.KeyDescriptor,
	remoteMultiSigKey keychain.KeyDescriptor,
	channelValueSat int64,
	remotePerCommitPoint *btcec.PublicKey,
	theirCommitTx *wire.MsgTx,
	theirWitscriptMap map[[32]byte][]byte,
) (input.Signature, error) {
	var err error
	sig0, err := ss.internalSigner.SignRemoteCommitment(
		chanID,
		localMultiSigKey,
		remoteMultiSigKey,
		channelValueSat,
		remotePerCommitPoint,
		theirCommitTx,
		theirWitscriptMap,
	)
	if err != nil {
		return nil, err
	}
	sig1, err := ss.remoteSigner.SignRemoteCommitment(
		chanID,
		localMultiSigKey,
		remoteMultiSigKey,
		channelValueSat,
		remotePerCommitPoint,
		theirCommitTx,
		theirWitscriptMap,
	)
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(sig0, sig1) {
		return nil, fmt.Errorf("ShadowSigner.SignRemoteCommitment mismatch: "+
			"internal=%v remote=%v", sig0, sig1)
	}
	return sig1, nil
}

func (ss *shadowSigner) SignFundingTx(
	signDescs []*input.SignDescriptor,
	multiSigIndex uint32,
	fundingTx *wire.MsgTx,
) ([]*input.Script, error) {
	scripts0, err := ss.internalSigner.SignFundingTx(
		signDescs, multiSigIndex, fundingTx)
	if err != nil {
		return nil, err
	}
	scripts1, err := ss.remoteSigner.SignFundingTx(
		signDescs, multiSigIndex, fundingTx)
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(scripts0, scripts1) {
		return nil, fmt.Errorf("ShadowSigner.SignFundingTx mismatch: "+
			"\ninternal=%v\nremote=%v",
			spew.Sdump(scripts0), spew.Sdump(scripts1))
	}
	return scripts1, nil
}

func (ss *shadowSigner) SignChannelAnnouncement(
	chanID lnwire.ChannelID,
	localFundingKey *btcec.PublicKey,
	dataToSign []byte,
) (input.Signature, input.Signature, error) {
	nodeSig0, bitcoinSig0, err := ss.internalSigner.SignChannelAnnouncement(
		chanID, localFundingKey, dataToSign)
	if err != nil {
		return nil, nil, err
	}
	nodeSig1, bitcoinSig1, err := ss.remoteSigner.SignChannelAnnouncement(
		chanID, localFundingKey, dataToSign)
	if err != nil {
		return nil, nil, err
	}
	if !reflect.DeepEqual(nodeSig0, nodeSig1) {
		return nil, nil, fmt.Errorf("ShadowSigner.SignChannelAnnouncement "+
			"node sig mismatch: "+
			"internal=%v remote=%v", nodeSig0, nodeSig1)
	}
	if !reflect.DeepEqual(bitcoinSig0, bitcoinSig1) {
		return nil, nil, fmt.Errorf("ShadowSigner.SignChannelAnnouncement "+
			"bitcoin sig mismatch: "+
			"internal=%v remote=%v", bitcoinSig0, bitcoinSig1)
	}
	return nodeSig1, bitcoinSig1, nil
}

func logBasepoints(pfx string, bps *contextsigner.ChannelBasepoints) {
	log.Debugf("%s:         MultiSigKey=%v %s",
		pfx, bps.MultiSigKey,
		hex.EncodeToString(bps.MultiSigKey.PubKey.SerializeCompressed()))
	log.Debugf("%s: RevocationBasePoint=%v %s",
		pfx, bps.RevocationBasePoint,
		hex.EncodeToString(
			bps.RevocationBasePoint.PubKey.SerializeCompressed()))
	log.Debugf("%s:       HtlcBasePoint=%v %s",
		pfx, bps.HtlcBasePoint,
		hex.EncodeToString(bps.HtlcBasePoint.PubKey.SerializeCompressed()))
	log.Debugf("%s:    PaymentBasePoint=%v %s",
		pfx, bps.PaymentBasePoint,
		hex.EncodeToString(bps.PaymentBasePoint.PubKey.SerializeCompressed()))
	log.Debugf("%s:      DelayBasePoint=%v %s",
		pfx, bps.DelayBasePoint,
		hex.EncodeToString(bps.DelayBasePoint.PubKey.SerializeCompressed()))
}

// Compile time check to make sure shadowSigner implements the
// requisite interfaces.
var _ contextsigner.ContextSigner = (*shadowSigner)(nil)
