package remotesigner

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil/bech32"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/contextsigner"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwire"
	"google.golang.org/grpc"
)

type RemoteSigner struct {
	networkName    string
	serverAddr     string
	conn           *grpc.ClientConn
	client         SignerClient
	nodeID         []byte
	pubKey         *btcec.PublicKey
	basePointIndex uint32
}

func NewRemoteSigner(
	networkName string,
	serverAddr string,
) (*RemoteSigner, error) {
	log.Infof("NewRemoteSigner: networkName=%s serverAddr=%s",
		networkName, serverAddr)

	conn, err := grpc.Dial(serverAddr, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		return nil, err
	}

	return &RemoteSigner{
		networkName:    networkName,
		serverAddr:     serverAddr,
		conn:           conn,
		client:         NewSignerClient(conn),
		basePointIndex: 0,
	}, nil
}

func (rsi *RemoteSigner) PubKey() *btcec.PublicKey {
	return rsi.pubKey
}

func (rsi *RemoteSigner) ECDH(pubKey *btcec.PublicKey) ([32]byte, error) {
	if rsi.nodeID == nil {
		return [32]byte{}, fmt.Errorf("remotesigner nodeID not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	rsp, err := rsi.client.ECDH(ctx, &ECDHRequest{
		NodeId: &NodeId{Data: rsi.nodeID},
		Point:  &PubKey{Data: pubKey.SerializeCompressed()},
	})
	if err != nil {
		// We need to log the error here because it seems callers don't
		// get this error into the log.
		log.Errorf("RemoteSigner.ECDH failed: %v", err)
		return [32]byte{}, err
	}

	var secret [32]byte
	copy(secret[:], rsp.SharedSecret.Data)
	log.Debugf("ECDH response: secret=%s", hex.EncodeToString(secret[:]))
	return secret, nil
}

func (rsi *RemoteSigner) SignNodeAnnouncement(
	dataToSign []byte) (input.Signature, error) {
	if rsi.nodeID == nil {
		return nil, fmt.Errorf("remotesigner nodeID not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	rsp, err := rsi.client.SignNodeAnnouncement(ctx,
		&SignNodeAnnouncementRequest{
			NodeId:           &NodeId{Data: rsi.nodeID[:]},
			NodeAnnouncement: dataToSign,
		})
	if err != nil {
		return nil, err
	}
	return btcec.ParseDERSignature(rsp.Signature.Data, btcec.S256())
}

func (rsi *RemoteSigner) SignChannelUpdate(
	dataToSign []byte) (input.Signature, error) {
	if rsi.nodeID == nil {
		return nil, fmt.Errorf("remotesigner nodeID not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	rsp, err := rsi.client.SignChannelUpdate(ctx,
		&SignChannelUpdateRequest{
			NodeId:        &NodeId{Data: rsi.nodeID[:]},
			ChannelUpdate: dataToSign,
		})
	if err != nil {
		return nil, err
	}
	return btcec.ParseDERSignature(rsp.Signature.Data, btcec.S256())
}

func (rsi *RemoteSigner) SignInvoice(
	hrp string, base32Bytes []byte) ([]byte, []byte, error) {
	if rsi.nodeID == nil {
		return nil, nil, fmt.Errorf("remotesigner nodeID not set")
	}

	// The signature is over the single SHA-256 hash of the hrp + the
	// tagged fields encoded in base256.
	taggedFieldsBytes, err := bech32.ConvertBits(base32Bytes, 5, 8, true)
	if err != nil {
		return nil, nil, err
	}
	toSign := append([]byte(hrp), taggedFieldsBytes...)
	hash := chainhash.HashB(toSign)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	rsp, err := rsi.client.SignInvoice(ctx,
		&SignInvoiceRequest{
			NodeId:            &NodeId{Data: rsi.nodeID[:]},
			DataPart:          base32Bytes,
			HumanReadablePart: hrp,
		})
	if err != nil {
		return nil, nil, err
	}

	// Convert the format of the recoverable signature.
	return hash, convertRecoverableSignatureFormat(rsp.Signature.Data), nil
}

func (rsi *RemoteSigner) SignMessage(
	dataToSign []byte) ([]byte, error) {
	if rsi.nodeID == nil {
		return nil, fmt.Errorf("remotesigner nodeID not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// The remotesigner will prefix the data with the standard prefix
	// ("Lightning Signed Message") itself, so remove when we pass.
	dataWithoutPrefix := dataToSign[25:]

	rsp, err := rsi.client.SignMessage(ctx,
		&SignMessageRequest{
			NodeId:  &NodeId{Data: rsi.nodeID[:]},
			Message: dataWithoutPrefix,
		})
	if err != nil {
		return nil, err
	}

	// Convert the format of the recoverable signature.
	return convertRecoverableSignatureFormat(rsp.Signature.Data), nil
}

func (rsi *RemoteSigner) ShimKeyRing(keyRing keychain.KeyRing) error {
	// The current remotesigner cannot support external funding.
	return fmt.Errorf("remotesigner does not support external funding")
}

// InitNode should only be called when a node (wallet) is created for
// the fist time.
func (rsi *RemoteSigner) InitNode(shadowSeed []byte) error {
	var err error

	log.Infof("InitNode: shadowSeed=%s", hex.EncodeToString(shadowSeed))
	if shadowSeed == nil {
		panic("InitNode called with shadowSeed unset")
		return fmt.Errorf("InitNode called with shadowSeed unset")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	rsp, err := rsi.client.Init(ctx, &InitRequest{
		NodeConfig: &NodeConfig{
			KeyDerivationStyle: NodeConfig_LND,
		},
		Chainparams: &ChainParams{NetworkName: rsi.networkName},
		Coldstart:   true,
		HsmSecret:   &BIP32Seed{Data: shadowSeed},
	})
	if err != nil {
		return err
	}

	if len(rsp.NodeId.Data) != 33 {
		return fmt.Errorf("nodeid from remotesigner wrong size: %v",
			len(rsp.NodeId.Data))
	}
	rsi.nodeID = rsp.NodeId.Data
	log.Infof("InitNode: nodeID: %s", hex.EncodeToString(rsi.nodeID))

	rsi.pubKey, err = btcec.ParsePubKey(rsi.nodeID, btcec.S256())
	if err != nil {
		return err
	}

	return nil
}

// SetNodeID is called when an existing wallet is reopened.
func (rsi *RemoteSigner) SetNodeID(pubkey *btcec.PublicKey) {
	rsi.pubKey = pubkey
	rsi.nodeID = pubkey.SerializeCompressed()
	log.Infof("SetNodeID: %s", hex.EncodeToString(rsi.nodeID))
}

func (rsi *RemoteSigner) NewChannel(
	peerNode *btcec.PublicKey,
	pendingChanID [32]byte,
) (*contextsigner.ChannelBasepoints, error) {
	log.Debugf("NewChannel request: nodeID=%s, peerNodeID=%s, pendingChanID=%s",
		hex.EncodeToString(rsi.nodeID[:]),
		hex.EncodeToString(peerNode.SerializeCompressed()),
		hex.EncodeToString(pendingChanID[:]))

	if rsi.nodeID == nil {
		return nil, fmt.Errorf("remotesigner nodeID not set")
	}

	channelNonceInitial := channelNonceInitial(peerNode, pendingChanID)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_, err := rsi.client.NewChannel(ctx,
		&NewChannelRequest{
			NodeId:        &NodeId{Data: rsi.nodeID[:]},
			ChannelNonce0: &ChannelNonce{Data: channelNonceInitial},
		})
	if err != nil {
		return nil, err
	}

	// ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	// defer cancel()

	rsp, err := rsi.client.GetChannelBasepoints(ctx,
		&GetChannelBasepointsRequest{
			NodeId:       &NodeId{Data: rsi.nodeID[:]},
			ChannelNonce: &ChannelNonce{Data: channelNonceInitial},
		})
	if err != nil {
		return nil, err
	}

	multiSigPoint, err :=
		btcec.ParsePubKey(rsp.Basepoints.FundingPubkey.Data, btcec.S256())
	if err != nil {
		return nil, err
	}

	revPoint, err :=
		btcec.ParsePubKey(rsp.Basepoints.Revocation.Data, btcec.S256())
	if err != nil {
		return nil, err
	}

	htlcPoint, err :=
		btcec.ParsePubKey(rsp.Basepoints.Htlc.Data, btcec.S256())
	if err != nil {
		return nil, err
	}

	payPoint, err :=
		btcec.ParsePubKey(rsp.Basepoints.Payment.Data, btcec.S256())
	if err != nil {
		return nil, err
	}

	delayPoint, err :=
		btcec.ParsePubKey(rsp.Basepoints.DelayedPayment.Data, btcec.S256())
	if err != nil {
		return nil, err
	}

	log.Debugf("GetChannelBasepoints response: "+
		"MultiSigKey=%s, "+
		"RevocationBasePoint=%s, "+
		"HtlcBasePoint=%s, "+
		"PaymentBasePoint=%s, "+
		"DelayBasePoint=%s ",
		hex.EncodeToString(multiSigPoint.SerializeCompressed()),
		hex.EncodeToString(revPoint.SerializeCompressed()),
		hex.EncodeToString(htlcPoint.SerializeCompressed()),
		hex.EncodeToString(payPoint.SerializeCompressed()),
		hex.EncodeToString(delayPoint.SerializeCompressed()),
	)

	bps := &contextsigner.ChannelBasepoints{
		MultiSigKey: keychain.KeyDescriptor{
			KeyLocator: keychain.KeyLocator{
				Family: keychain.KeyFamilyMultiSig,
				Index:  rsi.basePointIndex,
			},
			PubKey: multiSigPoint,
		},
		RevocationBasePoint: keychain.KeyDescriptor{
			KeyLocator: keychain.KeyLocator{
				Family: keychain.KeyFamilyRevocationBase,
				Index:  rsi.basePointIndex,
			},
			PubKey: revPoint,
		},
		HtlcBasePoint: keychain.KeyDescriptor{
			KeyLocator: keychain.KeyLocator{
				Family: keychain.KeyFamilyHtlcBase,
				Index:  rsi.basePointIndex,
			},
			PubKey: htlcPoint,
		},
		PaymentBasePoint: keychain.KeyDescriptor{
			KeyLocator: keychain.KeyLocator{
				Family: keychain.KeyFamilyPaymentBase,
				Index:  rsi.basePointIndex,
			},
			PubKey: payPoint,
		},
		DelayBasePoint: keychain.KeyDescriptor{
			KeyLocator: keychain.KeyLocator{
				Family: keychain.KeyFamilyDelayBase,
				Index:  rsi.basePointIndex,
			},
			PubKey: delayPoint,
		},
	}

	rsi.basePointIndex += 1

	return bps, nil
}

func (rsi *RemoteSigner) ReadyChannel(
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
	log.Debugf("ReadyChannel request: "+
		"nodeID=%s, "+
		"peerNodeID=%s, pendingChanID=%s, "+
		"isOutbound=%v, channelValueSat=%v, "+
		"pushValueMsat=%v, fundingOutpoint=%v, "+
		"localToSelfDelay=%v, localShutdownScript=%s, "+
		"remoteRevocationBasepoint=%s, "+
		"remotePaymentBasepoint=%s, "+
		"remoteHtlcBasepoint=%s, "+
		"remoteDelayedPaymentBasepoint=%s, "+
		"remoteFundingPubkey=%s, "+
		"remoteToSelfDelay=%v, "+
		"remoteShutdownScript=%s, "+
		"chanType=%v",
		hex.EncodeToString(rsi.nodeID[:]),
		hex.EncodeToString(peerNode.SerializeCompressed()),
		hex.EncodeToString(pendingChanID[:]),
		isOutbound, channelValueSat,
		pushValueMsat, fundingOutpoint,
		localToSelfDelay, hex.EncodeToString(localShutdownScript),
		hex.EncodeToString(remoteRevocationBasepoint.SerializeCompressed()),
		hex.EncodeToString(remotePaymentBasepoint.SerializeCompressed()),
		hex.EncodeToString(remoteHtlcBasepoint.SerializeCompressed()),
		hex.EncodeToString(remoteDelayedPaymentBasepoint.SerializeCompressed()),
		hex.EncodeToString(remoteFundingPubkey.SerializeCompressed()),
		remoteToSelfDelay,
		hex.EncodeToString(remoteShutdownScript),
		chanType)

	if rsi.nodeID == nil {
		return fmt.Errorf("remotesigner nodeID not set")
	}

	channelNonceInitial := channelNonceInitial(peerNode, pendingChanID)
	chanID := lnwire.NewChanIDFromOutPoint(fundingOutpoint)

	var commitmentType ReadyChannelRequest_CommitmentType
	if chanType.HasAnchors() {
		commitmentType = ReadyChannelRequest_ANCHORS
	} else if chanType.IsTweakless() {
		commitmentType = ReadyChannelRequest_STATIC_REMOTEKEY
	} else {
		commitmentType = ReadyChannelRequest_LEGACY
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_, err := rsi.client.ReadyChannel(ctx,
		&ReadyChannelRequest{
			NodeId:             &NodeId{Data: rsi.nodeID[:]},
			ChannelNonce0:      &ChannelNonce{Data: channelNonceInitial},
			OptionChannelNonce: &ChannelNonce{Data: chanID[:]},
			IsOutbound:         isOutbound,
			ChannelValueSat:    channelValueSat,
			PushValueMsat:      pushValueMsat,
			FundingOutpoint: &Outpoint{
				Txid:  fundingOutpoint.Hash[:],
				Index: fundingOutpoint.Index,
			},
			LocalToSelfDelay:    uint32(localToSelfDelay),
			LocalShutdownScript: localShutdownScript,
			RemoteBasepoints: &Basepoints{
				Revocation: &PubKey{
					Data: remoteRevocationBasepoint.SerializeCompressed(),
				},
				Payment: &PubKey{
					Data: remotePaymentBasepoint.SerializeCompressed(),
				},
				Htlc: &PubKey{
					Data: remoteHtlcBasepoint.SerializeCompressed(),
				},
				DelayedPayment: &PubKey{
					Data: remoteDelayedPaymentBasepoint.SerializeCompressed(),
				},
				FundingPubkey: &PubKey{
					Data: remoteFundingPubkey.SerializeCompressed(),
				},
			},
			RemoteToSelfDelay:    uint32(remoteToSelfDelay),
			RemoteShutdownScript: remoteShutdownScript,
			CommitmentType:       commitmentType,
		})
	if err != nil {
		return err
	}

	return nil
}

func (rsi *RemoteSigner) SignRemoteCommitment(
	ourKey keychain.KeyDescriptor,
	fundingOutput *wire.TxOut,
	fundingWitnessScript []byte,
	chanID lnwire.ChannelID,
	channelValueSat uint64,
	remotePerCommitPoint *btcec.PublicKey,
	theirCommitTx *wire.MsgTx,
	theirWitscriptMap map[[32]byte][]byte,
) (input.Signature, error) {
	if rsi.nodeID == nil {
		return nil, fmt.Errorf("remotesigner nodeID not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	var rawTxBytes bytes.Buffer
	err := theirCommitTx.BtcEncode(&rawTxBytes, 0, wire.WitnessEncoding)
	if err != nil {
		return nil, err
	}

	if len(theirCommitTx.TxIn) != 1 {
		return nil, fmt.Errorf("commitment tx must have one input")
	}
	var inputDescs []*InputDescriptor
	inputDescs = append(inputDescs, &InputDescriptor{
		PrevOutput: &TxOut{
			ValueSat: int64(channelValueSat),
		},
	})
	var outputDescs []*OutputDescriptor
	for _, txi := range theirCommitTx.TxOut {
		var pkscript [32]byte
		copy(pkscript[:], txi.PkScript)
		outputDescs = append(outputDescs, &OutputDescriptor{
			Witscript: theirWitscriptMap[pkscript],
		})
	}

	rsp, err := rsi.client.SignRemoteCommitmentTx(ctx,
		&SignRemoteCommitmentTxRequest{
			NodeId:       &NodeId{Data: rsi.nodeID[:]},
			ChannelNonce: &ChannelNonce{Data: chanID[:]},
			RemotePerCommitPoint: &PubKey{
				Data: remotePerCommitPoint.SerializeCompressed(),
			},
			Tx: &Transaction{
				RawTxBytes:  rawTxBytes.Bytes(),
				InputDescs:  inputDescs,
				OutputDescs: outputDescs,
			},
		})
	if err != nil {
		return nil, err
	}

	sig := rsp.Signature.Data

	// Chop off the sighash flag at the end of the signature.
	return btcec.ParseDERSignature(sig[:len(sig)-1], btcec.S256())
}

func (rsi *RemoteSigner) SignChannelAnnouncement(
	chanID lnwire.ChannelID,
	localFundingKey *btcec.PublicKey,
	dataToSign []byte,
) (input.Signature, input.Signature, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	rsp, err := rsi.client.SignChannelAnnouncement(ctx,
		&SignChannelAnnouncementRequest{
			NodeId:              &NodeId{Data: rsi.nodeID[:]},
			ChannelNonce:        &ChannelNonce{Data: chanID[:]},
			ChannelAnnouncement: dataToSign,
		},
	)
	if err != nil {
		return nil, nil, err
	}

	nodeSig, err := btcec.ParseDERSignature(
		rsp.NodeSignature.Data, btcec.S256())
	if err != nil {
		return nil, nil, err
	}
	bitcoinSig, err := btcec.ParseDERSignature(
		rsp.BitcoinSignature.Data, btcec.S256())
	if err != nil {
		return nil, nil, err
	}
	return nodeSig, bitcoinSig, nil
}

func channelNonceInitial(peerNode *btcec.PublicKey,
	pendingChanID [32]byte) []byte {
	retval := peerNode.SerializeCompressed()
	retval = append(retval, pendingChanID[:]...)
	log.Debugf("channelNonceInitial: %s", hex.EncodeToString(retval))
	return retval
}

// The remotesigner needs the witness script to properly validate the
// the transaction.  This helper returns an array of witness scripts
// one for each of the outputs of the transaction.
func generateRemoteCommitmentWitnessScripts(
	theirCommitPoint *btcec.PublicKey,
	chanType channeldb.ChannelType,
	localChanCfg, remoteChanCfg *channeldb.ChannelConfig,
	theirCommitTx *wire.MsgTx) ([][]byte, error) {

	// A Slice to byte array helper so we can use a map.
	s2a := func(slice []byte) [32]byte {
		var hash [32]byte
		copy(hash[:], slice)
		return hash
	}

	// Since the outputs are not in a particular order we will need
	// to match the witscripts by their pk_hash values.
	witscriptMap := make(map[[32]byte][]byte)

	remoteCommitmentKeys := lnwallet.DeriveCommitmentKeys(
		theirCommitPoint,
		false,
		chanType,
		localChanCfg,
		remoteChanCfg,
	)

	// Derive the to_self output witscript and hash.
	toLocalRedeemScript, err := input.CommitScriptToSelf(
		uint32(remoteChanCfg.CsvDelay),
		remoteCommitmentKeys.ToLocalKey,
		remoteCommitmentKeys.RevocationKey,
	)
	if err != nil {
		return nil, err
	}
	toLocalScriptHash, err := input.WitnessScriptHash(
		toLocalRedeemScript,
	)
	if err != nil {
		return nil, err
	}
	witscriptMap[s2a(toLocalScriptHash)] = toLocalRedeemScript

	// Derive the to_remote output witscript and hash.
	toRemoteScript, _, err := lnwallet.CommitScriptToRemote(
		chanType, remoteCommitmentKeys.ToRemoteKey,
	)
	if err != nil {
		return nil, err
	}
	witscriptMap[s2a(toRemoteScript.PkScript)] = toRemoteScript.WitnessScript

	// Add any anchor witscripts and hashes..
	if chanType.HasAnchors() {
		localAnchor, remoteAnchor, err := lnwallet.CommitScriptAnchors(
			localChanCfg, remoteChanCfg,
		)
		if err != nil {
			return nil, err
		}
		witscriptMap[s2a(localAnchor.PkScript)] = localAnchor.WitnessScript
		witscriptMap[s2a(remoteAnchor.PkScript)] = remoteAnchor.WitnessScript
	}

	// Scan the transaction, return the witness script for the
	// matching outputs and []byte{} placeholders for the others.
	var witscripts [][]byte
	for _, txi := range theirCommitTx.TxOut {
		witscripts = append(witscripts, witscriptMap[s2a(txi.PkScript)])
	}
	return witscripts, nil
}

// The remotesigner uses <R><S><recovery-id>, lnd uses <(byte of
// 27+public key solution)+4 if compressed >< padded bytes for
// signature R><padded bytes for signature S> as descibed in
// btcec.SignCompact source..
func convertRecoverableSignatureFormat(insig []byte) []byte {
	recoveryID := insig[len(insig)-1]
	hdrval := recoveryID + 27 + 4
	return append([]byte{hdrval}, insig[:len(insig)-1]...)
}

// A compile time check to ensure that RemoteSigner implements the
// requisite interfaces.
var _ contextsigner.ChannelContextSigner = (*RemoteSigner)(nil)
