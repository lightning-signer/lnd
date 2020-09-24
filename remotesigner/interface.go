package remotesigner

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwire"
	"google.golang.org/grpc"
)

type remoteSignerImpl struct {
	serverAddr       string
	conn             *grpc.ClientConn
	client           SignerClient
	nodeIDValid      bool
	nodeID           [33]byte
	pubKey           *btcec.PublicKey
	shadowPubKeyECDH *keychain.PubKeyECDH // SHADOWING only, remove after
}

func NewRemoteSigner(serverAddr string) (lnwallet.RemoteSigner, error) {
	log.Infof("Initialize: %s", serverAddr)

	conn, err := grpc.Dial(serverAddr, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		return nil, err
	}

	client := NewSignerClient(conn)

	return &remoteSignerImpl{
		serverAddr:  serverAddr,
		conn:        conn,
		client:      client,
		nodeIDValid: false,
	}, nil
}

func (rsi *remoteSignerImpl) InitNode(
	networkName string,
	seed0 []byte,
	debugCaller string,
) ([]byte, error) {
	var useSeed []byte

	if rsi.nodeIDValid {
		return nil, fmt.Errorf("InitNode called w/ nodeID already set: %v",
			hex.EncodeToString(rsi.nodeID[:]))
	}

	// If no entropy was supplied make some up.
	if seed0 != nil {
		useSeed = seed0
		log.Infof("InitNode: supplied seed %s for %s",
			hex.EncodeToString(useSeed), debugCaller)
	} else {
		var err error
		useSeed, err = hdkeychain.GenerateSeed(
			hdkeychain.RecommendedSeedLen)
		if err != nil {
			return nil, err
		}
		log.Infof("InitNode: generated seed %s for %s",
			hex.EncodeToString(useSeed), debugCaller)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	rsp, err := rsi.client.Init(ctx, &InitRequest{
		NodeConfig: &NodeConfig{
			KeyDerivationStyle: NodeConfig_LND,
		},
		Chainparams: &ChainParams{NetworkName: networkName},
		Coldstart:   true,
		HsmSecret:   &BIP32Seed{Data: useSeed},
	})
	if err != nil {
		return nil, err
	}

	if len(rsp.NodeId.Data) != 33 {
		return nil, fmt.Errorf("nodeid from remotesigner wrong size: %v",
			len(rsp.NodeId.Data))
	}
	rsi.pubKey, err = btcec.ParsePubKey(rsp.NodeId.Data, btcec.S256())
	if err != nil {
		return nil, err
	}
	copy(rsi.nodeID[:], rsp.NodeId.Data)
	rsi.nodeIDValid = true

	log.Infof("InitNode: returned nodeID: %s",
		hex.EncodeToString(rsi.nodeID[:]))

	// Return the seed we used.
	return useSeed, nil
}

func (rsi *remoteSignerImpl) setShadowNodeID(
	serializedPubKey [33]byte) error {
	// When lnd creates a new wallet the remotesigner's nodeid will
	// be returned from the InitNode call.  If an existing wallet is
	// being opened the InitNode call will not be made and the
	// remotesigner will have an empty nodeID at this point.
	//
	// If the remotesigner's nodeid is set compare it to the server's
	// nodeid.  Otherwise set the remotesigner's nodeid for future
	// interface calls.
	var err error
	if !rsi.nodeIDValid {
		log.Debugf("setShadowNodeID: setting nodeID: %s",
			hex.EncodeToString(serializedPubKey[:]))
		rsi.nodeID = serializedPubKey
		rsi.pubKey, err = btcec.ParsePubKey(serializedPubKey[:], btcec.S256())
		if err != nil {
			return err
		}
		rsi.nodeIDValid = true
	} else {
		log.Debugf("setShadowNodeID: comparing nodeID")
		if serializedPubKey != rsi.nodeID {
			log.Errorf("serializedPubKey %s != nodeID %s",
				hex.EncodeToString(serializedPubKey[:]),
				hex.EncodeToString(rsi.nodeID[:]))
			return fmt.Errorf("remotesigner nodeID mismatch")
		}
	}

	// Sanity check the shadowPubKeyECDH we're shadowing.
	if !bytes.Equal(
		rsi.pubKey.SerializeCompressed(),
		rsi.shadowPubKeyECDH.PubKey().SerializeCompressed(),
	) {
		panic("rsi.pubKey != rsi.shadowPubKeyECDH.PubKey")
	}

	return nil
}

func (rsi *remoteSignerImpl) SetShadowECDH(
	pubKeyECDH *keychain.PubKeyECDH) error {
	rsi.shadowPubKeyECDH = pubKeyECDH
	// Since the pubKeyECDH implies the nodeid, set/check it here.
	var serializedPubKey [33]byte
	copy(serializedPubKey[:], pubKeyECDH.PubKey().SerializeCompressed())
	return rsi.setShadowNodeID(serializedPubKey)
}

func (rsi *remoteSignerImpl) PubKey() *btcec.PublicKey {
	return rsi.pubKey
}

// This routine uses the remotesigner to compute the ECDH.  When we
// are not in SHADOW mode it becomes the public interface.
func (rsi *remoteSignerImpl) remoteECDH(
	pubKey *btcec.PublicKey) ([32]byte, error) {
	if !rsi.nodeIDValid {
		return [32]byte{}, lnwallet.ErrRemoteSignerNodeIDNotSet
	}
	log.Debugf("ECDH request: nodeID %s, pubKey %s",
		hex.EncodeToString(rsi.nodeID[:]),
		hex.EncodeToString(pubKey.SerializeCompressed()))

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	rsp, err := rsi.client.ECDH(ctx, &ECDHRequest{
		NodeId: &NodeId{Data: rsi.nodeID[:]},
		Point:  &PubKey{Data: pubKey.SerializeCompressed()},
	})
	if err != nil {
		// We need to log the error here because it seems callers don't
		// get this error into the log.
		log.Errorf("rsi.client.ECDH failed: %v", err)
		return [32]byte{}, err
	}

	var secret [32]byte
	copy(secret[:], rsp.SharedSecret.Data)
	log.Debugf("ECDH response: secret=%s", hex.EncodeToString(secret[:]))
	return secret, nil
}

// In SHADOW mode this routine calls the remote interface and compares
// the result to what is locally computed.
func (rsi *remoteSignerImpl) ECDH(pubKey *btcec.PublicKey) ([32]byte, error) {
	log.Debugf("ECDH: pubKey %s",
		hex.EncodeToString(pubKey.SerializeCompressed()))

	secretRemote, err := rsi.remoteECDH(pubKey)
	if err != nil {
		return [32]byte{}, err
	}

	secretLocal, err := rsi.shadowPubKeyECDH.ECDH(pubKey)
	if err != nil {
		return [32]byte{}, err
	}

	if secretRemote != secretLocal {
		log.Errorf("secretRemote %s != secretLocal %s",
			hex.EncodeToString(secretRemote[:]),
			hex.EncodeToString(secretLocal[:]))
		return [32]byte{}, fmt.Errorf("remotesigner ECDH mismatch")
	}

	return secretLocal, nil
}

func (rsi *remoteSignerImpl) SignAnnouncement(
	pubKey *btcec.PublicKey,
	msg lnwire.Message,
) (input.Signature, error) {
	if !rsi.nodeIDValid {
		return nil, lnwallet.ErrRemoteSignerNodeIDNotSet
	}

	// Validate the pubKey argument.
	if !bytes.Equal(pubKey.SerializeCompressed(), rsi.nodeID[:]) {
		log.Errorf("remotesigner.SignAnnouncement failed: "+
			"pubKey %s != rsi.nodeID %s",
			hex.EncodeToString(pubKey.SerializeCompressed()),
			rsi.nodeID[:])
		return nil, fmt.Errorf("remotesigner nodeid pubkey mismatch")
	}

	switch m := msg.(type) {
	case *lnwire.ChannelAnnouncement:
		return rsi.signChannelAnnouncement(pubKey, m)
	case *lnwire.ChannelUpdate:
		return rsi.signChannelUpdate(pubKey, m)
	case *lnwire.NodeAnnouncement:
		return rsi.signNodeAnnouncement(pubKey, m)
	default:
		return nil, fmt.Errorf("can't remotesign %T message", m)
	}
}

func (rsi *remoteSignerImpl) signChannelAnnouncement(pubKey *btcec.PublicKey,
	msg *lnwire.ChannelAnnouncement) (input.Signature, error) {
	if !rsi.nodeIDValid {
		return nil, lnwallet.ErrRemoteSignerNodeIDNotSet
	}
	log.Debugf("SignChannelAnnouncement request: nodeID=%s, pubKey=%s, msg=%v",
		hex.EncodeToString(rsi.nodeID[:]),
		hex.EncodeToString(pubKey.SerializeCompressed()), msg)

	return nil, fmt.Errorf("SignChannelAnnouncement UNIMPLEMENTED")
}

func (rsi *remoteSignerImpl) signChannelUpdate(pubKey *btcec.PublicKey,
	msg *lnwire.ChannelUpdate) (input.Signature, error) {
	if !rsi.nodeIDValid {
		return nil, lnwallet.ErrRemoteSignerNodeIDNotSet
	}
	log.Debugf("SignChannelUpdate request: nodeID=%s, pubKey=%s, msg=%v",
		hex.EncodeToString(rsi.nodeID[:]),
		hex.EncodeToString(pubKey.SerializeCompressed()), msg)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	data, err := msg.DataToSign()
	if err != nil {
		return nil, err
	}

	log.Debugf("SignChannelUpdate: DataToSign %s", hex.EncodeToString(data))

	rsp, err := rsi.client.SignChannelUpdate(ctx,
		&SignChannelUpdateRequest{
			NodeId:        &NodeId{Data: rsi.nodeID[:]},
			ChannelUpdate: data[:],
		})
	if err != nil {
		return nil, err
	}
	log.Debugf("SignChannelUpdate response: sig=%s",
		hex.EncodeToString(rsp.Signature.Data))
	return btcec.ParseDERSignature(rsp.Signature.Data, btcec.S256())
}

func (rsi *remoteSignerImpl) signNodeAnnouncement(pubKey *btcec.PublicKey,
	msg *lnwire.NodeAnnouncement) (input.Signature, error) {
	if !rsi.nodeIDValid {
		return nil, lnwallet.ErrRemoteSignerNodeIDNotSet
	}
	log.Debugf("SignNodeAnnouncement request: nodeID=%s, pubKey=%s, msg=%v",
		hex.EncodeToString(rsi.nodeID[:]),
		hex.EncodeToString(pubKey.SerializeCompressed()), msg)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	data, err := msg.DataToSign()
	if err != nil {
		return nil, err
	}

	log.Debugf("SignNodeAnnouncement: DataToSign %s", hex.EncodeToString(data))

	rsp, err := rsi.client.SignNodeAnnouncement(ctx,
		&SignNodeAnnouncementRequest{
			NodeId:           &NodeId{Data: rsi.nodeID[:]},
			NodeAnnouncement: data[:],
		})
	if err != nil {
		return nil, err
	}
	log.Debugf("SignNodeAnnouncement response: sig=%s",
		hex.EncodeToString(rsp.Signature.Data))
	return btcec.ParseDERSignature(rsp.Signature.Data, btcec.S256())
}

func (rsi *remoteSignerImpl) NewChannel(
	peerNode *btcec.PublicKey,
	pendingChanID [32]byte,
) error {
	if !rsi.nodeIDValid {
		return lnwallet.ErrRemoteSignerNodeIDNotSet
	}
	log.Debugf("NewChannel request: nodeID=%s, peerNodeID=%s, pendingChanID=%s",
		hex.EncodeToString(rsi.nodeID[:]),
		hex.EncodeToString(peerNode.SerializeCompressed()),
		hex.EncodeToString(pendingChanID[:]))

	channelNonceInitial := channelNonceInitial(peerNode, pendingChanID)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_, err := rsi.client.NewChannel(ctx,
		&NewChannelRequest{
			NodeId:        &NodeId{Data: rsi.nodeID[:]},
			ChannelNonce0: &ChannelNonce{Data: channelNonceInitial},
		})
	if err != nil {
		return err
	}

	return nil
}

func (rsi *remoteSignerImpl) GetChannelBasepoints(
	peerNode *btcec.PublicKey,
	pendingChanID [32]byte,
) (*lnwallet.ChannelBasepoints, error) {
	if !rsi.nodeIDValid {
		return nil, lnwallet.ErrRemoteSignerNodeIDNotSet
	}
	log.Debugf("GetChannelBasepoints request: "+
		"nodeID=%s, peerNodeID=%s, pendingChanID=%s",
		hex.EncodeToString(rsi.nodeID[:]),
		hex.EncodeToString(peerNode.SerializeCompressed()),
		hex.EncodeToString(pendingChanID[:]))

	channelNonceInitial := channelNonceInitial(peerNode, pendingChanID)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	rsp, err := rsi.client.GetChannelBasepoints(ctx,
		&GetChannelBasepointsRequest{
			NodeId:       &NodeId{Data: rsi.nodeID[:]},
			ChannelNonce: &ChannelNonce{Data: channelNonceInitial},
		})
	if err != nil {
		return nil, err
	}

	revPoint, err :=
		btcec.ParsePubKey(rsp.Basepoints.Revocation.Data, btcec.S256())
	if err != nil {
		return nil, err
	}

	payPoint, err :=
		btcec.ParsePubKey(rsp.Basepoints.Payment.Data, btcec.S256())
	if err != nil {
		return nil, err
	}

	htlcPoint, err :=
		btcec.ParsePubKey(rsp.Basepoints.Htlc.Data, btcec.S256())
	if err != nil {
		return nil, err
	}

	delayPoint, err :=
		btcec.ParsePubKey(rsp.Basepoints.DelayedPayment.Data, btcec.S256())
	if err != nil {
		return nil, err
	}

	fundPoint, err :=
		btcec.ParsePubKey(rsp.Basepoints.FundingPubkey.Data, btcec.S256())
	if err != nil {
		return nil, err
	}

	log.Debugf("GetChannelBasepoints response: "+
		"Revocation=%s, Payment=%s, Htlc=%s, "+
		"DelayedPayment=%s, FundingPubkey=%s ",
		hex.EncodeToString(revPoint.SerializeCompressed()),
		hex.EncodeToString(payPoint.SerializeCompressed()),
		hex.EncodeToString(htlcPoint.SerializeCompressed()),
		hex.EncodeToString(delayPoint.SerializeCompressed()),
		hex.EncodeToString(fundPoint.SerializeCompressed()),
	)

	return &lnwallet.ChannelBasepoints{
		Revocation:     revPoint,
		Payment:        payPoint,
		Htlc:           htlcPoint,
		DelayedPayment: delayPoint,
		FundingPubkey:  fundPoint,
	}, nil
}

func (rsi *remoteSignerImpl) ReadyChannel(
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
	if !rsi.nodeIDValid {
		return lnwallet.ErrRemoteSignerNodeIDNotSet
	}
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

	channelNonceInitial := channelNonceInitial(peerNode, pendingChanID)
	channelNoncePermanent := channelNoncePermanent(fundingOutpoint)

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
			OptionChannelNonce: &ChannelNonce{Data: channelNoncePermanent},
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

func (rsi *remoteSignerImpl) SignRemoteCommitment(
	fundingOutpoint *wire.OutPoint,
	channelValueSat uint64,
	remotePerCommitPoint *btcec.PublicKey,
	theirCommitTx *wire.MsgTx,
	witscripts [][]byte,
) (input.Signature, error) {
	if !rsi.nodeIDValid {
		return nil, lnwallet.ErrRemoteSignerNodeIDNotSet
	}
	log.Debugf("SignRemoteCommitment request: "+
		"nodeID=%s, "+
		"fundingOutpoint=%v, "+
		"channelValueSat=%v, "+
		"remotePerCommitPoint=%s, "+
		"theirCommitTx=%v",
		hex.EncodeToString(rsi.nodeID[:]),
		fundingOutpoint,
		channelValueSat,
		hex.EncodeToString(remotePerCommitPoint.SerializeCompressed()),
		theirCommitTx,
	)

	channelNonce := channelNoncePermanent(fundingOutpoint)

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
	for ndx, _ := range theirCommitTx.TxOut {
		outputDescs = append(outputDescs, &OutputDescriptor{
			Witscript: witscripts[ndx],
		})
	}

	rsp, err := rsi.client.SignRemoteCommitmentTx(ctx,
		&SignRemoteCommitmentTxRequest{
			NodeId:       &NodeId{Data: rsi.nodeID[:]},
			ChannelNonce: &ChannelNonce{Data: channelNonce},
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

func channelNonceInitial(peerNode *btcec.PublicKey,
	pendingChanID [32]byte) []byte {
	retval := peerNode.SerializeCompressed()
	retval = append(retval, pendingChanID[:]...)
	log.Debugf("channelNonceInitial: %s", hex.EncodeToString(retval))
	return retval
}

func channelNoncePermanent(fundingOutpoint *wire.OutPoint) []byte {
	var chanPointBuf bytes.Buffer
	if _, err := chanPointBuf.Write(fundingOutpoint.Hash[:]); err != nil {
		panic(fmt.Sprintf("channelNoncePermanent: hash write failed: %v", err))
	}
	if err := binary.Write(
		&chanPointBuf, binary.BigEndian, fundingOutpoint.Index); err != nil {
		panic(fmt.Sprintf("channelNoncePermanent: index write failed: %v", err))
	}
	retval := chanPointBuf.Bytes()
	log.Debugf("channelNoncePermanent: %s", hex.EncodeToString(retval))
	return retval
}

// A compile time check to ensure that remoteSignerImpl implements the
// requisite interfaces.
var _ keychain.SingleKeyECDH = (*remoteSignerImpl)(nil)
