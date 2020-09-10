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
	"github.com/go-errors/errors"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lnwire"
	"google.golang.org/grpc"
)

type remoteSignerState struct {
	serverAddr  string
	conn        *grpc.ClientConn
	client      SignerClient
	nodeIDValid bool
	nodeID      [33]byte
}

var (
	state remoteSignerState = remoteSignerState{
		serverAddr:  "localhost:50051",
		nodeIDValid: false,
	}

	ErrRemoteSignerNodeIDNotSet = errors.New("remotesigner nodeid not set")
)

func Initialize() error {
	var err error

	log.Infof("Initialize: %s", state.serverAddr)

	state.conn, err = grpc.Dial(
		state.serverAddr, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		return err
	}

	state.client = NewSignerClient(state.conn)

	return nil
}

func InitNode(networkName string, seed0 []byte, debugCaller string) ([]byte, error) {
	var useSeed []byte

	if state.nodeIDValid {
		return nil, fmt.Errorf("InitNode called w/ nodeID already set: %v",
			hex.EncodeToString(state.nodeID[:]))
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

	rsp, err := state.client.Init(ctx, &InitRequest{
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
	copy(state.nodeID[:], rsp.NodeId.Data)
	state.nodeIDValid = true

	log.Infof("InitNode: returned nodeID: %s",
		hex.EncodeToString(state.nodeID[:]))

	// Return the seed we used.
	return useSeed, nil
}

func SetNodeID(serializedPubKey [33]byte) error {
	// When lnd creates a new wallet the remotesigner's nodeid will
	// be returned from the InitNode call.  If an existing wallet is
	// being opened the InitNode call will not be made and the
	// remotesigner will have an empty nodeID at this point.
	//
	// If the remotesigner's nodeid is set compare it to the server's
	// nodeid.  Otherwise set the remotesigner's nodeid for future
	// interface calls.
	if !state.nodeIDValid {
		log.Debugf("SetNodeID: setting nodeID: %s",
			hex.EncodeToString(serializedPubKey[:]))
		state.nodeID = serializedPubKey
		state.nodeIDValid = true
	} else {
		log.Debugf("SetNodeID: comparing nodeID")
		if serializedPubKey != state.nodeID {
			log.Errorf("serializedPubKey %s != nodeID %s",
				hex.EncodeToString(serializedPubKey[:]),
				hex.EncodeToString(state.nodeID[:]))
			return fmt.Errorf("remotesigner nodeID mismatch")
		}
	}
	return nil
}

func ECDH(pubKey *btcec.PublicKey) ([32]byte, error) {
	if !state.nodeIDValid {
		return [32]byte{}, ErrRemoteSignerNodeIDNotSet
	}
	log.Debugf("ECDH request: nodeID %s, pubKey %s",
		hex.EncodeToString(state.nodeID[:]),
		hex.EncodeToString(pubKey.SerializeCompressed()))

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	rsp, err := state.client.ECDH(ctx, &ECDHRequest{
		NodeId: &NodeId{Data: state.nodeID[:]},
		Point:  &PubKey{Data: pubKey.SerializeCompressed()},
	})
	if err != nil {
		// We need to log the error here because it seems callers don't
		// get this error into the log.
		log.Errorf("state.client.ECDH failed: %v", err)
		return [32]byte{}, err
	}

	var secret [32]byte
	copy(secret[:], rsp.SharedSecret.Data)
	log.Debugf("ECDH response: secret=%s", hex.EncodeToString(secret[:]))
	return secret, nil
}

func SignAnnouncement(pubKey *btcec.PublicKey,
	msg lnwire.Message) (input.Signature, error) {
	if !state.nodeIDValid {
		return nil, ErrRemoteSignerNodeIDNotSet
	}

	err := validateLocalNodePublicKey(pubKey)
	if err != nil {
		return nil, err
	}

	switch m := msg.(type) {
	case *lnwire.ChannelAnnouncement:
		return signChannelAnnouncement(pubKey, m)
	case *lnwire.ChannelUpdate:
		return signChannelUpdate(pubKey, m)
	case *lnwire.NodeAnnouncement:
		return signNodeAnnouncement(pubKey, m)
	default:
		return nil, fmt.Errorf("can't remotesign %T message", m)
	}
}

func signChannelAnnouncement(pubKey *btcec.PublicKey,
	msg *lnwire.ChannelAnnouncement) (input.Signature, error) {
	if !state.nodeIDValid {
		return nil, ErrRemoteSignerNodeIDNotSet
	}
	log.Debugf("SignChannelAnnouncement request: nodeID=%s, pubKey=%s, msg=%v",
		hex.EncodeToString(state.nodeID[:]),
		hex.EncodeToString(pubKey.SerializeCompressed()), msg)

	return nil, fmt.Errorf("SignChannelAnnouncement UNIMPLEMENTED")
}

func signChannelUpdate(pubKey *btcec.PublicKey,
	msg *lnwire.ChannelUpdate) (input.Signature, error) {
	if !state.nodeIDValid {
		return nil, ErrRemoteSignerNodeIDNotSet
	}
	log.Debugf("SignChannelUpdate request: nodeID=%s, pubKey=%s, msg=%v",
		hex.EncodeToString(state.nodeID[:]),
		hex.EncodeToString(pubKey.SerializeCompressed()), msg)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	data, err := msg.DataToSign()
	if err != nil {
		return nil, err
	}

	log.Debugf("SignChannelUpdate: DataToSign %s", hex.EncodeToString(data))

	rsp, err := state.client.SignChannelUpdate(ctx,
		&SignChannelUpdateRequest{
			NodeId:        &NodeId{Data: state.nodeID[:]},
			ChannelUpdate: data[:],
		})
	if err != nil {
		return nil, err
	}
	log.Debugf("SignChannelUpdate response: sig=%s",
		hex.EncodeToString(rsp.Signature.Data))
	return btcec.ParseDERSignature(rsp.Signature.Data, btcec.S256())
}

func signNodeAnnouncement(pubKey *btcec.PublicKey,
	msg *lnwire.NodeAnnouncement) (input.Signature, error) {
	if !state.nodeIDValid {
		return nil, ErrRemoteSignerNodeIDNotSet
	}
	log.Debugf("SignNodeAnnouncement request: nodeID=%s, pubKey=%s, msg=%v",
		hex.EncodeToString(state.nodeID[:]),
		hex.EncodeToString(pubKey.SerializeCompressed()), msg)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	data, err := msg.DataToSign()
	if err != nil {
		return nil, err
	}

	log.Debugf("SignNodeAnnouncement: DataToSign %s", hex.EncodeToString(data))

	rsp, err := state.client.SignNodeAnnouncement(ctx,
		&SignNodeAnnouncementRequest{
			NodeId:           &NodeId{Data: state.nodeID[:]},
			NodeAnnouncement: data[:],
		})
	if err != nil {
		return nil, err
	}
	log.Debugf("SignNodeAnnouncement response: sig=%s",
		hex.EncodeToString(rsp.Signature.Data))
	return btcec.ParseDERSignature(rsp.Signature.Data, btcec.S256())
}

func validateLocalNodePublicKey(pubKey *btcec.PublicKey) error {
	if !bytes.Equal(pubKey.SerializeCompressed(), state.nodeID[:]) {
		log.Errorf("validateLocalNodePublicKey failed: "+
			"pubKey %s != state.nodeID %s",
			hex.EncodeToString(pubKey.SerializeCompressed()),
			state.nodeID[:])
		return fmt.Errorf("remotesigner nodeid pubkey mismatch")
	}
	return nil
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

func NewChannel(peerNode *btcec.PublicKey, pendingChanID [32]byte) error {
	if !state.nodeIDValid {
		return ErrRemoteSignerNodeIDNotSet
	}
	log.Debugf("NewChannel request: nodeID=%s, peerNodeID=%s, pendingChanID=%s",
		hex.EncodeToString(state.nodeID[:]),
		hex.EncodeToString(peerNode.SerializeCompressed()),
		hex.EncodeToString(pendingChanID[:]))

	channelNonceInitial := channelNonceInitial(peerNode, pendingChanID)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_, err := state.client.NewChannel(ctx,
		&NewChannelRequest{
			NodeId:        &NodeId{Data: state.nodeID[:]},
			ChannelNonce0: &ChannelNonce{Data: channelNonceInitial},
		})
	if err != nil {
		return err
	}

	return nil
}

type ChannelBasepoints struct {
	Revocation     *btcec.PublicKey
	Payment        *btcec.PublicKey
	Htlc           *btcec.PublicKey
	DelayedPayment *btcec.PublicKey
	FundingPubkey  *btcec.PublicKey
}

func GetChannelBasepoints(peerNode *btcec.PublicKey,
	pendingChanID [32]byte) (*ChannelBasepoints, error) {
	if !state.nodeIDValid {
		return nil, ErrRemoteSignerNodeIDNotSet
	}
	log.Debugf("GetChannelBasepoints request: "+
		"nodeID=%s, peerNodeID=%s, pendingChanID=%s",
		hex.EncodeToString(state.nodeID[:]),
		hex.EncodeToString(peerNode.SerializeCompressed()),
		hex.EncodeToString(pendingChanID[:]))

	channelNonceInitial := channelNonceInitial(peerNode, pendingChanID)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	rsp, err := state.client.GetChannelBasepoints(ctx,
		&GetChannelBasepointsRequest{
			NodeId:       &NodeId{Data: state.nodeID[:]},
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

	return &ChannelBasepoints{
		Revocation:     revPoint,
		Payment:        payPoint,
		Htlc:           htlcPoint,
		DelayedPayment: delayPoint,
		FundingPubkey:  fundPoint,
	}, nil
}

func ReadyChannel(
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
	commitmentType ReadyChannelRequest_CommitmentType,
) error {
	if !state.nodeIDValid {
		return ErrRemoteSignerNodeIDNotSet
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
		"commitmentType=%v",
		hex.EncodeToString(state.nodeID[:]),
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
		commitmentType)

	channelNonceInitial := channelNonceInitial(peerNode, pendingChanID)
	channelNoncePermanent := channelNoncePermanent(fundingOutpoint)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_, err := state.client.ReadyChannel(ctx,
		&ReadyChannelRequest{
			NodeId:             &NodeId{Data: state.nodeID[:]},
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

func SignRemoteCommitment(
	fundingOutpoint *wire.OutPoint,
	channelValueSat uint64,
	remotePerCommitPoint *btcec.PublicKey,
	theirCommitTx *wire.MsgTx,
	witscripts [][]byte,
) (input.Signature, error) {
	if !state.nodeIDValid {
		return nil, ErrRemoteSignerNodeIDNotSet
	}
	log.Debugf("SignRemoteCommitment request: "+
		"nodeID=%s, "+
		"fundingOutpoint=%v, "+
		"channelValueSat=%v, "+
		"remotePerCommitPoint=%s, "+
		"theirCommitTx=%v",
		hex.EncodeToString(state.nodeID[:]),
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

	rsp, err := state.client.SignRemoteCommitmentTx(ctx,
		&SignRemoteCommitmentTxRequest{
			NodeId:       &NodeId{Data: state.nodeID[:]},
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
