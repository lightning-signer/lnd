package remotesigner

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcec"
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
	log.Debugf("SignChannelAnnouncement: pubKey %s, msg %v",
		hex.EncodeToString(pubKey.SerializeCompressed()), msg)

	return nil, fmt.Errorf("SignChannelAnnouncement UNIMPLEMENTED")
}

func signChannelUpdate(pubKey *btcec.PublicKey,
	msg *lnwire.ChannelUpdate) (input.Signature, error) {
	if !state.nodeIDValid {
		return nil, ErrRemoteSignerNodeIDNotSet
	}
	log.Debugf("SignChannelUpdate: pubKey %s, msg %v",
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
	return btcec.ParseDERSignature(rsp.Signature.Data, btcec.S256())
}

func signNodeAnnouncement(pubKey *btcec.PublicKey,
	msg *lnwire.NodeAnnouncement) (input.Signature, error) {
	if !state.nodeIDValid {
		return nil, ErrRemoteSignerNodeIDNotSet
	}
	log.Debugf("SignNodeAnnouncement: pubKey %s, msg %v",
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

func channelNonce(peerNodeID *btcec.PublicKey, pendingChanID [32]byte) []byte {
	retval := peerNodeID.SerializeCompressed()
	retval = append(retval, pendingChanID[:]...)
	log.Debugf("channelNonce: %s", hex.EncodeToString(retval))
	return retval
}

func NewChannel(peerNodeID *btcec.PublicKey, pendingChanID [32]byte) error {
	if !state.nodeIDValid {
		return ErrRemoteSignerNodeIDNotSet
	}
	log.Debugf("NewChannel request: peerNodeID=%s, pendingChanID=%s",
		hex.EncodeToString(peerNodeID.SerializeCompressed()),
		hex.EncodeToString(pendingChanID[:]))

	channelNonce := channelNonce(peerNodeID, pendingChanID)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_, err := state.client.NewChannel(ctx,
		&NewChannelRequest{
			NodeId:       &NodeId{Data: state.nodeID[:]},
			ChannelNonce: &ChannelNonce{Data: channelNonce},
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

func GetChannelBasepoints(peerNodeID *btcec.PublicKey,
	pendingChanID [32]byte) (*ChannelBasepoints, error) {
	if !state.nodeIDValid {
		return nil, ErrRemoteSignerNodeIDNotSet
	}
	log.Debugf("GetChannelBasepoints request: peerNodeID=%s, pendingChanID=%s",
		hex.EncodeToString(peerNodeID.SerializeCompressed()),
		hex.EncodeToString(pendingChanID[:]))

	channelNonce := channelNonce(peerNodeID, pendingChanID)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	rsp, err := state.client.GetChannelBasepoints(ctx,
		&GetChannelBasepointsRequest{
			NodeId:       &NodeId{Data: state.nodeID[:]},
			ChannelNonce: &ChannelNonce{Data: channelNonce},
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
