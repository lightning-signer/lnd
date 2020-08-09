package remotesigner

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/go-errors/errors"
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
			hex.EncodeToString(state.nodeID[:]))
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
