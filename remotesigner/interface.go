package remotesigner

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/btcsuite/btcutil/hdkeychain"
	"google.golang.org/grpc"
)

var (
	serverAddr = "localhost:50051"

	conn *grpc.ClientConn

	client SignerClient

	nodeIDValid bool = false
	nodeID      [33]byte
)

func Initialize() error {
	var err error

	log.Infof("Initialize: %s", serverAddr)

	conn, err = grpc.Dial(serverAddr, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		return err
	}

	client = NewSignerClient(conn)

	return nil
}

func InitNode(networkName string, seed0 []byte, debugCaller string) ([]byte, error) {
	var useSeed []byte

	if nodeIDValid {
		return nil, fmt.Errorf("InitNode called w/ nodeID already set: %v",
			hex.EncodeToString(nodeID[:]))
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

	rsp, err := client.Init(ctx, &InitRequest{
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
	copy(nodeID[:], rsp.NodeId.Data)
	nodeIDValid = true

	log.Infof("InitNode: returned nodeID: %s", hex.EncodeToString(nodeID[:]))

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
	if !nodeIDValid {
		log.Debugf("SetNodeID: setting nodeID: %s",
			hex.EncodeToString(nodeID[:]))
		nodeID = serializedPubKey
		nodeIDValid = true
	} else {
		log.Debugf("SetNodeID: comparing nodeID")
		if serializedPubKey != nodeID {
			log.Errorf("serializedPubKey %s != nodeID %s",
				hex.EncodeToString(serializedPubKey[:]),
				hex.EncodeToString(nodeID[:]))
			return fmt.Errorf("remotesigner nodeID mismatch")
		}
	}
	return nil
}
