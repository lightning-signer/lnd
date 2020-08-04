package remotesigner

import (
	"bytes"
	"context"
	"encoding/hex"
	"time"

	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/go-errors/errors"
	"google.golang.org/grpc"
)

var (
	serverAddr = "localhost:50051"

	conn *grpc.ClientConn

	client SignerClient

	nodeID []byte

	ErrRemoteSignerUnimplemented = errors.New("remotesigner unimplemented")
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

func InitNode(networkName string, seed0 []byte) ([]byte, error) {
	var useSeed []byte

	// If no entropy was supplied make some up.
	if seed0 != nil {
		useSeed = seed0
	} else {
		var err error
		useSeed, err = hdkeychain.GenerateSeed(
			hdkeychain.RecommendedSeedLen)
		if err != nil {
			return nil, err
		}
	}

	log.Infof("InitNode seed: %s", hex.EncodeToString(useSeed))

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

	nodeID = rsp.NodeId.Data

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
	if len(nodeID) == 0 {
		nodeID = serializedPubKey[:]
	} else {
		if !bytes.Equal(serializedPubKey[:], nodeID) {
			log.Errorf("serializedPubKey %s != nodeID %s",
				hex.EncodeToString(serializedPubKey[:]),
				hex.EncodeToString(nodeID))
			return errors.New("remotesigner nodeID mismatch")
		}
	}
	return nil
}
