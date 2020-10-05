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
	"github.com/lightningnetwork/lnd/lnwallet/chanfunding"
	"google.golang.org/grpc"
)

type remoteSigner struct {
	serverAddr     string
	conn           *grpc.ClientConn
	client         SignerClient
	nodeID         [33]byte
	basePointIndex uint32
}

// TEMPORARY - in order to facilitate shadowing, we need to capture
// the same seed that the internal wallet uses for the remote signer.
// These routines are removed once we are done with the shadowing
// phase of remotesigner development.
var (
	shadowSeed []byte
)

// The argument to SetShadowSeed is sometimes empty, in which case
// we will generate the seed here and return the generated seed.
func EstablishShadowSeed(seed []byte, debugCaller string) ([]byte, error) {
	// If no entropy was supplied make some up.
	if seed != nil {
		shadowSeed = seed
		log.Infof("EstablishShadowSeed: seed %s was supplied for %s",
			hex.EncodeToString(shadowSeed), debugCaller)
	} else {
		var err error
		shadowSeed, err = hdkeychain.GenerateSeed(
			hdkeychain.RecommendedSeedLen)
		if err != nil {
			return nil, err
		}
		log.Infof("EstablishShadowSeed: generated seed %s for %s",
			hex.EncodeToString(shadowSeed), debugCaller)
	}
	return shadowSeed, nil
}

func NewRemoteSigner(
	networkName string,
	serverAddr string,
) (lnwallet.ChannelContextSigner, error) {
	log.Infof("NewRemoteSigner: networkName=%s serverAddr=%s",
		networkName, serverAddr)

	if shadowSeed == nil {
		return nil, fmt.Errorf("NewRemoteSigner called with shadowSeed unset")
	}

	conn, err := grpc.Dial(serverAddr, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		return nil, err
	}

	client := NewSignerClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	rsp, err := client.Init(ctx, &InitRequest{
		NodeConfig: &NodeConfig{
			KeyDerivationStyle: NodeConfig_LND,
		},
		Chainparams: &ChainParams{NetworkName: networkName},
		Coldstart:   true,
		HsmSecret:   &BIP32Seed{Data: shadowSeed},
	})
	if err != nil {
		return nil, err
	}

	if len(rsp.NodeId.Data) != 33 {
		return nil, fmt.Errorf("nodeid from remotesigner wrong size: %v",
			len(rsp.NodeId.Data))
	}

	rsi := &remoteSigner{
		serverAddr:     serverAddr,
		conn:           conn,
		client:         client,
		basePointIndex: 0,
	}
	copy(rsi.nodeID[:], rsp.NodeId.Data)

	log.Infof("InitNode: returned nodeID: %s",
		hex.EncodeToString(rsi.nodeID[:]))

	return rsi, nil
}

func (rsi *remoteSigner) NewChannel(
	peerNode *btcec.PublicKey,
	pendingChanID [32]byte,
) (*lnwallet.ChannelBasepoints, error) {
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
		return nil, err
	}

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

	bps := &lnwallet.ChannelBasepoints{
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

func (rsi *remoteSigner) ReadyChannel(
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

func (rsi *remoteSigner) SignRemoteCommitment(
	ourContribution *lnwallet.ChannelContribution,
	theirContribution *lnwallet.ChannelContribution,
	partialState *channeldb.OpenChannel,
	fundingIntent chanfunding.Intent,
	theirCommitTx *wire.MsgTx,
) (input.Signature, error) {
	fundingOutpoint := &partialState.FundingOutpoint
	channelValueSat := uint64(partialState.Capacity)
	remotePerCommitPoint := theirContribution.FirstCommitmentPoint
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

	witscripts, err := generateRemoteCommitmentWitnessScripts(
		remotePerCommitPoint,
		partialState.ChanType,
		ourContribution.ChannelConfig,
		theirContribution.ChannelConfig,
		theirCommitTx,
	)
	if err != nil {
		return nil, err
	}

	channelNonce := channelNoncePermanent(fundingOutpoint)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	var rawTxBytes bytes.Buffer
	err = theirCommitTx.BtcEncode(&rawTxBytes, 0, wire.WitnessEncoding)
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

// A compile time check to ensure that remoteSigner implements the
// requisite interfaces.
var _ lnwallet.ChannelContextSigner = (*remoteSigner)(nil)
