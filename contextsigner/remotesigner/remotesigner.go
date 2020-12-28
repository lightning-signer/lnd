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
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/davecgh/go-spew/spew"
	"github.com/lightningnetwork/lnd/contextsigner"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwire"
	"google.golang.org/grpc"
)

const (
	requestTimeout = 10 * time.Second
)

type TxInResolver interface {
	ResolveDerivation(
		signDesc *input.SignDescriptor,
	) (waddrmgr.KeyScope, waddrmgr.DerivationPath, waddrmgr.AddressType, error)

	// Finds the channel outpoint for a utxo from a unilaterally closed channel.
	LookupClosedChannelPoint(outpoint *wire.OutPoint,
	) (*wire.OutPoint, error)
}

type RemoteSigner struct {
	networkName    string
	serverAddr     string
	txInResolver   TxInResolver
	conn           *grpc.ClientConn
	client         SignerClient
	nodeID         []byte
	pubKey         *btcec.PublicKey
	basePointIndex uint32
}

func NewRemoteSigner(
	networkName string,
	serverAddr string,
	txInResolver TxInResolver,
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
		txInResolver:   txInResolver,
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

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	rsp, err := rsi.client.ECDH(ctx, &ECDHRequest{
		NodeId: &NodeId{Data: rsi.nodeID},
		Point:  &PubKey{Data: pubKey.SerializeCompressed()},
	})
	if err != nil {
		// We need to log the error here because it seems callers don't
		// get this error into the log.
		log.Errorf("ECDH failed: %v", err)
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
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
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

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
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

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
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

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
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

// TODO - Remove this hack.
func (rs *RemoteSigner) Hack() input.Signer {
	// We can't support this hack, so just panic
	panic("RemoteSigner.Hack() CALLED!")
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

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
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

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	_, err := rsi.client.NewChannel(ctx,
		&NewChannelRequest{
			NodeId:        &NodeId{Data: rsi.nodeID[:]},
			ChannelNonce0: &ChannelNonce{Data: channelNonceInitial},
		})
	if err != nil {
		return nil, err
	}

	// ctx, cancel = context.WithTimeout(context.Background(), requestTimeout)
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
	hasAnchors bool,
	isTweakless bool,
) error {
	if rsi.nodeID == nil {
		return fmt.Errorf("remotesigner nodeID not set")
	}

	channelNonceInitial := channelNonceInitial(peerNode, pendingChanID)
	chanID := lnwire.NewChanIDFromOutPoint(fundingOutpoint)

	var commitmentType ReadyChannelRequest_CommitmentType
	if hasAnchors {
		commitmentType = ReadyChannelRequest_ANCHORS
	} else if isTweakless {
		commitmentType = ReadyChannelRequest_STATIC_REMOTEKEY
	} else {
		commitmentType = ReadyChannelRequest_LEGACY
	}

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
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
			HolderToSelfDelay:    uint32(localToSelfDelay),
			HolderShutdownScript: localShutdownScript,
			CounterpartyBasepoints: &Basepoints{
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
			CounterpartyToSelfDelay:    uint32(remoteToSelfDelay),
			CounterpartyShutdownScript: remoteShutdownScript,
			CommitmentType:             commitmentType,
		})
	if err != nil {
		return err
	}

	return nil
}

func (rsi *RemoteSigner) SignMutualCloseTx(
	chanID lnwire.ChannelID,
	signDesc *input.SignDescriptor,
	ourCommitTx *wire.MsgTx,
) (input.Signature, error) {
	log.Debugf("SignMutualCloseTx: chanID=%s signDesc=%s ourCommitTx=%s",
		spew.Sdump(chanID), spew.Sdump(signDesc), spew.Sdump(ourCommitTx))

	if rsi.nodeID == nil {
		return nil, fmt.Errorf("remotesigner nodeID not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	var rawTxBytes bytes.Buffer
	err := ourCommitTx.BtcEncode(&rawTxBytes, 0, wire.WitnessEncoding)
	if err != nil {
		return nil, err
	}

	if len(ourCommitTx.TxIn) != 1 {
		return nil, fmt.Errorf("mutual close tx must have one input")
	}
	var inputDescs []*InputDescriptor
	inputDescs = append(inputDescs, &InputDescriptor{
		ValueSat: signDesc.Output.Value,
	})
	var outputDescs []*OutputDescriptor
	for _, txi := range ourCommitTx.TxOut {
		_ = txi
		outputDescs = append(outputDescs, &OutputDescriptor{
			// Witscript: ourRedeemScriptMap.Lookup(txi.PkScript),
		})
	}

	rsp, err := rsi.client.SignMutualCloseTx(ctx,
		&SignMutualCloseTxRequest{
			NodeId:       &NodeId{Data: rsi.nodeID[:]},
			ChannelNonce: &ChannelNonce{Data: chanID[:]},
			Tx: &Transaction{
				RawTxBytes:  rawTxBytes.Bytes(),
				InputDescs:  inputDescs,
				OutputDescs: outputDescs,
			},
		},
	)
	if err != nil {
		log.Errorf("SignMutualCloseTx failed: %v", err)
		return nil, err
	}
	sig := rsp.Signature.Data

	// Chop off the sighash flag at the end of the signature.
	return btcec.ParseDERSignature(sig[:len(sig)-1], btcec.S256())
}

func (rsi *RemoteSigner) SignFundingTx(
	signDescs []*input.SignDescriptor,
	multiSigIndex uint32,
	fundingTx *wire.MsgTx,
) ([]*input.Script, error) {
	log.Debugf("signDescs: %v", spew.Sdump(signDescs))

	if rsi.nodeID == nil {
		return nil, fmt.Errorf("remotesigner nodeID not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	fundingOutpoint := &wire.OutPoint{
		Hash:  fundingTx.TxHash(),
		Index: multiSigIndex,
	}
	chanID := lnwire.NewChanIDFromOutPoint(fundingOutpoint)

	var rawTxBytes bytes.Buffer
	err := fundingTx.BtcEncode(&rawTxBytes, 0, wire.WitnessEncoding)
	if err != nil {
		return nil, err
	}

	var inputDescs []*InputDescriptor
	for ndx, txi := range fundingTx.TxIn {
		desc := signDescs[ndx]

		keyScope, derivPath, addrType, err :=
			rsi.txInResolver.ResolveDerivation(desc)
		if err != nil {
			return nil, err
		}

		spendType := SpendType_INVALID
		switch addrType {
		case waddrmgr.WitnessPubKey:
			spendType = SpendType_P2WPKH
		case waddrmgr.NestedWitnessPubKey:
			spendType = SpendType_P2SH_P2WPKH
		}

		// Is this input from the wallet account?
		if keyScope.Purpose == 84 || keyScope.Coin == 0 {
			if derivPath.Account != 0 {
				return nil, fmt.Errorf(
					"remotesigner can't sign input %d with Account %d",
					ndx, derivPath.Account)
			}
			// This UTXO is from the wallet. Build an InputDescriptor
			// describing the wallet UTXO.
			inputDescs = append(inputDescs, &InputDescriptor{
				KeyLoc: &KeyLocator{
					KeyPath: []uint32{
						derivPath.Branch,
						derivPath.Index,
					},
				},
				ValueSat:  desc.Output.Value,
				SpendType: spendType,
			})
		} else {
			// This might be the UTXO from a unilaterally closed channel.
			// See if we can lookup the closed channel outpoint.
			closedChanOutpoint, err :=
				rsi.txInResolver.LookupClosedChannelPoint(&txi.PreviousOutPoint)
			if err != nil {
				return nil, fmt.Errorf(
					"remotesigner can't sign input %d with KeyScope %v",
					ndx, keyScope)
			}
			// Build an InputDescriptor describing the UTXO from the
			// unilaterally closed channel.
			closedChanID := lnwire.NewChanIDFromOutPoint(closedChanOutpoint)
			inputDescs = append(inputDescs, &InputDescriptor{
				KeyLoc: &KeyLocator{
					CloseInfo: &UnilateralCloseInfo{
						ChannelNonce: &ChannelNonce{Data: closedChanID[:]},
					},
				},
				ValueSat:  desc.Output.Value,
				SpendType: spendType,
			})
		}
	}

	rsp, err := rsi.client.SignFundingTx(ctx,
		&SignFundingTxRequest{
			NodeId:       &NodeId{Data: rsi.nodeID[:]},
			ChannelNonce: &ChannelNonce{Data: chanID[:]},
			Tx: &Transaction{
				RawTxBytes: rawTxBytes.Bytes(),
				InputDescs: inputDescs,
			},
		},
	)
	if err != nil {
		return nil, err
	}

	scripts := []*input.Script{}
	for _, wit := range rsp.Witnesses {
		if wit == nil {
			scripts = append(scripts, nil)
		} else {
			witness := wire.TxWitness{
				wit.Signature.Data,
				wit.Pubkey.Data,
			}
			script := &input.Script{Witness: witness}
			scripts = append(scripts, script)
		}
	}
	return scripts, nil
}

func (rsi *RemoteSigner) SignRemoteCommitmentTx(
	chanID lnwire.ChannelID,
	localMultiSigKey keychain.KeyDescriptor,
	remoteMultiSigKey keychain.KeyDescriptor,
	channelValueSat int64,
	remotePerCommitPoint *btcec.PublicKey,
	theirCommitTx *wire.MsgTx,
	theirRedeemScriptMap input.RedeemScriptMap,
) (input.Signature, error) {
	if rsi.nodeID == nil {
		return nil, fmt.Errorf("remotesigner nodeID not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	var rawTxBytes bytes.Buffer
	err := theirCommitTx.BtcEncode(&rawTxBytes, 0, wire.WitnessEncoding)
	if err != nil {
		return nil, err
	}

	if len(theirCommitTx.TxIn) != 1 {
		return nil, fmt.Errorf("remote commitment tx must have one input")
	}
	var inputDescs []*InputDescriptor
	inputDescs = append(inputDescs, &InputDescriptor{
		ValueSat: channelValueSat,
	})
	var outputDescs []*OutputDescriptor
	for _, txi := range theirCommitTx.TxOut {
		outputDescs = append(outputDescs, &OutputDescriptor{
			Witscript: theirRedeemScriptMap.Lookup(txi.PkScript),
		})
	}

	rsp, err := rsi.client.SignCounterpartyCommitmentTx(ctx,
		&SignCounterpartyCommitmentTxRequest{
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
		},
	)
	if err != nil {
		log.Errorf("SignCounterpartyCommitmentTx failed: %v", err)
		return nil, err
	}
	sig := rsp.Signature.Data

	// Chop off the sighash flag at the end of the signature.
	return btcec.ParseDERSignature(sig[:len(sig)-1], btcec.S256())
}

func (rsi *RemoteSigner) SignLocalCommitmentTx(
	chanID lnwire.ChannelID,
	signDesc *input.SignDescriptor,
	ourCommitTx *wire.MsgTx,
) (input.Signature, error) {
	log.Debugf("SignHolderCommitmentTx: chanID=%s signDesc=%s ourCommitTx=%s",
		spew.Sdump(chanID), spew.Sdump(signDesc), spew.Sdump(ourCommitTx))

	if rsi.nodeID == nil {
		return nil, fmt.Errorf("remotesigner nodeID not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	var rawTxBytes bytes.Buffer
	err := ourCommitTx.BtcEncode(&rawTxBytes, 0, wire.WitnessEncoding)
	if err != nil {
		return nil, err
	}

	if len(ourCommitTx.TxIn) != 1 {
		return nil, fmt.Errorf("local commitment tx must have one input")
	}
	var inputDescs []*InputDescriptor
	inputDescs = append(inputDescs, &InputDescriptor{
		ValueSat: signDesc.Output.Value,
	})
	var outputDescs []*OutputDescriptor
	for _, txi := range ourCommitTx.TxOut {
		_ = txi
		outputDescs = append(outputDescs, &OutputDescriptor{
			// FIXME - we'll need the witscript to validate.
			// Witscript: ourRedeemScriptMap.Lookup(txi.PkScript),
		})
	}

	rsp, err := rsi.client.SignHolderCommitmentTx(ctx,
		&SignHolderCommitmentTxRequest{
			NodeId:       &NodeId{Data: rsi.nodeID[:]},
			ChannelNonce: &ChannelNonce{Data: chanID[:]},
			Tx: &Transaction{
				RawTxBytes:  rawTxBytes.Bytes(),
				InputDescs:  inputDescs,
				OutputDescs: outputDescs,
			},
		},
	)
	if err != nil {
		log.Errorf("SignHolderCommitmentTx failed: %v", err)
		return nil, err
	}
	sig := rsp.Signature.Data

	// Chop off the sighash flag at the end of the signature.
	return btcec.ParseDERSignature(sig[:len(sig)-1], btcec.S256())
}

func (rsi *RemoteSigner) SignRemoteHTLCTx(
	chanID lnwire.ChannelID,
	signDesc *input.SignDescriptor,
	commitPoint *btcec.PublicKey,
	theirTx *wire.MsgTx,
	witnessScript []byte,
) (input.Signature, error) {
	if rsi.nodeID == nil {
		return nil, fmt.Errorf("remotesigner nodeID not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	var rawTxBytes bytes.Buffer
	err := theirTx.BtcEncode(&rawTxBytes, 0, wire.WitnessEncoding)
	if err != nil {
		return nil, err
	}

	if len(theirTx.TxIn) != 1 {
		return nil, fmt.Errorf("htlc tx must have one input")
	}
	var inputDescs []*InputDescriptor
	inputDescs = append(inputDescs, &InputDescriptor{
		ValueSat:     signDesc.Output.Value,
		RedeemScript: signDesc.WitnessScript,
	})
	if len(theirTx.TxOut) != 1 {
		return nil, fmt.Errorf("htlc tx must have one output")
	}
	var outputDescs []*OutputDescriptor
	outputDescs = append(outputDescs, &OutputDescriptor{
		Witscript: witnessScript,
	})

	rsp, err := rsi.client.SignCounterpartyHTLCTx(ctx,
		&SignCounterpartyHTLCTxRequest{
			NodeId:       &NodeId{Data: rsi.nodeID[:]},
			ChannelNonce: &ChannelNonce{Data: chanID[:]},
			Tx: &Transaction{
				RawTxBytes:  rawTxBytes.Bytes(),
				InputDescs:  inputDescs,
				OutputDescs: outputDescs,
			},
			RemotePerCommitPoint: &PubKey{
				Data: commitPoint.SerializeCompressed(),
			},
		},
	)
	if err != nil {
		log.Errorf("SignCounterpartyHTLCTx failed: %v", err)
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
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
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
