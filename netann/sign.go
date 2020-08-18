package netann

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcec"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/remotesigner"
)

// SignAnnouncement signs any type of gossip message that is announced on the
// network.
func SignAnnouncement(signer lnwallet.MessageSigner, pubKey *btcec.PublicKey,
	msg lnwire.Message) (input.Signature, error) {

	var (
		data []byte
		err  error
	)

	switch m := msg.(type) {
	case *lnwire.ChannelAnnouncement:
		data, err = m.DataToSign()
	case *lnwire.ChannelUpdate:
		data, err = m.DataToSign()
	case *lnwire.NodeAnnouncement:
		data, err = m.DataToSign()
	default:
		return nil, fmt.Errorf("can't sign %T message", m)
	}
	if err != nil {
		return nil, fmt.Errorf("unable to get data to sign: %v", err)
	}

	lclSignature, err := signer.SignMessage(pubKey, data)
	if err != nil {
		return nil, err
	}

	rmtSignature, err := remotesigner.SignAnnouncement(pubKey, msg)
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(lclSignature.Serialize(), rmtSignature.Serialize()) {
		log.Errorf(
			"SignAnnouncement: "+
				"remotesigner signature mismatch lcl %s != rmt %s",
			hex.EncodeToString(lclSignature.Serialize()),
			hex.EncodeToString(rmtSignature.Serialize()))
		return nil, fmt.Errorf("remote signature mismatch")
	}

	return lclSignature, nil
}
