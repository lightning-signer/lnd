package remotesigner

import (
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcec"
	"github.com/lightningnetwork/lnd/keychain"
)

func NewRemoteSignerECDH(keyDesc keychain.KeyDescriptor,
	ecdh keychain.ECDHRing) *RemoteSignerECDH {
	return &RemoteSignerECDH{
		PubKeyECDH: *keychain.NewPubKeyECDH(keyDesc, ecdh),
	}
}

type RemoteSignerECDH struct {
	keychain.PubKeyECDH
}

func (rs *RemoteSignerECDH) PubKey() *btcec.PublicKey {
	return rs.PubKeyECDH.PubKey()
}

func (rs *RemoteSignerECDH) ECDH(pubKey *btcec.PublicKey) ([32]byte, error) {
	log.Debugf("ECDH: pubKey %s",
		hex.EncodeToString(pubKey.SerializeCompressed()))

	secretRemote, err := ECDH(pubKey)
	if err != nil {
		return [32]byte{}, err
	}

	secretLocal, err := rs.PubKeyECDH.ECDH(pubKey)
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

// A compile time check to ensure that RemoteSignerECDH implements the
// PubKeyECDH interface.
var _ keychain.SingleKeyECDH = (*RemoteSignerECDH)(nil)
