package zpay32

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcutil/bech32"
)

type MockInvoiceSigner struct {
	privKey *btcec.PrivateKey
}

func NewMockInvoiceSigner(
	privKey *btcec.PrivateKey) *MockInvoiceSigner {
	return &MockInvoiceSigner{
		privKey: privKey,
	}
}

// Generate a signature for an invoice.
func (is *MockInvoiceSigner) SignInvoice(
	humanReadablePart string,
	fieldsData []byte,
) ([]byte, []byte, error) {
	// The signature is over the single SHA-256 hash of the hrp + the
	// tagged fields encoded in base256.
	taggedFieldsBytes, err := bech32.ConvertBits(fieldsData, 5, 8, true)
	if err != nil {
		return nil, nil, err
	}
	toSign := append([]byte(humanReadablePart), taggedFieldsBytes...)
	hash := chainhash.HashB(toSign)

	// Should the signature reference a compressed public key or not.
	isCompressedKey := true

	// btcec.SignCompact returns a pubkey-recoverable signature
	sign, err := btcec.SignCompact(
		btcec.S256(), is.privKey, hash, isCompressedKey,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("can't sign the hash: %v", err)
	}
	return hash, sign, nil
}
