package input

import (
	"crypto/sha256"
)

// Stores pkscript to redeemscript mappings.  Since golang maps don't
// allow slices as keys we take the hash of the pkscript and convert
// it to a fixed size byte array key.

type RedeemScriptMap map[[32]byte][]byte

func (rsm RedeemScriptMap) Insert(pkscript, redeemscript []byte) {
	rsm[sha256.Sum256(pkscript)] = redeemscript
}

func (rsm RedeemScriptMap) Lookup(pkscript []byte) []byte {
	return rsm[sha256.Sum256(pkscript)]
}
