package lnwallet

import (
	"github.com/go-errors/errors"
	"github.com/lightningnetwork/lnd/keychain"
)

type RemoteSigner interface {
	NodeContextSigner

	ChannelContextSigner

	InitNode(
		networkName string,
		seed0 []byte, // SHADOW mode only
		debugCaller string,
	) ([]byte, error)

	SetShadowECDH(*keychain.PubKeyECDH) error // SHADOW mode only
}

var (
	ErrRemoteSignerNodeIDNotSet = errors.New("remotesigner nodeid not set")
	remoteSignerInstance        RemoteSigner
)

func SetRemoteSigner(remoteSigner RemoteSigner) {
	remoteSignerInstance = remoteSigner
}

func GetRemoteSigner() RemoteSigner {
	return remoteSignerInstance
}
