package lnwallet

import (
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lnwallet/chanfunding"
)

type ChannelContextSigner interface {
	SignRemoteCommitment(
		ourContribution *ChannelContribution,
		theirContribution *ChannelContribution,
		partialState *channeldb.OpenChannel,
		fundingIntent chanfunding.Intent,
		theirCommitTx *wire.MsgTx,
	) (input.Signature, error)
}
