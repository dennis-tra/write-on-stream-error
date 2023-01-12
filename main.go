package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"github.com/ipfs/go-cid"
	"github.com/libp2p/go-libp2p"
	kaddht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/routing"
	rcmgr "github.com/libp2p/go-libp2p/p2p/host/resource-manager"
	mh "github.com/multiformats/go-multihash"
	"github.com/pkg/errors"
)

func main() {
	ctx := context.Background()

	// Configure the resource manager to not yell at us
	limiter := rcmgr.NewFixedLimiter(rcmgr.InfiniteLimits)
	rm, err := rcmgr.NewResourceManager(limiter)
	if err != nil {
		panic(err)
	}

	var dht *kaddht.IpfsDHT
	node, err := libp2p.New(
		libp2p.ResourceManager(rm),
		libp2p.Routing(func(h host.Host) (routing.PeerRouting, error) {
			var err error
			dht, err = kaddht.New(ctx, h)
			return dht, err
		}),
	)
	if err != nil {
		panic(err)
	}

	for _, bp := range kaddht.GetDefaultBootstrapPeerAddrInfos() {
		if err = node.Connect(ctx, bp); err != nil {
			fmt.Println(err)
		}
	}

	c, err := NewRandomContent()
	if err != nil {
		panic(err)
	}

	err = dht.Provide(ctx, c.CID, true)
	if err != nil {
		panic(err)
	}
}

// Content encapsulates multiple representations of the same data.
type Content struct {
	raw   []byte
	mhash mh.Multihash
	CID   cid.Cid
}

// NewRandomContent reads 1024 bytes from crypto/rand and builds a content struct.
func NewRandomContent() (*Content, error) {
	raw := make([]byte, 1024)
	if _, err := rand.Read(raw); err != nil {
		return nil, errors.Wrap(err, "read rand data")
	}
	hash := sha256.New()
	hash.Write(raw)

	mhash, err := mh.Encode(hash.Sum(nil), mh.SHA2_256)
	if err != nil {
		return nil, errors.Wrap(err, "encode multi hash")
	}

	return &Content{
		raw:   raw,
		mhash: mhash,
		CID:   cid.NewCidV0(mhash),
	}, nil
}
