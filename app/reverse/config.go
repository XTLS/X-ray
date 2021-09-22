package reverse

import (
	"crypto/rand"
	"io"

	"github.com/xtls/xray-core/common/dice"
)

func (c *Control) FillInRandom() {
	randomLength := dice.Roll(64)
	c.Random = make([]byte, randomLength)
	io.ReadFull(rand.Reader, c.Random)
}

func (x *BridgeConfig) Start() error {
	panic("implement me")
}

func (x *BridgeConfig) Close() error {
	panic("implement me")
}

func (x *PortalConfig) Start() error {
	panic("implement me")
}

func (x *PortalConfig) Close() error {
	panic("implement me")
}
