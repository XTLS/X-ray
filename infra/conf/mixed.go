package conf

import (
	"github.com/golang/protobuf/proto"
	"github.com/xtls/xray-core/proxy/mixed"
)

type MixedAccount struct {
	Username string `json:"user"`
	Password string `json:"pass"`
}

func (v *MixedAccount) Build() *mixed.Account {
	return &mixed.Account{
		Username: v.Password,
		Password: v.Password,
	}
}

type MixedServerConfig struct {
	Accounts        []*MixedAccount `json:"accounts"`
	Timeout         uint32          `json:"timeout"`
	UserLevel       uint32          `json:"userLevel"`
	SocksUDP        bool            `json:"socksUdp"`
	SocksHost       *Address        `json:"socksIp"`
	HttpTransparent bool            `json:"httpAllowTransparent"`
}

func (v *MixedServerConfig) Build() (proto.Message, error) {
	config := new(mixed.ServerConfig)
	if len(v.Accounts) > 0 {
		config.Accounts = make(map[string]string, len(v.Accounts))
		for _, account := range v.Accounts {
			config.Accounts[account.Username] = account.Password
		}
	}
	config.Timeout = v.Timeout
	config.UserLevel = v.UserLevel
	config.SocksUdpEnabled = v.SocksUDP
	if v.SocksHost != nil {
		config.SocksAddress = v.SocksHost.Build()
	}
	config.HttpAllowTransparent = v.HttpTransparent
	return config, nil
}
