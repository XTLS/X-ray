package conf

import (
	"github.com/xtls/xray-core/proxy/http"
	"github.com/xtls/xray-core/proxy/mixed"
	"github.com/xtls/xray-core/proxy/socks"

	"github.com/golang/protobuf/proto"
)

type MixedConfig struct {
	HTTPConfig  HTTPServerConfig  `json:"http_config"`
	SocksConfig SocksServerConfig `json:"socks_config"`
}

func (c *MixedConfig) Build() (proto.Message, error) {
	config := new(mixed.Config)

	config.HttpConfig = &http.ServerConfig{
		Timeout:          c.HTTPConfig.Timeout,
		AllowTransparent: c.HTTPConfig.Transparent,
		UserLevel:        c.HTTPConfig.UserLevel,
	}

	if len(c.HTTPConfig.Accounts) > 0 {
		config.HttpConfig.Accounts = make(map[string]string)
		for _, account := range c.HTTPConfig.Accounts {
			config.HttpConfig.Accounts[account.Username] = account.Password
		}
	}

	config.SocksConfig = &socks.ServerConfig{}

	switch c.SocksConfig.AuthMethod {
	case AuthMethodNoAuth:
		config.SocksConfig.AuthType = socks.AuthType_NO_AUTH
	case AuthMethodUserPass:
		config.SocksConfig.AuthType = socks.AuthType_PASSWORD
	default:
		// newError("unknown socks auth method: ", v.AuthMethod, ". Default to noauth.").AtWarning().WriteToLog()
		config.SocksConfig.AuthType = socks.AuthType_NO_AUTH
	}

	if len(c.SocksConfig.Accounts) > 0 {
		config.SocksConfig.Accounts = make(map[string]string, len(c.SocksConfig.Accounts))
		for _, account := range c.SocksConfig.Accounts {
			config.SocksConfig.Accounts[account.Username] = account.Password
		}
	}

	config.SocksConfig.UdpEnabled = c.SocksConfig.UDP
	if c.SocksConfig.Host != nil {
		config.SocksConfig.Address = c.SocksConfig.Host.Build()
	}

	config.SocksConfig.Timeout = c.SocksConfig.Timeout
	config.SocksConfig.UserLevel = c.SocksConfig.UserLevel

	return config, nil
}
