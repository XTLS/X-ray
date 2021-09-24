package conf_test

import (
	"testing"

	"github.com/xtls/xray-core/common/net"
	. "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/mixed"
)

func TestMixedServerConfig(t *testing.T) {
	creator := func() Buildable {
		return new(MixedServerConfig)
	}
	runMultiTestCase(t, []TestCase{
		{
			Input:  `{}`,
			Parser: loadJSON(creator),
			Output: &mixed.ServerConfig{
				Accounts:             nil,
				Timeout:              0,
				UserLevel:            0,
				SocksUdpEnabled:      false,
				SocksAddress:         nil,
				HttpAllowTransparent: false,
			},
		},
		{
			Input: `{
				"socksUdp": true
			}`,
			Parser: loadJSON(creator),
			Output: &mixed.ServerConfig{
				Accounts:             nil,
				Timeout:              0,
				UserLevel:            0,
				SocksUdpEnabled:      true,
				SocksAddress:         nil,
				HttpAllowTransparent: false,
			},
		},
		{
			Input: `{
				"accounts": [
					{
						"user": "user",
						"pass": "pass"
					}
				]
			}`,
			Parser: loadJSON(creator),
			Output: &mixed.ServerConfig{
				Accounts: map[string]string{
					"user": "pass",
				},
				Timeout:              0,
				UserLevel:            0,
				SocksUdpEnabled:      false,
				SocksAddress:         nil,
				HttpAllowTransparent: false,
			},
		},
		{
			Input: `{
				"accounts": [
					{
						"user": "user",
						"pass": "pass"
					}
				],
				"socksUdp": true
			}`,
			Parser: loadJSON(creator),
			Output: &mixed.ServerConfig{
				Accounts: map[string]string{
					"user": "pass",
				},
				Timeout:              0,
				UserLevel:            0,
				SocksUdpEnabled:      true,
				SocksAddress:         nil,
				HttpAllowTransparent: false,
			},
		},
		{
			Input: `{
				"accounts": [
					{
						"user": "user",
						"pass": "pass"
					}
				],
				"timeout": 5,
				"userLevel": 10,
				"socksUdp": true,
				"socksIp": "1.2.3.4",
				"httpAllowTransparent": true
			}`,
			Parser: loadJSON(creator),
			Output: &mixed.ServerConfig{
				Accounts: map[string]string{
					"user": "pass",
				},
				Timeout:         5,
				UserLevel:       10,
				SocksUdpEnabled: true,
				SocksAddress: &net.IPOrDomain{
					Address: &net.IPOrDomain_Ip{
						Ip: []byte{1, 2, 3, 4},
					},
				},
				HttpAllowTransparent: true,
			},
		},
	})
}
