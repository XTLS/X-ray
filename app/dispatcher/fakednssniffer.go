package dispatcher

import (
	"context"
	"strings"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
)

// newFakeDNSSniffer Create a Fake DNS metadata sniffer
func newFakeDNSSniffer(ctx context.Context) (protocolSnifferWithMetadata, error) {
	var fakeDNSEngine dns.FakeDNSEngine
	err := core.RequireFeatures(ctx, func(fdns dns.FakeDNSEngine) {
		fakeDNSEngine = fdns
	})
	if err != nil {
		return protocolSnifferWithMetadata{}, err
	}
	if fakeDNSEngine == nil {
		errNotInit := newError("FakeDNSEngine is not initialized, but such a sniffer is used").AtError()
		return protocolSnifferWithMetadata{}, errNotInit
	}
	return protocolSnifferWithMetadata{protocolSniffer: func(ctx context.Context, bytes []byte) (SniffResult, error) {
		Target := session.OutboundFromContext(ctx).Target
		if Target.Network == net.Network_TCP || Target.Network == net.Network_UDP {
			domainFromFakeDNS := fakeDNSEngine.GetDomainFromFakeDNS(Target.Address)
			if domainFromFakeDNS != "" {
				newError("fake dns got domain: ", domainFromFakeDNS, " for ip: ", Target.Address.String()).WriteToLog(session.ExportIDToError(ctx))
				return &fakeDNSSniffResult{domainName: domainFromFakeDNS}, nil
			}
		}

		if ipAddressInRangeValueI := ctx.Value(ipAddressInRange); ipAddressInRangeValueI != nil {
			ipAddressInRangeValue := ipAddressInRangeValueI.(*ipAddressInRangeOpt)
			if fkr0, ok := fakeDNSEngine.(dns.FakeDNSEngineRev0); ok {
				inPool := fkr0.IsIPInIPPool(Target.Address)
				ipAddressInRangeValue.addressInRange = &inPool
			}
		}

		return nil, common.ErrNoClue
	}, metadataSniffer: true}, nil
}

type fakeDNSSniffResult struct {
	domainName string
}

func (fakeDNSSniffResult) Protocol() string {
	return "fakedns"
}

func (f fakeDNSSniffResult) Domain() string {
	return f.domainName
}

type fakeDNSExtraOpts int

const ipAddressInRange fakeDNSExtraOpts = 1

type ipAddressInRangeOpt struct {
	addressInRange *bool
}

type DNSThenOthersSniffResult struct {
	domainName           string
	protocolOriginalName string
}

func (f DNSThenOthersSniffResult) IsProtoSubsetOf(protocolName string) bool {
	return strings.HasPrefix(protocolName, f.protocolOriginalName)
}

func (DNSThenOthersSniffResult) Protocol() string {
	return "fakedns+others"
}

func (f DNSThenOthersSniffResult) Domain() string {
	return f.domainName
}

func newFakeDNSThenOthers(ctx context.Context, fakeDNSSniffer protocolSnifferWithMetadata, others []protocolSnifferWithMetadata) (
	protocolSnifferWithMetadata, error) { // nolint: unparam
	// ctx may be used in the future
	_ = ctx
	return protocolSnifferWithMetadata{
		protocolSniffer: func(ctx context.Context, bytes []byte) (SniffResult, error) {
			ipAddressInRangeValue := &ipAddressInRangeOpt{}
			ctx = context.WithValue(ctx, ipAddressInRange, ipAddressInRangeValue)
			result, err := fakeDNSSniffer.protocolSniffer(ctx, bytes)
			if err == nil {
				return result, nil
			}
			if ipAddressInRangeValue.addressInRange != nil {
				if *ipAddressInRangeValue.addressInRange {
					for _, v := range others {
						if v.metadataSniffer || bytes != nil {
							if result, err := v.protocolSniffer(ctx, bytes); err == nil {
								return DNSThenOthersSniffResult{domainName: result.Domain(), protocolOriginalName: result.Protocol()}, nil
							}
						}
					}
					return nil, common.ErrNoClue
				}
				newError("ip address not in fake dns range, return as is").AtDebug().WriteToLog()
				return nil, common.ErrNoClue
			}
			newError("fake dns sniffer did not set address in range option, assume false.").AtWarning().WriteToLog()
			return nil, common.ErrNoClue
		},
		metadataSniffer: false,
	}, nil
}
