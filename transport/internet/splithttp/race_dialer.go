package splithttp

import (
	"context"
	gotls "crypto/tls"
	goerrors "errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"golang.org/x/net/http2"
)

const (
	// net/quic/quic_session_pool.cc
	// QuicSessionPool::GetTimeDelayForWaitingJob > kDefaultRTT
	chromeH2DefaultTryDelay = 300 * time.Millisecond
	// QuicSessionPool::GetTimeDelayForWaitingJob > srtt
	chromeH2TryDelayScale = 1.5

	// net/http/broken_alternative_services.cc
	// kDefaultBrokenAlternativeProtocolDelay
	chromeH3BrokenInitialDelay = 5 * time.Minute
	// kMaxBrokenAlternativeProtocolDelay
	chromeH3BrokenMaxDelay = 48 * time.Hour
	// kBrokenDelayMaxShift
	chromeH3BrokenMaxShift = 18

	// net/third_party/quiche/src/quiche/quic/core/congestion_control/rtt_stats.cc
	// kAlpha
	chromeH3SmoothRTTAlpha = 0.125

	h3MaxRoundTripScale = 3
)

type raceKeyType struct{}

var raceKey raceKeyType

type noDialKeyType struct{}

var noDialKey noDialKeyType

var (
	loseRaceError   = goerrors.New("lose race")
	brokenSpanError = goerrors.New("protocol temporarily broken")
)

func isRaceInternalError(err error) bool {
	return goerrors.Is(err, loseRaceError) || goerrors.Is(err, brokenSpanError)
}

type h3InitRoundTripTimeoutError struct {
	err      error
	duration time.Duration
}

func (h *h3InitRoundTripTimeoutError) Error() string {
	return fmt.Sprintf("h3 not receiving any data in %s (%dx handshake RTT), QUIC is likely blocked on this network", h.duration, h3MaxRoundTripScale)
}
func (h *h3InitRoundTripTimeoutError) Unwrap() error {
	return h.err
}

const (
	raceInitialized = 0
	raceEstablished = 1
	raceErrored     = -1
)

type raceResult int

const (
	raceInflight raceResult = 0
	raceH3       raceResult = 1
	raceH2       raceResult = 2
	raceFailed   raceResult = -1
	raceInactive raceResult = -2
)

const (
	traceInit     = 0
	traceInflight = 1
	traceSettled  = 2
)

type endpointInfo struct {
	lastFail  time.Time
	failCount int
	rtt       atomic.Int64
}

var h3EndpointCatalog map[string]*endpointInfo
var h3EndpointCatalogLock sync.RWMutex

func isH3Broken(endpoint string) bool {
	h3EndpointCatalogLock.RLock()
	defer h3EndpointCatalogLock.RUnlock()
	info, ok := h3EndpointCatalog[endpoint]
	if !ok {
		return false
	}

	brokenDuration := min(chromeH3BrokenInitialDelay<<min(info.failCount, chromeH3BrokenMaxShift), chromeH3BrokenMaxDelay)
	return time.Since(info.lastFail) < brokenDuration
}

func getH2Delay(endpoint string) time.Duration {
	h3EndpointCatalogLock.RLock()
	defer h3EndpointCatalogLock.RUnlock()
	info, ok := h3EndpointCatalog[endpoint]
	if !ok {
		return chromeH2DefaultTryDelay
	}
	if info.failCount > 0 {
		return 0
	}
	rtt := info.rtt.Load()
	if rtt == 0 {
		return chromeH2DefaultTryDelay
	}
	return time.Duration(chromeH2TryDelayScale * float64(rtt))
}

func updateH3Broken(endpoint string, brokenAt time.Time) int {
	h3EndpointCatalogLock.Lock()
	defer h3EndpointCatalogLock.Unlock()
	if h3EndpointCatalog == nil {
		h3EndpointCatalog = make(map[string]*endpointInfo)
	}

	info, ok := h3EndpointCatalog[endpoint]
	if brokenAt.IsZero() {
		if ok {
			info.failCount = 0
			info.lastFail = time.Time{}
		}

		return 0
	}

	if !ok {
		info = &endpointInfo{}
		h3EndpointCatalog[endpoint] = info
	}

	info.failCount++
	if brokenAt.After(info.lastFail) {
		info.lastFail = brokenAt
	}

	return info.failCount
}

func smoothedRtt(oldRtt, newRtt int64) int64 {
	if oldRtt == 0 {
		return newRtt
	}

	return int64((1-chromeH3SmoothRTTAlpha)*float64(oldRtt) + chromeH3SmoothRTTAlpha*float64(newRtt))
}

func updateH3RTT(endpoint string, rtt time.Duration) time.Duration {
	h3EndpointCatalogLock.RLock()
	info, ok := h3EndpointCatalog[endpoint]
	if !ok {
		h3EndpointCatalogLock.RUnlock()
		return updateH3RTTSlow(endpoint, rtt)
	}

	defer h3EndpointCatalogLock.RUnlock()
	for {
		oldRtt := info.rtt.Load()
		newRtt := smoothedRtt(oldRtt, int64(rtt))
		if info.rtt.CompareAndSwap(oldRtt, newRtt) {
			return time.Duration(newRtt)
		}
	}
}

func updateH3RTTSlow(endpoint string, rtt time.Duration) time.Duration {
	h3EndpointCatalogLock.Lock()
	defer h3EndpointCatalogLock.Unlock()
	if h3EndpointCatalog == nil {
		h3EndpointCatalog = make(map[string]*endpointInfo)
	}

	info, ok := h3EndpointCatalog[endpoint]
	if ok {
		newRtt := smoothedRtt(info.rtt.Load(), int64(rtt))
		info.rtt.Store(newRtt)
		return time.Duration(newRtt)
	} else {
		info = &endpointInfo{}
		info.rtt.Store(int64(rtt))
		h3EndpointCatalog[endpoint] = info
		return rtt
	}
}

type quicStreamTraced struct {
	quic.Stream

	conn  *quicConnectionTraced
	state atomic.Int32
}

func (s *quicStreamTraced) signal(success bool) {
	if success {
		s.conn.confirmedWorking.Store(true)
		updateH3Broken(s.conn.endpoint, time.Time{})
	} else {
		s.conn.signalTimeout()
		s.CancelRead(quic.StreamErrorCode(quic.ApplicationErrorErrorCode))
		s.CancelWrite(quic.StreamErrorCode(quic.ApplicationErrorErrorCode))
		_ = s.Close()
	}
}

func (s *quicStreamTraced) Write(b []byte) (int, error) {
	if s.state.CompareAndSwap(traceInit, traceInflight) {
		_ = s.SetReadDeadline(time.Now().Add(s.conn.timeoutDuration))
	}
	return s.Stream.Write(b)
}

func (s *quicStreamTraced) Read(b []byte) (int, error) {
	n, err := s.Stream.Read(b)
	if s.state.CompareAndSwap(traceInflight, traceSettled) {
		switch {
		case err == nil:
			_ = s.SetReadDeadline(time.Time{})
			s.signal(true)
		case goerrors.Is(err, os.ErrDeadlineExceeded):
			s.signal(false)
			err = &h3InitRoundTripTimeoutError{
				err:      err,
				duration: s.conn.timeoutDuration,
			}
		}
	}

	return n, err
}

type quicConnectionTraced struct {
	quic.EarlyConnection

	endpoint         string
	timeoutDuration  time.Duration
	confirmedWorking atomic.Bool
}

func (conn *quicConnectionTraced) signalTimeout() {
	_ = conn.CloseWithError(quic.ApplicationErrorCode(quic.ApplicationErrorErrorCode), "round trip timeout")
	updateH3Broken(conn.endpoint, time.Now())
}

func (conn *quicConnectionTraced) OpenStreamSync(ctx context.Context) (quic.Stream, error) {
	stream, err := conn.EarlyConnection.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	if conn.confirmedWorking.Load() {
		return stream, nil
	}

	return &quicStreamTraced{
		Stream: stream,
		conn:   conn,
	}, nil
}

type raceNotify struct {
	c      chan struct{}
	result raceResult

	// left is the remove counter. It should be released when it reached 0
	left atomic.Int32
}

func (r *raceNotify) wait() raceResult {
	<-r.c
	return r.result
}

type raceTransport struct {
	h3   *http3.Transport
	h2   *http2.Transport
	dest string

	flag   atomic.Int64
	notify atomic.Pointer[raceNotify]
}

func (t *raceTransport) setup() *raceTransport {
	h3dial := t.h3.Dial
	h2dial := t.h2.DialTLSContext

	t.h3.Dial = func(ctx context.Context, addr string, tlsCfg *gotls.Config, cfg *quic.Config) (conn quic.EarlyConnection, err error) {
		if ctx.Value(noDialKey) != nil {
			return nil, http3.ErrNoCachedConn
		}

		var dialStart time.Time

		defer func() {
			notify := t.notify.Load()
			if err == nil {
				currRTT := time.Since(dialStart)
				smoothRTT := updateH3RTT(t.dest, currRTT)
				notify.result = raceH3
				close(notify.c)

				conn = &quicConnectionTraced{
					EarlyConnection: conn,
					endpoint:        t.dest,
					timeoutDuration: max(currRTT, smoothRTT) * h3MaxRoundTripScale,
				}
			} else if !isRaceInternalError(err) {
				failed := updateH3Broken(t.dest, time.Now())
				errors.LogDebug(ctx, "Race Dialer: h3 connection to ", t.dest, " failed ", failed, " time(s)")
			}

			// We can safely remove the raceNotify here, since both h2 and h3 Transport
			// hold mutex while dialing.
			// So another request can't slip in after we removed raceNotify but before
			// Transport put the returned conn into pool - they will always reuse the conn we returned.
			if notify.left.Add(-1) == 0 {
				errors.LogDebug(ctx, "Race Dialer: h3 cleaning race wait")
				t.notify.Store(nil)
			}
		}()

		if isH3Broken(t.dest) {
			return nil, brokenSpanError
		}

		established := t.flag.Load()
		if established == raceEstablished {
			errors.LogDebug(ctx, "Race Dialer: h3 lose (h2 established before try)")
			return nil, loseRaceError
		}

		dialStart = time.Now()
		conn, err = h3dial(ctx, addr, tlsCfg, cfg)

		if err != nil {
			// We fail.
			// Record if we are the first.
			if t.flag.CompareAndSwap(raceInitialized, raceErrored) {
				errors.LogDebug(ctx, "Race Dialer: h3 lose (h3 error)")
			} else {
				errors.LogDebug(ctx, "Race Dialer: h3 draw (both error)")
			}
			return nil, err
		}

		flag := t.flag.Load()
		switch flag {
		case raceEstablished:
			// h2 wins.
			_ = conn.CloseWithError(quic.ApplicationErrorCode(quic.NoError), "lose race")
			errors.LogDebug(ctx, "Race Dialer: h3 lose (h2 established before handshake complete)")
			return nil, loseRaceError
		case raceErrored:
			// h2 errored first. We will always be used.
			errors.LogDebug(ctx, "Race Dialer: h3 win (h2 error)")
			return conn, nil
		case raceInitialized:
			// continue
		default:
			panic(fmt.Sprintf("unreachable: unknown race flag: %d", flag))
		}

		// Don't consider we win until handshake completed.
		<-conn.HandshakeComplete()
		errors.LogDebug(ctx, "Race Dialer: h3 handshake complete")

		if err = conn.Context().Err(); err != nil {
			if t.flag.CompareAndSwap(raceInitialized, raceErrored) {
				errors.LogDebug(ctx, "Race Dialer: h3 lose (h3 error first)")
				return nil, err
			}
			_ = conn.CloseWithError(quic.ApplicationErrorCode(quic.NoError), "lose race")
			conn = nil
		} else {
			if t.flag.CompareAndSwap(raceInitialized, raceEstablished) {
				errors.LogDebug(ctx, "Race Dialer: h3 win (h3 first)")
				return conn, nil
			}
		}

		flag = t.flag.Load()
		switch flag {
		case raceEstablished:
			// h2 wins.
			_ = conn.CloseWithError(quic.ApplicationErrorCode(quic.NoError), "lose race")
			errors.LogDebug(ctx, "Race Dialer: h3 lose (h2 established)")
			return nil, loseRaceError
		case raceErrored:
			// h2 errored first.
			if err == nil {
				errors.LogDebug(ctx, "Race Dialer: h3 win (h2 error)")
			} else {
				errors.LogDebug(ctx, "Race Dialer: h3 draw (both error)")
			}
			return conn, err
		case raceInitialized:
			panic("unreachable: race flag should not revert to raceInitialized")
		default:
			panic(fmt.Sprintf("unreachable: unknown race flag: %d", flag))
		}
	}

	t.h2.DialTLSContext = func(ctx context.Context, network, addr string, cfg *gotls.Config) (conn net.Conn, err error) {
		if ctx.Value(noDialKey) != nil {
			return nil, http2.ErrNoCachedConn
		}

		defer func() {
			notify := t.notify.Load()
			if err == nil {
				notify.result = raceH2
				close(notify.c)
			}
			if notify.left.Add(-1) == 0 {
				errors.LogDebug(ctx, "Race Dialer: h2 cleaning race wait")
				t.notify.Store(nil)
			}
		}()

		delay := getH2Delay(t.dest)
		errors.LogDebug(ctx, "Race Dialer: h2 dial delay: ", delay)
		time.Sleep(delay)

		established := t.flag.Load()
		if established == raceEstablished {
			errors.LogDebug(ctx, "Race Dialer: h2 lose (h3 established before try)")
			return nil, loseRaceError
		}

		conn, err = h2dial(ctx, network, addr, cfg)

		if err != nil {
			// We fail.
			// Record if we are the first.
			if t.flag.CompareAndSwap(raceInitialized, raceErrored) {
				errors.LogDebug(ctx, "Race Dialer: h2 lose (h2 error first)")
				return nil, err
			}
			if conn != nil {
				_ = conn.Close()
				conn = nil
			}
		} else {
			if t.flag.CompareAndSwap(raceInitialized, raceEstablished) {
				errors.LogDebug(ctx, "Race Dialer: h2 win (h2 first)")
				return conn, nil
			}
		}

		flag := t.flag.Load()
		switch flag {
		case raceEstablished:
			// h3 wins.
			if conn != nil {
				_ = conn.Close()
				conn = nil
			}
			errors.LogDebug(ctx, "Race Dialer: h2 lose (h3 established)")
			return nil, loseRaceError
		case raceErrored:
			// h3 errored first.
			if err == nil {
				errors.LogDebug(ctx, "Race Dialer: h2 win (h3 error)")
			} else {
				errors.LogDebug(ctx, "Race Dialer: h2 draw (both error)")
			}
			return conn, err
		case raceInitialized:
			panic("unreachable: race flag should not revert to raceInitialized")
		default:
			panic(fmt.Sprintf("unreachable: unknown race flag: %d", flag))
		}
	}

	return t
}

func (t *raceTransport) RoundTrip(req *http.Request) (_ *http.Response, rErr error) {
	ctx := req.Context()

	// If there is inflight racing, let it finish first,
	// so we can know and reuse winner's conn.
	notify := t.notify.Load()
	raceResult := raceInactive

WaitRace:
	if notify != nil {
		errors.LogDebug(ctx, "Race Dialer: found inflight race to ", t.dest, ", waiting race winner")
		raceResult = notify.wait()
		errors.LogDebug(ctx, "Race Dialer: winner for ", t.dest, " resolved, continue handling request")
	}

	// Avoid body being closed by failed RoundTrip attempt
	rawBody := req.Body
	if rawBody != nil {
		req.Body = io.NopCloser(rawBody)
		defer func(body io.ReadCloser) {
			if rErr != nil {
				_ = rawBody.Close()
			}
		}(rawBody)
	}

	reqNoDial := req.WithContext(context.WithValue(ctx, noDialKey, struct{}{}))

	// First see if there's cached connection, for both h3 and h2.
	// - raceInactive: no inflight race. Try both.
	// - raceH3/raceH2: another request just decided race winner.
	//                  Losing Transport may not yet fail, so avoid trying it.
	// - raceFailed: both failed. There won't be cached conn, no need to try.
	// - raceInflight: should not see this state.
	if raceResult == raceH3 || raceResult == raceInactive {
		if resp, err := t.h3.RoundTripOpt(reqNoDial, http3.RoundTripOpt{OnlyCachedConn: true}); err == nil {
			errors.LogInfo(ctx, "Race Dialer: use h3 connection for ", t.dest, " (reusing conn)")
			return resp, nil
		} else if !goerrors.Is(err, http3.ErrNoCachedConn) {
			return nil, err
		}
		// Another dial just succeeded, but no cached conn available.
		// This can happen if that request failed after dialing.
		// In this case we need to initiate another race.
	}

	if raceResult == raceH2 || raceResult == raceInactive {
		// http2.RoundTripOpt.OnlyCachedConn is not effective. However, our noDialKey will block dialing anyway.
		if resp, err := t.h2.RoundTripOpt(reqNoDial, http2.RoundTripOpt{OnlyCachedConn: true}); err == nil {
			errors.LogInfo(ctx, "Race Dialer: use h2 connection for ", t.dest, " (reusing conn)")
			return resp, nil
		} else if !goerrors.Is(err, http2.ErrNoCachedConn) {
			return nil, err
		}
	}

	// Both don't have cached conn. Now race between h2 and h3.
	// Recheck first.
	notify = &raceNotify{c: make(chan struct{})}
	notify.left.Store(2)
	if !t.notify.CompareAndSwap(nil, notify) {
		// Some other request started racing before us, we wait for them to finish.
		goto WaitRace
	}

	// We are the goroutine to initialize racing.
	errors.LogDebug(ctx, "Race Dialer: start race to ", t.dest)

	t.flag.Store(raceInitialized)

	h2resp := make(chan any)
	h3resp := make(chan any)
	raceDone := make(chan struct{})

	defer func() {
		if notify.result == raceInflight {
			notify.result = raceFailed
			close(notify.c)
		}
		close(raceDone)
	}()

	// Both RoundTripper can share req.Body, because only one can dial successfully,
	// and proceed to read request body.
	roundTrip := func(r http.RoundTripper, respChan chan any) {
		resp, err := r.RoundTrip(req)

		var result any
		if err == nil {
			result = resp
		} else {
			result = err
		}

		select {
		case respChan <- result:
		case <-raceDone:
		}
	}

	go roundTrip(t.h3, h3resp)
	go roundTrip(t.h2, h2resp)

	reportState := func(isH3 bool) {
		winner := "h2"
		if isH3 {
			winner = "h3"
		}
		errors.LogInfo(ctx, "Race Dialer: use ", winner, " connection for ", t.dest, " (race winner)")
	}

	handleResult := func(respErr any, other chan any, isH3 bool) (*http.Response, error) {
		switch value := respErr.(type) {
		case *http.Response:
			// we win
			reportState(isH3)
			return value, nil
		case error:
			switch otherValue := (<-other).(type) {
			case *http.Response:
				// other win
				reportState(!isH3)
				return otherValue, nil
			case error:
				switch {
				// hide internal error
				case isRaceInternalError(value):
					return nil, otherValue
				case isRaceInternalError(otherValue):
					return nil, value
				// prefer h3 error
				case isH3:
					return nil, value
				default:
					return nil, otherValue
				}
			default:
				panic(fmt.Sprintf("unreachable: unexpected response type %T", otherValue))
			}
		default:
			panic(fmt.Sprintf("unreachable: unexpected response type %T", value))
		}
	}

	select {
	case respErr := <-h3resp:
		return handleResult(respErr, h2resp, true)
	case respErr := <-h2resp:
		return handleResult(respErr, h3resp, false)
	}
}
