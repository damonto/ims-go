package voice

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/damonto/vowifi-go/ims/session"
	"github.com/damonto/vowifi-go/ims/sip"
)

func (s *Service) exchangeCallInvite(ctx context.Context, invite sip.Message) (sip.Message, error) {
	exchangeCtx, cancelExchange := context.WithCancel(ctx)
	defer cancelExchange()

	var timedOut atomic.Bool
	stopTimer := s.startMOCallRequestTimer(func() {
		timedOut.Store(true)
		cancelExchange()
	})
	defer stopTimer()

	resp, err := s.sess.ExchangeWithOptions(exchangeCtx, invite, session.ExchangeOptions{
		OnProvisional: func(sip.Message) {
			stopTimer()
		},
	})
	if err != nil && timedOut.Load() {
		return sip.Message{}, errors.New("waiting for first provisional INVITE response: timeout")
	}
	return resp, err
}

func (s *Service) startMOCallRequestTimer(cancel func()) func() {
	if s.cfg.MOCallRequestTimeout <= 0 {
		return func() {}
	}

	timer := time.NewTimer(s.cfg.MOCallRequestTimeout)
	var once sync.Once
	done := make(chan struct{})
	go func() {
		select {
		case <-timer.C:
			once.Do(func() {
				close(done)
				cancel()
			})
		case <-done:
		}
	}()

	return func() {
		once.Do(func() {
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			close(done)
		})
	}
}

func (s *Service) retryInviteWithMinSE(ctx context.Context, call *Call, invite sip.Message, resp sip.Message) (sip.Message, error) {
	minSE, ok := parseMinSessionSeconds(resp.Header("Min-SE"))
	if !ok {
		return sip.Message{}, fmt.Errorf("session timer retry: invalid Min-SE %q", resp.Header("Min-SE"))
	}

	state := s.reg.State()
	_, _, _, branch := sip.NewTransaction()
	seq := atomic.AddInt64(&s.cseq, 1)
	retry := invite
	retry.Headers = invite.Headers.Clone()
	retry.Body = append([]byte(nil), invite.Body...)
	retry.Headers.Set("Via", sip.BuildVia(sip.TransportToken(s.sess.LocalAddr()), state.ContactHost, state.MessagePort, branch))
	retry.Headers.Set("CSeq", fmt.Sprintf("%d INVITE", seq))
	retry.Headers.Set("Min-SE", strconv.Itoa(minSE))
	retry.Headers.Set("Session-Expires", sessionExpiresRequestHeader(s.cfg, retry).String())

	call.mu.Lock()
	if call.state == CallStateEnding {
		call.mu.Unlock()
		return resp, nil
	}
	call.inviteSeq = seq
	call.localCSeq = seq
	call.inviteRequest = retry
	call.inviteResponse = false
	call.cancelOnResponse = false
	call.cancelSent = false
	call.mu.Unlock()

	next, err := s.exchangeCallInvite(ctx, retry)
	if err != nil {
		return sip.Message{}, fmt.Errorf("session timer retry: %w", err)
	}
	return next, nil
}
