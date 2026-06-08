package vowifi

import (
	"context"
	"errors"
	"fmt"
)

func (c *Client) Close() error {
	var err error
	c.state.doClose(func() {
		active, ok := c.state.beginClose()
		if !ok {
			return
		}
		reader := c.reader
		c.reader = nil

		if active != nil && active.runtime != nil {
			active.runtime.stop()
		}
		if c.waitCloseTasks() {
			err = errors.Join(err, c.closeActive(active))
		} else {
			err = errors.Join(err, context.DeadlineExceeded)
			err = errors.Join(err, c.closeActiveRuntime(active))
			if active != nil && active.tunnel != nil {
				err = errors.Join(err, wrapCloseError(closeActionTunnel, normalizeCloseError(active.tunnel.Close())))
			}
		}
		if reader != nil {
			err = errors.Join(err, wrapCloseError(closeActionReader, reader.Close()))
		}
		c.emitStatus(StatusClosed)
		c.events.close()
	})
	return err
}

func (c *Client) waitCloseTasks() bool {
	return c.state.waitCloseTasks(defaultCloseTimeout)
}

func normalizeCloseError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return nil
	}
	return err
}

type closeAction uint8

const (
	closeActionReader closeAction = iota
	closeActionTunnel
	closeActionUSSDService
	closeActionVoiceService
	closeActionSMSService
	closeActionRegistrationService
	closeActionIMSSession
)

func (a closeAction) String() string {
	switch a {
	case closeActionReader:
		return "closing reader"
	case closeActionTunnel:
		return "closing tunnel"
	case closeActionUSSDService:
		return "closing USSD service"
	case closeActionVoiceService:
		return "closing voice service"
	case closeActionSMSService:
		return "closing SMS service"
	case closeActionRegistrationService:
		return "closing registration service"
	case closeActionIMSSession:
		return "closing IMS session"
	default:
		return "closing resource"
	}
}

func wrapCloseError(action closeAction, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", action, err)
}

func (c *Client) closeActive(active *activeConn) error {
	if active == nil {
		return nil
	}
	c.clearUSSDSessionBindings()

	err := active.ims.close()
	if active.tunnel != nil {
		err = errors.Join(err, wrapCloseError(closeActionTunnel, normalizeCloseError(active.tunnel.Close())))
	}
	return err
}

func (c *Client) closeActiveRuntime(active *activeConn) error {
	if active == nil {
		return nil
	}
	err := c.closeIMSRuntime(active)
	if active.tunnel != nil {
		err = errors.Join(err, wrapCloseError(closeActionTunnel, normalizeCloseError(active.tunnel.Close())))
	}
	return err
}

func (c *Client) closeIMSRuntime(active *activeConn) error {
	c.clearUSSDSessionBindings()
	return active.ims.close()
}

func (s *connectSetup) closeIMSRuntime() error {
	return s.ims.close()
}

func (r *imsRuntime) close() error {
	var err error
	if r.ussd != nil {
		err = errors.Join(err, wrapCloseError(closeActionUSSDService, r.ussd.Close()))
	}
	if r.voice != nil {
		err = errors.Join(err, wrapCloseError(closeActionVoiceService, r.voice.Close()))
	}
	if r.sms != nil {
		err = errors.Join(err, wrapCloseError(closeActionSMSService, r.sms.Close()))
	}
	if r.reg != nil {
		err = errors.Join(err, wrapCloseError(closeActionRegistrationService, r.reg.Close()))
	}
	if r.sip != nil {
		err = errors.Join(err, wrapCloseError(closeActionIMSSession, normalizeCloseError(r.sip.Close())))
	}
	*r = imsRuntime{}
	return err
}
