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
				err = errors.Join(err, wrapCloseError("closing tunnel", normalizeCloseError(active.tunnel.Close())))
			}
		}
		if reader != nil {
			err = errors.Join(err, wrapCloseError("closing reader", reader.Close()))
		}
		if err != nil {
			c.logger.Error("closing client", "err", err)
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

func wrapCloseError(action string, err error) error {
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
		err = errors.Join(err, wrapCloseError("closing tunnel", normalizeCloseError(active.tunnel.Close())))
	}
	return err
}

func (c *Client) closeActiveRuntime(active *activeConn) error {
	if active == nil {
		return nil
	}
	err := c.closeIMSRuntime(active)
	if active.tunnel != nil {
		err = errors.Join(err, wrapCloseError("closing tunnel", normalizeCloseError(active.tunnel.Close())))
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
		err = errors.Join(err, wrapCloseError("closing USSD service", r.ussd.Close()))
	}
	if r.voice != nil {
		err = errors.Join(err, wrapCloseError("closing voice service", r.voice.Close()))
	}
	if r.sms != nil {
		err = errors.Join(err, wrapCloseError("closing SMS service", r.sms.Close()))
	}
	if r.reg != nil {
		err = errors.Join(err, wrapCloseError("closing registration service", r.reg.Close()))
	}
	if r.sip != nil {
		err = errors.Join(err, wrapCloseError("closing IMS session", normalizeCloseError(r.sip.Close())))
	}
	*r = imsRuntime{}
	return err
}
