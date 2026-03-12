package ims

import (
	"context"
	"fmt"
	"strings"
)

func (c *Client) computeAKAResponseForNonce(ctx context.Context, nonce string) (string, error) {
	var challenge AuthChallenge
	if err := challenge.UnmarshalText(fmt.Appendf(nil, `Digest nonce=%q,realm=%q`, nonce, strings.TrimPrefix(c.registerURI, "sip:"))); err != nil {
		return "", err
	}
	c.authNonce = challenge.Nonce
	c.authRealm = challenge.Realm
	response, authIK, err := c.computeAKAResponseWithKeys(ctx, challenge.Realm, challenge.Nonce)
	if err != nil {
		return "", err
	}
	if len(authIK) != 0 {
		c.authIK = authIK
	}
	return response, nil
}
