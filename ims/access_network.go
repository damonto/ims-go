package ims

import "strings"

func (c *Client) accessNetworkInfo() string {
	if value := strings.TrimSpace(c.cfg.AccessNetworkInfo); value != "" {
		return value
	}
	if nodeID := strings.TrimSpace(c.cfg.WLANNodeID); nodeID != "" {
		return "IEEE-802.11;i-wlan-node-id=" + strings.ToLower(nodeID)
	}
	return ""
}

func (c *Client) addAccessNetworkInfo(msg *Message) {
	if value := c.accessNetworkInfo(); value != "" {
		msg.AddHeader("P-Access-Network-Info", value)
	}
}
