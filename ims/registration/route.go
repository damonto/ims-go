package registration

import (
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
)

func (s *Service) preloadedRoutes(flow Flow) []string {
	routes := make([]string, 0, len(flow.ServiceRoutes)+1)
	if route := pcscfRoute(s.sess.RemoteAddr(), flow); route != "" {
		routes = append(routes, route)
	}
	for _, route := range flow.ServiceRoutes {
		route = strings.TrimSpace(route)
		if route == "" || slices.ContainsFunc(routes, func(existing string) bool {
			return strings.EqualFold(existing, route)
		}) {
			continue
		}
		routes = append(routes, route)
	}
	return routes
}

func pcscfRoute(addr net.Addr, flow Flow) string {
	host, port := addrHostPort(addr)
	if host == "" || port == 0 {
		return ""
	}
	if flow.SecurityVerify != nil && flow.SecurityVerify.PortS != 0 {
		port = flow.SecurityVerify.PortS
	}
	return fmt.Sprintf("<%s;lr>", contactURI(host, port))
}

func addrHostPort(addr net.Addr) (string, int) {
	switch a := addr.(type) {
	case *net.UDPAddr:
		if a == nil {
			return "", 0
		}
		return sanitizeHost(a.IP.String()), a.Port
	case *net.TCPAddr:
		if a == nil {
			return "", 0
		}
		return sanitizeHost(a.IP.String()), a.Port
	}
	if addr == nil {
		return "", 0
	}
	host, portText, err := net.SplitHostPort(addr.String())
	if err != nil {
		return "", 0
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return "", 0
	}
	return sanitizeHost(host), port
}
