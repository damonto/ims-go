// Copyright 2020 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ipv4

import (
	"github.com/damonto/ims-go/ipsec/transport/netstack/tcpip"
	"github.com/damonto/ims-go/ipsec/transport/netstack/tcpip/network/ip"
	"github.com/damonto/ims-go/ipsec/transport/netstack/tcpip/stack"
)

var _ stack.IPNetworkEndpointStats = (*Stats)(nil)

// Stats holds statistics related to the IPv4 protocol family.
type Stats struct {
	// IP holds IPv4 statistics.
	IP tcpip.IPStats
}

// IsNetworkEndpointStats implements stack.NetworkEndpointStats.
func (*Stats) IsNetworkEndpointStats() {}

// IPStats implements stack.IPNetworkEndointStats
func (s *Stats) IPStats() *tcpip.IPStats {
	return &s.IP
}

type sharedStats struct {
	localStats Stats
	ip         ip.MultiCounterIPStats
}
