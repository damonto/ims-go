// Copyright 2018 The gVisor Authors.
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

package tcp

import (
	"fmt"
	"slices"
	"strings"

	"github.com/damonto/ims-go/ipsec/transport/netstack/tcpip/header"
	"github.com/damonto/ims-go/ipsec/transport/netstack/tcpip/seqnum"
)

const (
	// maxSACKBlocks is the maximum number of distinct SACKBlocks the
	// scoreboard will track. Once there are 100 distinct blocks, new
	// insertions will fail.
	maxSACKBlocks = 100
)

// SACKScoreboard stores a set of disjoint SACK ranges.
type SACKScoreboard struct {
	// smss is defined in RFC5681 as following:
	//
	//    The SMSS is the size of the largest segment that the sender can
	//    transmit.  This value can be based on the maximum transmission unit
	//    of the network, the path MTU discovery [RFC1191, RFC4821] algorithm,
	//    RMSS (see next item), or other factors.  The size does not include
	//    the TCP/IP headers and options.
	smss      uint16
	maxSACKED seqnum.Value
	sacked    seqnum.Size
	ranges    []header.SACKBlock
}

// NewSACKScoreboard returns a new SACK Scoreboard.
func NewSACKScoreboard(smss uint16, iss seqnum.Value) *SACKScoreboard {
	return &SACKScoreboard{
		smss:      smss,
		maxSACKED: iss,
	}
}

// Reset erases all known range information from the SACK scoreboard.
func (s *SACKScoreboard) Reset() {
	s.ranges = nil
	s.sacked = 0
}

// Insert inserts/merges the provided SACKBlock into the scoreboard.
func (s *SACKScoreboard) Insert(r header.SACKBlock) {
	if len(s.ranges) >= maxSACKBlocks {
		return
	}

	if s.maxSACKED.LessThan(r.End - 1) {
		s.maxSACKED = r.End - 1
	}

	// A scoreboard holds at most 100 ranges, so a compact sorted slice is
	// simpler and cheaper than maintaining a general-purpose tree.
	start := 0
	for start < len(s.ranges) && s.ranges[start].End.LessThan(r.Start) {
		start++
	}

	end := start
	for end < len(s.ranges) && !r.End.LessThan(s.ranges[end].Start) {
		sb := s.ranges[end]
		if sb.Start.LessThan(r.Start) {
			r.Start = sb.Start
		}
		if r.End.LessThan(sb.End) {
			r.End = sb.End
		}
		s.sacked -= sb.Start.Size(sb.End)
		end++
	}

	s.ranges = slices.Replace(s.ranges, start, end, r)
	s.sacked += r.Start.Size(r.End)
}

// IsSACKED returns true if the a given range of sequence numbers denoted by r
// are already covered by SACK information in the scoreboard.
func (s *SACKScoreboard) IsSACKED(r header.SACKBlock) bool {
	if s.Empty() {
		return false
	}

	i := s.rangeAtOrBefore(r.Start)
	return i >= 0 && s.ranges[i].Contains(r)
}

// String returns human-readable state of the scoreboard structure.
func (s *SACKScoreboard) String() string {
	var str strings.Builder
	str.WriteString("SACKScoreboard: {")
	for _, sb := range s.ranges {
		fmt.Fprintf(&str, "%v,", sb)
	}
	str.WriteString("}\n")
	return str.String()
}

// Delete removes all SACK information prior to seq.
func (s *SACKScoreboard) Delete(seq seqnum.Value) {
	if s.Empty() {
		return
	}
	i := 0
	for i < len(s.ranges) && s.ranges[i].End.LessThanEq(seq) {
		s.sacked -= s.ranges[i].Start.Size(s.ranges[i].End)
		i++
	}
	if i < len(s.ranges) && !seq.LessThan(s.ranges[i].Start) {
		s.sacked -= s.ranges[i].Start.Size(seq)
		s.ranges[i].Start = seq
	}
	s.ranges = slices.Delete(s.ranges, 0, i)
}

// Copy provides a copy of the SACK scoreboard.
func (s *SACKScoreboard) Copy() (sackBlocks []header.SACKBlock, maxSACKED seqnum.Value) {
	return slices.Clone(s.ranges), s.maxSACKED
}

// IsRangeLost implements the IsLost(SeqNum) operation defined in RFC 6675
// section 4 but operates on a range of sequence numbers and returns true if
// there are at least nDupAckThreshold SACK blocks greater than the range being
// checked or if at least (nDupAckThreshold-1)*s.smss bytes have been SACKED
// with sequence numbers greater than the block being checked.
func (s *SACKScoreboard) IsRangeLost(r header.SACKBlock) bool {
	if s.Empty() {
		return false
	}
	nDupSACK := 0
	nDupSACKBytes := seqnum.Size(0)
	isLost := false

	// Check the immediate lower range for containment or partial overlap.
	if i := s.rangeAtOrBefore(r.Start); i >= 0 {
		sacked := s.ranges[i]
		if sacked.Contains(r) {
			return false
		}
		if !sacked.End.LessThanEq(r.Start) {
			r.Start = sacked.End
		}
	}

	for _, sacked := range s.ranges {
		if sacked.Start.LessThan(r.Start) {
			continue
		}
		if sacked.Contains(r) {
			break
		}
		nDupSACKBytes += sacked.Start.Size(sacked.End)
		nDupSACK++
		if nDupSACK >= nDupAckThreshold || nDupSACKBytes >= seqnum.Size((nDupAckThreshold-1)*s.smss) {
			isLost = true
			break
		}
	}
	return isLost
}

// IsLost implements the IsLost(SeqNum) operation defined in RFC3517 section
// 4.
//
// This routine returns whether the given sequence number is considered to be
// lost. The routine returns true when either nDupAckThreshold discontiguous
// SACKed sequences have arrived above 'SeqNum' or (nDupAckThreshold * SMSS)
// bytes with sequence numbers greater than 'SeqNum' have been SACKed.
// Otherwise, the routine returns false.
func (s *SACKScoreboard) IsLost(seq seqnum.Value) bool {
	return s.IsRangeLost(header.SACKBlock{Start: seq, End: seq.Add(1)})
}

// Empty returns true if the SACK scoreboard has no entries, false otherwise.
func (s *SACKScoreboard) Empty() bool {
	return len(s.ranges) == 0
}

func (s *SACKScoreboard) rangeAtOrBefore(start seqnum.Value) int {
	for i, sb := range s.ranges {
		if start.LessThan(sb.Start) {
			return i - 1
		}
	}
	return len(s.ranges) - 1
}

// Sacked returns the current number of bytes held in the SACK scoreboard.
func (s *SACKScoreboard) Sacked() seqnum.Size {
	return s.sacked
}

// MaxSACKED returns the highest sequence number ever inserted in the SACK
// scoreboard.
func (s *SACKScoreboard) MaxSACKED() seqnum.Value {
	return s.maxSACKED
}

// SMSS returns the sender's MSS as held by the SACK scoreboard.
func (s *SACKScoreboard) SMSS() uint16 {
	return s.smss
}
