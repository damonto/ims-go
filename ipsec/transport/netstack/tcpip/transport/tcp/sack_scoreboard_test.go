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
	"testing"

	"github.com/damonto/ims-go/ipsec/transport/netstack/tcpip/header"
	"github.com/damonto/ims-go/ipsec/transport/netstack/tcpip/seqnum"
)

func newTestSACKScoreboard(blocks []header.SACKBlock, iss seqnum.Value) *SACKScoreboard {
	s := NewSACKScoreboard(1500, iss)
	for _, block := range blocks {
		s.Insert(block)
	}
	return s
}

func testSACKBlock(start, end seqnum.Value) header.SACKBlock {
	return header.SACKBlock{Start: start, End: end}
}

func testSACKBlockPtr(start, end seqnum.Value) *header.SACKBlock {
	block := testSACKBlock(start, end)
	return &block
}

func TestSACKScoreboardIsSACKED(t *testing.T) {
	tests := []struct {
		name   string
		iss    seqnum.Value
		blocks []header.SACKBlock
		query  header.SACKBlock
		want   bool
	}{
		{"merged overlap", 0, []header.SACKBlock{testSACKBlock(10, 20), testSACKBlock(10, 30), testSACKBlock(30, 40), testSACKBlock(41, 50), testSACKBlock(5, 10), testSACKBlock(1, 50)}, testSACKBlock(15, 21), true},
		{"hole", 0, []header.SACKBlock{testSACKBlock(1, 50), testSACKBlock(52, 120)}, testSACKBlock(50, 51), false},
		{"disjoint", 2288624809, []header.SACKBlock{testSACKBlock(2288624809, 2288810057), testSACKBlock(2288811477, 2288838565)}, testSACKBlock(2288810057, 2288811477), false},
		{"wrap around", 4294254144, []header.SACKBlock{testSACKBlock(4294254144, 225652), testSACKBlock(5340409, 5350509)}, testSACKBlock(4294254144, 1), true},
		{"out of order", 827426000, []header.SACKBlock{testSACKBlock(827450276, 827454536), testSACKBlock(827426028, 827428868)}, testSACKBlock(827426028, 827428867), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestSACKScoreboard(tt.blocks, tt.iss)
			if got := s.IsSACKED(tt.query); got != tt.want {
				t.Errorf("IsSACKED(%v) = %v, want %v", tt.query, got, tt.want)
			}
		})
	}
}

func TestSACKScoreboardIsRangeLost(t *testing.T) {
	s := NewSACKScoreboard(10, 0)
	for _, block := range []header.SACKBlock{
		testSACKBlock(1, 25), testSACKBlock(25, 50), testSACKBlock(51, 100), testSACKBlock(111, 120), testSACKBlock(101, 110),
		testSACKBlock(121, 141), testSACKBlock(145, 146), testSACKBlock(147, 148), testSACKBlock(149, 150), testSACKBlock(153, 154), testSACKBlock(155, 156),
	} {
		s.Insert(block)
	}

	tests := []struct {
		name  string
		block header.SACKBlock
		want  bool
	}{
		{"three higher blocks", testSACKBlock(0, 1), true},
		{"fully sacked", testSACKBlock(1, 45), false},
		{"enough higher bytes", testSACKBlock(120, 121), true},
		{"three disjoint higher blocks", testSACKBlock(141, 145), true},
		{"too few higher blocks", testSACKBlock(151, 152), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := s.IsRangeLost(tt.block); got != tt.want {
				t.Errorf("IsRangeLost(%v) = %v, want %v", tt.block, got, tt.want)
			}
		})
	}
}

func TestSACKScoreboardDelete(t *testing.T) {
	blocks := []header.SACKBlock{testSACKBlock(4294254144, 225652), testSACKBlock(5340409, 5350509)}
	s := newTestSACKScoreboard(blocks, 4294254143)

	tests := []struct {
		name      string
		seq       seqnum.Value
		wantEmpty bool
		wantBlock *header.SACKBlock
	}{
		{"drop wrapped block", 5340408, false, testSACKBlockPtr(5340409, 5350509)},
		{"trim remaining block", 5340410, false, testSACKBlockPtr(5340410, 5350509)},
		{"drop remaining block", 5350509, true, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s.Delete(tt.seq)
			if got := s.Empty(); got != tt.wantEmpty {
				t.Fatalf("Empty() = %v, want %v", got, tt.wantEmpty)
			}
			if tt.wantBlock != nil && !s.IsSACKED(*tt.wantBlock) {
				t.Errorf("IsSACKED(%v) = false, want true", *tt.wantBlock)
			}
		})
	}
}
