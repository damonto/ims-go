package tcp

import (
	"fmt"
	"sync/atomic"
)

type segmentRefs struct {
	count atomic.Int64
}

func (r *segmentRefs) InitRefs() {
	r.count.Store(1)
}

func (r *segmentRefs) IncRef() {
	if count := r.count.Add(1); count <= 1 {
		panic(fmt.Sprintf("incrementing released TCP segment reference %p", r))
	}
}

func (r *segmentRefs) DecRef(destroy func()) {
	switch count := r.count.Add(-1); {
	case count < 0:
		panic(fmt.Sprintf("decrementing released TCP segment reference %p", r))
	case count == 0 && destroy != nil:
		destroy()
	}
}
