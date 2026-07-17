package stack

import (
	"fmt"
	"sync/atomic"
)

type atomicRefs struct {
	count atomic.Int64
}

type addressStateRefs struct {
	atomicRefs
}

type packetBufferRefs struct {
	atomicRefs
}

func (r *atomicRefs) InitRefs() {
	r.count.Store(1)
}

func (r *atomicRefs) ReadRefs() int64 {
	return r.count.Load()
}

func (r *atomicRefs) IncRef() {
	if count := r.count.Add(1); count <= 1 {
		panic(fmt.Sprintf("incrementing released stack reference %p", r))
	}
}

func (r *atomicRefs) TryIncRef() bool {
	for {
		count := r.count.Load()
		if count == 0 {
			return false
		}
		if count < 0 {
			panic(fmt.Sprintf("incrementing invalid stack reference %p", r))
		}
		if r.count.CompareAndSwap(count, count+1) {
			return true
		}
	}
}

func (r *atomicRefs) DecRef(destroy func()) {
	switch count := r.count.Add(-1); {
	case count < 0:
		panic(fmt.Sprintf("decrementing released stack reference %p", r))
	case count == 0 && destroy != nil:
		destroy()
	}
}
