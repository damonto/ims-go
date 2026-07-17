package buffer

import (
	"fmt"
	"sync/atomic"
)

type chunkRefs struct {
	count atomic.Int64
}

func (r *chunkRefs) InitRefs() {
	r.count.Store(1)
}

func (r *chunkRefs) ReadRefs() int64 {
	return r.count.Load()
}

func (r *chunkRefs) IncRef() {
	if count := r.count.Add(1); count <= 1 {
		panic(fmt.Sprintf("incrementing released chunk reference %p", r))
	}
}

func (r *chunkRefs) DecRef(destroy func()) {
	switch count := r.count.Add(-1); {
	case count < 0:
		panic(fmt.Sprintf("decrementing released chunk reference %p", r))
	case count == 0 && destroy != nil:
		destroy()
	}
}
