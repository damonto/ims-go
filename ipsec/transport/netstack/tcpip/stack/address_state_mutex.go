package stack

import "sync"

type addressStateRWMutex struct {
	sync.RWMutex
}
