package stack

import "sync"

type nicRWMutex struct {
	sync.RWMutex
}
