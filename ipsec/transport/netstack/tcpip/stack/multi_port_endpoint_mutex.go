package stack

import "sync"

type multiPortEndpointRWMutex struct {
	sync.RWMutex
}
