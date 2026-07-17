package stack

import "sync"

type transportEndpointsRWMutex struct {
	sync.RWMutex
}
