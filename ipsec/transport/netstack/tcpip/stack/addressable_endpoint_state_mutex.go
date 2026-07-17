package stack

import "sync"

type addressableEndpointStateRWMutex struct {
	sync.RWMutex
}
