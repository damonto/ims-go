package channel

import "sync"

type endpointRWMutex struct {
	sync.RWMutex
}
