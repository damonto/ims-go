package stack

import "sync"

type cleanupEndpointsMutex struct {
	sync.Mutex
}
