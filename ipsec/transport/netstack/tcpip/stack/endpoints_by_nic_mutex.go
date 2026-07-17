package stack

import "sync"

type endpointsByNICRWMutex struct {
	sync.RWMutex
}
