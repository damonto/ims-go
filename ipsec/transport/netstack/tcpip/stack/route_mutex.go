package stack

import "sync"

type routeRWMutex struct {
	sync.RWMutex
}
