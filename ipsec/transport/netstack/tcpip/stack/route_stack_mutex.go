package stack

import "sync"

type routeStackRWMutex struct {
	sync.RWMutex
}
