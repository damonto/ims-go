package stack

import "sync"

type stackRWMutex struct {
	sync.RWMutex
}
