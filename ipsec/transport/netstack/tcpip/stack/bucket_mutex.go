package stack

import "sync"

type bucketRWMutex struct {
	sync.RWMutex
}
