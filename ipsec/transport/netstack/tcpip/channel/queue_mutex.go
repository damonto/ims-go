package channel

import "sync"

type queueRWMutex struct {
	sync.RWMutex
}
