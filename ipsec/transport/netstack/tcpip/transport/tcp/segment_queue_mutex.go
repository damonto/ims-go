package tcp

import "sync"

type segmentQueueMutex struct {
	sync.Mutex
}
