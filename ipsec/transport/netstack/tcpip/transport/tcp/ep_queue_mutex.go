package tcp

import "sync"

type epQueueMutex struct {
	sync.Mutex
}
