package tcp

import "sync"

type rcvQueueMutex struct {
	sync.Mutex
}
