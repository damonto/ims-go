package tcp

import "sync"

type sndQueueMutex struct {
	sync.Mutex
}
