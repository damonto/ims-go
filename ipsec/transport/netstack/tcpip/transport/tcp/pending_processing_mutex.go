package tcp

import "sync"

type pendingProcessingMutex struct {
	sync.Mutex
}
