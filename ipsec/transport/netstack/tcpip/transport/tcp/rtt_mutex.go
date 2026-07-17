package tcp

import "sync"

type rttMutex struct {
	sync.Mutex
}
