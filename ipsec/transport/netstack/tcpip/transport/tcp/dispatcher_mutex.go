package tcp

import "sync"

type dispatcherMutex struct {
	sync.Mutex
}
