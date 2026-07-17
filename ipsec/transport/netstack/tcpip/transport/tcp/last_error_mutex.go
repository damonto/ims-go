package tcp

import "sync"

type lastErrorMutex struct {
	sync.Mutex
}
