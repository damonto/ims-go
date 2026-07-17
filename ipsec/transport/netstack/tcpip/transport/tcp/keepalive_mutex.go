package tcp

import "sync"

type keepaliveMutex struct {
	sync.Mutex
}
