package tcp

import "sync"

type acceptMutex struct {
	sync.Mutex
}
