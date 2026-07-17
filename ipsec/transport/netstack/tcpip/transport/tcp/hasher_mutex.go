package tcp

import "sync"

type hasherMutex struct {
	sync.Mutex
}
