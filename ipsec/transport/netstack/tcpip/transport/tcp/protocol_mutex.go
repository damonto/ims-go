package tcp

import "sync"

type protocolRWMutex struct {
	sync.RWMutex
}
