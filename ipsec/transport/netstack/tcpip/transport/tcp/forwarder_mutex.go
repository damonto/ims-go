package tcp

import "sync"

type forwarderMutex struct {
	sync.Mutex
}
