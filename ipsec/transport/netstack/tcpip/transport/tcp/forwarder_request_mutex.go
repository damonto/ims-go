package tcp

import "sync"

type forwarderRequestMutex struct {
	sync.Mutex
}
