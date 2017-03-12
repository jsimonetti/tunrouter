package tcpconn

import "sync"

func (c *conn) Write(b []byte) (n int, err error) {
	return 0, nil
}

type writer struct {
	sequence *uint32

	sendLock sync.Mutex
	// map keyed by tcp Sequence number
	// holds all unacked packages
	sendBuffer map[uint32][]byte
}

func (w *writer) send(out chan l3Payload) {
}
