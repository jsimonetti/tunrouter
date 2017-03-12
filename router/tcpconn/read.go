package tcpconn

import "sync"

func (c *conn) Read(p []byte) (n int, err error) {
	return 0, nil
}

type reader struct {
	sequence *uint32

	recvLock   sync.Mutex
	recvBuffer map[uint32][]byte // map keyed by tcp Sequence number
}

func (r *reader) recv(in chan l3Payload) {

}
