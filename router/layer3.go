package router

import (
	"fmt"
	"io"
	"sync"
)

// make sure we implement io.ReadWriteCloser
var _ io.ReadWriteCloser = &l3ReadWriteCloser{}

type l3Payload struct {
	payload []byte
	err     error
}

type l3ReadWriteCloser struct {
	in  chan l3Payload
	out chan l3Payload

	lock     sync.Mutex
	isClosed bool
}

func (rwc *l3ReadWriteCloser) Read(p []byte) (n int, err error) {
	rwc.lock.Lock()
	defer rwc.lock.Unlock()
	if rwc.isClosed {
		return 0, fmt.Errorf("allready closed")
	}

	data := <-rwc.in
	n = len(data.payload)
	if n > 0 {
		p = data.payload
	}
	err = data.err

	if err != nil {
		rwc.out <- l3Payload{
			payload: nil,
			err:     err,
		}
		rwc.isClosed = true
		close(rwc.in)
	}

	return
}

func (rwc *l3ReadWriteCloser) Write(p []byte) (n int, err error) {
	// the upstream side closed his channel
	// we should close downstream to
	rwc.lock.Lock()
	defer rwc.lock.Unlock()
	if rwc.isClosed {
		err = fmt.Errorf("connection is closed")
		return
	}
	data := l3Payload{
		payload: p,
		err:     nil,
	}
	rwc.out <- data
	n = len(data.payload)

	return
}

func (rwc *l3ReadWriteCloser) Close() error {
	rwc.lock.Lock()
	defer rwc.lock.Unlock()
	if !rwc.isClosed {
		rwc.isClosed = true
		close(rwc.in)
		return nil
	}
	return fmt.Errorf("allready closed")
}
