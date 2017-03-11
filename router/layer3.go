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

	lock     sync.RWMutex
	isClosed bool
}

func (rwc *l3ReadWriteCloser) Read(p []byte) (n int, err error) {
	if len(p) == 0 {
		return
	}
	//	rwc.lock.RLock()
	//	defer rwc.lock.RUnlock()
	if rwc.isClosed {
		return 0, fmt.Errorf("allready closed")
	}

	data := <-rwc.out
	n = copy(p, data.payload)
	err = data.err

	if err != nil {
		rwc.in <- l3Payload{
			payload: nil,
			err:     err,
		}
		rwc.Close()
	}

	return
}

func (rwc *l3ReadWriteCloser) Write(p []byte) (n int, err error) {
	//	rwc.lock.RLock()
	//	defer rwc.lock.RUnlock()
	if rwc.isClosed {
		err = fmt.Errorf("connection is closed")
		return
	}
	data := l3Payload{
		payload: p[:len(p)],
		err:     nil,
	}
	n = len(data.payload)
	rwc.in <- data

	return
}

func (rwc *l3ReadWriteCloser) Close() error {
	//	rwc.lock.Lock()
	//	defer rwc.lock.Unlock()
	if !rwc.isClosed {
		rwc.isClosed = true
		close(rwc.out)
		return nil
	}
	return fmt.Errorf("allready closed")
}

func (r *router) IPHandler(rCh chan l3Payload, wCh chan l3Payload) {
	handlerCh := make(chan []byte)
	// handlerL3 is the handler for the L3 layer types
	var handlerL3 func(buff []byte, wCh chan []byte)

	// loop, reading packets from tun and passing them
	// allong to the respective handlers
	for {
		select {
		case buff := <-rCh:
			switch buff.payload[0] >> 4 {
			case 0x04: // IPv4
				handlerL3 = r.HandleIPv4
			case 0x06: // IPv6
				handlerL3 = r.HandleIPv6
			}

			if handlerL3 != nil {
				// fire the handler to do the rest
				go handlerL3(buff.payload, handlerCh)
				continue
			}
			r.log.Printf("unknow protocol packet [%x]", buff.payload[0]>>4)
		case data := <-handlerCh:
			wCh <- l3Payload{
				payload: data,
			}
		}
	}
}
