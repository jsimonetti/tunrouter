package router

import (
	"fmt"
	"io"
	"sync"
)

// make sure we implement io.ReadWriteCloser
var _ io.ReadWriteCloser = &l3ReadWriteCloser{}

// l3Payload hold a payload and an error
type l3Payload struct {
	payload []byte
	err     error
}

// l3ReadWriteCloser is the implementation of an io.ReadWriteCloser
// it allows a normal interface to the routers' L3 Handler
type l3ReadWriteCloser struct {
	in  chan l3Payload
	out chan l3Payload

	lock     sync.RWMutex
	isClosed bool
}

// Read will read from the router and send to the endpoint
func (rwc *l3ReadWriteCloser) Read(p []byte) (n int, err error) {
	// if nothing is writen, return
	if len(p) == 0 {
		return
	}
	//	rwc.lock.RLock()
	//	defer rwc.lock.RUnlock()
	if rwc.isClosed {
		return 0, fmt.Errorf("allready closed")
	}

	// receive data from router
	data := <-rwc.out
	n = copy(p, data.payload)
	err = data.err

	// if there was an error reading from the router,
	// send it back and close the RWC
	if err != nil {
		rwc.in <- l3Payload{
			payload: nil,
			err:     err,
		}
		rwc.Close()
	}

	return
}

// Write will read from the andpoint and send to the router
func (rwc *l3ReadWriteCloser) Write(p []byte) (n int, err error) {
	//	rwc.lock.RLock()
	//	defer rwc.lock.RUnlock()
	if rwc.isClosed {
		err = fmt.Errorf("connection is closed")
		return
	}

	// construct a l3Payload and send it
	data := l3Payload{
		payload: p[:len(p)],
		err:     nil,
	}
	n = len(data.payload)
	rwc.in <- data

	return
}

// Close will close the connection or return an error if it was allready closed
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

// IPHandler is the IP level handler for the router
// Data is flowing into the router via channel rCh and out via channel wCh
// It is an interface between the RWC and the routers' IP various handlers
func (r *router) IPHandler(rCh chan l3Payload, wCh chan l3Payload) {
	r.log.Printf("Router started in L3Mode")
	if r.isPrivileged {
		r.log.Printf("Running in privileged mode; icmp is enabled")
	} else {
		r.log.Printf("Running is unprivileged mode; icmp is disable")
	}

	handlerCh := make(chan []byte)

	// handlerL3 is the handler for the L3 layer types
	var handlerL3 func(buff []byte, wCh chan []byte)

	// loop, reading packets from RWC and passing them
	// allong to the respective handler
	for {
		select {
		case buff := <-rCh: // read data from the RWC
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
		case data := <-handlerCh: // send data to RWC
			wCh <- l3Payload{
				payload: data,
			}
		}
	}
}
