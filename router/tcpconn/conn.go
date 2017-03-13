package tcpconn

import (
	"math/rand"
	"net"
	"time"
)

type conn struct {
	in  chan l3Payload
	out chan l3Payload

	reader *reader
	writer *writer

	// sequence shared by recv and send
	sequence uint32
}

type TCPConn interface {
	net.Conn
}

type l3Payload struct {
	data []byte
	err  error
}

// New returns a new TCPCONN
func New() TCPConn {
	random := rand.NewSource(time.Now().UnixNano())

	c := &conn{sequence: uint32(random.Int63())}

	c.reader = &reader{sequence: &c.sequence}
	c.writer = &writer{sequence: &c.sequence}

	go c.reader.recv(c.in, c.out)
	go c.writer.send(c.out, c.in)

	return c
}
