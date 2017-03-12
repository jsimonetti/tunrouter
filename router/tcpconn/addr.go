package tcpconn

import "net"

type localAddr struct{}

func (l localAddr) Network() string {
	return "tcp:raw"
}

func (l localAddr) String() string {
	return "tcp:raw"
}

func (c *conn) LocalAddr() net.Addr {
	return localAddr{}
}

type remoteAddr struct{}

func (l remoteAddr) Network() string {
	return "tcp:raw"
}

func (l remoteAddr) String() string {
	return "tcp:raw"
}

func (c *conn) RemoteAddr() net.Addr {
	return remoteAddr{}
}
