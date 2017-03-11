package router

import (
	"fmt"
	"io"
	"log"
	"net"
)

// Config holds the configuration for this router
type Config struct {
	Log         *log.Logger
	SelfIPv4    net.IP // ip used as gateway
	NATSourceIp net.IP // ip used for internet/outbound traffic
}

// router holds some configuration data and the FlowTable
type router struct {
	log          *log.Logger
	selfIPv4     net.IP
	sourceIp     net.IP
	isPrivileged bool
	flowTable    FlowTable
}

// New returns an instance of router with the specified configuration
func New(config Config) Router {
	return &router{
		log:      config.Log,
		selfIPv4: config.SelfIPv4,
		sourceIp: config.NATSourceIp,
		flowTable: FlowTable{
			flowMap: make(map[uint64]*FlowHandler),
		},
		isPrivileged: runningPrivileged(),
	}
}

// Router is an interface for a tunnel router
type Router interface {
	//HandleIPv4(buff []byte, wCh chan []byte)
	//HandleIPv6(buff []byte, wCh chan []byte)
	//HandleICMPv4(packet gopacket.Packet, wCh chan []byte)
	//HandleICMPv6(packet gopacket.Packet, wCh chan []byte)
	//HandleTCP(packet gopacket.Packet, wCh chan []byte)
	//HandleUDP(packet gopacket.Packet, wCh chan []byte)
	Open(Mode) (io.ReadWriteCloser, error)
}

// make sure router implements Router
var _ Router = &router{}

// Mode are different methods of opening the Router
type Mode int

const (
	// Open the router in L2 mode (ethernet)
	L2Mode Mode = iota
	// Open the router in L3 mode (IP)
	L3Mode Mode = iota
)

// String returns a string representation of the Mode
func (m Mode) String() string {
	switch m {
	case L2Mode:
		return "L2Mode"
	case L3Mode:
		return "L3Mode"
	}
	return fmt.Sprintf("Mode(%d)", m)
}

// Open will return an RWC for the router in the specified operation mode
func (r *router) Open(openType Mode) (io.ReadWriteCloser, error) {
	if openType == L3Mode {
		fd := &l3ReadWriteCloser{
			in:  make(chan l3Payload),
			out: make(chan l3Payload),
		}
		// start the routers' interface between RWC and routers' handlers
		go r.IPHandler(fd.in, fd.out)
		return fd, nil
	}
	return nil, fmt.Errorf("opening for %#v is not accepted", openType)
}

// runningPrivileged will check if raw icmp is available
// raw icmp is needed for ICMP handling
func runningPrivileged() bool {
	conn, err := net.DialIP("ip4:icmp", &net.IPAddr{IP: net.ParseIP("127.0.0.1")}, &net.IPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		return false
	}
	defer conn.Close()
	return true
}
