package router

import (
	"log"
	"net"

	"github.com/google/gopacket"
)

// Config holds the configuration for this router
type Config struct {
	Log         *log.Logger
	SelfIPv4    net.IP // ip used as gateway
	NATSourceIp net.IP // ip used for internet/outbound traffic
}

// router holds some configuration data and the FlowTable
type router struct {
	log       *log.Logger
	selfIPv4  net.IP
	sourceIp  net.IP
	flowTable FlowTable
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
	}
}

// Router is an interface for a tunnel router
type Router interface {
	HandleIPv4(buff []byte, wCh chan []byte)
	HandleIPv6(buff []byte, wCh chan []byte)
	HandleICMPv4(packet gopacket.Packet, wCh chan []byte)
	HandleICMPv6(packet gopacket.Packet, wCh chan []byte)
	HandleTCP(packet gopacket.Packet, wCh chan []byte)
	HandleUDP(packet gopacket.Packet, wCh chan []byte)
}

// make sure router implements Router
var _ Router = &router{}
