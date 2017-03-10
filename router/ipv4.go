package router

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func (r *router) HandleIPv4(buff []byte, wCh chan []byte) {
	// decrypt the packet as type ipv4 with defaul decoder settings
	packet := gopacket.NewPacket(buff, layers.LayerTypeIPv4, gopacket.Default)
	if err := packet.ErrorLayer(); err != nil {
		r.log.Printf("Error decoding some part of the packet: %s", err)
		return
	}

	// handler is the actual payload handler function
	var handler func(packet gopacket.Packet, wCh chan []byte)

	// switch on the payload layer type of the ipv4 packet
	switch packet.Layers()[1].(type) {
	case *layers.ICMPv4:
		// payload is ICMPv4
		handler = r.handleICMPv4
	case *layers.TCP:
		// payload is TCP
		handler = r.handleTCP
	case *layers.UDP:
		// payload is UDP
		handler = r.handleUDP
	default:
		// other payload layer types are not supported
		r.log.Printf("ipv4: unhandled sublayer type: %v", packet.Layers()[1])
		return
	}

	// fire and forget the handler
	go handler(packet, wCh)
}
