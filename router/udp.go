package router

import "github.com/google/gopacket"

// HandleUDP is the handler for UDP traffic
// it selects a flowHandler from the FlowTable to handle the traffic
func (r *router) HandleUDP(packet gopacket.Packet, wCh chan []byte) {
	r.log.Printf("UDP protocol is not supported")
}
