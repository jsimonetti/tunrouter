package router

import "github.com/google/gopacket"

// HandleICMPv6 is the handler for ICMPv6 traffic
// it selects a flowHandler from the FlowTable to handle the traffic
func (r *router) HandleICMPv6(packet gopacket.Packet, wCh chan []byte) {
	r.log.Printf("ICMPv6 protocol is not supported")
}
