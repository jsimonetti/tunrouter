package router

import (
	"bytes"
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func (r *router) handleICMPv4(packet gopacket.Packet, wCh chan []byte) {
	ipv4 := packet.NetworkLayer().(*layers.IPv4)

	// handle icmp to myself
	if bytes.Equal(ipv4.DstIP, r.selfIPv4) {
		ICMPSelfHandler(packet, wCh, r.log)
		return
	}

	flowHash := ipv4.NetworkFlow().FastHash()

	var err error
	var flowHandler *FlowHandler

	// check if an existing flowHandler is allread in the flowTable.
	if flowHandler, err = flowTable.Get(flowHash); err != nil {
		if err != errNoSuchFlow {
			r.log.Print("error getting existing flow handler: %s", err)
			return
		}
		if flowHandler = flowTable.New(flowHash); flowHandler == nil {
			r.log.Print("error getting new flow handler")
			return
		}

		//new flowHandler created, setup the write channel, logger
		flowHandler.tunWch = wCh
		flowHandler.log = r.log

		// start an ICMP flow handler routine for this flow
		go ICMPFlowHandler(flowHandler)
	}

	// send the packet to the flow handler
	flowHandler.tunRCh <- packet
}

func ICMPSelfHandler(packet gopacket.Packet, wCh chan []byte, log *log.Logger) {

	ipv4 := packet.NetworkLayer().(*layers.IPv4)
	icmp := packet.Layers()[1].(*layers.ICMPv4)

	// only respond to certain types
	if icmp.TypeCode.Type() == layers.ICMPv4TypeEchoRequest {

		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}

		log.Printf("handled icmpv4 for self from %s\n", ipv4.SrcIP)

		//create reply
		ipLayer := layers.IPv4{
			Version:  4,
			TTL:      64,
			TOS:      ipv4.TOS,
			Id:       ipv4.Id,
			SrcIP:    ipv4.DstIP,
			DstIP:    ipv4.SrcIP,
			Protocol: layers.IPProtocolICMPv4,
		}
		icmpLayer := layers.ICMPv4{
			TypeCode: layers.ICMPv4TypeEchoReply,
			Id:       icmp.Id,
			Seq:      icmp.Seq,
		}

		// serialize reply into bytes
		err := gopacket.SerializeLayers(buf, opts, &ipLayer, &icmpLayer, gopacket.Payload(icmp.BaseLayer.Payload))
		if err != nil {
			panic(fmt.Sprintf("error serializing ICMPv4 packet: %s", err))
		}

		// send bytes to tun interface
		wCh <- buf.Bytes()
	} else {
		// silently ignore the rest
		log.Printf("ignoring ICMP packet to self of type: %s\n", icmp.TypeCode)
	}
}

func ICMPFlowHandler(f *FlowHandler) {

	select {
	case packet := <-f.tunRCh: // new packet incoming for this flowTable

		ipv4 := packet.NetworkLayer().(*layers.IPv4)

		icmp := packet.Layers()[1].(*layers.ICMPv4)
		f.log.Printf("handled icmpv4 for src: %s", ipv4.SrcIP)

		//return reply
		ipLayer := layers.IPv4{
			Version:  4,
			TTL:      64,
			TOS:      ipv4.TOS,
			Id:       ipv4.Id,
			SrcIP:    ipv4.DstIP,
			DstIP:    ipv4.SrcIP,
			Protocol: layers.IPProtocolICMPv4,
		}
		icmpLayer := layers.ICMPv4{
			TypeCode: layers.ICMPv4TypeEchoReply,
			Id:       icmp.Id,
			Seq:      icmp.Seq,
		}

		err := gopacket.SerializeLayers(f.buf, f.opts, &ipLayer, &icmpLayer, gopacket.Payload(icmp.BaseLayer.Payload))
		if err != nil {
			panic(fmt.Sprintf("error serializing ICMPv4 packet: %s", err))
		}

		f.tunWch <- f.buf.Bytes()

		f.Close()
	}
}
