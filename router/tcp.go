package router

import (
	"bytes"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// HandleTCP is the handler for TCP traffic
// it selects a flowHandler from the FlowTable to handle the traffic
func (r *router) HandleTCP(packet gopacket.Packet, wCh chan []byte) {
	var err error
	ipv4 := packet.NetworkLayer().(*layers.IPv4)

	// handle tcp to myself
	if bytes.Equal(ipv4.DstIP, r.selfIPv4) {
		go r.tcpSelfHandler(packet, wCh)
		return
	}

	if !r.isPrivileged {
		r.log.Print("tcp received, but disabled; running unpriviledged")
		return
	}

	flowHash := hashOf(ipv4.NetworkFlow().FastHash(), packet.TransportLayer().TransportFlow().Dst().Raw(), packet.TransportLayer().TransportFlow().Src().Raw())

	var flowHandler *FlowHandler

	// check if an existing flowHandler is allread in the flowTable.
	if flowHandler, err = r.flowTable.Get(flowHash); err != nil {
		if err != errNoSuchFlow {
			r.log.Print("error getting existing flow handler: %s", err)
			return
		}
		if flowHandler = r.flowTable.New(flowHash); flowHandler == nil {
			r.log.Print("error getting new flow handler")
			return
		}
		flowHandler.tunWch = wCh
		flowHandler.router = r

		go tcpFlowHandler(flowHandler)
	}

	flowHandler.tunRCh <- packet
}

// tcpSelfHandler is a FlowHandler for handling tcp directed to the router
func (r *router) tcpSelfHandler(packet gopacket.Packet, wCh chan []byte) {

	ipv4 := packet.NetworkLayer().(*layers.IPv4)
	tcp := packet.Layers()[1].(*layers.TCP)

	ipLayer, tcpLayer := tcpRst(ipv4, tcp)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err := gopacket.SerializeLayers(buf, opts, &ipLayer, &tcpLayer)
	if err != nil {
		panic(fmt.Sprintf("error serializing ICMPv4 packet: %s", err))
	}

	r.log.Print("ignoring TCP packet to self, sending RST")

	wCh <- buf.Bytes()
}

// tcpRst return the IP and TCP layers for a tcp RST of the specified layers
func tcpRst(ipv4 *layers.IPv4, tcp *layers.TCP) (ipLayer layers.IPv4, tcpLayer layers.TCP) {
	ipLayer = layers.IPv4{
		Version:  4,
		TTL:      64,
		TOS:      ipv4.TOS,
		Id:       ipv4.Id,
		SrcIP:    ipv4.DstIP,
		DstIP:    ipv4.SrcIP,
		Protocol: layers.IPProtocolTCP,
	}

	tcpLayer = layers.TCP{
		SrcPort: tcp.DstPort,
		DstPort: tcp.SrcPort,
		RST:     true,
		ACK:     true,
		Seq:     tcp.Seq,
		Ack:     tcp.Seq + 1,
		Window:  0,
	}
	tcpLayer.SetNetworkLayerForChecksum(&ipLayer)

	return
}

// tcpFlowHandler is a FlowHandler for handling transit tcp traffic
func tcpFlowHandler(f *FlowHandler) {
	defer f.Close()

	select {
	case packet := <-f.tunRCh: // new packet incoming for this flowTable

		ipv4 := packet.NetworkLayer().(*layers.IPv4)
		tcp := packet.Layers()[1].(*layers.TCP)

		ipLayer, tcpLayer := tcpRst(ipv4, tcp)
		err := gopacket.SerializeLayers(f.buf, f.opts, &ipLayer, &tcpLayer)
		if err != nil {
			panic(fmt.Sprintf("error serializing ICMPv4 packet: %s", err))
		}

		f.router.log.Print("sending RST")

		f.tunWch <- f.buf.Bytes()
		break
	}
}
