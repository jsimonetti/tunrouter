package router

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func (r *router) handleTCP(packet gopacket.Packet, wCh chan []byte) {
	ipv4 := packet.NetworkLayer().(*layers.IPv4)

	flowHash := ipv4.NetworkFlow().FastHash()

	var flowHandler *FlowHandler

	// check if an existing flowHandler is allread in the flowTable.
	if flowHandler, err := r.flowTable.Get(flowHash); err != nil {
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

		go TCPFlowHandler(flowHandler)
	}

	flowHandler.tunRCh <- packet
}

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

func TCPFlowHandler(f *FlowHandler) {
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

func TCPFlowHandler2(tunRCh chan []byte, tunWCh chan []byte) {
	netRCh := make(chan []byte)
	netECh := make(chan error)

	var conn net.Conn

	go func(netRCh chan []byte, netECh chan error) {
		for {
			// try to read the data
			netData := make([]byte, 512)
			_, err := conn.Read(netData)
			if err != nil {
				// send an error if it's encountered
				netECh <- err
				return
			}
			// send data if we read some.
			netRCh <- netData
		}
	}(netRCh, netECh)

	select {
	case tunData := <-tunRCh: //data came in from TUN to this flow
		// intermediate steps needed
		conn.Write(tunData)
	case netData := <-netRCh: //data came in from network to this flow
		// intermediate steps needed
		tunWCh <- netData
	case _ = <-netECh: //error came in from network to this flow
		close(tunRCh)
	}
}
