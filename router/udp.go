package router

import (
	"bytes"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// HandleUDP4 is the handler for UDP traffic
// it selects a flowHandler from the FlowTable to handle the traffic
func (r *router) HandleUDP4(packet gopacket.Packet, wCh chan []byte) {
	ipv4 := packet.NetworkLayer().(*layers.IPv4)

	// handle udp to myself
	if bytes.Equal(ipv4.DstIP, r.selfIPv4) {
		go r.udp4SelfHandler(packet, wCh)
		return
	}

	if !r.isPrivileged {
		r.log.Print("udp received, but disabled; running unpriviledged")
		return
	}

	flowHash := hashOf(ipv4.NetworkFlow().FastHash(), packet.TransportLayer().TransportFlow().Dst().Raw(), packet.TransportLayer().TransportFlow().Src().Raw())

	var err error
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

		//new flowHandler created, setup the write channel, logger
		flowHandler.tunWch = wCh
		flowHandler.router = r

		// start an ICMP flow handler routine for this flow
		go udp4FlowHandler(flowHandler)
	}

	// send the packet to the flow handler
	flowHandler.tunRCh <- packet
}

// udp4SelfHandler is a FlowHandler for handling udp directed to the router
func (r *router) udp4SelfHandler(packet gopacket.Packet, wCh chan []byte) {
	// silently ignore UDP to self
	r.log.Print("ignoring UDP packet to self")
}

// udp4FlowHandler is a FlowHandler for handling transit udp traffic
func udp4FlowHandler(f *FlowHandler) {
	defer f.Close()
	var err error

	// channels to use for the readRoutine
	netRCh := make(chan []byte)
	netECh := make(chan error)

	// globally save the original tunnel source and destination ip's for further use
	var tunSrcIP net.IP
	var tunDstIP net.IP

	// shorthand to reset the timeout
	timeout := func() { f.ResetTimeOut(5 * time.Second) }

	for {
		select {
		case <-f.timeout: // a timeout happend
			f.router.log.Printf("udp flow [%s] timed out; src %#v(%s), dst %#v(%s)", f.flowHash, tunSrcIP, tunSrcIP, tunDstIP, tunDstIP)
			return
		case tunData := <-f.tunRCh: // data came in from TUN to this flow
			timeout()

			// unravel the tunData
			ipv4 := tunData.NetworkLayer().(*layers.IPv4)
			udp := tunData.Layers()[1].(*layers.UDP)

			// open the remote connection if it was not open yet
			if f.conn == nil {
				tunSrcIP = ipv4.SrcIP
				tunDstIP = ipv4.DstIP

				f.conn, err = net.DialIP("ip:udp", &net.IPAddr{IP: f.router.sourceIp}, &net.IPAddr{IP: tunDstIP})
				if err != nil {
					f.router.log.Printf("dial err, %s", err)
					return
				}
				// start a read routine for this connection
				go readNetData(f.conn, netRCh, netECh)
			}

			ipLayer := layers.IPv4{
				SrcIP:    f.router.sourceIp,
				DstIP:    ipv4.DstIP,
				Protocol: ipv4.Protocol,
			}

			// build the forwarding layer
			udpLayer := layers.UDP{
				SrcPort: udp.SrcPort,
				DstPort: udp.DstPort,
				Length:  udp.Length,
			}
			udpLayer.SetNetworkLayerForChecksum(&ipLayer)

			// serialize the layer into a buffer
			err := gopacket.SerializeLayers(f.buf, f.opts, &udpLayer, gopacket.Payload(udp.BaseLayer.Payload))
			if err != nil {
				f.router.log.Printf("error serializing ICMPv4 packet: %s", err)
				return
			}

			// write the buffer into the conn
			if _, err := f.conn.Write(f.buf.Bytes()); err != nil {
				f.router.log.Printf("WriteTo err, %s", err)
				return
			}
		case netData := <-netRCh: // data came in from network to this flow
			timeout()

			// unmarshal data from the network into a packet
			packet := gopacket.NewPacket(netData, layers.LayerTypeIPv4, gopacket.Default)
			if err := packet.ErrorLayer(); err != nil {
				f.router.log.Printf("Error decoding some part of the packet: %s", err)
				return
			}

			// unravel the layers
			ipv4 := packet.Layers()[0].(*layers.IPv4)
			udp := packet.Layers()[1].(*layers.UDP)

			// create the forwarding reply
			ipLayer := layers.IPv4{
				Version:  4,
				TTL:      ipv4.TTL - 1,
				TOS:      ipv4.TOS,
				Id:       ipv4.Id,
				SrcIP:    tunDstIP,
				DstIP:    tunSrcIP,
				Protocol: layers.IPProtocolUDP,
			}

			// build the forwarding layer
			udpLayer := layers.UDP{
				SrcPort: udp.SrcPort,
				DstPort: udp.DstPort,
				Length:  udp.Length,
			}
			udpLayer.SetNetworkLayerForChecksum(&ipLayer)

			// serialize reply into bytes
			err = gopacket.SerializeLayers(f.buf, f.opts, &ipLayer, &udpLayer, gopacket.Payload(udp.BaseLayer.Payload))
			if err != nil {
				f.router.log.Printf("error serializing UDP packet: %s", err)
				return
			}

			// send bytes to tun interface
			f.tunWch <- f.buf.Bytes()
		case err = <-netECh: // error came in from network to this flow
			f.router.log.Printf("udp net read error: %s", err)
			return
		}
	}
}
