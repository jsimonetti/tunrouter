package router

import (
	"bytes"
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// HandleICMPv4 is the handler for ICMPv4 traffic
// it selects a flowHandler from the FlowTable to handle the traffic
func (r *router) HandleICMPv4(packet gopacket.Packet, wCh chan []byte) {
	ipv4 := packet.NetworkLayer().(*layers.IPv4)
	icmp := packet.Layers()[1].(*layers.ICMPv4)

	// handle icmp to myself
	if bytes.Equal(ipv4.DstIP, r.selfIPv4) {
		go r.icmpSelfHandler(packet, wCh)
		return
	}

	if !r.isPrivileged {
		r.log.Print("icmpv4 received, but disabled; running unpriviledged")
		return
	}

	flowHash := hashOf(ipv4.NetworkFlow().FastHash(), []byte{icmp.TypeCode.Type()}, []byte{icmp.TypeCode.Code()})

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
		go icmpFlowHandler(flowHandler)
	}

	// send the packet to the flow handler
	flowHandler.tunRCh <- packet
}

// icmpSelfHandler is a FlowHandler for handling icmp directed to the router
func (r *router) icmpSelfHandler(packet gopacket.Packet, wCh chan []byte) {

	ipv4 := packet.NetworkLayer().(*layers.IPv4)
	icmp := packet.Layers()[1].(*layers.ICMPv4)

	// only respond to certain types
	if icmp.TypeCode.Type() == layers.ICMPv4TypeEchoRequest {

		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}

		r.log.Printf("handled icmpv4 for self from %s\n", ipv4.SrcIP)

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
		r.log.Printf("ignoring ICMP packet to self of type: %s\n", icmp.TypeCode)
	}
}

// icmpFlowHandler is a FlowHandler for handling transit icmp traffic
func icmpFlowHandler(f *FlowHandler) {
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
			f.router.log.Printf("icmp flow [%s] timed out; src %#v(%s), dst %#v(%s)", f.flowHash, tunSrcIP, tunSrcIP, tunDstIP, tunDstIP)
			return
		case tunData := <-f.tunRCh: // data came in from TUN to this flow
			timeout()

			// unravel the tunData
			ipv4 := tunData.NetworkLayer().(*layers.IPv4)

			// open the remote connection if it was not open yet
			if f.conn == nil {
				tunSrcIP = ipv4.SrcIP
				tunDstIP = ipv4.DstIP

				f.conn, err = net.DialIP("ip4:icmp", &net.IPAddr{IP: f.router.sourceIp}, &net.IPAddr{IP: tunDstIP})
				if err != nil {
					f.router.log.Printf("dial err, %s", err)
					return
				}
			}

			// start a read routine for this connection
			go readNetData(f.conn, netRCh, netECh)

			// write the buffer into the conn
			if _, err := f.conn.Write(ipv4.Payload); err != nil {
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

			// create the forwarding reply
			ipLayer := layers.IPv4{
				Version:  4,
				TTL:      ipv4.TTL - 1,
				TOS:      ipv4.TOS,
				Id:       ipv4.Id,
				SrcIP:    tunDstIP,
				DstIP:    tunSrcIP,
				Protocol: layers.IPProtocolICMPv4,
			}

			// serialize reply into bytes
			err = gopacket.SerializeLayers(f.buf, f.opts, &ipLayer, gopacket.Payload(ipv4.Payload))
			if err != nil {
				f.router.log.Printf("error serializing ICMPv4 packet: %s", err)
				return
			}

			// send bytes to tun interface
			f.tunWch <- f.buf.Bytes()
		case err = <-netECh: // error came in from network to this flow
			f.router.log.Printf("icmp net read error: %s", err)
			return
		}
	}
}
