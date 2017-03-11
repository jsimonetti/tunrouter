package router

import (
	"bytes"
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func (r *router) handleICMPv4(packet gopacket.Packet, wCh chan []byte) {
	ipv4 := packet.NetworkLayer().(*layers.IPv4)

	// handle icmp to myself
	if bytes.Equal(ipv4.DstIP, r.selfIPv4) {
		r.icmpSelfHandler(packet, wCh)
		return
	}

	flowHash := ipv4.NetworkFlow().FastHash()

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

func icmpFlowHandler(f *FlowHandler) {
	defer f.Close()
	var err error

	netRCh := make(chan []byte)
	netECh := make(chan error)

	var ipv4 *layers.IPv4

	for {
		select {
		case tunData := <-f.tunRCh: //data came in from TUN to this flow
			ipv4 = tunData.NetworkLayer().(*layers.IPv4)
			icmp := tunData.Layers()[1].(*layers.ICMPv4)
			f.router.log.Printf("handled icmpv4 for type: %s, src: %s, dst: %s", icmp.TypeCode, ipv4.SrcIP, ipv4.DstIP)

			if f.conn == nil {
				f.conn, err = net.DialIP("ip4:icmp", &net.IPAddr{IP: net.ParseIP("10.10.1.182")}, &net.IPAddr{IP: ipv4.DstIP})
				if err != nil {
					f.router.log.Printf("dial err, %s", err)
					return
				}
			}

			go readNetData(f.conn, netRCh, netECh)

			icmpLayer := layers.ICMPv4{
				TypeCode: icmp.TypeCode,
				Id:       icmp.Id,
				Seq:      icmp.Seq,
			}
			err := gopacket.SerializeLayers(f.buf, f.opts, &icmpLayer, gopacket.Payload(icmp.BaseLayer.Payload))
			if err != nil {
				f.router.log.Printf("error serializing ICMPv4 packet: %s", err)
				return
			}

			if _, err := f.conn.Write(f.buf.Bytes()); err != nil {
				f.router.log.Printf("WriteTo err, %s", err)
				return
			}

			//f.router.log.Print("packet sent to remote connection")
		case netData := <-netRCh: //data came in from network to this flow
			//f.router.log.Print("remote connection data incoming")

			packet := gopacket.NewPacket(netData, layers.LayerTypeIPv4, gopacket.Default)
			if err := packet.ErrorLayer(); err != nil {
				f.router.log.Printf("Error decoding some part of the packet: %s", err)
				return
			}
			ipv42 := packet.Layers()[0].(*layers.IPv4)
			icmp := packet.Layers()[1].(*layers.ICMPv4)

			//create reply
			ipLayer := layers.IPv4{
				Version:  4,
				TTL:      ipv42.TTL - 1,
				TOS:      ipv42.TOS,
				Id:       ipv42.Id,
				SrcIP:    ipv4.DstIP,
				DstIP:    ipv4.SrcIP,
				Protocol: layers.IPProtocolICMPv4,
			}
			icmpLayer2 := layers.ICMPv4{
				TypeCode: icmp.TypeCode,
				Id:       icmp.Id,
				Seq:      icmp.Seq,
			}

			//buf := gopacket.NewSerializeBuffer()
			//opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
			// serialize reply into bytes
			err = gopacket.SerializeLayers(f.buf, f.opts, &ipLayer, &icmpLayer2, gopacket.Payload(icmp.BaseLayer.Payload))
			if err != nil {
				f.router.log.Printf("error serializing ICMPv4 packet: %s", err)
				return
			}

			// send bytes to tun interface
			f.tunWch <- f.buf.Bytes()

		case err = <-netECh: //error came in from network to this flow
			f.router.log.Printf("icmp net read error: %s", err)
			return
		}
	}
}

func icmpFlowHandler2(f *FlowHandler) {
	defer f.Close()

	select {
	case packet := <-f.tunRCh: // new packet incoming for this flowTable

		ipv4 := packet.NetworkLayer().(*layers.IPv4)
		icmp := packet.Layers()[1].(*layers.ICMPv4)
		f.router.log.Printf("handled icmpv4 for src: %s", ipv4.SrcIP)

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

		break
	}
}
