package router

import (
	"bytes"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// HandleTCP4 is the handler for TCP traffic
// it selects a flowHandler from the FlowTable to handle the traffic
func (r *router) HandleTCP4(packet gopacket.Packet, wCh chan []byte) {
	var err error
	ipv4 := packet.NetworkLayer().(*layers.IPv4)

	// handle tcp to myself
	if bytes.Equal(ipv4.DstIP, r.selfIPv4) {
		go r.tcp4SelfHandler(packet, wCh)
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

		go tcp4FlowHandler(flowHandler)
	}

	if !flowHandler.dialing {
		flowHandler.tunRCh <- packet
	}
}

// tcp4SelfHandler is a FlowHandler for handling tcp directed to the router
func (r *router) tcp4SelfHandler(packet gopacket.Packet, wCh chan []byte) {

	ipv4 := packet.NetworkLayer().(*layers.IPv4)
	tcp := packet.Layers()[1].(*layers.TCP)

	ipLayer, tcpLayer := tcp4Rst(ipv4, tcp)

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

// tcp4Rst return the IP and TCP layers for a tcp RST of the specified layers
func tcp4Rst(ipv4 *layers.IPv4, tcp *layers.TCP) (ipLayer layers.IPv4, tcpLayer layers.TCP) {
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

// tcp4FlowHandler is a FlowHandler for handling transit tcp traffic
func tcp4FlowHandler(f *FlowHandler) {
	defer f.Close()
	var err error

	// channels to use for the readRoutine
	netRCh := make(chan []byte)
	netECh := make(chan error)

	// globally save the original tunnel source and destination ip's for further use
	var tunSrcIP net.IP
	var tunDstIP net.IP
	var tunSrcPort int
	var netSrcPort int

	// shorthand to reset the timeout
	timeout := func() { f.ResetTimeOut(30 * time.Second) }

	for {
	START:
		select {
		case <-f.timeout: // a timeout happend
			f.router.log.Printf("tcp flow [%s] timed out; src %#v(%s), dst %#v(%s)", f.flowHash, tunSrcIP, tunSrcIP, tunDstIP, tunDstIP)
			return
		case tunData := <-f.tunRCh: // data came in from TUN to this flow
			timeout()

			// if this flow is not done clientside, finish the handshake
			if f.handShaking {
				finishTcp4Handshake(f, tunData)
				goto START
			}

			// unravel the tunData
			ipv4 := tunData.NetworkLayer().(*layers.IPv4)
			tcp := tunData.Layers()[1].(*layers.TCP)

			// open the remote connection if it was not open yet
			if f.conn == nil {
				f.Dialing(true)
				tunSrcIP = ipv4.SrcIP
				tunDstIP = ipv4.DstIP

				f.conn, err = net.DialTCP("tcp4",
					&net.TCPAddr{
						IP:   f.router.sourceIp,
						Port: 0,
					},
					&net.TCPAddr{
						IP:   tunDstIP,
						Port: int(tcp.DstPort),
					},
				)
				if err != nil {
					f.router.log.Printf("upstream connection failed: %s", err)
					f.conn = nil
					return
				}
				// save the ports used in this flow
				tunSrcPort = int(tcp.SrcPort)
				_, port, _ := net.SplitHostPort(f.conn.LocalAddr().String())
				netSrcPort, _ = strconv.Atoi(port)

				// start a read routine for this connection
				go readNetData(f.conn, netRCh, netECh)

				// finish dialing and start handshake clientside
				f.Dialing(false)
				f.Handshake(true)
				finishTcp4Handshake(f, tunData)
				goto START
			}

			// start a read routine for this connection
			go readNetData(f.conn, netRCh, netECh)

			// create the forwarding reply
			ipLayer := layers.IPv4{
				Version:    4,
				TTL:        ipv4.TTL - 1,
				TOS:        ipv4.TOS,
				Id:         ipv4.Id,
				SrcIP:      f.router.sourceIp,
				DstIP:      ipv4.DstIP,
				Protocol:   layers.IPProtocolTCP,
				Flags:      ipv4.Flags,
				FragOffset: ipv4.FragOffset,
				Options:    ipv4.Options,
			}

			// build the forwarding layer
			tcpLayer := layers.TCP{
				SrcPort:    layers.TCPPort(netSrcPort),
				DstPort:    tcp.DstPort,
				Seq:        tcp.Seq,
				Ack:        tcp.Ack,
				DataOffset: tcp.DataOffset,
				Window:     tcp.Window,
				Urgent:     tcp.Urgent,
				Options:    tcp.Options,
				FIN:        tcp.FIN,
				SYN:        tcp.SYN,
				RST:        tcp.RST,
				PSH:        tcp.PSH,
				ACK:        tcp.ACK,
				URG:        tcp.URG,
				ECE:        tcp.ECE,
				CWR:        tcp.CWR,
				NS:         tcp.NS,
			}

			tcpLayer.SetNetworkLayerForChecksum(&ipLayer)

			// serialize the layer into a buffer
			err := gopacket.SerializeLayers(f.buf, f.opts, &tcpLayer, gopacket.Payload(tcp.BaseLayer.Payload))
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
				f.router.log.Printf("Error decoding some part of the net packet: %s", err)
				return
			}

			// unravel the layers
			ipv4 := packet.Layers()[0].(*layers.IPv4)
			tcp := packet.Layers()[1].(*layers.TCP)

			// create the forwarding reply
			ipLayer := layers.IPv4{
				Version:    4,
				TTL:        ipv4.TTL - 1,
				TOS:        ipv4.TOS,
				Id:         ipv4.Id,
				SrcIP:      tunDstIP,
				DstIP:      tunSrcIP,
				Protocol:   layers.IPProtocolTCP,
				Flags:      ipv4.Flags,
				FragOffset: ipv4.FragOffset,
				Options:    ipv4.Options,
			}

			// build the forwarding layer
			tcpLayer := layers.TCP{
				SrcPort:    tcp.SrcPort,
				DstPort:    layers.TCPPort(tunSrcPort),
				Seq:        tcp.Seq,
				Ack:        tcp.Ack,
				DataOffset: tcp.DataOffset,
				Window:     tcp.Window,
				Urgent:     tcp.Urgent,
				Options:    tcp.Options,
				FIN:        tcp.FIN,
				SYN:        tcp.SYN,
				RST:        tcp.RST,
				PSH:        tcp.PSH,
				ACK:        tcp.ACK,
				URG:        tcp.URG,
				ECE:        tcp.ECE,
				CWR:        tcp.CWR,
				NS:         tcp.NS,
			}

			tcpLayer.SetNetworkLayerForChecksum(&ipLayer)

			// serialize reply into bytes
			err = gopacket.SerializeLayers(f.buf, f.opts, &ipLayer, &tcpLayer, gopacket.Payload(tcp.BaseLayer.Payload))
			if err != nil {
				f.router.log.Printf("error serializing TCP packet: %s", err)
				return
			}

			// send bytes to tun interface
			f.tunWch <- f.buf.Bytes()
		case err = <-netECh: // error came in from network to this flow
			f.router.log.Printf("tcp net read error: %s", err)
			return
		}
	}
}

func finishTcp4Handshake(f *FlowHandler, tunData gopacket.Packet) {
	// unravel the tunData
	ipv4 := tunData.NetworkLayer().(*layers.IPv4)
	tcp := tunData.Layers()[1].(*layers.TCP)

	if tcp.SYN && !tcp.ACK { // first part of handshake
		//send syn+ack

		ipLayer := layers.IPv4{
			Version:  4,
			TTL:      64,
			TOS:      ipv4.TOS,
			Id:       ipv4.Id,
			SrcIP:    ipv4.DstIP,
			DstIP:    ipv4.SrcIP,
			Protocol: layers.IPProtocolTCP,
		}

		tcpLayer := layers.TCP{
			SrcPort: tcp.DstPort,
			DstPort: tcp.SrcPort,
			Seq:     tcp.Seq,
			Ack:     tcp.Seq + 1,
			ACK:     true,
			SYN:     true,
			Window:  0x7210,
			Options: tcp.Options,
			/* []layers.TCPOption{
				layers.TCPOption{
					OptionType:   layers.TCPOptionKindMSS,
					OptionLength: 2,
					OptionData:   []byte{0x05, 0xb4}, // default of 1460
				},
				layers.TCPOption{
					OptionType:   layers.TCPOptionKindWindowScale,
					OptionLength: 1,
					OptionData:   []byte{0x02}, // 4 (multiplied by2)
				},
				layers.TCPOption{
					OptionType:   layers.TCPOptionKindSACKPermitted,
					OptionLength: 1,
					OptionData:   []byte{0x01}, // yes
				},
			},*/
		}

		tcpLayer.SetNetworkLayerForChecksum(&ipLayer)

		err := gopacket.SerializeLayers(f.buf, f.opts, &ipLayer, &tcpLayer)
		if err != nil {
			panic(fmt.Sprintf("error serializing ICMPv4 packet: %s", err))
		}

		f.router.log.Printf("sending ACK to client %s:%s", ipv4.SrcIP, tcp.SrcPort)
		f.tunWch <- f.buf.Bytes()
		return
	}

	//	if !tcp.SYN && tcp.ACK {
	f.router.log.Printf("finished handshake with client %s:%s", ipv4.SrcIP, tcp.SrcPort)
	f.handShaking = false
	//	}
}
