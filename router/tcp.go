package router

import (
	"bytes"
	"fmt"
	"math/rand"
	"net"
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

	flowHash := hashOf(ipv4.NetworkFlow().FastHash(), packet.TransportLayer().TransportFlow().Dst().Raw(), packet.TransportLayer().TransportFlow().Src().Raw())

	var flowHandler *Flow

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

		go startTCP4FlowHandler(flowHandler)
	}

	//	if !flowHandler.dialing {
	flowHandler.tunRCh <- packet
	//	}
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

func newTCP4FlowHandler(f *Flow) *tcp4FlowHandler {
	return &tcp4FlowHandler{
		Flow: f,
		FSM:  newTCP4FSM(f),
	}
}

type tcp4FlowHandler struct {
	*Flow

	exit chan bool

	FSM *tcp4FSM
}

func (t *tcp4FlowHandler) dialUpstream() (err error) {
	dst := fmt.Sprintf("%s:%d", t.FSM.dstIp, int(t.FSM.dstPort))

	tcpAddr := &net.TCPAddr{
		IP: t.Flow.router.sourceIp,
	}

	dialer := net.Dialer{
		Timeout:   1 * time.Second,
		LocalAddr: tcpAddr,
	}

	t.conn, err = dialer.Dial("tcp4", dst)
	return
}

func (t *tcp4FlowHandler) Close() {
	t.FSM.Close()
	t.Flow.Close()
	if t.conn != nil {
		defer t.conn.Close()
	}
	t.log("tcp flow closed")
	t.exit <- true
}

func (t *tcp4FlowHandler) log(format string, params ...interface{}) {
	info := fmt.Sprintf("[%d][%s] [%s:%d]-[%s:%d] [%s] ", t.FSM.id, t.Flow.hash, t.FSM.srcIp, t.FSM.srcPort, t.FSM.dstIp, t.FSM.dstPort, t.FSM.State())
	t.Flow.router.log.Printf(info+format, params...)
}

func (t *tcp4FlowHandler) Start() {
	// shorthand to reset the timeout
	timeout := func() { t.Flow.ResetTimeOut(30 * time.Second) }
	netRCh := make(chan l3Payload)
	ticker := time.NewTicker(time.Millisecond * 1)
	sendTicker := make(chan bool)

	for {
		select {
		case <-t.exit: // exit signal
			return
		case <-t.Flow.timeout: // a timeout happend
			t.log("tcp flow timed out")
			//t.Teardown()
			return
		case tunData := <-t.Flow.tunRCh:
			timeout()

			// unravel the tunData
			var ok bool
			var ipv4 *layers.IPv4
			if ipv4, ok = tunData.NetworkLayer().(*layers.IPv4); !ok {
				// not a tcp packet, drop
				t.log("received a non-ipv4 packet %#v", tunData.NetworkLayer())
				break
			}
			var tcp *layers.TCP
			if tcp, ok = tunData.TransportLayer().(*layers.TCP); !ok {
				// not a tcp packet, drop
				t.log("received a non-tcp packet %#v", tunData.TransportLayer())
				break
			}
			if t.FSM.State() == stateListen {
				t.FSM.srcIp = ipv4.SrcIP
				t.FSM.dstIp = ipv4.DstIP
			}
			prevState := t.FSM.State()
			state := t.FSM.tcpFSM(tcp)

			if state == stateClosed {
				return
			}

			if state == stateSynReceived { // open upstream before continueing

				err := t.dialUpstream()
				if err != nil {
					t.log("upstream connection failed: %s", err)
					t.FSM.RST()
					t.Close()
					return
					//break
				}
				go readNetData2(t.conn, netRCh)
				t.FSM.ACK([]tcpFlag{flagSYN}, nil) // send this here since we don't in the FSM
				break
			}

			if state != stateEstablished || prevState != stateEstablished {
				// packet is part of setup or teardown of connection
				// don't do anything with it, as this is done in the tcpFSM
				break
			}

			// received data packet
			if len(tcp.BaseLayer.Payload) > 0 {
				//t.Flow.router.log.Printf("received payload in state: %s, %s", t.state.String(), spew.Sdump(tcp.BaseLayer.Payload))

				t.FSM.Recv(tcp.BaseLayer.Payload, tcp.PSH)
				break
			}

			//we should never get here
			t.log("received unhandled packet: %v", flagsFromTcpLayer(tcp))
			//t.log("received bad tcp packet %#v, state: %s", tcp, t.state.String())
		case netData := <-netRCh:
			if netData.err != nil {
				t.log("error receive data from net %#v", netData.err)
				t.FSM.Teardown()
			}
			//t.FSM.sendLock.Lock()
			//t.sendBuffer = append(t.sendBuffer, netData.payload...)
			//t.FSM.sendLock.Unlock()

			t.FSM.Send(netData.payload)
		case <-ticker.C:
			t.FSM.sendSendBuffer(sendTicker)
		case <-sendTicker:
			t.FSM.sendSendBuffer(sendTicker)
		}
	}
}

// startTCP4FlowHandler is a FlowHandler for handling transit tcp traffic
func startTCP4FlowHandler(f *Flow) {
	f.router.log.Printf("started flow [%s]", f.hash)
	defer f.Close()
	t := newTCP4FlowHandler(f)
	rnd := rand.NewSource(time.Now().UnixNano())

	t.FSM.IncrSequence(uint32(rnd.Int63()))
	t.FSM.id = uint16(rnd.Int63())
	t.FSM.SetState(stateListen)
	t.FSM.log = t.log

	//	var wg sync.WaitGroup
	//	wg.Add(1)
	//	go func() {
	t.Start()
	//		wg.Done()
	//	}()
	//	wg.Wait()
}
