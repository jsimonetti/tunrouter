package router

import (
	"bytes"
	"fmt"
	"net"
	"sync"
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

type tcpFlag uint8

const (
	_ tcpFlag = iota
	flagFIN
	flagSYN
	flagRST
	flagPSH
	flagACK
	flagURG
	flagECE
	flagCWR
	flagNS
)

type tcpState uint8

const (
	stateListen tcpState = iota
	stateSynReceived
	stateSynSent
	stateEstablished
	stateLastAck
	stateFinWait1
	stateClosed
)

func flagsFromTcpLayer(tcp *layers.TCP) tcpFlags {
	flags := make(tcpFlags)
	if tcp.ACK {
		flags[flagACK] = true
	}
	if tcp.CWR {
		flags[flagCWR] = true
	}
	if tcp.ECE {
		flags[flagECE] = true
	}
	if tcp.FIN {
		flags[flagFIN] = true
	}
	if tcp.NS {
		flags[flagNS] = true
	}
	if tcp.PSH {
		flags[flagPSH] = true
	}
	if tcp.RST {
		flags[flagRST] = true
	}
	if tcp.URG {
		flags[flagURG] = true
	}
	if tcp.SYN {
		flags[flagSYN] = true
	}
	return flags
}

type tcpFlags map[tcpFlag]bool

func newTCP4FlowHandler(f *FlowHandler) *tcp4FlowHandler {
	return &tcp4FlowHandler{
		FlowHandler: f,
		state:       stateClosed,
		sequence:    0,
	}
}

type tcp4FlowHandler struct {
	*FlowHandler

	srcIp   net.IP
	dstIp   net.IP
	srcPort uint16
	dstPort uint16

	lock       sync.Mutex
	recvBuffer []byte
	sendBuffer []byte

	state tcpState

	sequence    uint32 // my sequence number
	lastAckSent uint32 // last client seq nr i acked

	conn net.Conn // upstream connection
}

func (t *tcp4FlowHandler) sendSendBuffer(myTicker chan bool) {
	t.lock.Lock()
	defer t.lock.Unlock()

	l := len(t.sendBuffer)
	if l > 0 {
		if l > 1460 {
			t.Send(t.sendBuffer[:1460])
			t.sendBuffer = t.sendBuffer[1460:]

			// imediate tick again to continue sending the buffer
			myTicker <- true
			return
		}
		t.Send(t.sendBuffer)
		t.sendBuffer = []byte{}
	}
}

func (t *tcp4FlowHandler) flushRecvBuffer() {
	///t.FlowHandler.router.log.Printf("flushing recvBuffer now")
	t.lock.Lock()
	defer t.lock.Unlock()

	_, err := t.conn.Write(t.recvBuffer)
	t.recvBuffer = []byte{}
	if err != nil {
		t.FlowHandler.router.log.Printf("error flushing recvBuffer: %s", err)
		t.Close()
	}
}

func (t *tcp4FlowHandler) dialUpstream() (err error) {
	dst := fmt.Sprintf("%s:%d", t.dstIp, int(t.dstPort))

	tcpAddr := &net.TCPAddr{
		IP: t.FlowHandler.router.sourceIp,
	}

	dialer := net.Dialer{
		Timeout:   1 * time.Second,
		LocalAddr: tcpAddr,
	}

	t.conn, err = dialer.Dial("tcp4", dst)
	return
}

func (t *tcp4FlowHandler) buildPacket() (layers.IPv4, layers.TCP) {
	// create the ip layer
	ipLayer := layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    t.dstIp,
		DstIP:    t.srcIp,
		Protocol: layers.IPProtocolTCP,
	}

	// create the tcp layer
	tcpLayer := layers.TCP{
		SrcPort: layers.TCPPort(t.dstPort),
		DstPort: layers.TCPPort(t.srcPort),
		Seq:     t.sequence,
		Ack:     t.lastAckSent,
		Window:  0x1000,
	}
	tcpLayer.SetNetworkLayerForChecksum(&ipLayer)
	return ipLayer, tcpLayer
}

// send should be the function every outbound packet goes through
func (t *tcp4FlowHandler) send(flags []tcpFlag, payload gopacket.Payload) {
	// every packet we send should go through here.
	ipLayer, tcpLayer := t.buildPacket()

	for _, f := range flags {
		switch f {
		case flagACK:
			tcpLayer.ACK = true
		case flagCWR:
			tcpLayer.CWR = true
		case flagECE:
			tcpLayer.ECE = true
		case flagFIN:
			tcpLayer.FIN = true
		case flagNS:
			tcpLayer.NS = true
		case flagPSH:
			tcpLayer.PSH = true
		case flagRST:
			tcpLayer.RST = true
		case flagURG:
			tcpLayer.URG = true
		case flagSYN:
			tcpLayer.SYN = true
		}
	}

	// serialize reply into bytes
	err := gopacket.SerializeLayers(t.FlowHandler.buf, t.FlowHandler.opts, &ipLayer, &tcpLayer, payload)
	if err != nil {
		t.FlowHandler.router.log.Printf("error serializing TCP packet for _send: %s", err)
		return
	}

	t.FlowHandler.tunWch <- t.FlowHandler.buf.Bytes()

	if len(payload) > 0 {
		t.sequence += uint32(len(payload))
	}
}

func (t *tcp4FlowHandler) sendSyn() {
	t.state = stateSynSent
	t.send([]tcpFlag{flagSYN}, nil)
}

func (t *tcp4FlowHandler) sendAck(flags []tcpFlag, data []byte) {
	t.send(append(flags, flagACK), data)
}

func (t *tcp4FlowHandler) Close() {
	if t.state != stateClosed {
		t.state = stateFinWait1
		t.sendAck([]tcpFlag{flagFIN}, nil)
	}
}

func (t *tcp4FlowHandler) nextSequence(tcp *layers.TCP) uint32 {
	flags := flagsFromTcpLayer(tcp)

	if len(tcp.Payload) > 0 {
		return tcp.Seq + uint32(len(tcp.Payload))
	}
	if _, ok := flags[flagSYN]; ok {
		return tcp.Seq + 1
	}
	if _, ok := flags[flagFIN]; ok {
		return tcp.Seq + 1
	}
	return t.sequence
}

func (t *tcp4FlowHandler) close() {
	t.state = stateClosed
	t.FlowHandler.Close()
}

func (t *tcp4FlowHandler) Send(data []byte) {
	for {
		if t.state == stateEstablished {
			break
		}
		time.Sleep(10 * time.Nanosecond)
	}
	t.sendAck([]tcpFlag{flagPSH}, data)
}

func (t *tcp4FlowHandler) Start() {
	// shorthand to reset the timeout
	timeout := func() { t.FlowHandler.ResetTimeOut(30 * time.Second) }
	netRCh := make(chan l3Payload)
	ticker := time.NewTicker(time.Millisecond * 1)
	sendTicker := make(chan bool)

	for {
		select {
		case <-t.FlowHandler.timeout: // a timeout happend
			t.FlowHandler.router.log.Printf("tcp flow [%s] timed out; src %s:%d, dst %s:%d", t.FlowHandler.flowHash, t.srcIp, t.srcPort, t.dstIp, t.dstPort)
			t.Close()
			return
		case tunData := <-t.FlowHandler.tunRCh:
			timeout()

			// unravel the tunData
			var ok bool
			var ipv4 *layers.IPv4
			if ipv4, ok = tunData.NetworkLayer().(*layers.IPv4); !ok {
				// not a tcp packet, drop
				t.FlowHandler.router.log.Printf("received a non-ipv4 packet %#v", tunData.NetworkLayer())
				break
			}
			var tcp *layers.TCP
			if tcp, ok = tunData.TransportLayer().(*layers.TCP); !ok {
				// not a tcp packet, drop
				t.FlowHandler.router.log.Printf("received a non-tcp packet %#v", tunData.TransportLayer())
				break
			}
			t.srcIp = ipv4.SrcIP
			t.dstIp = ipv4.DstIP
			t.srcPort = uint16(tcp.SrcPort)
			t.dstPort = uint16(tcp.DstPort)

			if t.state != stateListen {
				if t.lastAckSent != tcp.Seq {
					// we're not in a place to receive this packet. drop it.
					t.FlowHandler.router.log.Printf("out of order packet received %#v", tcp)
					break
				}
			}
			if t.nextSequence(tcp) > t.lastAckSent {
				t.lastAckSent = t.nextSequence(tcp)
			}

			recvFlags := flagsFromTcpLayer(tcp)

			// received data packet
			if len(tcp.Payload) > 0 {
				t.recvBuffer = append(t.recvBuffer, tcp.Payload...)
				if _, ok := recvFlags[flagPSH]; ok {
					// received push flag, should forward and flush buffer now
					t.flushRecvBuffer()
				}
				t.sendAck([]tcpFlag{}, nil)
				break
			}

			if _, ok := recvFlags[flagRST]; ok {
				t.FlowHandler.router.log.Print("received RST, closing")
				t.close()
				break
			}

			if _, ok := recvFlags[flagSYN]; ok {
				if t.state == stateListen {
					t.state = stateSynReceived
					err := t.dialUpstream()
					if err != nil {
						t.FlowHandler.router.log.Printf("upstream connection failed: %s", err)
						t.Close()
						break
					}
					go readNetData2(t.conn, netRCh)
					t.sendAck([]tcpFlag{flagSYN}, nil)
					break
				}
				if t.state == stateSynSent {
					t.sequence += 1
					t.state = stateEstablished
					break
				}
				t.sendAck([]tcpFlag{}, nil)
				break
			}

			if _, ok := recvFlags[flagFIN]; ok {
				if t.state == stateEstablished {
					t.sequence += 1
					t.state = stateLastAck
					t.sendAck([]tcpFlag{flagFIN}, nil)
					break
				}
				if t.state == stateFinWait1 {
					t.sequence += 1
					t.sendAck([]tcpFlag{}, nil)
					t.close()
					break
				}
				t.FlowHandler.router.log.Printf("received FIN when not in Established or FINWait1 state. State: %#v", t.state)
			}

			if _, ok := recvFlags[flagACK]; ok {
				if t.state == stateSynReceived {
					t.state = stateEstablished
					break
				}
				if t.state == stateLastAck {
					t.close()
					break
				}
				if tcp.Ack == t.sequence {
					t.FlowHandler.router.log.Printf("received ACK for sent packet. State: %#v", t.state)
					break
				}
				t.FlowHandler.router.log.Printf("received ACK when not in SynReceived or LastAck state. State: %#v", t.state)
			}

			//we should never get here
			t.FlowHandler.router.log.Printf("received bad tcp packet %#v", tcp)
		case netData := <-netRCh:
			if netData.err != nil {
				t.FlowHandler.router.log.Printf("error receive data from net %#v", netData.err)
				t.Close()
			}
			t.lock.Lock()
			//t.sendBuffer = append(t.sendBuffer, netData.payload...)
			t.Send(netData.payload)
			t.lock.Unlock()
		case <-ticker.C:
			t.sendSendBuffer(sendTicker)
		case <-sendTicker:
			t.sendSendBuffer(sendTicker)
		}
	}
}

// startTCP4FlowHandler is a FlowHandler for handling transit tcp traffic
func startTCP4FlowHandler(f *FlowHandler) {
	defer f.Close()
	t := newTCP4FlowHandler(f)
	t.state = stateListen

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		t.Start()
		wg.Done()
	}()
	wg.Wait()
}
