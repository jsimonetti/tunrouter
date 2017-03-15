package router

import (
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

//go:generate stringer -type=tcpFlag
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

//go:generate stringer -type=tcpState
type tcpState uint8

const (
	stateListen tcpState = iota
	stateSynReceived
	stateSynSent
	stateEstablished
	stateFinWait1
	stateFinWait2
	stateClosing
	stateCloseWait
	stateLastAck
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

func newTCP4FSM(f *Flow) *tcp4FSM {
	return &tcp4FSM{
		Flow:     f,
		state:    stateClosed,
		sequence: 0,
		log:      func(format string, params ...interface{}) {},
		buf:      gopacket.NewSerializeBuffer(),
		opts: gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
	}
}

type tcp4FSM struct {
	*Flow

	id uint16

	srcIp   net.IP
	dstIp   net.IP
	srcPort uint16
	dstPort uint16

	exit chan bool

	sendLock   sync.Mutex
	sendBuffer []byte

	recvLock   sync.Mutex
	recvBuffer []byte

	stateLock sync.Mutex
	state     tcpState

	sequenceLock sync.Mutex
	sequence     uint32 // my sequence number

	lastAckSent uint32 // last client seq nr i acked

	log  func(format string, params ...interface{})
	buf  gopacket.SerializeBuffer  // buffer for creating packets
	opts gopacket.SerializeOptions // serialization option
}

func (t *tcp4FSM) sendSendBuffer(myTicker chan bool) {
	t.sendLock.Lock()
	defer t.sendLock.Unlock()

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

func (t *tcp4FSM) Recv(data []byte, push bool) {
	t.recvLock.Lock()
	t.recvBuffer = append(t.recvBuffer, data...)
	t.recvLock.Unlock()
	t.ACK([]tcpFlag{}, nil)

	if push {
		t.flushRecvBuffer()
	}
}

func (t *tcp4FSM) flushRecvBuffer() {
	//t.log("flushing recvBuffer now")
	t.recvLock.Lock()
	defer t.recvLock.Unlock()

	_, err := t.conn.Write(t.recvBuffer)
	t.recvBuffer = []byte{}
	if err != nil {
		t.log("error flushing recvBuffer: %s", err)
		t.Teardown()
	}
}

func (t *tcp4FSM) buildPacket() (layers.IPv4, layers.TCP) {
	// create the ip layer
	ipLayer := layers.IPv4{
		Version:  4,
		TTL:      32,
		Id:       t.id,
		SrcIP:    t.dstIp,
		DstIP:    t.srcIp,
		Protocol: layers.IPProtocolTCP,
		Flags:    layers.IPv4DontFragment,
	}

	// create the tcp layer
	tcpLayer := layers.TCP{
		SrcPort: layers.TCPPort(t.dstPort),
		DstPort: layers.TCPPort(t.srcPort),
		Seq:     t.Sequence(),
		Ack:     t.lastAckSent,
		Window:  0x05b4,
		Options: []layers.TCPOption{
			layers.TCPOption{
				OptionType:   layers.TCPOptionKindMSS,
				OptionLength: 2,
				OptionData:   []byte{0x05, 0xb4},
			},
		},
	}

	tcpLayer.SetNetworkLayerForChecksum(&ipLayer)
	return ipLayer, tcpLayer
}

// send should be the function every outbound packet goes through
func (t *tcp4FSM) send(flags []tcpFlag, payload gopacket.Payload) {
	// every packet we send should go through here.
	ipLayer, tcpLayer := t.buildPacket()
	t.log("send: %v", flags)
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
	err := gopacket.SerializeLayers(t.buf, t.opts, &ipLayer, &tcpLayer, payload)
	if err != nil {
		t.log("error serializing TCP packet for _send: %s", err)
		return
	}

	t.Flow.tunWch <- t.buf.Bytes()

	if len(payload) > 0 {
		t.IncrSequence(uint32(len(payload)))
	}
}

func (t *tcp4FSM) SYN() {
	t.SetState(stateSynSent)
	t.send([]tcpFlag{flagSYN}, nil)
}

func (t *tcp4FSM) ACK(flags []tcpFlag, data []byte) {
	t.send(append(flags, flagACK), data)
}

func (t *tcp4FSM) FIN(flags []tcpFlag, data []byte) {
	t.send(append(flags, flagFIN), data)
}

func (t *tcp4FSM) RST() {
	t.send([]tcpFlag{flagRST}, nil)
}

func (t *tcp4FSM) Teardown() {
	if t.State() != stateClosed {
		t.SetState(stateFinWait1)
		t.FIN([]tcpFlag{}, nil)
	}
}

func (t *tcp4FSM) nextSequence(tcp *layers.TCP) uint32 {

	if len(tcp.Payload) > 0 {
		return tcp.Seq + uint32(len(tcp.Payload))
	}
	if tcp.SYN {
		return tcp.Seq + 1
	}
	if tcp.FIN {
		return tcp.Seq + 1
	}
	return t.Sequence()
}

func (t *tcp4FSM) Close() { // we should close remote end to depending on state
	t.SetState(stateClosed)
}

func (t *tcp4FSM) Send(data []byte) {
	if t.State() != stateEstablished {
		for {
			if t.State() == stateEstablished {
				break
			}
			time.Sleep(10 * time.Nanosecond)
		}
	}
	t.ACK([]tcpFlag{flagPSH}, data)
}

// tcpFSM is the TCP finite state machine
func (t *tcp4FSM) tcpFSM(tcp *layers.TCP) tcpState {

	t.log("received: %v", flagsFromTcpLayer(tcp))

	if tcp.RST {
		return t.SetState(stateClosed)
	}

	state := t.State()

	if state != stateListen {
		if t.lastAckSent != tcp.Seq {
			// we're not in a place to receive this packet. drop it.
			//t.log("unexpected packet received %#v", tcp)
			return state
		}
	}

	if t.nextSequence(tcp) > t.lastAckSent {
		t.lastAckSent = t.nextSequence(tcp)
	}

	switch state {
	case stateListen: // responder - open sequence

		if tcp.SYN {
			t.srcPort = uint16(tcp.SrcPort)
			t.dstPort = uint16(tcp.DstPort)

			// received initial SYN, send SYN,ACK
			state = t.SetState(stateSynReceived)
			//t.sendACK([]tcpFlag{flagSYN}, nil) // delay this untill the upstream connection is finished
			return state
		}

	case stateSynReceived: // responder - open sequence
		// waiting for ACK to finish 3-way
		if tcp.ACK {
			state = t.SetState(stateEstablished)
			t.IncrSequence(1)
			return state
		}

	case stateSynSent: // initiator - open sequence
		if tcp.SYN && tcp.ACK {
			state = t.SetState(stateEstablished)
			t.IncrSequence(1)
			t.ACK([]tcpFlag{}, nil)
			return state
		}
		if tcp.SYN { // simultaneous open
			state = t.SetState(stateSynReceived)
			t.ACK([]tcpFlag{}, nil)
			return state
		}

	case stateEstablished: // responder - close sequence
		if tcp.FIN {
			state = t.SetState(stateCloseWait)
			//t.IncrSequence(1)
			t.ACK([]tcpFlag{}, nil)
			// close application and wait for application close
			//
			// confirm application close by sending FIN
			state = t.SetState(stateLastAck)
			t.IncrSequence(1)
			t.FIN([]tcpFlag{}, nil)
			return state
		}

	case stateFinWait1: // initiator - close sequence
		if tcp.ACK {
			//received ACK for FIN
			state = t.SetState(stateFinWait2)
			return state
		}
		if tcp.FIN { // simultaneous close
			state = t.SetState(stateClosing)
			t.IncrSequence(1)
			t.ACK([]tcpFlag{}, nil)
			return state
		}

	case stateFinWait2: // initiator - close sequence
		if tcp.FIN {
			state = t.SetState(stateClosed) // we skip time-wait
			t.ACK([]tcpFlag{}, nil)
			return state
		}

	case stateClosing: // simultaneous close
		if tcp.ACK {
			state = t.SetState(stateClosed) // we skip time-stateFinWait1
			return state
		}

	case stateLastAck:
		if tcp.ACK {
			state = t.SetState(stateClosed) // we skip time-stateFinWait1
			return state
		}

	}
	return state
}

func (t *tcp4FSM) Sequence() uint32 {
	t.stateLock.Lock()
	defer t.stateLock.Unlock()
	return t.sequence
}

func (t *tcp4FSM) IncrSequence(s uint32) {
	t.stateLock.Lock()
	t.sequence += s
	t.stateLock.Unlock()
}

func (t *tcp4FSM) State() tcpState {
	t.stateLock.Lock()
	defer t.stateLock.Unlock()
	return t.state
}

func (t *tcp4FSM) SetState(state tcpState) tcpState {
	t.stateLock.Lock()
	t.state = state
	t.stateLock.Unlock()
	return state
}
