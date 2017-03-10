package router

import (
	"errors"
	"log"
	"net"
	"sync"

	"github.com/google/gopacket"
)

var (
	errNoSuchFlow = errors.New("no such flowHash")
)

var flowTable FlowTable = FlowTable{
	flowMap: make(map[uint64]*FlowHandler),
}

type FlowTable struct {
	lock    sync.Mutex
	flowMap map[uint64]*FlowHandler // keyed my flow.FastHash()
}

func (f *FlowTable) Get(flowHash uint64) (*FlowHandler, error) {
	f.lock.Lock()
	defer f.lock.Unlock()
	if handler, ok := f.flowMap[flowHash]; ok {
		return handler, nil
	}
	return nil, errNoSuchFlow
}

func (f *FlowTable) New(flowHash uint64) *FlowHandler {
	f.lock.Lock()
	defer f.lock.Unlock()

	//create new FlowHandler and set some values
	handler := &FlowHandler{
		flowHash: flowHash,
		buf:      gopacket.NewSerializeBuffer(),
		opts: gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
		tunRCh: make(chan gopacket.Packet),
	}

	f.flowMap[flowHash] = handler
	return handler
}

func (f *FlowTable) Delete(flowHash uint64) {
	f.lock.Lock()
	delete(f.flowMap, flowHash)
	f.lock.Unlock()
}

type FlowHandler struct {
	flowHash uint64 // save my hash

	tunRCh chan gopacket.Packet // channel this handler will accept data on from the tunnel
	tunWch chan []byte          // channel this handler will send data to the tunnel

	conn net.Conn // the upstream connection

	buf  gopacket.SerializeBuffer  // buffer for creating packets
	opts gopacket.SerializeOptions // serialization option

	log *log.Logger // inherited logger from router
}

func (f *FlowHandler) Close() {
	flowTable.Delete(f.flowHash)
	close(f.tunRCh)
	if f.conn != nil {
		f.conn.Close()
	}
}
