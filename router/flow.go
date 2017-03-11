package router

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
)

var (
	// error returned when there in no FlowHandler for the given flowHash in the FlowTable
	errNoSuchFlow = errors.New("no such flowHash")
)

// hashOf returns the hashstring of the parameters
func hashOf(ipv4Flow uint64, src []byte, dst []byte) string {
	return fmt.Sprintf("%d-%04x-%04x", ipv4Flow, src, dst)
}

// FlowTable holds a map to FlowHandlers keyed by a flowHash
// the hash if of type flow.FastHash()
type FlowTable struct {
	lock    sync.Mutex
	flowMap map[string]*FlowHandler
}

// Get attempts to return the FlowHandler for a flowHash
// If none can be found errNoSuchFlow is returned
func (f *FlowTable) Get(flowHash string) (*FlowHandler, error) {
	f.lock.Lock()
	defer f.lock.Unlock()
	if handler, ok := f.flowMap[flowHash]; ok {
		return handler, nil
	}
	return nil, errNoSuchFlow
}

// New allocates a new FlowHandler and add it to the FlowTable for the given flowHash
func (f *FlowTable) New(flowHash string) *FlowHandler {
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
	handler.ResetTimeOut(10 * time.Second)

	// check first if it doesn't exist
	if _, ok := f.flowMap[flowHash]; !ok {
		f.flowMap[flowHash] = handler
	}

	return f.flowMap[flowHash]
}

// Delete removes a FlowHandler from the FlowTable
func (f *FlowTable) Delete(flowHash string) {
	f.lock.Lock()
	delete(f.flowMap, flowHash)
	f.lock.Unlock()
}

// FlowHandler is a structure for a single handler of a flowHash
type FlowHandler struct {
	flowHash string // save my hash

	tunRCh chan gopacket.Packet // channel this handler will accept data on from the tunnel
	tunWch chan []byte          // channel this handler will send data to the tunnel

	conn net.Conn // the upstream connection

	buf  gopacket.SerializeBuffer  // buffer for creating packets
	opts gopacket.SerializeOptions // serialization option

	timeout <-chan time.Time // channel where a time.After channel is inserted

	router *router

	dialing bool // set to true while dialing out
}

// ResetTimeOut will reset the timeout for this flow
// It is called inside the handler everytime the timeout needs to be extended
func (f *FlowHandler) ResetTimeOut(extend time.Duration) {
	timer := time.NewTimer(extend)
	f.timeout = timer.C
}

// Close will remove the FlowHandler from the FlowTable and close any open connections handled by it
func (f *FlowHandler) Close() {
	f.router.flowTable.Delete(f.flowHash)
	close(f.tunRCh)
	if f.conn != nil {
		f.conn.Close()
	}
}

// Dialing will set the handler to dial mode to drop retries from the client
func (f *FlowHandler) Dialing(v bool) {
	f.dialing = v
}

// readNetData will read data from conn and put it on channel netRCh
// on error the error is forwarded to channel netECh
func readNetData(conn net.Conn, netRCh chan []byte, netECh chan error) {
	data := make([]byte, 4096)
	for {
		n, err := conn.Read(data)
		if err != nil {
			if n > 0 { // always write remaining bytes
				netRCh <- data[:n]
			}
			// error io.EOF is a normal error for reading from a conn
			if err != io.EOF {
				netECh <- err
			}
			break
		}
		// put the read data in the channel
		netRCh <- data[:n]
	}
}
