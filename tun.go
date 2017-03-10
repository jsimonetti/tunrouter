package main

import (
	"log"
	"os"
	"time"

	"github.com/jsimonetti/tunrouter/router"
	"github.com/songgao/water"
)

func main() {
	t := New(Config{})
	t.Start()
}

// Config contains options for the tunnelrouter
type Config struct {
}

// tun is the struct wich holds the tunnelrouter
type tun struct {
	log        *log.Logger
	handleIPv4 func(buff []byte, wCh chan []byte)
	handleIPv6 func(buff []byte, wCh chan []byte)
}

// New returns a new tunnelrouter
func New(config Config) *tun {
	t := &tun{
		log: log.New(os.Stdout, "", log.Ldate|log.Lmicroseconds),
	}

	r := router.New(router.Config{Log: t.log})
	t.handleIPv4 = r.HandleIPv4
	t.handleIPv6 = r.HandleIPv6

	return t
}

// Start will start the tunnel listener and router
func (t *tun) Start() {

	t.log.Printf("opening tunnel device")

	// create a new tunnel interface
	ifce, err := water.New(water.Config{
		DeviceType: water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{
			ComponentID: "tap0901", // windows specific componentid
			Network:     "192.168.1.10/24",
		},
	})
	if err != nil {
		t.log.Fatal(err)
	}

	t.log.Printf("Interface Name: %s\n", ifce.Name())

	// local tun interface read and write channel.
	rCh := make(chan []byte, 1024)
	wCh := make(chan []byte, 1024)

	// fire off the read and write routines to get/put data from/to the tun interface
	go t.readRoutine(rCh, ifce)
	go t.writeRoutine(wCh, ifce)

	// timeout for now after 30 seconds
	timeOut := time.After(60 * time.Second)

	// handlerL3 is the handler for the L3 layer types
	var handlerL3 func(buff []byte, wCh chan []byte)

	// loop, reading packets from tun and passing them
	// allong to the respective handlers
	for {
		select {
		case buff := <-rCh:
			switch buff[0] >> 4 {
			case 0x04: // IPv4
				handlerL3 = t.handleIPv4
			case 0x06: // IPv6
				handlerL3 = t.handleIPv6
			}

			if handlerL3 != nil {
				// fire the handler to do the rest
				go handlerL3(buff, wCh)
				break
			}
			t.log.Printf("unknow protocol packet [%x]", buff[0]>>4)
		case <-timeOut:
			return
		}
	}
}

// readRoutine will read from the tun interface and put the read bytes
// into rCh
func (t *tun) readRoutine(rCh chan []byte, ifce *water.Interface) {
	defer func() {
		close(rCh)
	}()

	buff := make([]byte, 4096)
	for {
		n, err := ifce.Read(buff)
		if err != nil {
			t.log.Printf("error TUN read: %s", err)
		}
		rCh <- buff[:n]
	}
}

// writeRoutine will write bytes from the wCh onto the tun interface
func (t *tun) writeRoutine(wCh chan []byte, ifce *water.Interface) {
	defer func() {
		ifce.Close()
	}()
	for {
		data := <-wCh
		_, err := ifce.Write(data)
		if err != nil {
			t.log.Printf("error writing: %s", err)
		}
	}
}
