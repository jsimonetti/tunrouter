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
	log    *log.Logger
	router router.Router
}

// New returns a new tunnelrouter
func New(config Config) *tun {
	t := &tun{
		log: log.New(os.Stdout, "", log.Ldate|log.Lmicroseconds),
	}

	r := router.New(router.Config{
		Log:         t.log,
		SelfIPv4:    []byte{0xc0, 0xa8, 0x01, 0x01}, // 192.168.1.1
		NATSourceIp: []byte{0x0a, 0x0a, 0x01, 0xb6}, //10.10.1.182
	})

	t.router = r

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

	// open the router for L3 packets
	l3rwc, err := t.router.Open(router.OpenForL3)
	if err != nil {
		t.log.Fatalf("error from router.Open: %s", err)
	}
	defer l3rwc.Close()

	// fire a goroutine to read from the router
	go func() {
		buff := make([]byte, 4096)
		for {
			n, err := l3rwc.Read(buff)
			if err != nil {
				if n > 0 {
					wCh <- buff[:n]
				}
				return
			}
			wCh <- buff[:n]
		}
	}()

	// loop until timeout
	for {
		select {
		case buff := <-rCh:
			l3rwc.Write(buff)
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
