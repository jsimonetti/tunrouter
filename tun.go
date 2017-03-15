package main

import (
	"io"
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

	// timeout for now after 30 seconds
	timeOut := time.After(60 * time.Second)
	eof := make(chan bool)

	// open the router for L3 packets
	l3rwc, err := t.router.Open(router.L3Mode)
	if err != nil {
		t.log.Fatalf("error from router.Open: %s", err)
	}
	defer l3rwc.Close()

	go func() {
		io.Copy(l3rwc, ifce)
		eof <- true
	}()
	go func() {
		io.Copy(ifce, l3rwc)
		eof <- true
	}()

	// loop until timeout
	for {
		select {
		case <-eof:
			return
		case <-timeOut:
			return
		}

	}
}
