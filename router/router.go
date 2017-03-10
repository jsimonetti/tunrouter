package router

import (
	"log"
	"net"
)

type Config struct {
	Log *log.Logger
}

type router struct {
	log       *log.Logger
	selfIPv4  net.IP
	flowTable FlowTable
}

func New(config Config) *router {
	return &router{
		log:      config.Log,
		selfIPv4: []byte{0xc0, 0xa8, 0x01, 0x01}, // 192.168.1.1
		flowTable: FlowTable{
			flowMap: make(map[uint64]*FlowHandler),
		},
	}
}
