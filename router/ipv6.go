package router

// HandleIPv6 is the handler for IPv6 traffic
// it selects a protocol handler to handle the traffic
func (r *router) HandleIPv6(buff []byte, wCh chan []byte) {
	r.log.Printf("IPv6 protocol is not supported")
}
