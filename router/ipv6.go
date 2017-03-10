package router

func (r *router) HandleIPv6(buff []byte, wCh chan []byte) {
	r.log.Printf("Ipv6 protocol is not supported")
}
