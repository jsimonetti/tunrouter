// Code generated by "stringer -type=tcpState"; DO NOT EDIT

package router

import "fmt"

const _tcpState_name = "stateListenstateSynReceivedstateSynSentstateEstablishedstateFinWait1stateFinWait2stateClosingstateCloseWaitstateLastAckstateClosed"

var _tcpState_index = [...]uint8{0, 11, 27, 39, 55, 68, 81, 93, 107, 119, 130}

func (i tcpState) String() string {
	if i >= tcpState(len(_tcpState_index)-1) {
		return fmt.Sprintf("tcpState(%d)", i)
	}
	return _tcpState_name[_tcpState_index[i]:_tcpState_index[i+1]]
}
