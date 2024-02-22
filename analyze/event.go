package analyze

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/berryalen02/processflow/utils"
)

const (
	TASK_COMM_LEN = 16
)

var TrackerChan chan Tracker

var Event_protosw_mutex sync.Mutex

var event_protosw = make(map[int]Tracker)

type event_module struct {
	hookfunc    uint16
	module_name string
}

func (ei *event_module) GetHookFunc() uint16 {
	return ei.hookfunc
}

func (ei *event_module) GetModuleName() string {
	return ei.module_name
}

type event_general struct {
	event_module
	TSUS int64
	PID  uint32
	UID  uint32
	AF   uint32
	TASK [TASK_COMM_LEN]byte
}

func (ei *event_general) GetUid() int {
	return int(ei.UID)
}

func (ei *event_general) GetPid() int {
	return int(ei.PID)
}

func (ei *event_general) GetTask() []byte {
	taskSlice := make([]byte, len(ei.TASK))
	copy(taskSlice, ei.TASK[:])
	return taskSlice
}

func (ei *event_general) GetTSUS() time.Time {
	return time.Unix(ei.TSUS, 0)
}

func (ei *event_general) GetProtocol() int {
	return int(ei.AF)
}

type EventIPV4 struct {
	event_general
	LAddr uint32
	LPort uint16
	RAddr uint32
	RPort uint16
}

func (ei *EventIPV4) GetLaddr() net.IP {
	return utils.Uint32ToIP(ei.LAddr)
}

func (ei *EventIPV4) GetRaddr() net.IP {
	return utils.Uint32ToIP(ei.RAddr)
}

func (ei *EventIPV4) GetLport() int {
	return int(ei.LPort)
}

func (ei *EventIPV4) GetRport() int {
	return int(ei.RPort)
}

// IPv6
type EventIPV6 struct {
	event_general
	RAddr [16]byte
	RPort uint16
}

// ipv6 暂时不提取本地IP
func (ei *EventIPV6) GetLaddr() net.IP {
	fmt.Printf("[socket_connect:IPV6] LAddr == nil !!")
	return nil
}

func (ei *EventIPV6) GetRaddr() net.IP {
	return utils.Byte16ToIPV6(ei.RAddr)
}

// ipv6 暂时不提取本地端口
func (ei *EventIPV6) GetLport() int {
	fmt.Printf("[socket_connect:IPV6] Lport == nil !!")
	return 0
}

func (ei *EventIPV6) GetRport() int {
	return int(ei.RPort)
}

// Other
type EventUnknow struct {
	event_general
}

func GetEventProto() map[int]Tracker {
	return event_protosw
}

func init() {
	event_protosw[int(utils.AF_INET)] = &EventIPV4{}
	event_protosw[int(utils.AF_INET6)] = &EventIPV6{}
	event_protosw[int(utils.AF_UNSPEC)] = &EventUnknow{}
}
