package probe

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/berryalen02/processflow/analyze"
	"github.com/berryalen02/processflow/utils"
)

const TASK_COMM_LEN = 16

var module_name = "EBPFProbeKTCPSec"

type event_module struct {
	// hook的函数名称
	hookfunc uint16
	// 模块名称
	module_name string
}

type event_general struct {
	TSUS int64
	PID  uint32
	UID  uint32
	AF   uint32
	TASK [TASK_COMM_LEN]byte
	event_module
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

// 向事件对象注入模块信息
func (ei *event_module) put_event_module_info() {
	ei.module_name = module_name
	ei.hookfunc = ei.hookfunc
}

func (ei *event_module) GetHookFunc() uint16 {
	return ei.hookfunc
}

func (ei *event_module) GetModuleName() string {
	return ei.module_name
}

func (ei *event_general) GetTSUS() time.Time {
	return time.Unix(ei.TSUS, 0)
}

func (ei *event_general) GetProtocol() int {
	return int(ei.AF)
}

// 并发安全地传送事件对象给tracker模块
func (ei *event_general) CopyObjToTracker() {
	analyze.Event_protosw_mutex.Lock()
	event_proto := analyze.GetEventProto()
	event_proto[int(ei.AF)] = ei
	analyze.Event_protosw_mutex.Unlock()

	// 发送副本给tracker
	analyze.TrackerChan <- analyze.Tracker(ei)
}

type EventIPV4 struct {
	event_general
	LAddr uint32
	LPort uint16
	RAddr uint32
	RPort uint16
}

// 按照小端序处理Map中读取的二进制数据
func (ei *EventIPV4) Decode(payload []byte) (err error) {
	buf := bytes.NewBuffer(payload)
	if err = binary.Read(buf, binary.LittleEndian, &ei.TSUS); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ei.PID); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ei.UID); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ei.AF); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ei.LAddr); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ei.LPort); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ei.RAddr); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ei.RPort); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ei.TASK); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ei.hookfunc); err != nil {
		return
	}
	ei.put_event_module_info()
	return nil
}

func (ei *EventIPV4) String() string {
	t_start := time.UnixMicro(ei.TSUS).Format("15:04:05")
	return fmt.Sprintf("start time:%s, PID:%d, UID:%d, AF:%d, TASK:%s", t_start, ei.PID, ei.UID, ei.AF, ei.TASK)
}

func (ei *EventIPV4) Clone() IEventStruct {
	return new(EventIPV4)
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

func (ei *EventIPV6) Decode(payload []byte) (err error) {
	buf := bytes.NewBuffer(payload)
	if err = binary.Read(buf, binary.LittleEndian, &ei.TSUS); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ei.PID); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ei.UID); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ei.AF); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ei.TASK); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ei.RAddr); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ei.RPort); err != nil {
		return
	}
	ei.put_event_module_info()
	return nil
}

func (ei *EventIPV6) String() string {
	t_start := time.UnixMicro(ei.TSUS).Format("15:04:05")
	return fmt.Sprintf("start time:%s, PID:%d, UID:%d, AF:%d, TASK:%s", t_start, ei.PID, ei.UID, ei.AF, ei.TASK)
}

func (ei *EventIPV6) Clone() IEventStruct {
	return new(EventIPV6)
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
type EventOther struct {
	event_general
}

func (ei *EventOther) Decode(payload []byte) (err error) {
	buf := bytes.NewBuffer(payload)
	if err = binary.Read(buf, binary.LittleEndian, &ei.TSUS); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ei.PID); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ei.UID); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ei.AF); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ei.TASK); err != nil {
		return
	}
	ei.put_event_module_info()
	return nil
}

func (ei *EventOther) String() string {
	t_start := time.UnixMicro(ei.TSUS).Format("15:04:05")
	return fmt.Sprintf("start time:%s, PID:%d, UID:%d, AF:%d, TASK:%s", t_start, ei.PID, ei.UID, ei.AF, ei.TASK)
}

func (ei *EventOther) Clone() IEventStruct {
	return new(EventOther)
}
