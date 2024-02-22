package analyze

import (
	"fmt"
	"net"
	"sync"
	"time"
)

type Tracker interface {
	// 获取UID
	GetUid() int
	// 获取PID
	GetPid() int
	// 获取协议名称
	GetProtocol() int
	// 获取进程名称
	GetTask() []byte
	// 获取时间戳
	GetTSUS() time.Time
	// 获取Hookfunc名称
	GetHookFunc() uint16
	// 获取模块名称
	GetModuleName() string
}

type AppTracker interface {
	Tracker
	// 获取saddr
	GetLaddr() net.IP
	// 获取daddr
	GetRaddr() net.IP
	// 获取sport
	GetLport() int
	// 获取dport
	GetRport() int
}

var tracker_mutex sync.Mutex
var trackers []Tracker

// analyze系统初始化
func Init() {
	TrackerChan = make(chan Tracker, 100)
	go func() {
		fmt.Printf("start getting trackers......\n")
		getTrackers()
	}()
}

// analyze模块开始工作
func Run() {
	// trackers已经获取到事件对象，开始数据处理
	//
}

// 从probe模块获取tracker对象
func getTrackers() {
	for eventInterface := range TrackerChan {
		tracker_mutex.Lock()
		trackers = append(trackers, eventInterface)
		tracker_mutex.Unlock()
	}
}
