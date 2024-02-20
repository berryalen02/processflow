package user

import "net"

type proceflow_API interface {
	IdentifyProcessTraffic()
	MonitorProcessTraffic()
	AnalyzeProcessTraffic()
}

type Processflow_watcher struct {
	API proceflow_API
	traffic_info
	event_info
	pid      int
	protocol int
	net      net.Interface
}

func Watcher_create() {

}

func Watcher_free() {

}
