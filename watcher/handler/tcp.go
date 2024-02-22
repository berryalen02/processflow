package handler

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	probe "github.com/berryalen02/processflow/ProbeManager"
	"github.com/berryalen02/processflow/utils"
	"github.com/berryalen02/processflow/watcher"
	"github.com/cilium/ebpf/rlimit"
)

type TCP_handler struct {
	Name   string
	Layer  string
	Port   int
	probes []string
}

func (t *TCP_handler) GetName() string {
	return t.Name
}

func (t *TCP_handler) GetPort() int {
	return t.Port
}

func (t *TCP_handler) GetLayer() string {
	return t.Layer
}

func (t *TCP_handler) Run() error {
	err := t.pfMonitor()
	if err != nil {
		return err
	}
	return nil
}

// 监控，查看进程流量信息
func (t *TCP_handler) pfMonitor() error {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	ctx, cancelFun := context.WithCancel(context.TODO())

	logger := log.Default()
	logger.Println("[processflow] |protocol:TCP| start monitoring....")

	modules := probe.GetModules()
	for _, probe_name := range t.probes {
		logger.Printf("start to run %s module", probe_name)
		// 初始化
		err := modules[probe_name].Init(ctx, logger)
		if err != nil {
			logger.Println("%v", err)
			return err
		}

		// 加载ebpf，挂载到hook点上，开始监听
		go func(module probe.AModule) {
			err := modules[probe_name].Run()
			if err != nil {
				logger.Printf("%v\n", err)
			}
		}(modules[probe_name])

		// 开启analyze模块，接收
	}

	<-stopper
	cancelFun()

	logger.Println("Received signal, exiting program..")
	time.Sleep(time.Millisecond * 100)
	return nil
}

func init() {
	m := &TCP_handler{}
	m.Name = utils.PROTOCOL_TYPE_TCP
	m.Layer = utils.PROTOCOL_LAYER_L4

	m.probes = []string{
		"EBPFProbeKTCPSec",
	}

	watcher.Register_proto(m)
}
