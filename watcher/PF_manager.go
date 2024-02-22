package watcher

import (
	"fmt"
	"net"

	"github.com/berryalen02/processflow/analyze"
)

type PF_manager struct {
	PID      int
	Protocol []string
	Net      net.Interface
	Delay    int

	ManagerOptions
}

type ManagerOptions struct {
}

// Manager各模块初始化
func (p *PF_manager) Init() {
	// analyze模块初始化
	analyze.Init()
}

// 开始监听
func (p *PF_manager) Start() {

	// logger := log.Default()
	// logger.Printf("[processflow] start monitoring....\n")
	fmt.Printf("[processflow] start monitoring....\n")

	for _, name := range p.Protocol {
		protosw := pf_protos[name]

		go func() {
			err := protosw.Run()
			if err != nil {
				fmt.Printf("%v\n", err)
			}
		}()
	}

	// logger.Println("[processflow] Received signal, exiting progam..")

}

func (p *PF_manager) Stop() {

}

func Create(pid int) *PF_manager {
	manager := &PF_manager{
		PID: pid,
	}

	return manager
}

// ManagerOptions:
func (m *PF_manager) InitWithOptions(ops *ManagerOptions) bool {
	return true
}
