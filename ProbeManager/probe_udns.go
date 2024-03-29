package probe

import (
	"bytes"
	"context"
	"ehids/assets"
	"log"
	"math"

	"github.com/cilium/ebpf"
	manager "github.com/gojue/ebpfmanager"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

type MUDNSProbe struct {
	Module_general
	bpfManager        *manager.Manager
	bpfManagerOptions manager.Options
	eventFuncMaps     map[*ebpf.Map]IEventStruct
	eventMaps         []*ebpf.Map
}

// 对象初始化
func (this *MUDNSProbe) Init(ctx context.Context, logger *log.Logger) error {
	this.Module_general.Init(ctx, logger)
	this.Module_general.SetChild(this)
	this.eventMaps = make([]*ebpf.Map, 0, 2)
	this.eventFuncMaps = make(map[*ebpf.Map]IEventStruct)
	return nil
}

func (this *MUDNSProbe) Start() error {
	if err := this.start(); err != nil {
		return err
	}
	return nil
}

func (this *MUDNSProbe) start() error {

	// fetch ebpf assets
	javaBuf, err := assets.Asset("user/bytecode/dns_lookup_kern.o")
	if err != nil {
		return errors.Wrap(err, "couldn't find asset")
	}

	// setup the managers
	this.setupManagers()

	// initialize the bootstrap manager
	if err := this.bpfManager.InitWithOptions(bytes.NewReader(javaBuf), this.bpfManagerOptions); err != nil {
		return errors.Wrap(err, "couldn't init manager")
	}

	// start the bootstrap manager
	if err := this.bpfManager.Start(); err != nil {
		return errors.Wrap(err, "couldn't start bootstrap manager")
	}

	// 加载map信息，map对应events decode表。
	err = this.initDecodeFun()
	if err != nil {
		return err
	}

	return nil
}

func (this *MUDNSProbe) Close() error {
	if err := this.bpfManager.Stop(manager.CleanAll); err != nil {
		return errors.Wrap(err, "couldn't stop manager")
	}
	return nil
}

func (this *MUDNSProbe) setupManagers() {
	this.bpfManager = &manager.Manager{
		Probes: []*manager.Probe{
			{
				Section:          "uprobe/getaddrinfo",
				EbpfFuncName:     "getaddrinfo_entry",
				AttachToFuncName: "getaddrinfo",
				BinaryPath:       "/lib/x86_64-linux-gnu/libc.so.6",
			},
			{
				Section:          "uretprobe/getaddrinfo",
				EbpfFuncName:     "getaddrinfo_return",
				AttachToFuncName: "getaddrinfo",
				BinaryPath:       "/lib/x86_64-linux-gnu/libc.so.6",
			},
		},

		Maps: []*manager.Map{
			{
				Name: "events",
			},
		},
	}

	this.bpfManagerOptions = manager.Options{
		DefaultKProbeMaxActive: 512,

		VerifierOptions: ebpf.CollectionOptions{
			Programs: ebpf.ProgramOptions{
				LogSize: 2097152,
			},
		},

		RLimit: &unix.Rlimit{
			Cur: math.MaxUint64,
			Max: math.MaxUint64,
		},
	}
}

func (this *MUDNSProbe) DecodeFun(em *ebpf.Map) (IEventStruct, bool) {
	fun, found := this.eventFuncMaps[em]
	return fun, found
}

func (this *MUDNSProbe) initDecodeFun() error {
	//eventMap 与解码函数映射
	DNSEventsMap, found, err := this.bpfManager.GetMap("events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map:events")
	}
	this.eventMaps = append(this.eventMaps, DNSEventsMap)
	this.eventFuncMaps[DNSEventsMap] = &DNSEVENT{}

	return nil
}

func (this *MUDNSProbe) Events() []*ebpf.Map {
	return this.eventMaps
}

func init() {
	mod := &MUDNSProbe{}
	mod.name = "EBPFProbeUDNS"
	mod.mType = PROBE_TYPE_UPROBE
	Register_Module(mod)
}
