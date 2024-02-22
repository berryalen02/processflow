package watcher

import "fmt"

type pf_protosw interface {
	// 获取注册协议名称
	GetName() string
	// 获取协议端口
	GetPort() int
	// 获取协议层级
	GetLayer() string
	// 启动进程流量识别
	Run() error
}

var pf_protos = make(map[string]pf_protosw)

type Protocol struct {
	Name  string
	Port  int
	Layer string
}

func (p *Protocol) GetName() string {
	return p.Name
}

func (p *Protocol) GetLayer() string {
	return p.Layer
}

func (p *Protocol) GetPort() int {
	return p.Port
}

// 应用层协议
type message struct {
	Protocol
	// 请求明文
	Data []byte
}

// 解析协议包数据
func (a *message) ParseData() {

}

func Register_proto(p pf_protosw) {
	if p == nil {
		panic("[X] Register protocol is nil")
	}
	name := p.GetName()
	if _, dup := pf_protos[name]; dup {
		panic(fmt.Sprintf("Register called twice for protocol %s", name))
	}
	pf_protos[name] = p
}

func GetPfProtos() map[string]pf_protosw {
	return pf_protos
}
