package utils

const (
	AF_UNIX   = uint16(1)
	AF_UNSPEC = uint16(0)
	AF_FILE   = uint16(1)
	AF_INET   = uint16(2)
	AF_INET6  = uint16(10)
)

const (
	PROTOCOL_TYPE_TCP = "tcp"
)

const (
	PROTOCOL_LAYER_L4 = "L4"
)

const (
	PROBE_TYPE_UPROBE = "uprobe"
	PROBE_TYPE_KPROBE = "kprobe"
	PROBE_TYPE_TP     = "tracepoint"
	PROBE_TYPE_XDP    = "XDP"
)

const (
	HOOK_SOCKET_CONNECT = uint16(1000)
)
