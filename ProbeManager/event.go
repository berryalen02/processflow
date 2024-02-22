package probe

type IEventStruct interface {
	Decode(payload []byte) (err error)
	String() string
	Clone() IEventStruct
	// 拷贝事件副本给analyze模块
	CopyObjToTracker()
}
