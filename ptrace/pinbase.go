package ptrace

import (
	"syscall"
)

/*

	1. PID 可能会有多个，增加存储PID和域名的map
	2. 调整syscall.Wait4 函数的结构，让 pid 根据 wait4 调整
	3. 实施计划的方案来劫持实现透明代理， 劫持udp ，分配随机ip作为id, 并将该id 改为结果 （怎么直接结束掉该调用，或者劫持本地host缓存）
			tcp连接时查询得到真是目的地址，并将其作为地一个特殊包直接发送给代理


*/

const (
	MAGIC_FD = 7777777
)

type SocketInfo struct {
	pid      int
	magic_fd uint64
	fd       int
	domain   int
	dtype    int
}

var parentid int

var (
	CacheArea = struct {
		PidPin           map[int]*Pin
		HandlerMap       map[uint64]func(mem *Memory, args ...RArg)
		PtraceWaitStatus syscall.WaitStatus
		MainPid          int
	}{
		HandlerMap: make(map[uint64]func(mem *Memory, args ...RArg)),
		PidPin:     make(map[int]*Pin),
	}
)

type Handle struct {
	entry   bool
	handler func(mem *Memory, args ...RArg)
}

type Pin struct {
	pid       int
	fd        int
	flag      int
	regsEntry *syscall.PtraceRegs
	regsExit  *syscall.PtraceRegs
}

func NewPin(pid int) (pin *Pin) {
	pin = new(Pin)
	pin.pid = pid
	pin.regsEntry = new(syscall.PtraceRegs)
	pin.regsExit = new(syscall.PtraceRegs)
	return
}

func (pin *Pin) PtraceEntry() (exit bool) {
	defer func() {
		pin.flag = ENTRYED
	}()

	syscall.PtraceGetRegs(pin.pid, pin.regsEntry)

	if handle, ok := CacheArea.HandlerMap[pin.regsEntry.Orig_rax]; ok {

		handle(&Memory{
			Pid:  Pid(pin.pid),
			Exit: false,
			Reg:  pin.regsEntry,
		}, GetArgs(pin.regsEntry)...)
		pin.flag = ENTRYED
	}
	return
}

func (pin *Pin) SavePinByPid() {
	CacheArea.PidPin[pin.pid] = pin
}

func (pin *Pin) PtraceExit() (exit bool) {
	defer func() {
		pin.flag = NOENTRYED
	}()

	syscall.PtraceGetRegs(pin.pid, pin.regsExit)
	if handle, ok := CacheArea.HandlerMap[pin.regsExit.Orig_rax]; ok {
		handle(&Memory{
			Pid:  Pid(pin.pid),
			Exit: true,
			Reg:  pin.regsExit,
		}, GetArgs(pin.regsEntry)...)
	}

	if pin.regsExit.Orig_rax == syscall.SYS_EXIT || pin.regsExit.Orig_rax == syscall.SYS_EXIT_GROUP {
		exit = true
	}
	return
}

func (pin *Pin) PTrace() (e bool) {
	// update Pin after ptrace
	defer pin.SavePinByPid()
	if pin.flag == ENTRYED {
		e = pin.PtraceExit()
		pin.flag = NOENTRYED
	} else {
		e = pin.PtraceEntry()
	}
	return
}
