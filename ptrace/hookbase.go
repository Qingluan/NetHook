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
		HandlerMap       map[uint64]Handle
		PtraceWaitStatus syscall.WaitStatus
		MainPid          int
	}{
		HandlerMap: make(map[uint64]Handle),
		PidPin:     make(map[int]*Pin),
	}
)

type Handle struct {
	entry   bool
	handler func(pid Pid, reg *syscall.PtraceRegs, args ...RArg)
}

type Pin struct {
	pid       int
	fd        int
	flag      int
	regsEntry *syscall.PtraceRegs
	regsExit  *syscall.PtraceRegs
	HandleMap map[uint64]Handle
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

	if handle, ok := pin.HandleMap[pin.regsEntry.Orig_rax]; ok && handle.entry {
		handle.handler(Pid(pin.pid), pin.regsEntry, GetArgs(pin.regsEntry)...)
	}
	return
}

func (pin *Pin) PtraceExit() (exit bool) {
	defer func() {
		pin.flag = NOENTRYED
	}()

	syscall.PtraceGetRegs(pin.pid, pin.regsExit)
	if handle, ok := pin.HandleMap[pin.regsExit.Orig_rax]; ok && !handle.entry {
		// handle.handler(pin.pid, pin.regsExit)
		handle.handler(Pid(pin.pid), pin.regsExit, GetArgs(pin.regsEntry)...)
	}

	if pin.regsExit.Orig_rax == syscall.SYS_EXIT || pin.regsExit.Orig_rax == syscall.SYS_EXIT_GROUP {
		exit = true
	}
	return
}

func (pin *Pin) PTrace() bool {
	if pin.flag == ENTRYED {
		return pin.PtraceExit()
	} else {
		return pin.PtraceEntry()
	}
}
