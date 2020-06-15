package ptrace

import (
	"bytes"
	"encoding/binary"
	"os"
	"syscall"
	"unsafe"
)

const (
	STARTUP   = 0
	NOENTRYED = 1
	ENTRYED   = 2
)

var (
	regOffset = map[string]uintptr{
		"rdi": unsafe.Offsetof(syscall.PtraceRegs{}.Rdi),
		"rsi": unsafe.Offsetof(syscall.PtraceRegs{}.Rsi),
		"rbx": unsafe.Offsetof(syscall.PtraceRegs{}.Rbx),
		"rcx": unsafe.Offsetof(syscall.PtraceRegs{}.Rcx),
		"rdx": unsafe.Offsetof(syscall.PtraceRegs{}.Rbx),
		"rbp": unsafe.Offsetof(syscall.PtraceRegs{}.Rbp),
		"r10": unsafe.Offsetof(syscall.PtraceRegs{}.R10),
		"r9":  unsafe.Offsetof(syscall.PtraceRegs{}.R9),
		"r8":  unsafe.Offsetof(syscall.PtraceRegs{}.R8),
		"r11": unsafe.Offsetof(syscall.PtraceRegs{}.R11),
		"r12": unsafe.Offsetof(syscall.PtraceRegs{}.R12),
		"r13": unsafe.Offsetof(syscall.PtraceRegs{}.R13),
	}
)

// Memory a piece of memory at the moment.
type Memory struct {
	Pid  Pid
	Reg  *syscall.PtraceRegs
	Exit bool
}

/*WaitAPin do wait child pid and check process status
this code is immplement for c code:

		child = wait(&status);
		if (child < 0)
			return 0;
		pinfp = find_proc_info(child);
		if (!pinfp)
			pinfp = alloc_proc_info(child);

		if (pinfp->flags & FLAG_STARTUP) {
			pinfp->flags &= ~FLAG_STARTUP;

			if (ptrace(PTRACE_SETOPTIONS, child, 0,
				   PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC |
				   PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK) <
			    0) {
				perror("ptrace");
				exit(errno);
			}
		}
		event = ((unsigned)status >> 16);
		if (event != 0) {
			sig = 0;
			goto end;
		}
		if (WIFSIGNALED(status) || WIFEXITED(status)
		    || !WIFSTOPPED(status)) {
			// TODO free pinfp
			continue;
		}
*/
func WaitAPin() (pin *Pin, exited bool, continued bool) {

	var pid int
	var err error

	if pid, err = syscall.Wait4(-1, &CacheArea.PtraceWaitStatus,
		// syscall.WALL|syscall.WNOTHREAD|syscall.WUNTRACED,
		0,
		nil); err != nil {
		myPid := os.Getpid()
		L.Fatal(err, "Main Pid:", CacheArea.MainPid, "Sub pid:", pid, "My Pid:", myPid)
	} else {
		// mytid
	}
	// L.GI("Pid:", pid)
	if pid < 0 {
		L.RI("Exit ....")
		exited = true
		return
	}
	pin = FindPinByPidOrInit(pid)
	if pin.flag == STARTUP {
		// set pin.flag Startef

		if err = syscall.PtraceSetOptions(pin.pid, syscall.PTRACE_O_TRACECLONE|syscall.PTRACE_O_TRACESYSGOOD|syscall.PTRACE_O_TRACEEXEC|syscall.PTRACE_O_TRACEFORK|syscall.PTRACE_O_TRACEVFORK); err != nil {
			L.Fatal(err, pin.pid)
			return
		}
	}
	if CacheArea.PtraceWaitStatus.Exited() || CacheArea.PtraceWaitStatus.Signaled() || !CacheArea.PtraceWaitStatus.Stopped() {
		/* Re alloc Pin : because this pid which has finished!
		delete by pid
		*/
		L.YI("delete cache Pin")
		DeletePinByPid(pid)
		/*
			Init Pin by Pid
		*/
		pin = nil
		continued = true
	}

	/*
		implemented C code:
			event = ((unsigned)status >> 16);
			if (event != 0) {
				sig = 0;
				goto end;
			}
	*/
	if uint64(CacheArea.PtraceWaitStatus.Signal())>>16 != 0 {
		// if pin.flag == STARTUP {
		// 	// continued = true
		// 	return
		// }
		// L.YI("~~ Bye unknow:")
		// exited = true
		return
	}

	if CacheArea.PtraceWaitStatus.Stopped() {
		if pin.flag == STARTUP {
			// continued = true
			return
		}
		L.YI("~~ Bye Normal:")
		exited = true
	}
	return
}

func AddHandle(syscall_id uint64, h func(mem *Memory, args ...RArg) error) {
	CacheArea.HandlerMap[syscall_id] = h
}

func FindPinByPidOrInit(pid int) *Pin {
	if pin, ok := CacheArea.PidPin[pid]; ok {

		// L.YI("finded Pin")
		return pin
	} else {

		L.YI("init Pin")
		pin := NewPin(pid)
		CacheArea.PidPin[pid] = pin
		return pin
	}
}

func DeletePinByPid(pid int) {
	delete(CacheArea.PidPin, pid)
}

/*
PtraceRun start run ptrace
*/
func PtraceRun(mainpid int) {
	CacheArea.MainPid = mainpid
	var (
		pin             *Pin
		exit, continued bool
	)
	i := 0
	// AddHandle(syscall.SYS_CLONE, func(mem *Memory, args ...RArg) {
	// 	if !mem.Exit {
	// 		flags := args[0]
	// 		L.YI("flags:", flags, "^flasg:", ^uint64(syscall.CLONE_UNTRACED))
	// 		mem.Reg.Rdi = mem.Reg.Rdi & ^uint64(syscall.CLONE_UNTRACED)
	// 		syscall.PtraceSetRegs(int(mem.Pid), mem.Reg)

	// 	} else {
	// 		L.GI("clone args:", args, "clone ret:", mem.Reg.Rax)
	// 	}
	// })
	for {
		i++
		/*
			Detail in WaitAPin:
		*/
		// L.GI("exit in ", i)

		if pin, exit, continued = WaitAPin(); exit {
			break
		} else if continued {
			continue
		} else if pin == nil {
			continue
		}
		// L.GI("Good:", pin.pid)
		// child end, no need to syscall resume ptrace
		if continued = pin.PTrace(); continued {
			// log.Println("Con?")
			continue
		}
		syscall.PtraceSyscall(pin.pid, 0)

	}
}

// Args in memory
func (mem *Memory) Args() (args []RArg) {
	args = GetArgs(mem.Reg)
	return
}

// Unmarshal dump reg argsaddr to struct
func (mem *Memory) Dump(argAddr RArg, obj interface{}) (err error) {
	return argAddr.As(mem.Pid, obj)
}

// Marshal set data to memory struct
func (mem *Memory) Load(argAddr RArg, obj interface{}) (err error) {
	buf := bytes.NewBuffer(nil)
	binary.Write(buf, binary.BigEndian, obj)
	_, err = syscall.PtracePokeData(int(mem.Pid), uintptr(argAddr), buf.Bytes())
	return
}
