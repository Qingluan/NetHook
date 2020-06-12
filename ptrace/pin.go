package ptrace

import (
	"log"
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
	AddrInLen = unsafe.Sizeof(syscall.RawSockaddrInet4{})
	ADDRLEN   = unsafe.Sizeof(syscall.RawSockaddr{})
)

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
	if pid, err = syscall.Wait4(CacheArea.MainPid, &CacheArea.PtraceWaitStatus, syscall.WALL, nil); err != nil {
		log.Fatal("Wait Function Exe Error: ", err)
	}
	pin = FindPinByPidOrInit(pid)
	if pin.flag == STARTUP {
		// set pin.flag Startef
		pin.flag++
		if err = syscall.PtraceSetOptions(pin.pid, syscall.PTRACE_O_TRACECLONE|syscall.PTRACE_O_TRACESYSGOOD|syscall.PTRACE_O_TRACEEXEC|syscall.PTRACE_O_TRACEFORK|syscall.PTRACE_O_TRACEVFORK); err != nil {
			log.Fatal("Init Pid Ptrace Option Error:", err)
			return
		}
	}
	if CacheArea.PtraceWaitStatus.Exited() || CacheArea.PtraceWaitStatus.Signaled() || !CacheArea.PtraceWaitStatus.Stopped() {
		/* Re alloc Pin : because this pid which has finished!
		delete by pid
		*/
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
		log.Println("~~ Bye unknow:")
		exited = true
	}

	if CacheArea.PtraceWaitStatus.Stopped() {
		log.Println("~~ Bye Normal:")
		exited = true
	}
	return
}

func AddHandle(syscall_id uint64, is_do_in_entry bool, h func(pid Pid, reg *syscall.PtraceRegs, args ...RArg)) {
	CacheArea.HandlerMap[syscall_id] = Handle{
		entry:   is_do_in_entry,
		handler: h,
	}
}

func FindPinByPidOrInit(pid int) *Pin {
	if pin, ok := CacheArea.PidPin[pid]; ok {
		return pin
	} else {
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
	for {
		/*
			Detail in WaitAPin:
		*/
		if pin, exit, continued = WaitAPin(); exit {
			break
		} else if continued {
			continue
		} else if pin == nil {
			continue
		}
		// child end, no need to syscall resume ptrace
		if continued = pin.PTrace(); continued {
			continue
		}
		syscall.PtraceSyscall(pin.pid, 0)

	}
}
