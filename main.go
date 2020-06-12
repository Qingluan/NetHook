package main

import (
	"fmt"
	"syscall"

	"github.com/Qingluan/HookNet/ptrace"
	Ptr "github.com/Qingluan/HookNet/ptrace"
)

// func ChildDo(cmd string, args ...string) {
// 	fmt.Println("Child:", cmd, args, os.Getpid())
// 	ptrace.Exec(cmd, args...)
// }

// func ParentDo() {
// 	log.Println("Parent:", os.Args, os.Getpid())
// 	if cmd, er := fork(); er != nil {
// 		log.Fatal(er)
// 	} else {
// 		cmd.Start()
// 		// pid := cmd.Process.Pid
// 		pin := NewPin(cmd)
// 		pin.addHandle(syscall.SYS_SOCKET, true, func(pid int, reg *syscall.PtraceRegs) {
// 			fmt.Println("Entry Socket")
// 		})
// 		pin.PtraceLoop()
// 		// SnifferSocket(pid)
// 		// log.Println("for out:", string(o))
// 	}
// }

func main() {
	cmd := ptrace.Execv()

	// pin := ptrace.NewPin(cmd)
	// ptrace.AddHandle(syscall.SYS_SOCKET, true, func(pid int, reg *syscall.PtraceRegs) {
	// 	// fmt.Println("Entry Socket")
	// })
	// pin.addHandle(syscall.SYS_GET)
	Ptr.AddHandle(syscall.SYS_CONNECT, true, func(pid Ptr.Pid, reg *syscall.PtraceRegs, args ...Ptr.RArg) {
		addroffset := args[1]
		// buf := (reg, addroffset, int(ptrace.SocketInLen))
		addrIn := new(syscall.RawSockaddrInet4)

		addroffset.As(pid, addrIn)
		fmt.Println(Ptr.Addr(addrIn.Addr).IP().String(), "Port:", addrIn.Port)
	})
	// pin.PtraceLoop()
	Ptr.PtraceRun(cmd.Process.Pid)

}
