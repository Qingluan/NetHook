package main

import (
	"os"
	"syscall"

	dns "github.com/Qingluan/HookNet/dnspack"
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
	if len(os.Args) < 2 {
		Ptr.L.GI("少参数")
		os.Exit(1)
	}
	go dns.StartServer()
	cmd := Ptr.Execv()
	// ptrace.Execv()
	Ptr.AddHandle(syscall.SYS_CONNECT, func(mem *Ptr.Memory, args ...Ptr.RArg) {
		AddrPtrt := args[1]
		addrIn := new(syscall.RawSockaddrInet4)
		mem.Dump(AddrPtrt, addrIn)
		Ptr.L.GI("Entry:", !mem.Exit, Ptr.Addr(addrIn.Addr).IP().String(), "Port:", addrIn.Port)

		if !mem.Exit {
			addrIn.Addr = [4]byte{127, 0, 0, 1}
			addrIn.Port = 10053
			mem.Load(AddrPtrt, addrIn)
		}
	})

	Ptr.PtraceRun(cmd.Process.Pid)
	// Ptr.PtraceRun(os.Getpid())
}
