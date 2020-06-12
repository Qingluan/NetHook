package main

import (
	"os"
	"syscall"

	dns "github.com/Qingluan/HookNet/dnspack"
	Ptr "github.com/Qingluan/HookNet/ptrace"
)

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
		if addrIn.Port != 53 {
			return
		}
		Ptr.L.GI("Entry:", addrIn.Family, !mem.Exit, Ptr.Addr(addrIn.Addr).IP().String(), "Port:", addrIn.Port)

		if !mem.Exit {
			addrIn.Addr = [4]byte{127, 0, 0, 1}
			addrIn.Port = 40053
			mem.Load(AddrPtrt, addrIn)
		}
	})

	Ptr.PtraceRun(cmd.Process.Pid)
	// Ptr.PtraceRun(os.Getpid())
}
