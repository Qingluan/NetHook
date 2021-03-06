package main

import (
	"flag"
	"os"
	"syscall"

	dns "github.com/Qingluan/HookNet/dnspack"
	Ptr "github.com/Qingluan/HookNet/ptrace"
)

func main() {
	if len(os.Args) < 2 {
		Ptr.L.GI("少参数")
		os.Exit(1)
	} else if os.Args[1] == "-h" {
		flag.Parse()
		return
	} else if os.Args[1][0] == '-' {

		red := Ptr.NewRedirector("127.0.0.1:1091")
		Ptr.L.GI("->", red.RedirectServer)
		red.Socks5Server()
		return
	}
	go dns.StartServer()
	cmd := Ptr.Execv()
	// ptrace.Execv()
	Ptr.AddHandle(syscall.SYS_SOCKET, Ptr.HookCacheSocketInfo)
	Ptr.AddHandle(syscall.SYS_CONNECT, Ptr.SmartHookTCP)

	Ptr.PtraceRun(cmd.Process.Pid)
	Ptr.PtraceRun(os.Getpid())
}
