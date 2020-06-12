package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"syscall"

	ptrace "github.com/Qingluan/HookNet/ptrace"
)

func execv() (cmd *exec.Cmd) {
	args := os.Args[1:]
	runnpath, err := exec.LookPath(args[0])
	if err != nil {
		ptrace.E(err)
	}
	cmd = exec.Command(runnpath, args[1:]...)

	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{Ptrace: true}
	} else {
		cmd.SysProcAttr.Ptrace = true
	}
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	runtime.LockOSThread()
	if err := cmd.Start(); err != nil {
		ptrace.E(err)
	}
	return
}

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
	cmd := execv()

	pin := ptrace.NewPin(cmd)
	pin.AddHandle(syscall.SYS_SOCKET, true, func(pid int, reg *syscall.PtraceRegs) {
		// fmt.Println("Entry Socket")
	})
	// pin.addHandle(syscall.SYS_GET)
	pin.AddHandle(syscall.SYS_CONNECT, true, func(pid int, reg *syscall.PtraceRegs) {
		addroffset := pin.GetArg(1, reg)
		buf := pin.GetData(reg, addroffset, int(ptrace.SocketInLen))
		addin := new(syscall.RawSockaddrInet4)
		binary.Read(bytes.NewBuffer(buf), binary.BigEndian, addin)
		fmt.Println(net.IP{addin.Addr[0], addin.Addr[1], addin.Addr[2], addin.Addr[3]}.String(), "Port:", addin.Port)
	})
	pin.PtraceLoop()
}
