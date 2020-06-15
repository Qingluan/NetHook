package ptrace

import (
	"log"
	"net"
	"os"
	"os/exec"
	"syscall"
)

func Execv() (cmd *exec.Cmd) {
	args := os.Args[1:]
	runnpath, err := exec.LookPath(args[0])
	if err != nil {
		log.Fatal(err)
	}
	cmd = exec.Command(runnpath, args[1:]...)

	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Ptrace: true,
			// Cloneflags: uintptr(syscall.CLONE_VM | syscall.CLONE_VFORK | syscall.CLONE_NEWUTS | syscall.SIGCHLD),
		}
	} else {
		cmd.SysProcAttr.Ptrace = true
	}
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	// runtime.LockOSThread()
	if err := cmd.Start(); err != nil {
		log.Fatal(err)
	}
	return
}

type Addr [4]byte

func (addr Addr) IP() net.IP {
	return net.IP{addr[0], addr[1], addr[2], addr[3]}
}
