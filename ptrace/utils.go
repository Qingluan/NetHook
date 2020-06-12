package ptrace

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"syscall"

	"github.com/gen2brain/dlgs"
)

func E(err error) {
	_, fn, line, _ := runtime.Caller(1)
	dlgs.Error("Msg ::", fmt.Sprintf("%s : %d : \n%s", fn, line, err.Error()))
}

func Execv() (cmd *exec.Cmd) {
	args := os.Args[1:]
	runnpath, err := exec.LookPath(args[0])
	if err != nil {
		log.Fatal(err)
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
		log.Fatal(err)
	}
	return
}

type Addr [4]byte

func (addr Addr) IP() net.IP {
	return net.IP{addr[0], addr[1], addr[2], addr[3]}
}
