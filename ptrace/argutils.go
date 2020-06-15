package ptrace

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"
	"syscall"
	"unsafe"
)

// Pid is process pid int
type Pid int

// RegArg is reg's value
type RArg uint64

func (pid Pid) ParseData(addr uint64, len int) []byte {
	out := make([]byte, len)
	Glen, err := syscall.PtracePeekData(int(pid), uintptr(addr), out)
	if err != nil {
		E(err)
	}
	return out[:Glen]
}

func (regarg RArg) ParseData(pid Pid, len int) []byte {
	out := make([]byte, len)
	Glen, err := syscall.PtracePeekData(int(pid), uintptr(regarg), out)
	if err != nil {
		E(err)
	}
	return out[:Glen]
}

func (regarg RArg) As(pid Pid, obj interface{}) (err error) {
	Otp := reflect.ValueOf(obj)
	len := unsafe.Sizeof(Otp)
	out := make([]byte, len)
	Glen, err := syscall.PtracePeekData(int(pid), uintptr(regarg), out)
	if err != nil {
		return
	}
	err = binary.Read(bytes.NewBuffer(out[:Glen]), binary.BigEndian, obj)
	return
}

func GetData(pid int, reg *syscall.PtraceRegs, addr uint64, len int) []byte {
	out := make([]byte, len)
	fmt.Println("addr:", addr)
	g_l, err := syscall.PtracePeekData(pid, uintptr(addr), out)
	if err != nil {
		E(err)
	}
	return out[:g_l]
}

func GetArgs(reg *syscall.PtraceRegs) (args []RArg) {
	for i := 0; i < 6; i++ {
		args = append(args, GetArg(i, reg))
	}
	return
}

func GetArg(order int, reg *syscall.PtraceRegs) RArg {
	if reg == nil {
		return 0
	}
	switch order {
	case 0:
		return RArg(reg.Rdi)
	case 1:
		return RArg(reg.Rsi)
	case 2:
		return RArg(reg.Rdx)
	case 3:
		return RArg(reg.R10)
	case 4:
		return RArg(reg.R8)
	case 5:
		return RArg(reg.R9)

	}
	return 0
}
