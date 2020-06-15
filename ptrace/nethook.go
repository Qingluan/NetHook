package ptrace

// +build cgo,!netgo
/* C code */

/*
#include <sys/socket.h>

typedef unsigned long long uint64_t;
struct socket_info {
	pid_t pid;
	uint64_t magic_fd;
	int fd;
	int domain;
	int type;
};

*/
// import "C"
import (
	"sync"
	"syscall"

	dns "github.com/Qingluan/HookNet/dnspack"
)

// import "C"

var (
	FdHookList = make(map[uint64]SockInfo)
	locker     sync.RWMutex
	NULL_ADDR  = [4]byte{0, 0, 0, 0}
)

func SaveHookInfo(k uint64, so SockInfo) {
	locker.Lock()
	defer locker.Unlock()
	FdHookList[k] = so
}

func DelHookInfo(fd uint64) {
	locker.Lock()
	defer locker.Unlock()
	delete(FdHookList, fd)
}

type SockInfo struct {
	Domain     int
	SocketType int
	SocketFd   int
	Pid        int
}

func GetPK(pid int, sockfd uint64) uint64 {
	return uint64(sockfd)<<31 + uint64(pid)
}

func HookCacheSocketInfo(mem *Memory, args ...RArg) (err error) {

	// get args after call socket(AF_INET, SOCK_STREAM, options) 's domain and socket tp
	// SOCK_DGRAM : 2
	// L.RI("So:", args[1])
	// if int(args[0]) != syscall.AF_INET || int(syscall.AF_INET6) != int(args[0]) {
	// 	return
	// }
	if !mem.Exit {
		return
	}
	domain := args[0]
	tp := args[1]
	// if (tp&syscall.SOCK_STREAM) < 1 || domain != syscall.AF_INET {
	if (tp&syscall.SOCK_DGRAM) < 1 || domain != syscall.AF_INET {

		// L.YI
		return
	}
	// if int(args[1]) == syscall.SOCK_DGRAM {
	L.YI("<< Cased", "pid:", mem.Pid, "Socket FD:", int(mem.Reg.Rax), "Cache ", "Tp:", int(tp&syscall.SOCK_DGRAM))
	SaveHookInfo(GetPK(int(mem.Pid), mem.Reg.Rax), SockInfo{
		Domain:     int(args[0]),
		SocketType: int(args[1]),
		SocketFd:   int(mem.Reg.Rax),
	})
	// }
	return
}

func SmartHookTCP(mem *Memory, args ...RArg) (err error) {
	AddrPtr := args[1]
	SocketPtr := args[0]

	addrIn := new(syscall.RawSockaddrInet4)
	err = mem.Dump(AddrPtr, addrIn)
	if err != nil {
		// L.RI(err, AddrPtr, mem.Reg.Orig_rax == syscall.SYS_CONNECT, "In Exit:", mem.Exit)
		// L.RI(args, mem.Reg.Orig_rax)
		return
	}
	if addrIn.Addr == NULL_ADDR {
		return
	}
	if mem.Exit {
		realDomain := dns.SearchByIP(addrIn.Addr)

	} else {
		// L.GI("pid:", mem.Pid, "Socket FD:", int(SocketPtr), "Entry:", !mem.Exit, Addr(addrIn.Addr).IP().String(), "Port:", addrIn.Port)

		switch addrIn.Port {
		case 53:
			pk := GetPK(int(mem.Pid), uint64(SocketPtr))
			if si, ok := FdHookList[pk]; ok && si.SocketType&syscall.SOCK_DGRAM > 0 {
				L.GI(" ---> Udo Send", si.SocketFd)
				addrIn.Addr = [4]byte{127, 0, 0, 1}
				addrIn.Port = 40053
				mem.Load(AddrPtr, addrIn)
				defer DelHookInfo(pk)
			}

		}

	}
	return

}
