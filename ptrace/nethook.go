// +build cgo,!netgo

package ptrace

/* C code */

/*
#include <errno.h>
#include <sys/socket.h>
#include <stdio.h>

typedef unsigned long long uint64_t;
struct socket_info {
	pid_t pid;
	uint64_t magic_fd;
	int fd;
	int domain;
	int type;
};

int
WriteToSocket(int fd, char *buf){
	size_t size;
	size = strlen(buf);
	if (fwrite(fd, buf, size) <= 0) {
		if (errno)
			perror("write");
		fprintf(stderr, "write failed!\n");
	}
}

*/
// import "C"
import (
	"encoding/binary"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"

	dns "github.com/Qingluan/HookNet/dnspack"
)

// import "C"

var (
	FdHookList = make(map[uint64]SockInfo)
	locker     sync.RWMutex
	NULL_ADDR  = [4]byte{0, 0, 0, 0}
	PROXY_DEST = "127.0.0.1"
	PROXY_PORT = 1091
	PROXY_TP   = "socks5"
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

func str2ip(s string) [4]byte {
	ss := strings.SplitN(s, ".", 4)
	sd := [4]byte{}
	for no, sss := range ss {
		si, _ := strconv.Atoi(sss)
		sd[no] = byte(si)
	}
	return sd
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

func GetSocks5Data(mem *Memory, args ...RArg) (outBuf []byte, err error) {
	AddrPtr := args[1]
	SocketPtr := args[0]

	addrIn := new(syscall.RawSockaddrInet4)
	err = mem.Dump(AddrPtr, addrIn)
	realDest, err := mem.CacheGet(int(SocketPtr))
	if err != nil {
		L.MI(err)
		return
	}
	mem.CacheDel(int(SocketPtr))
	_tmp := strings.SplitN(realDest, "://", 2)

	if _tmp[0] == "ip" {
		ip := net.ParseIP(_tmp[1]).To4()
		firstData := []byte{0x05, 0x01, 0x00, 0x01}
		firstData = append(firstData, ip...)
		buf := make([]byte, 2)
		binary.BigEndian.PutUint16(buf, addrIn.Port)
		firstData = append(firstData, buf...)
		L.MI("Data:", net.IP(addrIn.Addr[0:4]).String(), firstData)

		if _, err := syscall.Write(int(SocketPtr), firstData); err != nil {
			L.MI(err)
		}

		outBuf = firstData
	} else {
		domainLen := len(_tmp[1])
		firstData := []byte{0x05, 0x01, 0x00, 0x03}
		buf := make([]byte, 2)
		binary.BigEndian.PutUint16(buf, uint16(domainLen))

		firstData = append(firstData, buf...)
		firstData = append(firstData, []byte(_tmp[1])...)
		L.MI("Data:", firstData)
		if _, err := syscall.Write(int(SocketPtr), firstData); err != nil {
			L.MI(err)
		}

		outBuf = firstData
	}
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
				return
			}
		}
		if domain, isIp := dns.SearchByIP(addrIn.Addr); !isIp {
			mem.CacheSave(int(SocketPtr), domain, false)
		} else {
			if !IsLocal(addrIn.Addr) {
				mem.CacheSave(int(SocketPtr), net.IP(addrIn.Addr[:4]).String(), true)
			}
		}
		if !IsLocal(addrIn.Addr) {

			L.GI(addrIn.Addr, "===>", PROXY_DEST, PROXY_PORT)
			addrIn.Addr = str2ip(PROXY_DEST)
			addrIn.Port = uint16(PROXY_PORT)
			mem.Load(AddrPtr, addrIn)
			// if socksData, err := GetSocks5Data(mem, args...); err != nil {
			// 	L.MI(err)
			// } else {
			// 	// if _, err := syscall.Write(int(SocketPtr), socksData); err != nil {
			// 	// 	L.MI(err)
			// 	// }
			// 	// C.WriteToSocket(int(SocketPtr), C.CBytes(socksData))
			// }
		}

	}
	return

}

func IsLocal(addr [4]byte) bool {
	if net.IP(addr[:4]).String() == "127.0.0.1" {
		// fmt.Println("s.")
		return true
	}
	// } else if addr[0] == 192 && addr[1] == 168 {
	// 	return true
	// } else if addr[0] == 10 {
	// 	return true
	// }
	return false
}
