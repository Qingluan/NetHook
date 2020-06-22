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
	FdHookList     = make(map[uint64]SockInfo)
	locker         sync.RWMutex
	NULL_ADDR      = [4]byte{0, 0, 0, 0}
	PROXY_DEST     = "127.0.0.1"
	PROXY_PORT     = 50093
	PROXY_TP       = "socks5"
	ClientUnixSock = NewCacheUnixSocket("/tmp/unix.sock")
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
	IsUdp      bool
	isTcp      bool
	Pid        int
	Dst        string
	Dport      int
	OnlyIp     bool
}

func (socks *SockInfo) Sock5Data() (firstData []byte) {
	if socks.OnlyIp {

		firstData = []byte{0x05, 0x01, 0x00, 0x01}
		firstData = append(firstData, net.ParseIP(socks.Dst)...)
		buf := make([]byte, 2)
		binary.BigEndian.PutUint16(buf, uint16(socks.Dport))
		firstData = append(firstData, buf...)

	} else {
		firstData = []byte{0x05, 0x01, 0x00, 0x03}
		bufl := make([]byte, 2)
		binary.BigEndian.PutUint16(bufl, uint16(len(socks.Dst)))

		firstData = append(firstData, bufl...)
		firstData = append(firstData, []byte(socks.Dst)...)

		buf := make([]byte, 2)
		binary.BigEndian.PutUint16(buf, uint16(socks.Dport))
		firstData = append(firstData, buf...)
	}
	return
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
	if domain != syscall.AF_INET {
		return
	}
	L.YI("<< Cased", "pid:", mem.Pid, "Socket FD:", int(mem.Reg.Rax), "Cache ", "Tcp:", int(tp)&syscall.SOCK_STREAM, "Udp:", int(tp)&syscall.SOCK_DGRAM)
	sockInfo := SockInfo{
		Domain:     int(args[0]),
		SocketType: int(args[1]),
		SocketFd:   int(mem.Reg.Rax),
	}
	// if (tp&syscall.SOCK_STREAM) < 1 || domain != syscall.AF_INET {
	if (tp & syscall.SOCK_STREAM) > 0 {
		// if int(args[1]) == syscall.SOCK_DGRAM {
		sockInfo.isTcp = true
		SaveHookInfo(GetPK(int(mem.Pid), mem.Reg.Rax), sockInfo)
	} else if (tp & syscall.SOCK_DGRAM) > 0 {
		// if int(args[1]) == syscall.SOCK_DGRAM {
		sockInfo.IsUdp = true
		SaveHookInfo(GetPK(int(mem.Pid), mem.Reg.Rax), sockInfo)
	}
	return
}

func GetSocks5Data(mem *Memory, args ...RArg) (outBuf []byte, err error) {
	AddrPtr := args[1]
	SocketPtr := args[0]

	addrIn := new(syscall.RawSockaddrInet4)
	err = mem.Dump(AddrPtr, addrIn)
	// realDest, err := mem.CacheGet(int(SocketPtr))
	pk := GetPK(int(mem.Pid), uint64(SocketPtr))
	sockInfo, ok := FdHookList[pk]
	if err != nil || !ok {
		L.MI(err)
		return
	}
	realDest := sockInfo.Dst
	// mem.CacheDel(int(SocketPtr))
	// _tmp := strings.SplitN(realDest, "://", 2)
	// a := strings.SplitN(_tmp[1], ":", 2)
	// port, _ := strconv.Atoi(a[1])
	if sockInfo.OnlyIp {
		ip := net.ParseIP(realDest).To4()
		firstData := []byte{0x05, 0x01, 0x00, 0x01}
		firstData = append(firstData, ip...)
		buf := make([]byte, 2)
		binary.BigEndian.PutUint16(buf, addrIn.Port)
		firstData = append(firstData, buf[1])
		L.MI("Data IP:", net.IP(addrIn.Addr[0:4]).String(), firstData)

		outBuf = firstData
	} else {
		firstData := []byte{0x05, 0x01, 0x00, 0x03}
		bufl := make([]byte, 2)
		binary.BigEndian.PutUint16(bufl, uint16(len(realDest)))

		firstData = append(firstData, bufl[1])
		firstData = append(firstData, []byte(realDest)...)
		buf := make([]byte, 2)
		binary.BigEndian.PutUint16(buf, addrIn.Port)
		firstData = append(firstData, buf...)
		L.MI("Data domain:", net.IP(addrIn.Addr[0:4]).String(), firstData)
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

	pk := GetPK(int(mem.Pid), uint64(SocketPtr))

	sockInfo, ok := FdHookList[pk]

	if !ok {
		return
	}
	if mem.Exit {
		defer DelHookInfo(pk)
		// if sockInfo.isTcp {
		// 	addrIn.Addr = [4]byte{127, 0, 0, 1}
		if sockInfo.isTcp {
			addrIn.Port = uint16(PROXY_PORT)

			L.GI("Connect Tcp to", addrIn.Addr, addrIn.Port, addrIn.Family, sockInfo)
			mem.Load(AddrPtr, addrIn)

		} else if sockInfo.IsUdp {
			L.GI("Connect to", addrIn.Addr, addrIn.Port, addrIn.Family, sockInfo.IsUdp)

		}

		// }
		return
	} else {
		// L.GI("pid:", mem.Pid, "Socket FD:", int(SocketPtr), "Entry:", !mem.Exit, Addr(addrIn.Addr).IP().String(), "Port:", addrIn.Port)

		if sockInfo.IsUdp {
			if addrIn.Port == 53 {
				L.GI(" ---> Udo Send", sockInfo.SocketFd)
				addrIn.Addr = [4]byte{127, 0, 0, 1}
				addrIn.Port = 40053
				mem.Load(AddrPtr, addrIn)
			} else {
				// data, err := GetSocks5Data(mem, args...)
				data := sockInfo.Sock5Data()
				if err != nil {
					L.Fatal(err)
				}
				NewCacheUnixSocket("/tmp/unix.sock").Set(sockInfo.SocketFd, data)
				L.GI("Set Data:", data)

			}
			return
		} else if sockInfo.isTcp {
			if domain, isIp := dns.SearchByIP(addrIn.Addr); !isIp {
				// pk := GetPK(int(mem.Pid), uint64(SocketPtr))
				sockInfo.Dst = domain
				sockInfo.Dport = int(addrIn.Port)
				// mem.CacheSave(int(SocketPtr), domain, false)
			} else {
				sockInfo.Dst = net.IP(addrIn.Addr[:4]).String()
				sockInfo.OnlyIp = true
				sockInfo.Dport = int(addrIn.Port)
				// if !IsLocal(addrIn.Addr) {
				// 	mem.CacheSave(int(SocketPtr), net.IP(addrIn.Addr[:4]).String(), true)
				// }
			}
			FdHookList[pk] = sockInfo
			if !IsLocal(addrIn.Addr) {

				L.GI(addrIn.Addr, "===>", PROXY_DEST, PROXY_PORT)
				// data, erre := GetSocks5Data(mem, args...)
				// if err != nil {
				// 	L.MI("Socks5 error:", erre)
				// 	return
				// }
				// L.GI("Set Data:", "ok")
				// addrIN := &syscall.RawSockaddrInet4{
				// 	Addr:   [4]byte{127, 0, 0, 1},
				// 	Port:   uint16(PROXY_PORT),
				// 	Family: addrIn.Family,
				// 	Zero:   addrIn.Zero,
				// }
				addrIn.Addr = [4]byte{127, 0, 0, 1}
				addrIn.Port = uint16(PROXY_PORT)
				if err := mem.Load(AddrPtr, addrIn); err != nil {
					L.MI("Err load:", err)
				}

			}

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
