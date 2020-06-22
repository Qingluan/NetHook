package ptrace

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"reflect"
	"strconv"
	"time"
)

var (
	SMSG           = []byte("SED")
	SETMSG         = []byte("SET")
	RMSG           = []byte("GET")
	OKMSG          = []byte("OJBK")
	UnixServerAddr = flag.String("Service", "", "-Service 127.0.0.1:1091")
)

type UnixSocket struct {
	filename string
	bufsize  int
	handler  func([]byte) []byte
	mapConn  map[string][]byte
}

func NewUnixSocket(filename string, size ...int) *UnixSocket {
	size1 := 10480
	if size != nil {
		size1 = size[0]
	}
	return &UnixSocket{
		filename: filename,
		bufsize:  size1,
		mapConn:  make(map[string][]byte),
	}
}

func (sock *UnixSocket) CreateServer(onrecv ...func(buf []byte) []byte) (err error) {

	os.Remove(sock.filename)
	if len(onrecv) > 0 {
		sock.handler = onrecv[0]
	}
	addr, err := net.ResolveUnixAddr("unix", sock.filename)
	if err != nil {
		panic("Can not resolve unix addr:" + err.Error())
	}
	listener, err := net.ListenUnix("unix", addr)
	defer listener.Close()
	if err != nil {
		return err
	}
	L.GI("Listen unix socket:", listener.Addr())
	for {
		c, err := listener.Accept()
		if err != nil {
			return err
		}
		go sock.HandlerCon(c)
	}
}

func (sock *UnixSocket) Client(sendbuf []byte) (recvbuf []byte, err error) {
	addr, err := net.ResolveUnixAddr("unix", sock.filename)
	if err != nil {
		return
	}
	c, err := net.DialUnix("unix", nil, addr)
	if err != nil {
		return
	}
	defer c.Close()
	if _, err = c.Write(sendbuf); err != nil {
		return
	}
	recvbuf = make([]byte, sock.bufsize)
	if nr, err := c.Read(recvbuf); err != nil {
		return nil, err
	} else {
		L.GI("Read:", nr)
		return recvbuf[:nr], nil
	}

}

func (sock *UnixSocket) HandlerCon(con net.Conn) {
	defer con.Close()
	buf := make([]byte, sock.bufsize)
	nr, err := con.Read(buf)
	if err != nil {
		L.MI("Handle Read Err:", err.Error())
		return
	}
	result := sock.call(buf[:nr])
	_, err = con.Write(result)
	L.GI("reply:", result)
	if err != nil {
		L.MI("Err:", err)
		return
	}
}

func (sock *UnixSocket) call(buf []byte) (res []byte) {
	if sock.handler != nil {
		res = sock.handler(buf)
		return
	} else {
		L.GI("I recv:", buf)
		res = buf
	}
	return
}

type CacheUnixSocket struct {
	sock    *UnixSocket
	buf     chan []byte
	mapConn map[int][]byte
}

func NewCacheUnixSocket(filename string) *CacheUnixSocket {
	return &CacheUnixSocket{
		sock: NewUnixSocket(filename),
		buf:  make(chan []byte, 5),
	}
}

func (csock *CacheUnixSocket) StartService() {
	csock.sock.CreateServer(func(rB []byte) (reply []byte) {
		if bytes.Compare(rB, RMSG) == 0 {

			reply = <-csock.buf

		} else if bytes.HasPrefix(rB, SMSG) && len(rB) > 5 {
			l := binary.BigEndian.Uint16(rB[3:5])
			csock.buf <- rB[5 : 5+l]
			L.GI("Add S:", rB)
			reply = OKMSG
		} else if bytes.HasPrefix(rB, SETMSG) && len(rB) > 3 {
			L.GI("Add S:", rB[3:])
			tmp := bytes.SplitN(rB[3:], []byte("::"), 2)
			fd, _ := strconv.Atoi(string(tmp[0]))
			csock.mapConn[fd] = tmp[1]
			reply = OKMSG
		}
		return
	})
}

func (csock *CacheUnixSocket) Recv() ([]byte, error) {
	return csock.sock.Client(RMSG)
}

func (csock *CacheUnixSocket) Set(fd int, buf []byte) (reply []byte, err error) {
	b := bytes.NewBuffer(SETMSG)
	key := []byte(fmt.Sprintf("%d::", fd))
	b.Write(key)
	b.Write(buf)
	reply, err = csock.sock.Client(b.Bytes())
	L.GI("reply:", reply)
	return
}

func (csock *CacheUnixSocket) Send(addr string, port int) ([]byte, error) {
	s := bytes.NewBuffer(SMSG)
	d := PackAddrToBuf(addr, port)
	_, err := s.Write(d)
	if err != nil {
		return nil, err
	}
	L.GI("P:", d)
	return csock.sock.Client(s.Bytes())
}

type Redirector struct {
	RedirectServer string
	SockServer     *CacheUnixSocket
}

func NewRedirector(addr string) *Redirector {
	return &Redirector{
		RedirectServer: addr,
		SockServer:     NewCacheUnixSocket("/tmp/unix.sock"),
	}
}

func GetFD(con net.Conn) int {
	v := reflect.ValueOf(con)
	netFD := reflect.Indirect(reflect.Indirect(v).FieldByName("fd"))
	fd := int(netFD.FieldByName("sysfd").Int())
	return fd
}

func (Red *Redirector) Socks5Server() {
	serv, err := net.Listen("tcp", "127.0.0.1:50093")
	// go Red.SockServer.StartService()

	if err != nil {
		L.Fatal(err)
	}
	L.GI("Listen tcp : ", "127.0.0.1:50093")
	for {

		con, err := serv.Accept()
		fd := GetFD(con)
		socksData := Red.SockServer.mapConn[fd]
		delete(Red.SockServer.mapConn, fd)
		L.GI("R:", con)
		if err != nil {
			L.MI("Accept Err:", err)
			continue
		}

		go Red.RedirectTo(con, socksData)
	}
}

func (Red *Redirector) RedirectTo(src net.Conn, socksData []byte) {
	// defer con.SetReadDeadline(20 * time.Second)
	defer src.Close()
	data := make([]byte, 1024)
	n, err := src.Read(data)
	if err != nil {
		log.Println(err)
	}
	log.Println("raw:", data)

	// data = append(data, realServer...)
	dst, err := net.Dial("tcp", Red.RedirectServer)
	if err != nil {
		L.Fatal(err, "Redirect Socks5:")
	}
	defer dst.Close()
	socks5AuthRes := Red.Sock5Auth(dst, socksData)
	L.GI("sock5 x:", socks5AuthRes)
	// L.GI("Conne")
	// if !socks5AuthRes {

	// }else{

	// }
	readChan, writeChan := make(chan int64), make(chan int64)
	dst.Write(data[:n])
	go pipe(src, dst, readChan)
	go pipe(dst, src, writeChan)
	<-readChan
	<-writeChan

}

func (Red *Redirector) Sock5Auth(con2 net.Conn, socksData []byte) bool {

	buf := make([]byte, 10)
	con2.Write([]byte{0x5, 0x0})
	con2.Read(buf)
	con2.Write(socksData)
	con2.Read(buf)
	if bytes.Compare(buf, []byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x08, 0x43}) == 0 {
		return true
	}
	return false
}

func pipe(dst, src net.Conn, c chan int64) {
	n, _ := io.Copy(dst, src)
	now := time.Now()
	dst.SetDeadline(now)
	src.SetDeadline(now)
	c <- n
}

func PackAddrToBuf(server string, port int) (out []byte) {
	l := len(server)
	out = make([]byte, l+4)
	binary.BigEndian.PutUint16(out[:2], uint16(l))
	out = append(out, []byte(server)...)
	binary.BigEndian.PutUint16(out[l+2:], uint16(port))
	return
}
