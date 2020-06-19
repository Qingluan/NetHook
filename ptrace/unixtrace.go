package ptrace

import (
	"bytes"
	"encoding/binary"
	"flag"
	"io"
	"net"
	"os"
)

var (
	SMSG           = []byte("SET")
	RMSG           = []byte("GET")
	OKMSG          = []byte("OJBK")
	UnixServerAddr = flag.String("Service", "", "-Service 127.0.0.1:1091")
)

type UnixSocket struct {
	filename string
	bufsize  int
	handler  func([]byte) []byte
}

func NewUnixSocket(filename string, size ...int) *UnixSocket {
	size1 := 10480
	if size != nil {
		size1 = size[0]
	}
	return &UnixSocket{
		filename: filename,
		bufsize:  size1,
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
	if _, err = c.Write(sendbuf); err != nil {
		return
	}
	recvbuf = make([]byte, sock.bufsize)
	if nr, err := c.Read(recvbuf); err != nil {
		return nil, err
	} else {
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
	sock *UnixSocket
	buf  chan []byte
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
		}
		return
	})
}

func (csock *CacheUnixSocket) Recv() ([]byte, error) {
	return csock.sock.Client(RMSG)
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

func (Red *Redirector) Socks5Server() {
	serv, err := net.Listen("tcp", ":50092")
	go Red.SockServer.StartService()

	if err != nil {
		L.Fatal(err)
	}
	L.GI("Listen tcp : ", ":50092")
	for {

		con, err := serv.Accept()
		L.GI("R:", con)
		if err != nil {
			L.MI("Accept Err:", err)
			continue
		}
		realServerInfo := <-Red.SockServer.buf

		go Red.RedirectTo(con, realServerInfo)

	}
}

func (Red *Redirector) RedirectTo(con net.Conn, realServer []byte) {
	// defer con.SetReadDeadline(20 * time.Second)
	defer con.Close()
	L.GI("-->", realServer)
	data := []byte{0x05, 0x01, 0x00, 0x03}
	data = append(data, realServer...)
	con2, err := net.Dial("tcp", Red.RedirectServer)
	if err != nil {
		L.Fatal(err, "Redirect Socks5:")
	}
	defer con2.Close()
	con2.Write(data)
	go io.Copy(con2, con)
	io.Copy(con, con2)

}

func PackAddrToBuf(server string, port int) (out []byte) {
	l := len(server)
	out = make([]byte, l+4)
	binary.BigEndian.PutUint16(out[:2], uint16(l))
	out = append(out, []byte(server)...)
	binary.BigEndian.PutUint16(out[l+2:], uint16(port))
	return
}
