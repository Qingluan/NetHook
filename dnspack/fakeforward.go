package dnspack

import (
	"crypto/rand"
	"log"
	"net"
	"sync"

	// "github.com/Qingluan/HookNet/ptrace"
	"golang.org/x/net/dns/dnsmessage"
)

var (
	IPDomainMAP = make(map[[4]byte]string)
	DomainIPMAP = make(map[string][4]byte)
	LOCKER      sync.RWMutex
)

func SearchByIP(ip [4]byte) string {
	o, ok := IPDomainMAP[ip]
	if ok {
		return o
	}
	i := net.IP{ip[0], ip[1], ip[2], ip[3]}
	return i.String()
}

func FindByDomain(domain string) (ip [4]byte) {
	if e, ok := DomainIPMAP[domain]; ok {
		return e
	}
	LOCKER.Lock()
	defer LOCKER.Unlock()
	token := make([]byte, 4)
	rand.Read(token)
	ip[0] = token[0]
	ip[1] = token[1]
	ip[2] = token[2]
	ip[3] = token[3]
	DomainIPMAP[domain] = ip
	IPDomainMAP[ip] = domain
	return
}

func (s *DNSService) GetADNSReply(p *dnsmessage.Message) (reply []byte, err error) {
	q := p.Questions[0]
	domain := q.Name.String()
	log.Println("Try to Random:", domain)
	ip := FindByDomain(domain)
	// ip := [4]byte{127, 0, 0, 1}
	p.Answers = append(p.Answers, dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name:  q.Name,
			Class: dnsmessage.ClassINET,
		},
		Body: &dnsmessage.AResource{
			A: ip,
		},
	})
	reply, err = p.Pack()
	return
}

func (s *DNSService) QueryFake(p Packet) {
	if len(p.message.Questions) == 0 {
		return
	}
	// q := p.message.Questions[0]

	packed, err := s.GetADNSReply(&p.message)
	if err != nil {
		log.Println(err)
		return
	}
	// ptrace.L.GI("Found In Hook DNS Server: IP Answer ->", p.message.Answers)
	_, err = s.conn.WriteToUDP(packed, &p.addr)
	if err != nil {
		log.Println(err)
	}
}
