package main

import (
	"log"
	"net"
	"time"
)

type ICMP struct {
	Type           uint8
	Code           uint8
	Checksum       uint16
	Identifier     uint16
	SequenceNumber uint16
}

func init() {
	log.SetFlags(log.Llongfile)
}

func main() {
	timeout := 3000 * time.Millisecond
	conn, err := net.DialTimeout("ip:icmp", "bing.com", timeout)
	if err != nil {
		log.Println(err.Error())
		return
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))
}
