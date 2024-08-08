package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"time"
)

type ICMP struct {
	Type           uint8
	Code           uint8
	Checksum       uint16
	Identifier     uint16
	SequenceNumber uint16
	Data           [48]byte
}

var (
	address string
)

func init() {
	log.SetFlags(log.Llongfile)
	getAddress()
}

func main() {
	timeout := 3000 * time.Millisecond
	conn, err := net.DialTimeout("ip4:icmp", address, timeout)
	if err != nil {
		log.Println(err.Error())
		return
	}
	defer conn.Close()

	var icmp ICMP
	remoteAddr := conn.RemoteAddr()
	fmt.Printf("PING %s (%s): %d data bytes\n", address, remoteAddr, binary.Size(icmp))

	for i := 0; i < 5; i++ {
		icmp = ICMP{Type: 8, SequenceNumber: uint16(i)}

		pid := os.Getpid()
		icmp.Identifier = binary.BigEndian.Uint16([]byte{byte(pid >> 8), byte(pid & 0xfff)})

		conn.SetDeadline(time.Now().Add(timeout))

		var buffer bytes.Buffer
		err := binary.Write(&buffer, binary.BigEndian, icmp)
		if err != nil {
			log.Fatalln(err.Error())
		}

		request := buffer.Bytes()
		checkSum := calculateICMPChecksum(request)
		request[2] = byte(checkSum >> 8)
		request[3] = byte(checkSum)

		_, err = conn.Write(request)
		if err != nil {
			log.Fatalln(err.Error())
		}

		response := make([]byte, 1024)
		startReplyTime := time.Now()
		readN, err := conn.Read(response)
		if err != nil {
			log.Fatalln(err.Error())
		}

		replyTime := float64(time.Since(startReplyTime).Nanoseconds()) / float64(time.Millisecond)
		fmt.Printf("%d bytes from %s: icmp_seq=%d ttl=%d time=%.3f ms\n", readN-20, remoteAddr, icmp.SequenceNumber, response[8], replyTime)
		time.Sleep(time.Second)
	}
}
func getAddress() {
	if len(os.Args) == 1 {
		log.Fatalln("Address required")
	}
	address = os.Args[len(os.Args)-1]
}
func calculateICMPChecksum(buf []byte) uint16 {
	var sum uint32
	// 处理奇数长度的情况
	if len(buf)%2 != 0 {
		buf = append(buf, 0)
	}

	// 对所有16位字做二进制加法
	for i := 0; i < len(buf); i += 2 {
		word := binary.BigEndian.Uint16(buf[i : i+2])
		sum += uint32(word)
	}

	// 加上进位
	for sum>>16 > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	// 取反得到校验和
	checksum := ^uint16(sum)
	return checksum
}
