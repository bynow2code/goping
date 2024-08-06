package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
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
	conn, err := net.DialTimeout("ip4:icmp", "bing.com", timeout)
	if err != nil {
		log.Println(err.Error())
		return
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))

	icmp := ICMP{
		Type:           8,
		Code:           0,
		Checksum:       0,
		Identifier:     0,
		SequenceNumber: 0,
	}

	var buffer bytes.Buffer

	binary.Write(&buffer, binary.BigEndian, icmp)
	data := make([]byte, 48)
	binary.Write(&buffer, binary.BigEndian, data)

	request := buffer.Bytes()
	checkSum := calculateICMPChecksum(request)
	request[2] = byte(checkSum >> 8)
	request[3] = byte(checkSum)

	fmt.Println(request)

	_, err = conn.Write(request)
	if err != nil {
		log.Println(err.Error())
		return
	}

	response := make([]byte, 1024)
	_, err = conn.Read(response)
	if err != nil {
		log.Println(err.Error())
		return
	}
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
