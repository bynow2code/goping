package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"math"
	"net"
	"os"
	"os/signal"
	"syscall"
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
	timeout time.Duration
)

var (
	totalT      int64
	minDelay    int64 = math.MaxInt64
	maxDelay    int64 = math.MinInt64
	transmitted int
	received    int
)

func init() {
	log.SetFlags(log.Llongfile)
	flagParse()
	setAddress()
}

func main() {
	go func() {
		for i := 0; ; i++ {
			conn, err := net.DialTimeout("ip4:icmp", address, timeout)
			if err != nil {
				log.Fatalln(err.Error())
			}

			remoteAddr := conn.RemoteAddr()
			icmp := ICMP{}
			icmp.Type = 8
			icmp.SequenceNumber = uint16(i)
			pid := os.Getpid()
			icmp.Identifier = binary.BigEndian.Uint16([]byte{byte(pid >> 8), byte(pid & 0xfff)})

			if i == 0 {
				fmt.Printf("PING %s (%s): %d data bytes\n", address, remoteAddr, binary.Size(icmp))
			}

			var buffer bytes.Buffer
			err = binary.Write(&buffer, binary.BigEndian, icmp)
			if err != nil {
				log.Fatalln(err.Error())
			}

			request := buffer.Bytes()

			checkSum := calculateICMPChecksum(request)
			request[2] = byte(checkSum >> 8)
			request[3] = byte(checkSum)

			err = conn.SetDeadline(time.Now().Add(timeout))
			if err != nil {
				log.Fatalln(err.Error())
			}

			_, err = conn.Write(request)
			if err != nil {
				log.Fatalln(err.Error())
			} else {
				transmitted++
			}

			response := make([]byte, 1024)
			startReplyTime := time.Now()
			r, err := conn.Read(response)
			if err != nil {
				_ = conn.Close()
				fmt.Printf("Request timeout for icmp_seq %d\n", icmp.SequenceNumber)
				time.Sleep(time.Second)
				continue
			} else {
				received++
				t := time.Since(startReplyTime).Nanoseconds()
				totalT += t
				maxDelay = max(t, maxDelay)
				minDelay = min(t, minDelay)

				replyTime := float64(t) / float64(time.Millisecond)
				fmt.Printf("%d bytes from %s: icmp_seq=%d ttl=%d time=%.3f ms\n", r-20, remoteAddr, icmp.SequenceNumber, response[8], replyTime)
				time.Sleep(time.Second)
			}
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT)

	<-sigChan
	loss := float64(transmitted-received) / float64(transmitted) * 100
	fmt.Printf("\n--- %s ping statistics ---\n", address)
	fmt.Printf("%d packets transmitted, %d packets received, %.2f%% packet loss\n", transmitted, received, loss)

	maxTime := 0.0
	minTime := 0.0
	avgTime := 0.0
	if transmitted == 0 {
		maxTime = float64(maxDelay) / float64(time.Millisecond)
		minTime = float64(minDelay) / float64(time.Millisecond)
		avgTime = float64(totalT) / float64(transmitted) / float64(time.Millisecond)
	}
	fmt.Printf("round-trip min/max/avg = %.3f/%.3f/%.3f\n", minTime, maxTime, avgTime)
	os.Exit(0)
}

func setAddress() {
	if len(os.Args) == 1 {
		log.Fatalln("address required")
	}
	address = os.Args[len(os.Args)-1]
}
func flagParse() {
	flag.DurationVar(&timeout, "t", 1000*time.Millisecond, "设置icmp拨号、请求和响应等待时间")
	flag.Parse()
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
