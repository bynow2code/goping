package gpconn

import (
	"log"
	"net"
	"time"
)

type IGPConn interface {
	Ok() bool
	RemoteAddr() net.Addr
	SetDeadline(t time.Time)
	Read(b []byte) (n int, err error)
	Write(b []byte) (n int, err error)
	Close()
}

type GPConn struct {
	conn net.Conn
}

func (G *GPConn) Ok() bool {
	return G.conn != nil
}

func DialTimeout(address string, timeout time.Duration) IGPConn {
	conn, err := net.DialTimeout("ip4:icmp", address, timeout)
	if err != nil {
		log.Fatalln(err.Error())
	}
	return &GPConn{conn: conn}
}

func (G *GPConn) Close() {
	if G.Ok() {
		_ = G.conn.Close()
		G.conn = nil
	}
}

func (G *GPConn) Read(b []byte) (n int, err error) {
	return G.conn.Read(b)
}

func (G *GPConn) Write(b []byte) (n int, err error) {
	return G.conn.Write(b)
}

func (G *GPConn) RemoteAddr() net.Addr {
	return G.conn.RemoteAddr()
}

func (G *GPConn) SetDeadline(t time.Time) {
	err := G.conn.SetDeadline(t)
	if err != nil {
		log.Fatalln(err.Error())
	}
}
