package ssh

import (
	"encoding/binary"
	"encoding/hex"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
	"syscall"
	"unsafe"

	gossh "golang.org/x/crypto/ssh"
)

const (
	x11RequestType = "x11-req"
	x11ChannelType = "x11"

	X11DisplayHost = "localhost"
	X11DisplayBasePort = 6000
	X11DisplayOffset = 10
)

type x11ChannelData struct {
	OriginAddr string
	OriginPort uint32
}

type XAuthority struct {
	Family    uint16
	AddrLen   uint16
	Addr      string
	NumberLen uint16
	Number    string
	NameLen   uint16
	Name      string
	DataLen   uint16
	Data      string
}

// isLittleEndian returns whether the host architecture uses little-endian.
func isLittleEndian() bool {
	var i int32 = 0x01020304
	u := unsafe.Pointer(&i)
	pb := (*byte)(u)
	b := *pb
	return b == 0x04
}

// prepareXAuthority returns the content of an .Xauthority file that can be
// used to connect to the proxied X11 display, using the fake authentication
// data created by the SSH client.
func prepareXAuthority(request X11, seat int) ([]byte, error) {
	data, err := hex.DecodeString(request.AuthData)
	if err != nil {
		return nil, err
	}

	hostname, err := os.Hostname()
	if err != nil {
		return nil, err
	}

	family := uint16(syscall.AF_LOCAL)
	number := strconv.Itoa(seat)

	addrLen := uint16(len(hostname))
	numberLen := uint16(len(number))
	nameLen := uint16(len(request.AuthProtocol))
	dataLen := uint16(len(data))

	buf := make([]byte, addrLen + numberLen + nameLen + dataLen + 2*5)
	pos := uint16(0)

	if isLittleEndian() {
		binary.LittleEndian.PutUint16(buf[pos:], family)
	} else {
		binary.BigEndian.PutUint16(buf[pos:], family)
	}
	pos += 2

	binary.BigEndian.PutUint16(buf[pos:], addrLen)
	pos += 2
	copy(buf[pos:], []byte(hostname))
	pos += addrLen

	binary.BigEndian.PutUint16(buf[pos:], numberLen)
	pos += 2
	copy(buf[pos:], []byte(number))
	pos += numberLen

	binary.BigEndian.PutUint16(buf[pos:], nameLen)
	pos += 2
	copy(buf[pos:], []byte(request.AuthProtocol))
	pos += nameLen

	binary.BigEndian.PutUint16(buf[pos:], dataLen)
	pos += 2
	copy(buf[pos:], data)
	return buf, nil
}

// NewX11Forwarder sets up a temporary TCP socket that can be communicated
// to the session environment and used for forwarding X11 traffic.
// It also sets up an Xauthority file with appropriate authentication data.
func NewX11Forwarder(request X11) (net.Listener, *os.File, error) {
	var err error

	xauthFile, err := ioutil.TempFile("", ".Xauthority")
	if err != nil {
		return nil, nil, err
	}

	// Try to find an available port to proxy X11 connections.
	// X11DisplayOffset is used to limit the risk of a conflict with
	// the host's X11 seats.
	for i := 0; i < 50; i++ {
		port := int(X11DisplayBasePort + X11DisplayOffset + i)
		addr := net.JoinHostPort(X11DisplayHost, strconv.Itoa(port))
		ln, err := net.Listen("tcp", addr)
		if err == nil {
			buf, err := prepareXAuthority(request, X11DisplayOffset + i)
			if err != nil {
				ln.Close()
				os.Remove(xauthFile.Name())
				return nil, nil, err
			}

			err = os.WriteFile(xauthFile.Name(), buf, 0600)
			if err != nil {
				ln.Close()
				os.Remove(xauthFile.Name())
				return nil, nil, err
			}

			return ln, xauthFile, nil
		}
		log.Println(err)
	}

	os.Remove(xauthFile.Name())
	return nil, nil, err
}

// ForwardX11Connections takes X11 connections from a listener and proxies them
// through the SSH tunnel to the client's DISPLAY.
func ForwardX11Connections(l net.Listener, xauth *os.File, s Session) {
	defer os.Remove(xauth.Name())
	sshConn := s.Context().Value(ContextKeyConn).(gossh.Conn)
	for {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		go func(conn net.Conn) {
			defer conn.Close()
			originAddr, orignPortStr, _ := net.SplitHostPort(conn.RemoteAddr().String())
			originPort, _ := strconv.Atoi(orignPortStr)
			payload := gossh.Marshal(&x11ChannelData{
				OriginAddr: originAddr,
				OriginPort: uint32(originPort),
			})
			channel, reqs, err := sshConn.OpenChannel(x11ChannelType, payload)
			if err != nil {
				return
			}
			defer channel.Close()
			go gossh.DiscardRequests(reqs)
			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				io.Copy(conn, channel)
				conn.(*net.TCPConn).CloseWrite()
				wg.Done()
			}()
			go func() {
				io.Copy(channel, conn)
				channel.CloseWrite()
				wg.Done()
			}()
			wg.Wait()
		}(conn)
	}
}
