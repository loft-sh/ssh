package ssh

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"

	"golang.org/x/crypto/ssh"
)

func generateSigner() (ssh.Signer, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(key)
}

func parsePtyRequest(s []byte) (pty Pty, ok bool) {
	term, s, ok := parseString(s)
	if !ok {
		return
	}
	width32, s, ok := parseUint32(s)
	if !ok {
		return
	}
	height32, _, ok := parseUint32(s)
	if !ok {
		return
	}
	pty = Pty{
		Term: term,
		Window: Window{
			Width:  int(width32),
			Height: int(height32),
		},
	}
	return
}

func parseX11Request(s []byte) (x11 X11, ok bool) {
	single, s, ok := parseBool(s)
	if !ok {
		return
	}
	protocol, s, ok := parseString(s)
	if !ok {
		return
	}
	data, s, ok := parseString(s)
	if !ok {
		return
	}
	screen, _, ok := parseUint32(s)
	if !ok {
		return
	}
	x11 = X11{
		SingleConnection: single,
		AuthProtocol: protocol,
		AuthData: data,
		ScreenNumber: int(screen),
	}
	return
}

func parseWinchRequest(s []byte) (win Window, ok bool) {
	width32, s, ok := parseUint32(s)
	if width32 < 1 {
		ok = false
	}
	if !ok {
		return
	}
	height32, _, ok := parseUint32(s)
	if height32 < 1 {
		ok = false
	}
	if !ok {
		return
	}
	win = Window{
		Width:  int(width32),
		Height: int(height32),
	}
	return
}

func parseString(in []byte) (out string, rest []byte, ok bool) {
	if len(in) < 4 {
		return
	}
	length := binary.BigEndian.Uint32(in)
	if uint32(len(in)) < 4+length {
		return
	}
	out = string(in[4 : 4+length])
	rest = in[4+length:]
	ok = true
	return
}

func parseUint32(in []byte) (uint32, []byte, bool) {
	if len(in) < 4 {
		return 0, nil, false
	}
	return binary.BigEndian.Uint32(in), in[4:], true
}

func parseBool(in []byte) (bool, []byte, bool) {
	if len(in) < 1 {
		return false, nil, false
	}
	return uint8(in[0]) == 1, in[1:], true
}
