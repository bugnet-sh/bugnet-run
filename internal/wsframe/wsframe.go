// Package wsframe speaks the part of RFC 6455 that a byte stream in binary messages needs
package wsframe

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Opcodes of RFC 6455 section 5.2
const (
	opContinuation = 0x0
	opText         = 0x1
	opBinary       = 0x2
	opClose        = 0x8
	opPing         = 0x9
	opPong         = 0xa
)

// Close codes of RFC 6455 section 7.4.1
const (
	closeNormal      = 1000
	closeProtocol    = 1002
	closeUnsupported = 1003
)

const (
	maxControl = 125
	closeWait  = time.Second
	acceptGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
)

// ErrProtocol means the peer broke RFC 6455 or sent a text message
var ErrProtocol = errors.New("websocket protocol error")

// ErrNotUpgrade means a request is not a WebSocket upgrade that offers the protocol
var ErrNotUpgrade = errors.New("not a websocket upgrade")

var errClosed = errors.New("websocket close already sent")

type header struct {
	fin    bool
	rsv    byte
	op     byte
	masked bool
	mask   [4]byte
	length int64
}

// Conn carries a byte stream in binary WebSocket messages, one message per Write
type Conn struct {
	conn   net.Conn
	br     *bufio.Reader
	client bool

	wmu       sync.Mutex
	closeSent bool

	left      int64
	mask      [4]byte
	masked    bool
	maskPos   int
	inMessage bool
	readErr   error
}

// NewConn wraps a connection past its handshake, br holding any bytes read beyond it
func NewConn(conn net.Conn, br *bufio.Reader, client bool) *Conn {
	return &Conn{conn: conn, br: br, client: client}
}

// Read returns the payload bytes of binary messages and io.EOF once the peer closes
func (c *Conn) Read(p []byte) (int, error) {
	for c.left == 0 {
		if c.readErr != nil {
			return 0, c.readErr
		}
		if err := c.next(); err != nil {
			c.readErr = err
			return 0, err
		}
	}
	if int64(len(p)) > c.left {
		p = p[:c.left]
	}
	n, err := c.br.Read(p)
	if c.masked {
		for i := range n {
			p[i] ^= c.mask[(c.maskPos+i)%4]
		}
		c.maskPos = (c.maskPos + n) % 4
	}
	c.left -= int64(n)
	if errors.Is(err, io.EOF) {
		err = io.ErrUnexpectedEOF
	}
	return n, err
}

// next reads frames until one starts message payload, answering control frames on the way
func (c *Conn) next() error {
	for {
		h, err := c.readHeader()
		if err != nil {
			return err
		}
		if h.rsv != 0 || h.masked == c.client {
			return c.fail(closeProtocol, "bad frame bits")
		}
		if h.op&0x8 != 0 {
			if err := c.control(h); err != nil {
				return err
			}
			continue
		}
		switch {
		case h.op == opText:
			return c.fail(closeUnsupported, "text message")
		case h.op == opBinary && c.inMessage, h.op == opContinuation && !c.inMessage:
			return c.fail(closeProtocol, "broken fragmentation")
		case h.op != opBinary && h.op != opContinuation:
			return c.fail(closeProtocol, fmt.Sprintf("opcode %#x", h.op))
		}
		c.inMessage = !h.fin
		c.left, c.mask, c.masked, c.maskPos = h.length, h.mask, h.masked, 0
		if c.left > 0 {
			return nil
		}
	}
}

func (c *Conn) control(h header) error {
	if !h.fin || h.length > maxControl {
		return c.fail(closeProtocol, "bad control frame")
	}
	payload := make([]byte, h.length)
	if _, err := io.ReadFull(c.br, payload); err != nil {
		return err
	}
	if h.masked {
		for i := range payload {
			payload[i] ^= h.mask[i%4]
		}
	}
	switch h.op {
	case opClose:
		echo := payload
		if len(echo) > 2 {
			echo = echo[:2]
		}
		_ = c.sendClose(echo)
		return io.EOF
	case opPing:
		return c.writeFrame(opPong, true, payload)
	case opPong:
		return nil
	}
	return c.fail(closeProtocol, fmt.Sprintf("opcode %#x", h.op))
}

// fail sends a close with code and leaves closing the connection to Close
func (c *Conn) fail(code int, why string) error {
	_ = c.sendClose(closePayload(code))
	return fmt.Errorf("%w: %s", ErrProtocol, why)
}

func (c *Conn) readHeader() (header, error) {
	var b [8]byte
	if _, err := io.ReadFull(c.br, b[:2]); err != nil {
		return header{}, err
	}
	h := header{fin: b[0]&0x80 != 0, rsv: b[0] & 0x70, op: b[0] & 0x0f, masked: b[1]&0x80 != 0}
	switch n := b[1] & 0x7f; n {
	case 126:
		if _, err := io.ReadFull(c.br, b[:2]); err != nil {
			return header{}, unexpected(err)
		}
		h.length = int64(binary.BigEndian.Uint16(b[:2]))
	case 127:
		if _, err := io.ReadFull(c.br, b[:8]); err != nil {
			return header{}, unexpected(err)
		}
		n := binary.BigEndian.Uint64(b[:8])
		if n>>63 != 0 {
			return header{}, c.fail(closeProtocol, "length past 63 bits")
		}
		h.length = int64(n)
	default:
		h.length = int64(n)
	}
	if h.masked {
		if _, err := io.ReadFull(c.br, h.mask[:]); err != nil {
			return header{}, unexpected(err)
		}
	}
	return h, nil
}

func unexpected(err error) error {
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}

// Write sends p as one binary message
func (c *Conn) Write(p []byte) (int, error) {
	if err := c.writeFrame(opBinary, true, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close sends a normal close unless one was sent, then closes the connection
func (c *Conn) Close() error {
	_ = c.sendClose(closePayload(closeNormal))
	return c.conn.Close()
}

func (c *Conn) sendClose(payload []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.closeSent {
		return nil
	}
	c.closeSent = true
	_ = c.conn.SetWriteDeadline(time.Now().Add(closeWait))
	defer func() { _ = c.conn.SetWriteDeadline(time.Time{}) }()
	return c.writeLocked(opClose, true, payload)
}

func (c *Conn) writeFrame(op byte, fin bool, payload []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.closeSent {
		return errClosed
	}
	return c.writeLocked(op, fin, payload)
}

func (c *Conn) writeLocked(op byte, fin bool, payload []byte) error {
	var hdr [14]byte
	hdr[0] = op
	if fin {
		hdr[0] |= 0x80
	}
	n := 2
	switch l := len(payload); {
	case l <= maxControl:
		hdr[1] = byte(l)
	case l <= 0xffff:
		hdr[1] = 126
		binary.BigEndian.PutUint16(hdr[2:], uint16(l))
		n = 4
	default:
		hdr[1] = 127
		binary.BigEndian.PutUint64(hdr[2:], uint64(l))
		n = 10
	}
	if c.client {
		hdr[1] |= 0x80
		key := hdr[n : n+4]
		_, _ = rand.Read(key)
		n += 4
		masked := make([]byte, len(payload))
		for i, b := range payload {
			masked[i] = b ^ key[i%4]
		}
		payload = masked
	}
	bufs := net.Buffers{hdr[:n], payload}
	_, err := bufs.WriteTo(c.conn)
	return err
}

func closePayload(code int) []byte {
	return binary.BigEndian.AppendUint16(nil, uint16(code))
}

/* Handshake */

// AcceptKey returns the Sec-WebSocket-Accept value for a Sec-WebSocket-Key
func AcceptKey(key string) string {
	sum := sha1.Sum([]byte(key + acceptGUID))
	return base64.StdEncoding.EncodeToString(sum[:])
}

// Check reports whether r is a WebSocket upgrade that offers protocol
func Check(r *http.Request, protocol string) error {
	if r.Method != http.MethodGet || !hasToken(r.Header, "Connection", "upgrade", false) ||
		!hasToken(r.Header, "Upgrade", "websocket", false) ||
		r.Header.Get("Sec-WebSocket-Version") != "13" {
		return ErrNotUpgrade
	}
	key, err := base64.StdEncoding.DecodeString(r.Header.Get("Sec-WebSocket-Key"))
	if err != nil || len(key) != 16 {
		return ErrNotUpgrade
	}
	if protocol != "" && !hasToken(r.Header, "Sec-WebSocket-Protocol", protocol, true) {
		return ErrNotUpgrade
	}
	return nil
}

// Accept answers r's upgrade for protocol, sending the headers already set on w with the 101
func Accept(w http.ResponseWriter, r *http.Request, protocol string) (*Conn, error) {
	if err := Check(r, protocol); err != nil {
		return nil, err
	}
	conn, rw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	h := w.Header().Clone()
	h.Set("Upgrade", "websocket")
	h.Set("Connection", "Upgrade")
	h.Set("Sec-WebSocket-Accept", AcceptKey(r.Header.Get("Sec-WebSocket-Key")))
	if protocol != "" {
		h.Set("Sec-WebSocket-Protocol", protocol)
	}
	var b bytes.Buffer
	b.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
	_ = h.Write(&b)
	b.WriteString("\r\n")
	if _, err := conn.Write(b.Bytes()); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return NewConn(conn, rw.Reader, false), nil
}

// UpgradeError is an answer to Handshake other than a WebSocket 101 for the protocol
type UpgradeError struct {
	// Status is the answer's HTTP status
	Status int
	why    string
}

func (e *UpgradeError) Error() string {
	return fmt.Sprintf("websocket upgrade answered %d: %s", e.Status, e.why)
}

// Handshake asks the server at the far end of conn to upgrade path on host for protocol
func Handshake(conn net.Conn, host, path, protocol string, h http.Header) (*Conn, error) {
	if strings.ContainsAny(host+path+protocol, " \t\r\n") || !strings.HasPrefix(path, "/") {
		return nil, errors.New("websocket handshake target holds a space or a line break")
	}
	var nonce [16]byte
	_, _ = rand.Read(nonce[:])
	key := base64.StdEncoding.EncodeToString(nonce[:])
	out := h.Clone()
	if out == nil {
		out = http.Header{}
	}
	out.Set("Upgrade", "websocket")
	out.Set("Connection", "Upgrade")
	out.Set("Sec-WebSocket-Key", key)
	out.Set("Sec-WebSocket-Version", "13")
	if protocol != "" {
		out.Set("Sec-WebSocket-Protocol", protocol)
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "GET %s HTTP/1.1\r\nHost: %s\r\n", path, host)
	_ = out.Write(&b)
	b.WriteString("\r\n")
	if _, err := conn.Write(b.Bytes()); err != nil {
		return nil, err
	}
	br := bufio.NewReader(conn)
	res, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		return nil, err
	}
	_ = res.Body.Close()
	switch {
	case res.StatusCode != http.StatusSwitchingProtocols:
		return nil, &UpgradeError{Status: res.StatusCode, why: "not switching protocols"}
	case !hasToken(res.Header, "Upgrade", "websocket", false) ||
		!hasToken(res.Header, "Connection", "upgrade", false):
		return nil, &UpgradeError{Status: res.StatusCode, why: "not a websocket upgrade"}
	case res.Header.Get("Sec-WebSocket-Accept") != AcceptKey(key):
		return nil, &UpgradeError{Status: res.StatusCode, why: "wrong accept key"}
	case res.Header.Get("Sec-WebSocket-Protocol") != protocol:
		return nil, &UpgradeError{Status: res.StatusCode, why: "another subprotocol"}
	}
	return NewConn(conn, br, true), nil
}

func hasToken(h http.Header, name, token string, exact bool) bool {
	for _, v := range h.Values(name) {
		for t := range strings.SplitSeq(v, ",") {
			t = strings.TrimSpace(t)
			if t == token || !exact && strings.EqualFold(t, token) {
				return true
			}
		}
	}
	return false
}
