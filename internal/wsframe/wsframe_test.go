package wsframe

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

func eq[T any](t *testing.T, got, want T) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// pair returns a server and a client end of one loopback TCP connection
func pair(t *testing.T) (server, client *Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	defer func() { _ = ln.Close() }()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
		close(accepted)
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	must(t, err)
	s := <-accepted
	if s == nil {
		t.Fatal("accept failed")
	}
	server = NewConn(s, bufio.NewReader(s), false)
	client = NewConn(c, bufio.NewReader(c), true)
	t.Cleanup(func() { _ = s.Close(); _ = c.Close() })
	return server, client
}

func TestAcceptKey(t *testing.T) {
	t.Parallel()
	eq(t, AcceptKey("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
}

func TestBinaryBothWaysAtEveryLengthForm(t *testing.T) {
	t.Parallel()
	server, client := pair(t)
	for _, n := range []int{0, 1, 125, 126, 127, 65535, 65536, 300000} {
		msg := make([]byte, n)
		_, _ = rand.Read(msg)
		for _, dir := range [][2]*Conn{{client, server}, {server, client}} {
			go func() { _, _ = dir[0].Write(msg) }()
			got := make([]byte, n)
			_, err := io.ReadFull(dir[1], got)
			must(t, err)
			if !bytes.Equal(got, msg) {
				t.Fatalf("%d bytes arrived changed", n)
			}
		}
	}
}

func TestClientFramesAreMaskedServerFramesAreNot(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	for _, client := range []bool{true, false} {
		c := NewConn(a, bufio.NewReader(a), client)
		go func() { _, _ = c.Write([]byte("hi")) }()
		head := make([]byte, 2)
		_, err := io.ReadFull(b, head)
		must(t, err)
		eq(t, head[0], byte(0x82))
		eq(t, head[1]&0x80 != 0, client)
		rest := 2
		if client {
			rest += 4
		}
		_, err = io.ReadFull(b, make([]byte, rest))
		must(t, err)
	}
}

func TestPingIsAnsweredAndFragmentsJoin(t *testing.T) {
	t.Parallel()
	server, client := pair(t)
	must(t, client.writeFrame(opPing, true, []byte("p1")))
	must(t, client.writeFrame(opBinary, false, []byte("ab")))
	must(t, client.writeFrame(opPong, true, nil))
	must(t, client.writeFrame(opContinuation, false, []byte("cd")))
	must(t, client.writeFrame(opContinuation, true, []byte("ef")))
	got := make([]byte, 6)
	_, err := io.ReadFull(server, got)
	must(t, err)
	eq(t, string(got), "abcdef")

	op, fin, payload := readRawFrame(t, client)
	eq(t, op, byte(opPong))
	eq(t, fin, true)
	eq(t, string(payload), "p1")
}

func TestCloseHandshake(t *testing.T) {
	t.Parallel()
	server, client := pair(t)
	done := make(chan error, 1)
	go func() {
		_, err := server.Read(make([]byte, 1))
		done <- err
	}()
	must(t, client.writeFrame(opClose, true, closePayload(closeNormal)))
	eq(t, <-done, io.EOF)
	op, _, payload := readRawFrame(t, client)
	eq(t, op, byte(opClose))
	eq(t, binary.BigEndian.Uint16(payload), uint16(closeNormal))

	_, err := server.Read(make([]byte, 1))
	eq(t, err, io.EOF)
}

func TestProtocolErrorsClose(t *testing.T) {
	t.Parallel()
	cases := map[string]func(c *Conn) error{
		"text": func(c *Conn) error { return c.writeFrame(opText, true, []byte("x")) },
		"bare continuation": func(c *Conn) error {
			return c.writeFrame(opContinuation, true, []byte("x"))
		},
		"binary inside a message": func(c *Conn) error {
			if err := c.writeFrame(opBinary, false, []byte("x")); err != nil {
				return err
			}
			return c.writeFrame(opBinary, true, []byte("y"))
		},
		"long ping": func(c *Conn) error {
			return c.writeFrame(opPing, true, make([]byte, 126))
		},
	}
	for name, send := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			server, client := pair(t)
			must(t, send(client))
			_, err := io.ReadAll(server)
			eq(t, errors.Is(err, ErrProtocol), true)
			op, _, _ := readRawFrame(t, client)
			eq(t, op, byte(opClose))
		})
	}
}

func TestServerRefusesUnmaskedFrames(t *testing.T) {
	t.Parallel()
	server, client := pair(t)
	client.client = false
	must(t, client.writeFrame(opBinary, true, []byte("x")))
	_, err := server.Read(make([]byte, 1))
	eq(t, errors.Is(err, ErrProtocol), true)
}

func TestAcceptChecksTheUpgrade(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Bugnet-Gate-Response", "1")
		c, err := Accept(w, r, "bugnet-ssh.v1")
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		defer func() { _ = c.Close() }()
		_, _ = io.Copy(c, c)
	}))
	t.Cleanup(srv.Close)

	good := func() http.Header {
		return http.Header{
			"Upgrade": {"websocket"}, "Connection": {"keep-alive, Upgrade"},
			"Sec-Websocket-Version": {"13"}, "Sec-Websocket-Key": {"dGhlIHNhbXBsZSBub25jZQ=="},
			"Sec-Websocket-Protocol": {"other, bugnet-ssh.v1"},
		}
	}
	conn, br, res := dialUpgrade(t, srv.Listener.Addr().String(), good())
	eq(t, res.StatusCode, http.StatusSwitchingProtocols)
	eq(t, res.Header.Get("Sec-Websocket-Accept"), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
	eq(t, res.Header.Get("Sec-Websocket-Protocol"), "bugnet-ssh.v1")
	eq(t, res.Header.Get("Bugnet-Gate-Response"), "1")
	c := NewConn(conn, br, true)
	_, err := c.Write([]byte("echo"))
	must(t, err)
	got := make([]byte, 4)
	_, err = io.ReadFull(c, got)
	must(t, err)
	eq(t, string(got), "echo")

	for name, change := range map[string]func(http.Header){
		"no upgrade":    func(h http.Header) { h.Del("Upgrade") },
		"no connection": func(h http.Header) { h.Set("Connection", "keep-alive") },
		"version 8":     func(h http.Header) { h.Set("Sec-Websocket-Version", "8") },
		"short key":     func(h http.Header) { h.Set("Sec-Websocket-Key", "c2hvcnQ=") },
		"protocol":      func(h http.Header) { h.Set("Sec-Websocket-Protocol", "bugnet-ssh.v2") },
	} {
		h := good()
		change(h)
		_, _, res := dialUpgrade(t, srv.Listener.Addr().String(), h)
		if res.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", name, res.StatusCode)
		}
	}
}

func dialUpgrade(t *testing.T, addr string,
	h http.Header) (net.Conn, *bufio.Reader, *http.Response) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	must(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	req, err := http.NewRequest(http.MethodGet, "http://"+addr+"/", nil)
	must(t, err)
	req.Header = h
	must(t, req.Write(conn))
	br := bufio.NewReader(conn)
	must(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	res, err := http.ReadResponse(br, req)
	must(t, err)
	must(t, conn.SetReadDeadline(time.Time{}))
	return conn, br, res
}

// readRawFrame reads one whole unmasked frame the server side wrote
func readRawFrame(t *testing.T, c *Conn) (byte, bool, []byte) {
	t.Helper()
	must(t, c.conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	h, err := c.readHeader()
	must(t, err)
	payload := make([]byte, h.length)
	_, err = io.ReadFull(c.br, payload)
	must(t, err)
	return h.op, h.fin, payload
}
