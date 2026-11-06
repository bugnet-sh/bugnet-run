// Command fakesshd stands in for sshd in tests, listening where its config says and logging signals
package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// hupDelay is how long the old listener answers after a SIGHUP, as when sshd acts on it late
const hupDelay = 300 * time.Millisecond

func main() {
	cfgPath, test := "", false
	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-t":
			test = true
		case "-f":
			if i+1 < len(args) {
				i++
				cfgPath = args[i]
			}
		case "-D", "-e":
		default:
			die("unknown flag")
		}
	}
	cfg, err := readConfig(cfgPath)
	if err != nil || cfg["port"] == "" || cfg["pidfile"] == "" || cfg["listenaddress"] == "" {
		die("bad config")
	}
	if test {
		if cfg["refuse"] != "" {
			die("refused SetEnv " + cfg["setenv"])
		}
		if key := cfg["hostkey"]; key != "" {
			if _, err := os.ReadFile(key); err != nil {
				die("no hostkeys available")
			}
		}
		return
	}
	logPath := filepath.Join(filepath.Dir(cfgPath), "fake-sshd.log")
	ln := listen(cfg)
	record(logPath, "start "+cfg["port"])
	pidFile := cfg["pidfile"]
	writePid(pidFile)
	signals := make(chan os.Signal, 4)
	signal.Notify(signals, syscall.SIGHUP, syscall.SIGTERM)
	for sig := range signals {
		if sig == syscall.SIGTERM {
			_ = os.Remove(pidFile)
			return
		}
		// sshd drops its pid file and listener, runs itself again, and writes the pid file last
		time.Sleep(hupDelay)
		_ = os.Remove(pidFile)
		_ = ln.Close()
		next, err := readConfig(cfgPath)
		if err != nil {
			die("bad config on reload")
		}
		ln = listen(next)
		record(logPath, "hup "+next["port"])
		pidFile = next["pidfile"]
		writePid(pidFile)
	}
}

func writePid(path string) {
	if err := os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o644); err != nil {
		die("pid file")
	}
}

// readConfig returns the first value of each keyword in lower case, as sshd reads them
func readConfig(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	cfg := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, _ := strings.Cut(strings.TrimSpace(sc.Text()), " ")
		k = strings.ToLower(k)
		if _, ok := cfg[k]; !ok && k != "" && !strings.HasPrefix(k, "#") {
			cfg[k] = v
		}
	}
	return cfg, sc.Err()
}

func listen(cfg map[string]string) net.Listener {
	ln, err := net.Listen("tcp", net.JoinHostPort(cfg["listenaddress"], cfg["port"]))
	if err != nil {
		die("listen")
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("SSH-2.0-fake\r\n"))
			_ = c.Close()
		}
	}()
	return ln
}

func record(path, line string) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		die("log")
	}
	_, _ = fmt.Fprintln(f, line)
	_ = f.Close()
}

func die(msg string) {
	_, _ = fmt.Fprintln(os.Stderr, "fakesshd: "+msg)
	os.Exit(1)
}
