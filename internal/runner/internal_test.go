package runner

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/oynozan/bugnet-run/frame"
)

func TestParsePid(t *testing.T) {
	t.Parallel()
	valid := map[string]int{"2": 2, "4321\n": 4321, " 99999 ": 99999, "2147483647": 2147483647}
	for in, want := range valid {
		if got, err := parsePid([]byte(in)); err != nil || got != want {
			t.Errorf("parsePid(%q) = %d, %v, want %d", in, got, err, want)
		}
	}
	// kill truncates to 32 bits, so the group of 4294967297 would become -1
	invalid := []string{
		"", "\n", "0", "1", "-1", "-4321", "+4321", "00", "01", "4321x", "43 21", "0x10", "1e3",
		"2147483648", "4294967295", "4294967297", "99999999999999999999",
	}
	for _, in := range invalid {
		if got, err := parsePid([]byte(in)); err == nil {
			t.Errorf("parsePid(%q) = %d, want an error", in, got)
		}
	}
}

// chaser appends to a job's stdout on every frame it receives, so a follower never catches up
type chaser struct {
	out    *os.File
	frames []frame.Frame
}

func (c *chaser) Write(p []byte) (int, error) {
	if len(c.frames) >= 1000 {
		return 0, errors.New("follower still draining after 1000 frames")
	}
	f, err := frame.NewDecoder(bytes.NewReader(p)).Next()
	if err != nil {
		return 0, err
	}
	c.frames = append(c.frames, f)
	if _, err := c.out.WriteString("more\n"); err != nil {
		return 0, err
	}
	return len(p), nil
}

func TestFollowStopsAtSizesSeenAtEnd(t *testing.T) {
	t.Parallel()
	dead := exec.Command("true")
	if err := dead.Run(); err != nil {
		t.Fatal(err)
	}
	hello := frame.Frame{Kind: frame.KindStdout, Data: []byte("hello\n")}
	cases := []struct {
		name    string
		file    string
		content string
		frames  []frame.Frame
		err     error
	}{
		{"exited", exitFile, "0\n", []frame.Frame{hello, {Kind: frame.KindExit, Out: 6}}, nil},
		{"lost", spidFile, strconv.Itoa(dead.Process.Pid), []frame.Frame{hello}, errJobLost},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			files := map[string]string{outFile: "hello\n", errFile: "", tc.file: tc.content}
			for name, content := range files {
				path := filepath.Join(dir, name)
				if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			out, err := os.OpenFile(filepath.Join(dir, outFile), os.O_WRONLY|os.O_APPEND, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = out.Close() }()

			c := &chaser{out: out}
			if err := follow(c, dir, 0, 0, time.Hour, 0); !errors.Is(err, tc.err) {
				t.Fatalf("follow returned %v, want %v", err, tc.err)
			}
			if !reflect.DeepEqual(c.frames, tc.frames) {
				t.Errorf("frames %+v, want %+v", c.frames, tc.frames)
			}
		})
	}
}
