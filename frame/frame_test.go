package frame_test

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/oynozan/bugnet-run/frame"
)

func allBytes() []byte {
	b := make([]byte, 256)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

func sampleFrames() []frame.Frame {
	return []frame.Frame{
		{Kind: frame.KindStdout, Offset: 0, Data: []byte("hello\n")},
		{Kind: frame.KindStdout, Offset: 6, Data: []byte("10%\r50%\r\n")},
		{Kind: frame.KindStderr, Offset: 1 << 40, Data: allBytes()},
		{Kind: frame.KindHeartbeat, Out: 15, Err: 256},
		{Kind: frame.KindExit, Code: 3, Out: 15, Err: 256},
		{Kind: frame.KindExit},
		{Kind: frame.KindError, Reason: frame.ReasonJobExists},
		{Kind: frame.KindError, Reason: frame.ReasonJobNotFound},
		{Kind: frame.KindError, Reason: frame.ReasonBadArgs},
		{Kind: frame.KindError, Reason: frame.ReasonSpawnFailed},
		{Kind: frame.KindError, Reason: frame.ReasonJobLost},
		{Kind: frame.KindPong},
	}
}

func encodeAll(t *testing.T, frames []frame.Frame) []byte {
	t.Helper()
	var buf bytes.Buffer
	for _, f := range frames {
		if err := frame.Encode(&buf, f); err != nil {
			t.Fatalf("Encode(%+v): %v", f, err)
		}
	}
	return buf.Bytes()
}

func decodeAll(t *testing.T, r io.Reader) []frame.Frame {
	t.Helper()
	dec := frame.NewDecoder(r)
	var got []frame.Frame
	for {
		f, err := dec.Next()
		if errors.Is(err, io.EOF) {
			return got
		}
		if err != nil {
			t.Fatalf("Next after %d frames: %v", len(got), err)
		}
		got = append(got, f)
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	want := sampleFrames()
	stream := encodeAll(t, want)

	lines := bytes.SplitAfter(stream, []byte("\n"))
	if last := lines[len(lines)-1]; len(last) != 0 {
		t.Fatalf("stream does not end with a newline, trailing %q", last)
	}
	if n := len(lines) - 1; n != len(want) {
		t.Fatalf("got %d lines for %d frames", n, len(want))
	}
	if !bytes.Contains(stream, []byte(`{"t":"o","d":"aGVsbG8K"}`)) {
		t.Errorf("stdout frame not encoded with the short field names: %s", stream)
	}

	got := decodeAll(t, bytes.NewReader(stream))
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip mismatch\n got %+v\nwant %+v", got, want)
	}
}

func TestDecoderPartialLines(t *testing.T) {
	want := sampleFrames()
	stream := encodeAll(t, want)

	for i := 0; i <= len(stream); i++ {
		r := io.MultiReader(bytes.NewReader(stream[:i]), bytes.NewReader(stream[i:]))
		if got := decodeAll(t, r); !reflect.DeepEqual(got, want) {
			t.Fatalf("split at byte %d\n got %+v\nwant %+v", i, got, want)
		}
	}
	if got := decodeAll(t, iotest.OneByteReader(bytes.NewReader(stream))); !reflect.DeepEqual(
		got, want) {
		t.Fatalf("one byte reads\n got %+v\nwant %+v", got, want)
	}
}

func TestDecoderRejectsGarbage(t *testing.T) {
	cases := []struct {
		name, line string
	}{
		{"not json", "this is not json"},
		{"missing kind", `{"off":3}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stream := encodeAll(t, []frame.Frame{{Kind: frame.KindPong}})
			stream = append(stream, tc.line+"\n"...)
			dec := frame.NewDecoder(bytes.NewReader(stream))
			if _, err := dec.Next(); err != nil {
				t.Fatalf("first frame: %v", err)
			}
			_, err := dec.Next()
			if err == nil {
				t.Fatal("garbage line decoded without an error")
			}
			if !strings.Contains(err.Error(), "line 2") {
				t.Errorf("error %q does not name line 2", err)
			}
			if !strings.Contains(err.Error(), strconv.Quote(tc.line)) {
				t.Errorf("error %q does not quote the line %q", err, tc.line)
			}
		})
	}
}
