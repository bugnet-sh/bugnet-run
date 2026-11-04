package frame

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// maxLine bounds one frame line far above the 16 KiB data chunks bugnet-run emits
const maxLine = 1 << 20

// Decoder reads frames from a stream of JSON lines, buffering partial lines between reads
type Decoder struct {
	r    *bufio.Reader
	buf  []byte
	line int
}

// NewDecoder returns a Decoder that reads from r
func NewDecoder(r io.Reader) *Decoder {
	return &Decoder{r: bufio.NewReaderSize(r, 64<<10)}
}

// Next returns the next frame, or io.EOF once the stream ends
func (d *Decoder) Next() (Frame, error) {
	for {
		line, err := d.readLine()
		if err != nil {
			return Frame{}, err
		}
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var f Frame
		if err := json.Unmarshal(line, &f); err != nil {
			return Frame{}, d.lineError(line, err)
		}
		if f.Kind == "" {
			return Frame{}, d.lineError(line, errors.New("missing kind"))
		}
		return f, nil
	}
}

func (d *Decoder) readLine() ([]byte, error) {
	d.buf = d.buf[:0]
	for {
		chunk, err := d.r.ReadSlice('\n')
		d.buf = append(d.buf, chunk...)
		if len(d.buf) > maxLine {
			return nil, fmt.Errorf("frame: line %d is longer than %d bytes", d.line+1, maxLine)
		}
		switch {
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case err == nil, errors.Is(err, io.EOF) && len(d.buf) > 0:
			d.line++
			return d.buf, nil
		default:
			return nil, err
		}
	}
}

func (d *Decoder) lineError(line []byte, err error) error {
	if len(line) > 80 {
		line = line[:80]
	}
	return fmt.Errorf("frame: line %d %q: %w", d.line, line, err)
}
