// Package protocol 提供 Snappy 流压缩支持，对标 NPS lib/conn/snappy.go。
// Snappy 相比 gzip 压缩速度快约 10 倍，适合实时隧道数据流。
package protocol

import (
	"io"

	"github.com/golang/snappy"
)

// SnappyReadWriter 实现 Snappy 流压缩的 io.ReadWriteCloser。
type SnappyReadWriter struct {
	w *snappy.Writer
	r *snappy.Reader
	c io.Closer
}

// NewSnappyReadWriter 创建一个 Snappy 流压缩包装器。
func NewSnappyReadWriter(rw io.ReadWriteCloser) *SnappyReadWriter {
	return &SnappyReadWriter{
		w: snappy.NewBufferedWriter(rw),
		r: snappy.NewReader(rw),
		c: rw,
	}
}

func (s *SnappyReadWriter) Read(b []byte) (int, error) {
	return s.r.Read(b)
}

func (s *SnappyReadWriter) Write(b []byte) (int, error) {
	n, err := s.w.Write(b)
	if err != nil {
		return n, err
	}
	return n, s.w.Flush()
}

func (s *SnappyReadWriter) Close() error {
	_ = s.w.Close()
	return s.c.Close()
}
