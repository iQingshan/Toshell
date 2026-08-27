package protocol

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"sync"

	"github.com/golang/snappy"
)

var (
	ErrPacketTooShort = fmt.Errorf("packet too short")
	ErrPacketTooLarge = fmt.Errorf("packet too large")
	ErrInvalidMagic   = fmt.Errorf("invalid magic bytes")
	ErrInvalidVersion = fmt.Errorf("invalid protocol version")
	ErrChecksumFailed = fmt.Errorf("checksum verification failed")
)

type Encoder struct {
	compressThreshold int
	compressLevel     int
	bufPool           sync.Pool
}

type EncoderOption func(*Encoder)

func WithCompressThreshold(threshold int) EncoderOption {
	return func(e *Encoder) {
		e.compressThreshold = threshold
	}
}

func WithCompressLevel(level int) EncoderOption {
	return func(e *Encoder) {
		e.compressLevel = level
	}
}

func NewEncoder(opts ...EncoderOption) *Encoder {
	e := &Encoder{
		compressThreshold: 1024,
		compressLevel:     gzip.DefaultCompression,
		bufPool: sync.Pool{
			New: func() interface{} {
				return new(bytes.Buffer)
			},
		},
	}
	
	for _, opt := range opts {
		opt(e)
	}
	
	return e
}

func (e *Encoder) Encode(p *Packet) ([]byte, error) {
	payload := p.Payload
	flags := p.Flags

	// 优先使用 Snappy（比 gzip 快约 10 倍）
	if len(payload) > e.compressThreshold {
		compressed := snappy.Encode(nil, payload)
		if len(compressed) < len(payload) {
			payload = compressed
			flags |= FlagSnappy
		}
	}

	totalLen := HeaderSize + len(payload)
	data := make([]byte, totalLen)

	data[0] = p.Magic[0]
	data[1] = p.Magic[1]
	data[2] = p.Version
	data[3] = p.Type
	data[4] = flags
	binary.BigEndian.PutUint32(data[5:9], p.TunnelID)
	binary.BigEndian.PutUint32(data[9:13], uint32(len(payload)))
	binary.BigEndian.PutUint32(data[13:17], p.Sequence)

	copy(data[HeaderSize:], payload)

	return data, nil
}

func (e *Encoder) EncodeWithBuffer(p *Packet, buf []byte) ([]byte, error) {
	payload := p.Payload
	flags := p.Flags

	// Snappy 快速压缩
	if len(payload) > e.compressThreshold {
		compressed := snappy.Encode(nil, payload)
		if len(compressed) < len(payload) {
			payload = compressed
			flags |= FlagSnappy
		}
	}

	totalLen := HeaderSize + len(payload)
	if cap(buf) < totalLen {
		buf = make([]byte, totalLen)
	} else {
		buf = buf[:totalLen]
	}

	buf[0] = p.Magic[0]
	buf[1] = p.Magic[1]
	buf[2] = p.Version
	buf[3] = p.Type
	buf[4] = flags
	binary.BigEndian.PutUint32(buf[5:9], p.TunnelID)
	binary.BigEndian.PutUint32(buf[9:13], uint32(len(payload)))
	binary.BigEndian.PutUint32(buf[13:17], p.Sequence)

	copy(buf[HeaderSize:], payload)

	return buf, nil
}

func (e *Encoder) compress(data []byte) ([]byte, error) {
	buf := e.bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer e.bufPool.Put(buf)
	
	w, err := gzip.NewWriterLevel(buf, e.compressLevel)
	if err != nil {
		return nil, err
	}
	
	if _, err := w.Write(data); err != nil {
		w.Close()
		return nil, err
	}
	
	if err := w.Close(); err != nil {
		return nil, err
	}
	
	compressed := make([]byte, buf.Len())
	copy(compressed, buf.Bytes())
	
	return compressed, nil
}

type Decoder struct {
	maxPacketSize int
	bufPool       sync.Pool
}

type DecoderOption func(*Decoder)

func WithMaxPacketSize(size int) DecoderOption {
	return func(d *Decoder) {
		d.maxPacketSize = size
	}
}

func NewDecoder(opts ...DecoderOption) *Decoder {
	d := &Decoder{
		maxPacketSize: MaxPayloadSize,
		bufPool: sync.Pool{
			New: func() interface{} {
				return new(bytes.Buffer)
			},
		},
	}
	
	for _, opt := range opts {
		opt(d)
	}
	
	return d
}

func (d *Decoder) Decode(data []byte) (*Packet, error) {
	if len(data) < HeaderSize {
		return nil, ErrPacketTooShort
	}
	
	if data[0] != MagicByte1 || data[1] != MagicByte2 {
		return nil, ErrInvalidMagic
	}
	
	if data[2] != ProtocolVersion {
		return nil, ErrInvalidVersion
	}
	
	p := &Packet{
		Version:  data[2],
		Type:     data[3],
		Flags:    data[4],
		TunnelID: binary.BigEndian.Uint32(data[5:9]),
		Length:   binary.BigEndian.Uint32(data[9:13]),
		Sequence: binary.BigEndian.Uint32(data[13:17]),
	}
	
	if p.Length > uint32(d.maxPacketSize) {
		return nil, ErrPacketTooLarge
	}
	
	if int(p.Length) > len(data)-HeaderSize {
		return nil, ErrPacketTooShort
	}
	
	payload := data[HeaderSize : HeaderSize+p.Length]

	if p.HasFlag(FlagSnappy) {
		decompressed, err := snappy.Decode(nil, payload)
		if err != nil {
			return nil, fmt.Errorf("snappy decompress failed: %w", err)
		}
		payload = decompressed
		p.Flags &^= FlagSnappy
	} else if p.HasFlag(FlagCompressed) {
		decompressed, err := d.decompress(payload)
		if err != nil {
			return nil, fmt.Errorf("gzip decompress failed: %w", err)
		}
		payload = decompressed
		p.Flags &^= FlagCompressed
	}
	
	p.Payload = payload
	
	return p, nil
}

func (d *Decoder) decompress(data []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	
	buf := d.bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer d.bufPool.Put(buf)
	
	if _, err := io.Copy(buf, r); err != nil {
		return nil, err
	}
	
	decompressed := make([]byte, buf.Len())
	copy(decompressed, buf.Bytes())
	
	return decompressed, nil
}

func (d *Decoder) DecodeHeader(data []byte) (byte, byte, uint32, uint32, error) {
	if len(data) < HeaderSize {
		return 0, 0, 0, 0, ErrPacketTooShort
	}
	
	if data[0] != MagicByte1 || data[1] != MagicByte2 {
		return 0, 0, 0, 0, ErrInvalidMagic
	}
	
	return data[3], data[4], binary.BigEndian.Uint32(data[5:9]), binary.BigEndian.Uint32(data[9:13]), nil
}

type StreamDecoder struct {
	decoder   *Decoder
	buf       []byte
	bufLen    int
	headerBuf [HeaderSize]byte
	headerLen int
}

func NewStreamDecoder(maxPacketSize int) *StreamDecoder {
	return &StreamDecoder{
		decoder: NewDecoder(WithMaxPacketSize(maxPacketSize)),
		buf:     make([]byte, 64*1024),
	}
}

func (sd *StreamDecoder) Feed(data []byte) []*Packet {
	var packets []*Packet
	
	for len(data) > 0 {
		if sd.headerLen < HeaderSize {
			need := HeaderSize - sd.headerLen
			take := need
			if take > len(data) {
				take = len(data)
			}
			
			copy(sd.headerBuf[sd.headerLen:], data[:take])
			sd.headerLen += take
			data = data[take:]
			
			if sd.headerLen < HeaderSize {
				break
			}
		}
		
		payloadLen := int(binary.BigEndian.Uint32(sd.headerBuf[9:13]))
		totalLen := HeaderSize + payloadLen
		
		if sd.bufLen == 0 && len(data) >= payloadLen {
			pkt, err := sd.decoder.Decode(append(sd.headerBuf[:], data[:payloadLen]...))
			if err == nil {
				packets = append(packets, pkt)
			}
			data = data[payloadLen:]
			sd.headerLen = 0
			continue
		}
		
		if sd.bufLen == 0 {
			copy(sd.buf, sd.headerBuf[:])
			sd.bufLen = HeaderSize
		}
		
		need := totalLen - sd.bufLen
		take := need
		if take > len(data) {
			take = len(data)
		}
		
		copy(sd.buf[sd.bufLen:], data[:take])
		sd.bufLen += take
		data = data[take:]
		
		if sd.bufLen >= totalLen {
			pkt, err := sd.decoder.Decode(sd.buf[:totalLen])
			if err == nil {
				packets = append(packets, pkt)
			}
			sd.bufLen = 0
			sd.headerLen = 0
		}
	}
	
	return packets
}

func (sd *StreamDecoder) Reset() {
	sd.bufLen = 0
	sd.headerLen = 0
}

var defaultEncoder = NewEncoder()
var defaultDecoder = NewDecoder()

func Encode(p *Packet) ([]byte, error) {
	return defaultEncoder.Encode(p)
}

func Decode(data []byte) (*Packet, error) {
	return defaultDecoder.Decode(data)
}
