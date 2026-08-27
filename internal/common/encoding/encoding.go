package encoding

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
)

type Encoder interface {
	Encode([]byte) string
	Decode(string) ([]byte, error)
}

type Base64Encoder struct{}

func (e *Base64Encoder) Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func (e *Base64Encoder) Decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

type HexEncoder struct{}

func (e *HexEncoder) Encode(data []byte) string {
	return hex.EncodeToString(data)
}

func (e *HexEncoder) Decode(s string) ([]byte, error) {
	return hex.DecodeString(s)
}

type JSONEncoder struct{}

func (e *JSONEncoder) Encode(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}

func (e *JSONEncoder) Decode(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}

type GobEncoder struct{}

func (e *GobEncoder) Encode(v interface{}) ([]byte, error) {
	buf := new(bytes.Buffer)
	encoder := gob.NewEncoder(buf)
	err := encoder.Encode(v)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (e *GobEncoder) Decode(data []byte, v interface{}) error {
	buf := bytes.NewReader(data)
	decoder := gob.NewDecoder(buf)
	return decoder.Decode(v)
}

func IntToBytes(val uint64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, val)
	return buf
}

func BytesToInt(buf []byte) uint64 {
	return binary.BigEndian.Uint64(buf)
}

func Int16ToBytes(val uint16) []byte {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, val)
	return buf
}

func BytesToInt16(buf []byte) uint16 {
	return binary.BigEndian.Uint16(buf)
}
