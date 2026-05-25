// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 Stiftelsen Digipomps and HAVEN contributors

package cellprotocol

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	webSocketOpcodeContinuation = 0x0
	webSocketOpcodeText         = 0x1
	webSocketOpcodeBinary       = 0x2
	webSocketOpcodeClose        = 0x8
	webSocketOpcodePing         = 0x9
	webSocketOpcodePong         = 0xa

	defaultWebSocketMaxMessageBytes int64 = 16 << 20
)

type webSocketClient struct {
	conn     net.Conn
	reader   *bufio.Reader
	writeMu  sync.Mutex
	maxBytes int64
}

type webSocketDialOptions struct {
	HandshakeTimeout       time.Duration
	InsecureSkipVerify     bool
	Headers                map[string]string
	MaxMessageBytes        int64
	AllowInsecureWebSocket bool
}

func dialWebSocket(ctx context.Context, endpoint string, opts webSocketDialOptions) (*webSocketClient, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	if parsed.Scheme != "ws" && parsed.Scheme != "wss" {
		return nil, fmt.Errorf("unsupported websocket scheme %q", parsed.Scheme)
	}
	if parsed.Scheme == "ws" && !opts.AllowInsecureWebSocket {
		return nil, fmt.Errorf("insecure ws transport is disabled")
	}
	timeout := opts.HandshakeTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	hostPort := parsed.Host
	if !strings.Contains(hostPort, ":") {
		if parsed.Scheme == "wss" {
			hostPort += ":443"
		} else {
			hostPort += ":80"
		}
	}

	var dialer net.Dialer
	rawConn, err := dialer.DialContext(dialCtx, "tcp", hostPort)
	if err != nil {
		return nil, err
	}
	conn := rawConn
	if parsed.Scheme == "wss" {
		host := parsed.Hostname()
		tlsConn := tls.Client(rawConn, &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: opts.InsecureSkipVerify,
			MinVersion:         tls.VersionTLS12,
		})
		if err := tlsConn.HandshakeContext(dialCtx); err != nil {
			_ = rawConn.Close()
			return nil, err
		}
		conn = tlsConn
	}

	keyBytes := make([]byte, 16)
	if _, err := rand.Read(keyBytes); err != nil {
		_ = conn.Close()
		return nil, err
	}
	key := base64.StdEncoding.EncodeToString(keyBytes)
	path := parsed.RequestURI()
	if path == "" {
		path = "/"
	}
	var request bytes.Buffer
	fmt.Fprintf(&request, "GET %s HTTP/1.1\r\n", path)
	fmt.Fprintf(&request, "Host: %s\r\n", parsed.Host)
	fmt.Fprintf(&request, "Upgrade: websocket\r\n")
	fmt.Fprintf(&request, "Connection: Upgrade\r\n")
	fmt.Fprintf(&request, "Sec-WebSocket-Key: %s\r\n", key)
	fmt.Fprintf(&request, "Sec-WebSocket-Version: 13\r\n")
	for header, value := range opts.Headers {
		if strings.EqualFold(header, "host") ||
			strings.EqualFold(header, "upgrade") ||
			strings.EqualFold(header, "connection") ||
			strings.EqualFold(header, "sec-websocket-key") ||
			strings.EqualFold(header, "sec-websocket-version") {
			continue
		}
		fmt.Fprintf(&request, "%s: %s\r\n", header, value)
	}
	request.WriteString("\r\n")

	if deadline, ok := dialCtx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if _, err := conn.Write(request.Bytes()); err != nil {
		_ = conn.Close()
		return nil, err
	}
	reader := bufio.NewReader(conn)
	req, _ := http.NewRequest("GET", endpoint, nil)
	response, err := http.ReadResponse(reader, req)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusSwitchingProtocols {
		_ = conn.Close()
		return nil, fmt.Errorf("websocket upgrade failed: %s", response.Status)
	}
	expectedAccept := webSocketAcceptKey(key)
	if response.Header.Get("Sec-WebSocket-Accept") != expectedAccept {
		_ = conn.Close()
		return nil, fmt.Errorf("websocket upgrade failed: invalid Sec-WebSocket-Accept")
	}
	_ = conn.SetDeadline(time.Time{})
	maxBytes := opts.MaxMessageBytes
	if maxBytes <= 0 {
		maxBytes = defaultWebSocketMaxMessageBytes
	}
	return &webSocketClient{conn: conn, reader: reader, maxBytes: maxBytes}, nil
}

func (c *webSocketClient) SendText(ctx context.Context, message []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.conn.SetWriteDeadline(deadline)
		defer c.conn.SetWriteDeadline(time.Time{})
	}
	return writeWebSocketFrame(c.conn, webSocketOpcodeText, message, true)
}

func (c *webSocketClient) ReadMessage() ([]byte, error) {
	var fragments []byte
	var fragmentedOpcode byte
	for {
		opcode, payload, err := readWebSocketFrame(c.reader, c.maxBytes)
		if err != nil {
			return nil, err
		}
		switch opcode {
		case webSocketOpcodeText, webSocketOpcodeBinary:
			if fragmentedOpcode != 0 {
				return nil, fmt.Errorf("unexpected new websocket message before fragmented message completed")
			}
			return payload, nil
		case webSocketOpcodeContinuation:
			if fragmentedOpcode == 0 {
				return nil, fmt.Errorf("unexpected websocket continuation frame")
			}
			fragments = append(fragments, payload...)
			return fragments, nil
		case webSocketOpcodePing:
			c.writeMu.Lock()
			err := writeWebSocketFrame(c.conn, webSocketOpcodePong, payload, true)
			c.writeMu.Unlock()
			if err != nil {
				return nil, err
			}
		case webSocketOpcodePong:
			continue
		case webSocketOpcodeClose:
			c.writeMu.Lock()
			_ = writeWebSocketFrame(c.conn, webSocketOpcodeClose, payload, true)
			c.writeMu.Unlock()
			return nil, io.EOF
		default:
			return nil, fmt.Errorf("unsupported websocket opcode %d", opcode)
		}
	}
}

func (c *webSocketClient) Close() error {
	c.writeMu.Lock()
	_ = writeWebSocketFrame(c.conn, webSocketOpcodeClose, nil, true)
	c.writeMu.Unlock()
	return c.conn.Close()
}

func webSocketAcceptKey(key string) string {
	sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func readWebSocketFrame(reader *bufio.Reader, maxBytes int64) (byte, []byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil {
		return 0, nil, err
	}
	fin := header[0]&0x80 != 0
	opcode := header[0] & 0x0f
	if !fin {
		return 0, nil, fmt.Errorf("fragmented websocket frames are not supported yet")
	}
	masked := header[1]&0x80 != 0
	length := int64(header[1] & 0x7f)
	switch length {
	case 126:
		var extended [2]byte
		if _, err := io.ReadFull(reader, extended[:]); err != nil {
			return 0, nil, err
		}
		length = int64(binary.BigEndian.Uint16(extended[:]))
	case 127:
		var extended [8]byte
		if _, err := io.ReadFull(reader, extended[:]); err != nil {
			return 0, nil, err
		}
		length = int64(binary.BigEndian.Uint64(extended[:]))
	}
	if maxBytes > 0 && length > maxBytes {
		return 0, nil, fmt.Errorf("websocket message exceeds read limit")
	}
	var maskKey [4]byte
	if masked {
		if _, err := io.ReadFull(reader, maskKey[:]); err != nil {
			return 0, nil, err
		}
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return 0, nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= maskKey[i%4]
		}
	}
	return opcode, payload, nil
}

func writeWebSocketFrame(writer io.Writer, opcode byte, payload []byte, mask bool) error {
	if len(payload) > int(^uint(0)>>1) {
		return fmt.Errorf("payload too large")
	}
	var frame bytes.Buffer
	frame.WriteByte(0x80 | opcode)
	maskBit := byte(0)
	if mask {
		maskBit = 0x80
	}
	length := len(payload)
	switch {
	case length < 126:
		frame.WriteByte(maskBit | byte(length))
	case length <= 0xffff:
		frame.WriteByte(maskBit | 126)
		var extended [2]byte
		binary.BigEndian.PutUint16(extended[:], uint16(length))
		frame.Write(extended[:])
	default:
		frame.WriteByte(maskBit | 127)
		var extended [8]byte
		binary.BigEndian.PutUint64(extended[:], uint64(length))
		frame.Write(extended[:])
	}
	if mask {
		var maskKey [4]byte
		if _, err := rand.Read(maskKey[:]); err != nil {
			return err
		}
		frame.Write(maskKey[:])
		masked := make([]byte, len(payload))
		for i := range payload {
			masked[i] = payload[i] ^ maskKey[i%4]
		}
		frame.Write(masked)
	} else {
		frame.Write(payload)
	}
	_, err := writer.Write(frame.Bytes())
	return err
}
