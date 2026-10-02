// Package capture implements protocol-specific frame/event capture for
// connections that have already left the plain HTTP request/response model
// behind — currently WebSocket (RFC 6455) and Server-Sent Events.
package capture

import (
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/overkazaf/cap/internal/types"
)

// WebSocket opcodes, per RFC 6455 §11.8. These are the values stored in
// types.WSFrame.Opcode.
const (
	WSOpcodeContinuation = 0x0
	WSOpcodeText         = 0x1
	WSOpcodeBinary       = 0x2
	WSOpcodeClose        = 0x8
	WSOpcodePing         = 0x9
	WSOpcodePong         = 0xA
)

// Direction values recorded on every captured types.WSFrame, identifying
// which half of the connection the frame travelled.
const (
	wsDirectionClient = "client"
	wsDirectionServer = "server"
)

// WSRawFrame is a single RFC 6455 WebSocket frame as parsed directly off the
// wire, before Intercept enriches it with flow metadata (a capture ID, flow
// ID, direction, timestamp) to build a types.WSFrame.
type WSRawFrame struct {
	IsFinal bool
	Opcode  int
	Masked  bool
	Data    []byte
}

// ParseWSFrame reads exactly one WebSocket frame from r, per RFC 6455 §5.2:
// a 2-byte header (FIN bit, opcode, mask bit, 7-bit payload length), an
// optional 16-bit or 64-bit extended length, an optional 4-byte masking
// key, and the payload itself.
//
// If the frame's mask bit is set — always true for client-to-server
// frames, and never for server-to-client ones, per the protocol — the
// payload is unmasked (RFC 6455 §5.3) before being returned in Data.
//
// Continuation frames and fragmentation are not handled specially: each
// frame on the wire, continuation or not, is parsed and returned exactly as
// received.
func ParseWSFrame(r io.Reader) (*WSRawFrame, error) {
	var header [2]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}

	isFinal := header[0]&0x80 != 0
	opcode := int(header[0] & 0x0f)
	masked := header[1]&0x80 != 0
	length := uint64(header[1] & 0x7f)

	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return nil, err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return nil, err
		}
		length = binary.BigEndian.Uint64(ext[:])
	}

	var maskKey [4]byte
	if masked {
		if _, err := io.ReadFull(r, maskKey[:]); err != nil {
			return nil, err
		}
	}

	data := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(r, data); err != nil {
			return nil, err
		}
	}

	if masked {
		for i := range data {
			data[i] ^= maskKey[i%4]
		}
	}

	return &WSRawFrame{
		IsFinal: isFinal,
		Opcode:  opcode,
		Masked:  masked,
		Data:    data,
	}, nil
}

// NewWSCapture creates a WSCapture that invokes onFrame for every WebSocket
// frame observed on connections passed to Intercept. onFrame may be nil, in
// which case Intercept still proxies data transparently but discards parsed
// frames.
func NewWSCapture(onFrame func(*types.WSFrame)) *WSCapture {
	return &WSCapture{onFrame: onFrame}
}

// WSCapture captures WebSocket frames flowing over an already-upgraded TCP
// connection.
type WSCapture struct {
	onFrame func(*types.WSFrame)
}

// Intercept proxies data bidirectionally between clientConn and serverConn
// — the two halves of an already-upgraded WebSocket connection, as held by
// a MITM proxy once it has relayed the HTTP Upgrade handshake — while
// parsing and reporting every frame in both directions via onFrame.
//
// Bytes are forwarded transparently and unmodified in both directions
// (masked client frames are forwarded still masked, exactly as received):
// Intercept observes the stream for capture purposes, it never rewrites it.
//
// Intercept blocks until both directions finish, which normally happens
// because one side closed the connection; at that point it closes both
// connections (if not already closed, so the other side unblocks too) and
// returns. Fragmentation is not reassembled — each individual frame read
// off the wire is reported to onFrame as-is.
func (c *WSCapture) Intercept(clientConn, serverConn io.ReadWriteCloser, flowID string) {
	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			clientConn.Close()
			serverConn.Close()
		})
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer closeBoth()
		c.pump(clientConn, serverConn, flowID, wsDirectionClient)
	}()
	go func() {
		defer wg.Done()
		defer closeBoth()
		c.pump(serverConn, clientConn, flowID, wsDirectionServer)
	}()
	wg.Wait()
}

// pump reads frames from src and reports each to onFrame, while
// transparently forwarding every byte read to dst via io.TeeReader — so dst
// always receives the exact original wire bytes regardless of how
// ParseWSFrame subsequently interprets (and, for masked frames, mutates its
// own copy of) them. It returns once reading from src fails, typically
// io.EOF when the peer closes its end of the connection.
func (c *WSCapture) pump(src io.Reader, dst io.Writer, flowID, direction string) {
	tee := io.TeeReader(src, dst)
	for {
		frame, err := ParseWSFrame(tee)
		if err != nil {
			return
		}
		if c.onFrame != nil {
			c.onFrame(&types.WSFrame{
				ID:        nextWSFrameID(),
				FlowID:    flowID,
				Timestamp: time.Now(),
				Direction: direction,
				Opcode:    frame.Opcode,
				Data:      frame.Data,
				Len:       len(frame.Data),
				IsFinal:   frame.IsFinal,
			})
		}
	}
}

var wsFrameIDSeq atomic.Int64

// nextWSFrameID returns a unique, process-local ID for a captured
// types.WSFrame (e.g. "ws1", "ws2", ...).
func nextWSFrameID() string {
	return fmt.Sprintf("ws%d", wsFrameIDSeq.Add(1))
}
