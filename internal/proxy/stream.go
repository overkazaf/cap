package proxy

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/overkazaf/cap/internal/types"
)

const (
	defaultMaxBodyBytes         int64 = 1024 * 1024
	defaultMaxStreamPayloadSize int64 = 256 * 1024
)

// StreamEventType identifies the streaming protocol represented by an event.
type StreamEventType string

const (
	StreamEventWebSocketFrame StreamEventType = "websocket_frame"
	StreamEventSSE            StreamEventType = "sse_event"
)

// StreamDirection describes traffic direction from the proxied client's view.
type StreamDirection string

const (
	StreamDirectionClientServer StreamDirection = "client_to_server"
	StreamDirectionServerClient StreamDirection = "server_to_client"
)

// StreamEvent is an incremental capture unit from a WebSocket or SSE relay.
type StreamEvent struct {
	ID          string
	FlowID      string
	Timestamp   time.Time
	Type        StreamEventType
	Direction   StreamDirection
	Opcode      string
	Event       string
	LastEventID string
	Payload     []byte
	Truncated   bool
}

func normalizeLimits(opts *Options) {
	if opts.MaxBodyBytes <= 0 {
		opts.MaxBodyBytes = defaultMaxBodyBytes
	}
	if opts.MaxStreamPayloadBytes <= 0 {
		opts.MaxStreamPayloadBytes = defaultMaxStreamPayloadSize
	}
}

func isWebSocketUpgrade(resp *http.Response) bool {
	return resp != nil &&
		resp.StatusCode == http.StatusSwitchingProtocols &&
		strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(resp.Header.Get("Connection")), "upgrade")
}

func isServerSentEvent(resp *http.Response) bool {
	return resp != nil &&
		strings.HasPrefix(strings.ToLower(resp.Header.Get("Content-Type")), "text/event-stream")
}

type prefixedBody struct {
	reader io.Reader
	closer io.Closer
}

func (body *prefixedBody) Read(p []byte) (int, error) {
	return body.reader.Read(p)
}

func (body *prefixedBody) Close() error {
	if body.closer == nil {
		return nil
	}
	return body.closer.Close()
}

func captureBody(body io.ReadCloser, limit int64) ([]byte, io.ReadCloser, error) {
	prefix, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		_ = body.Close()
		return nil, nil, err
	}
	if int64(len(prefix)) <= limit {
		_ = body.Close()
		return prefix, &prefixedBody{
			reader: bytes.NewReader(prefix),
			closer: body,
		}, nil
	}
	return prefix[:len(prefix)-1], &prefixedBody{
		reader: io.MultiReader(bytes.NewReader(prefix[:len(prefix)-1]), body),
		closer: body,
	}, nil
}

func (p *Proxy) nextStreamID() string {
	return fmt.Sprintf("s%d", p.idSeq.Add(1))
}

func (p *Proxy) emitStreamEvent(event StreamEvent) {
	if p.opts.OnStreamEvent != nil {
		p.opts.OnStreamEvent(event)
	}
}

type websocketCaptureBody struct {
	body       io.ReadWriteCloser
	proxy      *Proxy
	flowID     string
	maxPayload int64
	reader     websocketFrameParser
	writer     websocketFrameParser
}

func (p *Proxy) websocketBody(body io.ReadCloser, flow *types.Flow) io.ReadCloser {
	readWriter, ok := body.(io.ReadWriteCloser)
	if !ok {
		return body
	}
	return &websocketCaptureBody{
		body:       readWriter,
		proxy:      p,
		flowID:     flow.ID,
		maxPayload: p.opts.MaxStreamPayloadBytes,
	}
}

func (body *websocketCaptureBody) Read(p []byte) (int, error) {
	n, err := body.body.Read(p)
	if n > 0 {
		body.reader.Feed(p[:n], StreamDirectionServerClient, body)
	}
	return n, err
}

func (body *websocketCaptureBody) Write(p []byte) (int, error) {
	n, err := body.body.Write(p)
	if n > 0 {
		body.writer.Feed(p[:n], StreamDirectionClientServer, body)
	}
	return n, err
}

func (body *websocketCaptureBody) Close() error {
	return body.body.Close()
}

type websocketParseState int

const (
	websocketHeader websocketParseState = iota
	websocketPayload
	websocketDiscard
	websocketInvalid
)

type websocketFrameParser struct {
	state       websocketParseState
	header      []byte
	payload     []byte
	payloadLeft int64
	fin         bool
	opcode      byte
	masked      bool
	mask        [4]byte
	maskOffset  int
	maxPayload  int64
}

func (parser *websocketFrameParser) Feed(data []byte, direction StreamDirection, body *websocketCaptureBody) {
	for len(data) > 0 {
		switch parser.state {
		case websocketHeader:
			needed, valid := websocketHeaderSize(parser.header)
			if !valid {
				parser.state = websocketInvalid
				continue
			}
			take := min(len(data), needed-len(parser.header))
			parser.header = append(parser.header, data[:take]...)
			data = data[take:]
			if len(parser.header) == needed {
				parser.startFrame()
			}

		case websocketPayload:
			take := min(int64(len(data)), parser.payloadLeft)
			destination := parser.payload[len(parser.payload)-int(parser.payloadLeft):]
			copy(destination, data[:take])
			if parser.masked {
				maskOffset := parser.maskOffset
				for index := 0; int64(index) < take; index++ {
					destination[index] ^= parser.mask[maskOffset%len(parser.mask)]
					maskOffset++
				}
				parser.maskOffset = maskOffset
			}
			parser.payloadLeft -= take
			data = data[take:]
			if parser.payloadLeft == 0 {
				body.emitFrame(direction, parser.fin, parser.opcode, parser.payload, false)
				parser.reset()
			}

		case websocketDiscard:
			take := min(int64(len(data)), parser.payloadLeft)
			parser.payloadLeft -= take
			data = data[take:]
			if parser.payloadLeft == 0 {
				body.emitFrame(direction, parser.fin, parser.opcode, parser.payload, true)
				parser.reset()
			}

		case websocketInvalid:
			return
		}
	}
}

func (body *websocketCaptureBody) emitFrame(direction StreamDirection, fin bool, opcode byte, payload []byte, truncated bool) {
	body.proxy.emitStreamEvent(StreamEvent{
		ID:        body.proxy.nextStreamID(),
		FlowID:    body.flowID,
		Timestamp: time.Now(),
		Type:      StreamEventWebSocketFrame,
		Direction: direction,
		Opcode:    websocketOpcodeName(fin, opcode),
		Payload:   append([]byte{}, payload...),
		Truncated: truncated,
	})
}

func websocketHeaderSize(header []byte) (int, bool) {
	if len(header) < 2 {
		return 2, true
	}
	size := 2
	switch header[1] & 0x7f {
	case 126:
		size += 2
	case 127:
		size += 8
	}
	if header[1]&0x80 != 0 {
		size += 4
	}
	return size, true
}

func (parser *websocketFrameParser) startFrame() {
	parser.fin = parser.header[0]&0x80 != 0
	parser.opcode = parser.header[0] & 0x0f
	parser.masked = parser.header[1]&0x80 != 0
	length := int64(parser.header[1] & 0x7f)
	offset := 2
	switch length {
	case 126:
		length = int64(binary.BigEndian.Uint16(parser.header[offset:]))
		offset += 2
	case 127:
		length = int64(binary.BigEndian.Uint64(parser.header[offset:]))
		offset += 8
	}
	if length < 0 || length > math.MaxInt64 {
		parser.state = websocketInvalid
		return
	}
	copy(parser.mask[:], parser.header[offset:])
	parser.payloadLeft = length

	if length > parser.maxPayload {
		parser.payload = make([]byte, min(parser.maxPayload, 0))
		parser.state = websocketDiscard
		return
	}
	parser.payload = make([]byte, length)
	parser.state = websocketPayload
}

func (parser *websocketFrameParser) reset() {
	parser.header = parser.header[:0]
	parser.payload = nil
	parser.payloadLeft = 0
	parser.maskOffset = 0
	parser.state = websocketHeader
}

func websocketOpcodeName(fin bool, opcode byte) string {
	switch opcode {
	case 0:
		return "continuation"
	case 1:
		return "text"
	case 2:
		return "binary"
	case 8:
		return "close"
	case 9:
		return "ping"
	case 10:
		return "pong"
	default:
		return fmt.Sprintf("unknown_%d", opcode)
	}
}

type sseCaptureBody struct {
	body   io.ReadCloser
	proxy  *Proxy
	flowID string
	parser sseParser
}

func (p *Proxy) sseBody(body io.ReadCloser, flow *types.Flow) io.ReadCloser {
	return &sseCaptureBody{
		body:   body,
		proxy:  p,
		flowID: flow.ID,
	}
}

func (body *sseCaptureBody) Read(p []byte) (int, error) {
	n, err := body.body.Read(p)
	if n > 0 {
		body.parser.Feed(p[:n], body)
	}
	if err == io.EOF {
		body.parser.Finish(body)
	}
	return n, err
}

func (body *sseCaptureBody) Close() error {
	body.parser.Finish(body)
	return body.body.Close()
}

type sseParser struct {
	limit         int64
	line          []byte
	lineTruncated bool
	eventName     string
	lastEventID   string
	data          []byte
	dataTruncated bool
}

func (parser *sseParser) Feed(data []byte, body *sseCaptureBody) {
	if parser.limit == 0 {
		parser.limit = body.proxy.opts.MaxStreamPayloadBytes
		parser.data = []byte{}
	}
	for _, current := range data {
		if current != '\n' {
			if int64(len(parser.line)) < parser.limit {
				parser.line = append(parser.line, current)
			} else {
				parser.lineTruncated = true
			}
			continue
		}
		parser.completeLine(body)
	}
}

func (parser *sseParser) completeLine(body *sseCaptureBody) {
	line := parser.line
	if len(line) > 0 && line[len(line)-1] == '\r' {
		line = line[:len(line)-1]
	}
	parser.line = parser.line[:0]

	if len(line) == 0 {
		if len(parser.data) > 0 {
			body.emitEvent(parser.eventName, parser.lastEventID, parser.data, parser.lineTruncated || parser.dataTruncated)
		}
		parser.eventName = ""
		parser.lastEventID = ""
		parser.data = parser.data[:0]
		parser.lineTruncated = false
		parser.dataTruncated = false
		return
	}

	field, value := line, []byte{}
	if colon := bytes.IndexByte(line, ':'); colon >= 0 {
		field, value = line[:colon], line[colon+1:]
		if len(value) > 0 && value[0] == ' ' {
			value = value[1:]
		}
	}
	switch string(field) {
	case "data":
		if len(parser.data) > 0 {
			if int64(len(parser.data))+1 <= parser.limit {
				parser.data = append(parser.data, '\n')
			} else {
				parser.dataTruncated = true
			}
		}
		remaining := parser.limit - int64(len(parser.data))
		if remaining < int64(len(value)) {
			if remaining > 0 {
				parser.data = append(parser.data, value[:remaining]...)
			}
			parser.dataTruncated = true
		} else {
			parser.data = append(parser.data, value...)
		}
	case "event":
		parser.eventName = string(value)
	case "id":
		if !bytes.ContainsRune(value, 0) {
			parser.lastEventID = string(value)
		}
	}
}

func (parser *sseParser) Finish(body *sseCaptureBody) {
	if parser.data == nil {
		return
	}
	if parser.line != nil {
		parser.completeLine(body)
		parser.line = nil
	}
	if len(parser.data) > 0 {
		body.emitEvent(parser.eventName, parser.lastEventID, parser.data, parser.lineTruncated || parser.dataTruncated)
		parser.data = nil
		parser.eventName = ""
		parser.lastEventID = ""
	}
}

func (body *sseCaptureBody) emitEvent(eventName, lastEventID string, payload []byte, truncated bool) {
	body.proxy.emitStreamEvent(StreamEvent{
		ID:          body.proxy.nextStreamID(),
		FlowID:      body.flowID,
		Timestamp:   time.Now(),
		Type:        StreamEventSSE,
		Direction:   StreamDirectionServerClient,
		Event:       eventName,
		LastEventID: lastEventID,
		Payload:     append([]byte{}, payload...),
		Truncated:   truncated,
	})
}
