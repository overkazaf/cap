package capture_test

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/overkazaf/cap/internal/capture"
	"github.com/overkazaf/cap/internal/types"
)

// buildWSFrame constructs the raw wire bytes for a single RFC 6455 frame
// carrying opcode/payload, masking it with a fixed, non-trivial key when
// masked is true — mirroring how a real client (always masked) or server
// (never masked) frame looks on the wire.
func buildWSFrame(masked bool, opcode int, payload []byte) []byte {
	var buf bytes.Buffer

	buf.WriteByte(0x80 | byte(opcode&0x0f)) // FIN=1, RSV1-3=0

	length := len(payload)
	var b1 byte
	if masked {
		b1 = 0x80
	}
	switch {
	case length <= 125:
		buf.WriteByte(b1 | byte(length))
	case length <= 0xFFFF:
		buf.WriteByte(b1 | 126)
		var ext [2]byte
		binary.BigEndian.PutUint16(ext[:], uint16(length))
		buf.Write(ext[:])
	default:
		buf.WriteByte(b1 | 127)
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(length))
		buf.Write(ext[:])
	}

	data := make([]byte, length)
	copy(data, payload)

	if masked {
		key := [4]byte{0x37, 0xfa, 0x21, 0x3d}
		buf.Write(key[:])
		for i := range data {
			data[i] ^= key[i%4]
		}
	}
	buf.Write(data)

	return buf.Bytes()
}

func TestParseWSFrame(t *testing.T) {
	frameBytes := buildWSFrame(false, capture.WSOpcodeText, []byte("hello"))

	frame, err := capture.ParseWSFrame(bytes.NewReader(frameBytes))
	if err != nil {
		t.Fatalf("ParseWSFrame: %v", err)
	}
	if frame.Opcode != capture.WSOpcodeText {
		t.Errorf("Opcode = %d, want %d", frame.Opcode, capture.WSOpcodeText)
	}
	if !frame.IsFinal {
		t.Error("IsFinal = false, want true")
	}
	if frame.Masked {
		t.Error("Masked = true, want false (server-style frame is never masked)")
	}
	if string(frame.Data) != "hello" {
		t.Errorf("Data = %q, want %q", frame.Data, "hello")
	}
}

func TestParseWSFrameExtendedLength16(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), 200) // > 125: forces the 16-bit extended length path
	frameBytes := buildWSFrame(false, capture.WSOpcodeBinary, payload)

	frame, err := capture.ParseWSFrame(bytes.NewReader(frameBytes))
	if err != nil {
		t.Fatalf("ParseWSFrame: %v", err)
	}
	if frame.Opcode != capture.WSOpcodeBinary {
		t.Errorf("Opcode = %d, want %d", frame.Opcode, capture.WSOpcodeBinary)
	}
	if !bytes.Equal(frame.Data, payload) {
		t.Fatalf("len(Data) = %d, want %d (16-bit extended length not parsed correctly)", len(frame.Data), len(payload))
	}
}

func TestParseWSFrameExtendedLength64(t *testing.T) {
	payload := bytes.Repeat([]byte("y"), 70000) // > 65535: forces the 64-bit extended length path
	frameBytes := buildWSFrame(false, capture.WSOpcodeBinary, payload)

	frame, err := capture.ParseWSFrame(bytes.NewReader(frameBytes))
	if err != nil {
		t.Fatalf("ParseWSFrame: %v", err)
	}
	if !bytes.Equal(frame.Data, payload) {
		t.Fatalf("len(Data) = %d, want %d (64-bit extended length not parsed correctly)", len(frame.Data), len(payload))
	}
}

func TestWSFrameUnmask(t *testing.T) {
	payload := []byte("secret-client-payload")
	frameBytes := buildWSFrame(true, capture.WSOpcodeBinary, payload)

	frame, err := capture.ParseWSFrame(bytes.NewReader(frameBytes))
	if err != nil {
		t.Fatalf("ParseWSFrame: %v", err)
	}
	if !frame.Masked {
		t.Error("Masked = false, want true (client-style frame is always masked)")
	}
	if string(frame.Data) != string(payload) {
		t.Errorf("Data = %q, want %q (unmasking should recover the original payload)", frame.Data, payload)
	}
}

func TestWSCaptureBidirectional(t *testing.T) {
	clientSide, clientConn := net.Pipe()
	serverSide, serverConn := net.Pipe()
	t.Cleanup(func() {
		clientSide.Close()
		serverSide.Close()
	})

	var (
		mu     sync.Mutex
		frames []*types.WSFrame
	)
	done := make(chan struct{})
	const wantFrames = 2

	wsc := capture.NewWSCapture(func(f *types.WSFrame) {
		mu.Lock()
		frames = append(frames, f)
		n := len(frames)
		mu.Unlock()
		if n == wantFrames {
			close(done)
		}
	})

	go wsc.Intercept(clientConn, serverConn, "flow-ws-1")

	// Drain the bytes Intercept forwards to each fake peer so the
	// TeeReader-based forwarding (which blocks on Write until read, since
	// net.Pipe is unbuffered) never stalls the capture goroutines.
	go io.Copy(io.Discard, clientSide)
	go io.Copy(io.Discard, serverSide)

	clientFrame := buildWSFrame(true, capture.WSOpcodeText, []byte("hi")) // client frames are masked
	if _, err := clientSide.Write(clientFrame); err != nil {
		t.Fatalf("write client frame: %v", err)
	}

	serverFrame := buildWSFrame(false, capture.WSOpcodeText, []byte("yo")) // server frames are unmasked
	if _, err := serverSide.Write(serverFrame); err != nil {
		t.Fatalf("write server frame: %v", err)
	}

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for both frames to be captured")
	}

	mu.Lock()
	defer mu.Unlock()

	var sawClient, sawServer bool
	for _, f := range frames {
		if f.FlowID != "flow-ws-1" {
			t.Errorf("FlowID = %q, want %q", f.FlowID, "flow-ws-1")
		}
		switch f.Direction {
		case "client":
			sawClient = true
			if string(f.Data) != "hi" {
				t.Errorf("client frame Data = %q, want %q", f.Data, "hi")
			}
		case "server":
			sawServer = true
			if string(f.Data) != "yo" {
				t.Errorf("server frame Data = %q, want %q", f.Data, "yo")
			}
		default:
			t.Errorf("unexpected Direction = %q", f.Direction)
		}
	}
	if !sawClient {
		t.Error("no frame captured with Direction = client")
	}
	if !sawServer {
		t.Error("no frame captured with Direction = server")
	}
}
