package h3

import (
	"bytes"
	"io"

	"github.com/quic-go/quic-go/quicvarint"
)

// Frame types
const (
	FRAME_DATA                = 0x00
	FRAME_HEADERS             = 0x01
	FRAME_CANCEL_PUSH         = 0x03
	FRAME_SETTINGS            = 0x04
	FRAME_PUSH_PROMISE        = 0x05
	FRAME_GOAWAY              = 0x07
	FRAME_MAX_PUSH_ID         = 0x0D
	FRAME_WEBTRANSPORT_STREAM = 0x41
)

// HTTP/3 frame
type Frame struct {
	Type      uint64
	SessionID uint64
	Length    uint64
	Data      []byte
}

// Read reads an HTTP/3 frame from a reader and stores it in the frame.
func (f *Frame) Read(r io.Reader) error {
	qr := quicvarint.NewReader(r)
	t, err := quicvarint.Read(qr)
	if err != nil {
		return err
	}
	l, err := quicvarint.Read(qr)
	if err != nil {
		return err
	}

	f.Type = t

	// For most (but not all) frame types, l is the data length
	switch t {
	case FRAME_WEBTRANSPORT_STREAM:
		// For WebTransport streams, l is the requestSessionID
		f.Length = 0
		f.SessionID = l
		f.Data = []byte{}
		return nil
	default:
		// For most frame types, l is the data length
		f.Length = l
		f.Data = make([]byte, l)
		_, err := r.Read(f.Data)
		return err
	}
}

// Write writes an HTTP/3 frame to a writer.
func (f *Frame) Write(w io.Writer) (int, error) {
	// Create a bytes.Buffer to store the frame
	buf := &bytes.Buffer{}

	// Write the frame type
	buf.Write(quicvarint.Append(nil, f.Type))

	// Write the length of the frame (or the requestSessionID for WebTransport streams)
	if f.Type == FRAME_WEBTRANSPORT_STREAM {
		// For WebTransport streams, the length is the requestSessionID
		buf.Write(quicvarint.Append(nil, f.SessionID))
	} else {
		// For most frame types, the length is the data length
		buf.Write(quicvarint.Append(nil, f.Length))
	}

	// Write the frame data
	buf.Write(f.Data)

	// Write the frame to the writer
	return w.Write(buf.Bytes())
}
