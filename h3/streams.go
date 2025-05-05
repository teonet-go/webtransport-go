package h3

import (
	"bytes"
	"fmt"
	"io"

	"github.com/quic-go/quic-go/quicvarint"
)

// Stream types
const (
	STREAM_CONTROL                 = 0x00
	STREAM_PUSH                    = 0x01
	STREAM_QPACK_ENCODER           = 0x02
	STREAM_QPACK_DECODER           = 0x03
	STREAM_WEBTRANSPORT_UNI_STREAM = 0x54
)

// HTTP/3 stream header
type StreamHeader struct {
	Type uint64
	ID   uint64
}

// Read reads the stream header from the reader and stores it in the StreamHeader.
func (s *StreamHeader) Read(r io.Reader) error {
	qr := quicvarint.NewReader(r)
	t, err := quicvarint.Read(qr)
	if err != nil {
		return err
	}
	s.Type = t

	// Handle different stream types
	switch t {
	// One-byte streams
	case STREAM_CONTROL, STREAM_QPACK_ENCODER, STREAM_QPACK_DECODER:
		// No further data is needed
		return nil
	// Two-byte streams
	case STREAM_PUSH, STREAM_WEBTRANSPORT_UNI_STREAM:
		// Read the second byte
		l, err := quicvarint.Read(qr)
		if err != nil {
			return err
		}
		s.ID = l
		return nil
	default:
		// skip over unknown streams
		return fmt.Errorf("unknown stream type")
	}
}

// Write writes the stream header to the writer.
func (s *StreamHeader) Write(w io.Writer) (int64, error) {
	buf := &bytes.Buffer{}

	// Write the stream type
	buf.Write(quicvarint.Append(nil, s.Type))

	// Handle different stream types
	switch s.Type {
	// One-byte streams, no further data is needed
	case STREAM_CONTROL, STREAM_QPACK_ENCODER, STREAM_QPACK_DECODER:
		// Return the number of bytes written
		return buf.WriteTo(w)
	// Two-byte streams
	case STREAM_PUSH, STREAM_WEBTRANSPORT_UNI_STREAM:
		// Write the second byte (the stream ID)
		buf.Write(quicvarint.Append(nil, s.ID))
		// Return the number of bytes written
		return buf.WriteTo(w)
	default:
		// skip over unknown streams
		return 0, fmt.Errorf("unknown stream type")
	}
}
