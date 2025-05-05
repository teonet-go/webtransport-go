// Copyright 2025 Kirill Scherba <kirill@scherba.ru>. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Stream module of webtransport package.

package webtransport

import (
	"bytes"
	"fmt"

	"github.com/teonet-go/webtransport-go/h3"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/quicvarint"
)

var ErrWrongStreamType = fmt.Errorf("unidirectional stream received with the wrong stream type")

// Stream wraps a quic.Stream providing a bidirectional client server stream,
// including Read and Write functions.
type Stream quic.Stream

// ReceiveStream wraps a quic.ReceiveStream providing a unidirectional
// WebTransport client server stream, including a Read function.
type ReceiveStream struct {
	quic.ReceiveStream
	readHeaderBeforeData bool
	headerRead           bool
	requestSessionID     uint64
}

// SendStream wraps a quic.SendStream providing a unidirectional WebTransport
// client server stream, including a Write function.
type SendStream struct {
	quic.SendStream
	writeHeaderBeforeData bool
	headerWritten         bool
	requestSessionID      uint64
}

// Read reads up to len(p) bytes from a WebTransport unidirectional stream,
// and return the actual number of bytes read or an error.
//
// Before first read it reads stream header and checks that the stream type is
// correct (it should be h3.STREAM_WEBTRANSPORT_UNI_STREAM). If the stream type
// is wrong, it returns ErrWrongStreamType. After reading the stream header it
// stores the requestSessionID field and marks the header as read.
func (s *ReceiveStream) Read(p []byte) (int, error) {

	// Read stream header before first data read
	if s.readHeaderBeforeData && !s.headerRead {
		streamHeader := h3.StreamHeader{}
		if err := streamHeader.Read(s.ReceiveStream); err != nil {
			return 0, err
		}
		if streamHeader.Type != h3.STREAM_WEBTRANSPORT_UNI_STREAM {
			return 0, ErrWrongStreamType
		}
		// Store the requestSessionID from the stream header
		s.requestSessionID = streamHeader.ID
		// Mark the header as read
		s.headerRead = true
	}

	// Read data
	return s.ReceiveStream.Read(p)
}

// Write writes up to len(p) bytes to a WebTransport unidirectional stream,
// and return the actual number of bytes written or an error.
//
// Before first write it writes stream header, which is:
// - one byte with the stream type (should be h3.STREAM_WEBTRANSPORT_UNI_STREAM)
// - requestSessionID, which is the ID of the stream, as it is sent in the
//   WebTransport stream header.
func (s *SendStream) Write(p []byte) (int, error) {

	// Write stream header before first data write
	if s.writeHeaderBeforeData && !s.headerWritten {
		buf := &bytes.Buffer{}
		// Write stream type
		buf.Write(quicvarint.Append(nil, h3.STREAM_WEBTRANSPORT_UNI_STREAM))
		// Write requestSessionID
		buf.Write(quicvarint.Append(nil, s.requestSessionID))
		// Write the buffer to the stream
		if _, err := s.SendStream.Write(buf.Bytes()); err != nil {
			// Close the stream if there is an error
			s.Close()
			return 0, err
		}
		// Mark the header as written
		s.headerWritten = true
	}

	// Write data
	return s.SendStream.Write(p)
}
