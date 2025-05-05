// Copyright 2025 Kirill Scherba <kirill@scherba.ru>. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Datagram module of webtransport package.

package webtransport

import (
	"bytes"
	"context"
	"fmt"

	"github.com/quic-go/quic-go/quicvarint"
)

var ErrSTreamClosed = fmt.Errorf("webtransport stream closed")

// datagramMessage is a helper struct for ReceiveDatagram.
type datagramMessage struct {
	msg []byte
	err error
}

// SendDatagram sends a datagram over a WebTransport session. It use the
// WebTransport session's Context() so that ending the WebTransport session
// automatically cancels this call.
//
// Note that datagrams are unreliable - depending on network conditions,
// datagrams sent by the server may never be received by the client.
//
// A datagram is a sequence of bytes that is sent in a single UDP packet.
// WebTransport datagrams are associated with a particular HTTP/3 request,
// and are sent on the same connection as that request. The WebTransport
// datagram is sent with the "quarter stream ID" of the associated request
// stream, as per:
// https://datatracker.ietf.org/doc/html/draft-ietf-masque-h3-datagram
func (s *Session) SendDatagram(msg []byte) error {
	buf := &bytes.Buffer{}

	// "Quarter Stream ID" (!) of associated request stream, as per:
	// https://datatracker.ietf.org/doc/html/draft-ietf-masque-h3-datagram
	// TODO: check if this id is correct
	buf.Write(quicvarint.Append(nil, uint64(s.StreamID()/4)))

	// Add the datagram to the end of the buffer
	buf.Write(msg)

	// Send the buffer
	return s.Session.SendDatagram(buf.Bytes())
}

// ReceiveDatagram returns a datagram received from a WebTransport session,
// blocking if necessary until one is available. Supply your own context, or use
// the WebTransport session's Context() so that ending the WebTransport session
// automatically cancels this call.
//
// Note that datagrams are unreliable - depending on network conditions,
// datagrams sent by the client may never be received by the server.
//
// The datagram returned is a sequence of bytes that is sent in a single UDP
// packet.
//
// WebTransport datagrams are associated with a particular HTTP/3 request,
// and are sent on the same connection as that request. The WebTransport
// datagram is sent with the "quarter stream ID" of the associated request
// stream, as per:
// https://datatracker.ietf.org/doc/html/draft-ietf-masque-h3-datagram
func (s *Session) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	resultChannel := make(chan datagramMessage)

	go func() {
		// Receive the datagram from the WebTransport session
		msg, err := s.Session.ReceiveDatagram(ctx)
		resultChannel <- datagramMessage{msg: msg, err: err}
	}()

	select {
	case result := <-resultChannel:
		// If an error occurred, return it
		if result.err != nil {
			return nil, result.err
		}

		// The datagram is a sequence of bytes that is sent in a single UDP packet.
		// We need to read the "quarter stream ID" of the associated request stream
		// from the beginning of the datagram, and return the rest of the datagram.
		datastream := bytes.NewReader(result.msg)
		quarterStreamId, err := quicvarint.Read(datastream)
		if err != nil {
			return nil, err
		}

		return result.msg[quicvarint.Len(quarterStreamId):], nil

	case <-ctx.Done():
		// If the context was canceled, return ErrSTreamClosed
		return nil, ErrSTreamClosed
	}
}
