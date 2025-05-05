// Copyright 2025 Kirill Scherba <kirill@scherba.ru>. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Session module of webtransport package.

package webtransport

import (
	"bytes"
	"context"
	"net/http"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/teonet-go/webtransport-go/h3"
)

// Session is a WebTransport session (and the Body of a WebTransport http.Request)
// wrapping the request stream (a quic.Stream), the two control streams and a
// quic.Connection.
type Session struct {
	quic.Stream
	Session             quic.Connection
	ClientControlStream quic.ReceiveStream
	ServerControlStream quic.SendStream
	responseWriter      *h3.ResponseWriter
	context             context.Context
	cancel              context.CancelFunc
}

// Context returns the context for the WebTransport session.
func (s *Session) Context() context.Context {
	return s.context
}

// AcceptSession accepts an incoming WebTransport session. Call it in your
// http.HandleFunc.
func (s *Session) AcceptSession() {
	r := s.responseWriter
	r.WriteHeader(http.StatusOK)
	r.Flush()
}

// AcceptSession rejects an incoming WebTransport session, returning the
// supplied HTML error code to the client. Call it in your http.HandleFunc.
func (s *Session) RejectSession(errorCode int) {
	r := s.responseWriter
	r.WriteHeader(errorCode)
	r.Flush()
	s.CloseSession()
}

// AcceptStream accepts an incoming (that is, client-initated) bidirectional
// stream, blocking if necessary until one is available. Supply your own
// context, or use the WebTransport session's Context() so that ending the
// WebTransport session automatically cancels this call.
func (s *Session) AcceptStream() (Stream, error) {
	stream, err := s.Session.AcceptStream(s.context)
	if err != nil {
		return stream, err
	}

	streamFrame := h3.Frame{}
	err = streamFrame.Read(stream)

	return stream, err
}

// AcceptUniStream accepts an incoming (that is, client-initated) unidirectional
// stream, blocking if necessary until one is available. Supply your own context,
// or use the WebTransport session's Context() so that ending the WebTransport
// session automatically cancels this call.
func (s *Session) AcceptUniStream(ctx context.Context) (ReceiveStream, error) {
	stream, err := s.Session.AcceptUniStream(ctx)
	return ReceiveStream{
		ReceiveStream:        stream,
		readHeaderBeforeData: true,
		headerRead:           false,
	}, err
}

// OpenStream creates an outgoing (that is, server-initiated) bidirectional
// stream. It returns immediately.
func (s *Session) OpenStream() (Stream, error) {
	return s.openStream(nil, false)
}

// OpenStream creates an outgoing (that is, server-initiated) bidirectional
// stream. It generally returns immediately, but if the session's maximum number
// of streams has been exceeded, it will block until a slot is available. Supply
// your own context, or use the WebTransport session's Context() so that ending
// the WebTransport session automatically cancels this call.
func (s *Session) OpenStreamSync(ctx context.Context) (Stream, error) {
	return s.openStream(&ctx, true)
}

// OpenUniStream creates an outgoing (that is, server-initiated) bidirectional
// stream. It returns immediately.
func (s *Session) OpenUniStream() (SendStream, error) {
	return s.openUniStream(nil, false)
}

// OpenUniStreamSync creates an outgoing (that is, server-initiated)
// unidirectional stream. It generally returns immediately, but if the session's
// maximum number of streams has been exceeded, it will block until a slot is
// available. Supply your own context, or use the WebTransport session's Context()
// so that ending the WebTransport session automatically cancels this call.
func (s *Session) OpenUniStreamSync(ctx context.Context) (SendStream, error) {
	return s.openUniStream(&ctx, true)
}

// CloseSession cleanly closes a WebTransport session. All active streams are
// cancelled before terminating the session.
func (s *Session) CloseSession() {
	s.cancel()
	s.Close()
}

// CloseWithError closes a WebTransport session with a supplied error code and
// string.
func (s *Session) CloseWithError(code quic.ApplicationErrorCode, str string) {
	s.Session.CloseWithError(code, str)
}

// openStream creates an outgoing (that is, server-initiated) bidirectional
// stream. It returns immediately.
//
// It writes frame header to the stream, which is:
//   - one byte with the frame type (should be h3.FRAME_WEBTRANSPORT_STREAM)
//   - requestSessionID, which is the ID of the stream, as it is sent in the
//     WebTransport stream header.
func (s *Session) openStream(ctx *context.Context, sync bool) (Stream, error) {
	var stream quic.Stream
	var err error

	if sync {
		stream, err = s.Session.OpenStreamSync(*ctx)
	} else {
		stream, err = s.Session.OpenStream()
	}

	if err == nil {
		// Write frame header
		buf := &bytes.Buffer{}
		buf.Write(quicvarint.Append(nil, h3.FRAME_WEBTRANSPORT_STREAM))
		buf.Write(quicvarint.Append(nil, uint64(s.StreamID())))
		if _, err := stream.Write(buf.Bytes()); err != nil {
			stream.Close()
		}
	}

	return stream, err
}

// openUniStream creates an outgoing (that is, server-initiated) unidirectional
// stream. It returns immediately.
func (s *Session) openUniStream(ctx *context.Context, sync bool) (SendStream, error) {
	var stream quic.SendStream
	var err error

	if sync {
		stream, err = s.Session.OpenUniStreamSync(*ctx)
	} else {
		stream, err = s.Session.OpenUniStream()
	}
	return SendStream{
		SendStream:            stream,
		writeHeaderBeforeData: true,
		headerWritten:         false,
		requestSessionID:      uint64(s.StreamID()),
	}, err
}
