// Copyright 2025 Kirill Scherba <kirill@scherba.ru>. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package webtransport provides a WebTransport-over-HTTP/3 server
// implementation in Go.
//
// This package depend of the [quic-go](https://github.com/quic-go/quic-go)
// package.
//
// This package uses in Teonet project but has not any relation with Teonet and
// may be used in any other golang projects.
package webtransport

import (
	"context"
	"log"
	"net/http"
	"net/url"

	"slices"

	"github.com/quic-go/qpack"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/teonet-go/webtransport-go/h3"
)

// A Server defines parameters for running a WebTransport server. Use
// http.HandleFunc to register HTTP/3 endpoints for handling WebTransport
// requests.
type Server struct {
	http.Handler
	// ListenAddr sets an address to bind server to, e.g. ":4433"
	ListenAddr string
	// TLSCert defines a path to, or byte array containing, a certificate
	// (CRT file)
	TLSCert CertFile
	// TLSKey defines a path to, or byte array containing, the certificate's
	// private key (KEY file)
	TLSKey CertFile
	// AllowedOrigins represents list of allowed origins to connect from
	AllowedOrigins []string
	// Additional configuration parameters to pass onto QUIC listener
	QuicConfig *QuicConfig
}

// QuicConfig is a wrapper for quic.Config.
type QuicConfig quic.Config

// Starts a WebTransport server and blocks while it's running. Cancel the
// supplied Context to stop the server.
func (s *Server) Run(ctx context.Context) error {
	if s.Handler == nil {
		s.Handler = http.DefaultServeMux
	}
	if s.QuicConfig == nil {
		s.QuicConfig = &QuicConfig{}
	}
	s.QuicConfig.EnableDatagrams = true

	tlsConfig, err := s.makeTLSConfig()
	if err != nil {
		return err
	}

	listener, err := quic.ListenAddr(s.ListenAddr, tlsConfig, (*quic.Config)(s.QuicConfig))
	if err != nil {
		return err
	}

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	for {
		sess, err := listener.Accept(ctx)
		if err != nil {
			return err
		}
		go s.handleSession(ctx, sess)
	}
}

// handleSession is called for each new quic.Connection and handles the
// initial messages exchanged on the control streams.
func (s *Server) handleSession(ctx context.Context, sess quic.Connection) {
	// Open a unidirectional stream for the server control stream
	serverControlStream, err := sess.OpenUniStream()
	if err != nil {
		return
	}

	// Write server settings header
	streamHeader := h3.StreamHeader{Type: h3.STREAM_CONTROL}
	streamHeader.Write(serverControlStream)

	// Write server settings
	settingsFrame := (h3.SettingsMap{
		h3.H3_DATAGRAM_05:      1,
		h3.ENABLE_WEBTRANSPORT: 1,
	}).ToFrame()
	settingsFrame.Write(serverControlStream)

	// Accept control stream - client settings will appear here
	clientControlStream, err := sess.AcceptUniStream(context.Background())
	if err != nil {
		log.Println(err)
		return
	}

	// Read client settings
	clientSettingsReader := quicvarint.NewReader(clientControlStream)
	quicvarint.Read(clientSettingsReader)

	// Read client settings
	clientSettingsFrame := h3.Frame{}
	if err = clientSettingsFrame.Read(clientControlStream); err != nil ||
		clientSettingsFrame.Type != h3.FRAME_SETTINGS {
		return
	}

	// Accept request stream
	requestStream, err := sess.AcceptStream(ctx)
	if err != nil {
		return
	}

	// Create context
	ctx, cancelFunction := context.WithCancel(requestStream.Context())
	ctx = context.WithValue(ctx, http3.ServerContextKey, s)
	ctx = context.WithValue(ctx, http.LocalAddrContextKey, sess.LocalAddr())

	// Read headers
	headersFrame := h3.Frame{}
	err = headersFrame.Read(requestStream)
	if err != nil {
		cancelFunction()
		requestStream.Close()
		return
	}
	if headersFrame.Type != h3.FRAME_HEADERS {
		cancelFunction()
		requestStream.Close()
		return
	}

	// Decode headers
	decoder := qpack.NewDecoder(nil)
	hfs, err := decoder.DecodeFull(headersFrame.Data)
	if err != nil {
		cancelFunction()
		requestStream.Close()
		return
	}
	req, protocol, err := h3.RequestFromHeaders(hfs)
	if err != nil {
		cancelFunction()
		requestStream.Close()
		return
	}
	req.RemoteAddr = sess.RemoteAddr().String()

	// Create request
	req = req.WithContext(ctx)
	rw := h3.NewResponseWriter(requestStream)
	rw.Header().Add("sec-webtransport-http3-draft", "draft02")
	req.Body = &Session{
		Stream:              requestStream,
		Session:             sess,
		ClientControlStream: clientControlStream,
		ServerControlStream: serverControlStream,
		responseWriter:      rw,
		context:             ctx,
		cancel:              cancelFunction,
	}

	// Validate origin
	if protocol != "webtransport" || !s.validateOrigin(req.Header.Get("origin")) {
		req.Body.(*Session).RejectSession(http.StatusBadRequest)
		return
	}

	// Close the request stream when the response is sent
	go func() {
		for {
			buf := make([]byte, 1024)
			_, err := requestStream.Read(buf)
			if err != nil {
				cancelFunction()
				requestStream.Close()
				break
			}
		}
	}()

	// Serve the request
	s.ServeHTTP(rw, req)
}

// validateOrigin checks if the given origin is allowed to access the
// WebTransport server. An empty AllowedOrigins slice allows all origins.
func (s *Server) validateOrigin(origin string) bool {
	// No origin specified - everything is allowed
	if s.AllowedOrigins == nil {
		return true
	}

	// Enforce allowed origins
	// Parse the origin URL
	u, err := url.Parse(origin)
	if err != nil {
		// Invalid URL - reject
		return false
	}

	// Check if the host is in the allowed origins
	return slices.Contains(s.AllowedOrigins, u.Host)
}
