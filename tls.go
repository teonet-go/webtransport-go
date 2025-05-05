// Copyright 2025 Kirill Scherba <kirill@scherba.ru>. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// TLS configuration and CertFile type for webtransport package.
// This module provides a CertFile type and a function to generate a tls.Config
// from a pair of CertFile values representing a TLS certificate and key.

package webtransport

import (
	"crypto/tls"
)

// A CertFile represents a TLS certificate or key, expressed either as a file
// path or file contents as a []byte.
type CertFile struct {
	Path string
	Data []byte
}

// Returns true if this CertFile references a file path.
func (c *CertFile) isFilePath() bool {
	return c.Path != ""
}

// makeTLSConfig generates a TLS configuration from the Server's TLS cert and key.
// The cert and key can be specified either as file paths or as byte slices.
//
// The NextProtos are set to all the HTTP/3 versions supported by this package.
func (s *Server) makeTLSConfig() (*tls.Config, error) {
	var cert tls.Certificate
	var err error

	if s.TLSCert.isFilePath() && s.TLSKey.isFilePath() {
		// Load the cert and key from files.
		cert, err = tls.LoadX509KeyPair(s.TLSCert.Path, s.TLSKey.Path)
	} else {
		// Load the cert and key from byte slices.
		cert, err = tls.X509KeyPair(s.TLSCert.Data, s.TLSKey.Data)
	}
	if err != nil {
		return nil, err
	}

	// The NextProtos are the ALPN protocols that this server supports.
	// See https://tools.ietf.org/html/rfc7540#section-3
	// and https://quicwg.org/base-drafts/draft-ietf-quic-http.html#section-6.1
	// for the list of allowed values.
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h3", "h3-32", "h3-31", "h3-30", "h3-29"},
	}, nil
}
