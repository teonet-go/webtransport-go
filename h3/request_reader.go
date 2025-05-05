package h3

import (
	"crypto/tls"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/quic-go/qpack"
)

var ErrPathAuthorityMethodEmpty = errors.New(":path, :authority and :method must not be empty")

// RequestFromHeaders returns a new http.Request from the given headers.
// It takes into account the HTTP/3 specific headers and sets the
// request URI, method, headers, content length, host and TLS connection state.
// It returns the parsed request and the protocol version.
// If an error occurs, it returns an error.
func RequestFromHeaders(headers []qpack.HeaderField) (request *http.Request,
	protocol string, err error) {

	// The :path, :authority and :method headers are mandatory
	// https://tools.ietf.org/html/draft-ietf-quic-http-12#section-4.1
	var path, authority, method, contentLengthStr string

	// The other headers are HTTP headers
	httpHeaders := http.Header{}

	// Parse the headers
	for _, h := range headers {
		switch h.Name {
		case ":path":
			path = h.Value
		case ":method":
			method = h.Value
		case ":authority":
			authority = h.Value
		case ":protocol":
			protocol = h.Value
		case "content-length":
			contentLengthStr = h.Value
		default:
			// If the header is not a pseudo header, it is an HTTP header
			if !h.IsPseudo() {
				httpHeaders.Add(h.Name, h.Value)
			}
		}
	}

	// Concatenate Cookie headers, see
	// https://tools.ietf.org/html/rfc6265#section-5.4
	if len(httpHeaders["Cookie"]) > 0 {
		httpHeaders.Set("Cookie", strings.Join(httpHeaders["Cookie"], "; "))
	}

	var u *url.URL
	var requestURI string

	switch {

	// If connected, the request URI is the path
	case method == http.MethodConnect:
		u, err = url.ParseRequestURI("https://" + authority + path)
		if err != nil {
			return
		}
		requestURI = path

	// If not connected, the request URI is the path
	default:
		if len(path) == 0 || len(authority) == 0 || len(method) == 0 {
			err = ErrPathAuthorityMethodEmpty
			return
		}

		u, err = url.ParseRequestURI(path)
		if err != nil {
			return
		}
		requestURI = path
	}

	// Set the content length
	var contentLength int64
	if len(contentLengthStr) > 0 {
		contentLength, err = strconv.ParseInt(contentLengthStr, 10, 64)
		if err != nil {
			return
		}
	}

	// Set the protocol version of the request
	if len(protocol) == 0 {
		protocol = "h3"
	}

	// Return the request and the protocol
	return &http.Request{
		Method:        method,
		URL:           u,
		Proto:         "HTTP/3",
		ProtoMajor:    3,
		ProtoMinor:    0,
		Header:        httpHeaders,
		Body:          nil,
		ContentLength: contentLength,
		Host:          authority,
		RequestURI:    requestURI,
		TLS:           &tls.ConnectionState{},
	}, protocol, nil
}
