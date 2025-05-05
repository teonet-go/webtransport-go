package h3

import (
	"bufio"
	"bytes"
	"net/http"
	"strconv"
	"strings"

	"github.com/quic-go/qpack"
	"github.com/quic-go/quic-go"
)

// DataStreamer lets the caller take over the stream. After a call to DataStream
// the HTTP server library will not do anything else with the connection.
//
// It becomes the caller's responsibility to manage and close the stream.
//
// After a call to DataStream, the original Request.Body must not be used.
type DataStreamer interface {
	DataStream() quic.Stream
}

type ResponseWriter struct {
	stream         quic.Stream // needed for DataStream()
	bufferedStream *bufio.Writer

	header         http.Header
	status         int // status code passed to WriteHeader
	headerWritten  bool
	dataStreamUsed bool // set when DataSteam() is called
}

// NewResponseWriter returns a new ResponseWriter that writes to the given stream.
// All writes will be buffered.
func NewResponseWriter(stream quic.Stream) *ResponseWriter {
	return &ResponseWriter{
		// header contains the response headers
		header: http.Header{},
		// stream is the underlying stream
		stream: stream,
		// bufferedStream is a buffered writer wrapping the stream
		bufferedStream: bufio.NewWriter(stream),
	}
}

// Header returns the response headers.
//
// The Header map is a reference to the map used by the ResponseWriter,
// so changes to the map will affect future calls to Header() and
// WriteHeader(). Keys and values must not be modified.
func (w *ResponseWriter) Header() http.Header {
	return w.header
}

// WriteHeader sends an HTTP response header with the provided status code.
//
// The Header map in the ResponseWriter is updated as a side effect of this call.
// The provided value for status code must be a valid HTTP status code as
// documented in http.StatusText.
//
// The Header map is a reference to the map used by the ResponseWriter,
// so changes to the map will affect future calls to Header() and
// WriteHeader(). Keys and values must not be modified.
func (w *ResponseWriter) WriteHeader(status int) {
	if w.headerWritten {
		return
	}

	if status < 100 || status >= 200 {
		w.headerWritten = true
	}
	w.status = status

	var headers bytes.Buffer
	enc := qpack.NewEncoder(&headers)

	// The ":status" pseudo-header is always sent first
	enc.WriteField(qpack.HeaderField{Name: ":status", Value: strconv.Itoa(status)})

	// Then the other headers
	for k, v := range w.header {
		for index := range v {
			enc.WriteField(qpack.HeaderField{Name: strings.ToLower(k), Value: v[index]})
		}
	}

	// Create a frame with the headers
	headersFrame := Frame{Type: FRAME_HEADERS, Length: uint64(headers.Len()), Data: headers.Bytes()}

	// Write the frame to the stream
	headersFrame.Write(w.bufferedStream)

	// If this is a 1xx response, flush the stream
	if !w.headerWritten {
		w.Flush()
	}
}

// Write writes the data to the client in a series of HTTP/3 DATA frames.
// If WriteHeader has not been called explicitly, Write calls WriteHeader(http.StatusOK).
// To write a response with a non-2xx status code, WriteHeader must be called explicitly.
func (w *ResponseWriter) Write(p []byte) (int, error) {
	// If WriteHeader has not been called, write a 200 OK header
	if !w.headerWritten {
		w.WriteHeader(200)
	}

	// If a 1xx, 204, or 304 status code has been set, do not write the body
	if !bodyAllowedForStatus(w.status) {
		return 0, http.ErrBodyNotAllowed
	}

	// Create a frame with the data
	dataFrame := Frame{Type: FRAME_DATA, Length: uint64(len(p)), Data: p}

	// Write the frame to the stream
	return dataFrame.Write(w.bufferedStream)
}

// Flush implements http.Flusher.
// It flushes the buffered stream.
func (w *ResponseWriter) Flush() {
	// Flush the buffered stream
	w.bufferedStream.Flush()
}

// DataStream lets the caller take over the stream. After a call to DataStream
// the HTTP server library will not do anything else with the connection.
//
// It becomes the caller's responsibility to manage and close the stream.
//
// After a call to DataStream, the original Request.Body must not be used.
func (w *ResponseWriter) DataStream() quic.Stream {
	// Mark that the data stream was used
	w.dataStreamUsed = true

	// Flush the buffered stream
	w.Flush()

	// Return the stream
	return w.stream
}

// copied from http2/http2.go
// bodyAllowedForStatus reports whether a given response status code
// permits a body. See RFC 2616, section 4.4.
func bodyAllowedForStatus(status int) bool {
	switch {
	case status >= 100 && status <= 199:
		return false
	case status == 204:
		return false
	case status == 304:
		return false
	}
	return true
}
