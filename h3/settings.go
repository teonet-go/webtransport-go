package h3

import (
	"bytes"
	"fmt"

	"github.com/quic-go/quic-go/quicvarint"
)

// Settings
const (
	// https://datatracker.ietf.org/doc/html/draft-ietf-quic-http-34
	SETTINGS_MAX_FIELD_SECTION_SIZE = SettingID(0x6)

	// https://datatracker.ietf.org/doc/html/draft-ietf-quic-qpack-21
	SETTINGS_QPACK_MAX_TABLE_CAPACITY = SettingID(0x1)
	SETTINGS_QPACK_BLOCKED_STREAMS    = SettingID(0x7)

	// https://datatracker.ietf.org/doc/html/draft-ietf-masque-h3-datagram-05#section-9.1
	H3_DATAGRAM_05 = SettingID(0xffd277)

	// https://www.ietf.org/archive/id/draft-ietf-webtrans-http3-02.html#section-8.2
	ENABLE_WEBTRANSPORT = SettingID(0x2b603742)
)

type SettingID uint64

type SettingsMap map[SettingID]uint64

// FromFrame reads a Frame and stores it in the SettingsMap.
//
// It returns an error if the frame size is too large or if there are duplicate settings.
func (s *SettingsMap) FromFrame(f Frame) error {
	if f.Length > 8*(1<<10) {
		return fmt.Errorf("unexpected size for SETTINGS frame: %d", f.Length)
	}

	b := bytes.NewReader(f.Data)
	for b.Len() > 0 {
		id, err := quicvarint.Read(b)
		if err != nil { // should not happen. We allocated the whole frame already.
			return err
		}
		val, err := quicvarint.Read(b)
		if err != nil { // should not happen. We allocated the whole frame already.
			return err
		}

		if _, ok := (*s)[SettingID(id)]; ok {
			return fmt.Errorf("duplicate setting: %d", id)
		}
		(*s)[SettingID(id)] = val
	}
	return nil
}

// ToFrame converts the SettingsMap to a frame.
//
// It returns an error if the frame size is too large or if there are duplicate settings.
func (s SettingsMap) ToFrame() Frame {
	f := Frame{Type: FRAME_SETTINGS}

	var l uint64
	for id, val := range s {
		l += uint64(quicvarint.Len(uint64(id)) + quicvarint.Len(val))
	}

	f.Length = l
	b := &bytes.Buffer{}
	for id, val := range s {
		b.Write(quicvarint.Append(nil, uint64(id)))
		b.Write(quicvarint.Append(nil, val))
	}
	f.Data = b.Bytes()

	return f
}

// String returns a human-readable representation of the setting ID.
func (id SettingID) String() string {
	switch id {
	case 0x01:
		// QPACK_MAX_TABLE_CAPACITY (draft-ietf-quic-qpack-21)
		return "QPACK_MAX_TABLE_CAPACITY"
	case 0x06:
		// MAX_FIELD_SECTION_SIZE (draft-ietf-quic-http-34)
		return "MAX_FIELD_SECTION_SIZE"
	case 0x07:
		// QPACK_BLOCKED_STREAMS (draft-ietf-quic-qpack-21)
		return "QPACK_BLOCKED_STREAMS"
	case 0x2b603742:
		// ENABLE_WEBTRANSPORT (draft-ietf-webtrans-http3-02)
		return "ENABLE_WEBTRANSPORT"
	case 0xffd277:
		// H3_DATAGRAM_05 (draft-ietf-masque-h3-datagram-05)
		return "H3_DATAGRAM_05"
	default:
		return fmt.Sprintf("%#x", uint64(id))
	}
}
