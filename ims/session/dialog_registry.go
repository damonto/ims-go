package session

import (
	"errors"

	"github.com/damonto/ims-client/ims/sip"
)

type dialogEntry struct {
	session *Session
	id      sip.DialogID
	key     string
	closed  bool
}

func (s *Session) RegisterDialog(id sip.DialogID, key string) (Attachment, error) {
	if id.CallID == "" {
		return nil, errors.New("registering dialog: call id is empty")
	}
	if key == "" {
		return nil, errors.New("registering dialog: key is empty")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errors.New("registering dialog: session is closed")
	}
	entry := &dialogEntry{session: s, id: id, key: key}
	s.dialogs[id.CallID] = append(s.dialogs[id.CallID], entry)
	return entry, nil
}

func (s *Session) LookupDialogKey(msg sip.Message) (string, bool) {
	callID := msg.Header("Call-ID")
	if callID == "" {
		return "", false
	}
	s.mu.Lock()
	entries := append([]*dialogEntry(nil), s.dialogs[callID]...)
	s.mu.Unlock()
	for _, entry := range entries {
		if entry.closed {
			continue
		}
		if entry.id.Matches(msg) {
			return entry.key, true
		}
	}
	return "", false
}

func (d *dialogEntry) Close() error {
	d.session.mu.Lock()
	defer d.session.mu.Unlock()
	if d.closed {
		return nil
	}
	d.closed = true
	entries := d.session.dialogs[d.id.CallID]
	filtered := entries[:0]
	for _, entry := range entries {
		if entry == d {
			continue
		}
		filtered = append(filtered, entry)
	}
	if len(filtered) == 0 {
		delete(d.session.dialogs, d.id.CallID)
		return nil
	}
	d.session.dialogs[d.id.CallID] = filtered
	return nil
}
