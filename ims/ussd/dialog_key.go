package ussd

import (
	"fmt"
	"strings"

	"github.com/damonto/vowifi-go/ims/sip"
)

func (s *Session) localDialogURI() string {
	if uri := strings.TrimSpace(s.localURI); uri != "" {
		return uri
	}
	return preferredIdentity(s.service.reg.State())
}

func (s *Session) sessionKey() string {
	return dialogSessionKey(sip.DialogID{
		CallID:    s.callID,
		LocalTag:  s.localTag,
		RemoteTag: s.remoteTag,
	})
}

func (s *Session) inviteRequestKey() string {
	if !s.networkInitiated {
		return ""
	}
	return strings.TrimSpace(s.incomingInviteID)
}

func dialogSessionKey(id sip.DialogID) string {
	return id.CallID + "|" + id.LocalTag + "|" + id.RemoteTag
}

func incomingInviteKey(msg sip.Message) string {
	method := strings.ToUpper(strings.TrimSpace(msg.Method()))
	if method == "" {
		return ""
	}
	if method == "ACK" || method == "CANCEL" {
		method = "INVITE"
	}

	via := strings.TrimSpace(msg.Header("Via"))
	branch := strings.TrimSpace(sip.TopViaBranch(via))
	if strings.HasPrefix(branch, "z9hG4bK") {
		sentBy := strings.TrimSpace(sip.TopViaSentBy(via))
		if sentBy == "" {
			return ""
		}
		return branch + "|" + sentBy + "|" + method
	}

	requestURI := strings.TrimSpace(sip.RequestURI(msg))
	callID := strings.TrimSpace(msg.Header("Call-ID"))
	cseq := strings.TrimSpace(msg.Header("CSeq"))
	if number := sip.CSeqNumber(cseq); number > 0 && (strings.EqualFold(sip.CSeqMethod(cseq), "ACK") || strings.EqualFold(sip.CSeqMethod(cseq), "CANCEL")) {
		cseq = fmt.Sprintf("%d INVITE", number)
	}
	fromTag := strings.TrimSpace(sip.HeaderTag(msg.Header("From")))
	toTag := strings.TrimSpace(sip.HeaderTag(msg.Header("To")))
	if requestURI == "" || via == "" || callID == "" || cseq == "" || fromTag == "" {
		return ""
	}
	return requestURI + "|" + toTag + "|" + fromTag + "|" + callID + "|" + cseq + "|" + via
}

func looksLikeDialogMessage(msg sip.Message) bool {
	if strings.EqualFold(msg.Method(), "INFO") {
		return sip.TokenListContains(msg.Header("Info-Package"), infoPackage) || strings.Contains(strings.ToLower(msg.Header("Content-Type")), xmlContentType)
	}
	if strings.EqualFold(msg.Method(), "BYE") {
		return strings.Contains(strings.ToLower(msg.Header("Content-Type")), xmlContentType)
	}
	return false
}
