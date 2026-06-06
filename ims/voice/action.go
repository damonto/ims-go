package voice

type callAction uint8

const (
	callActionHold callAction = iota
	callActionResume
	callActionRemoteSessionModification
	callActionEndAfterMediaEvent
	callActionExpireSessionTimer
	callActionReleaseForked2xx
	callActionReleaseCancelled2xx
	callActionReleaseAcknowledgedFailure
	callActionHangUp
	callActionReadMedia
	callActionReadRTCP
	callActionWriteRTCP
)

func (a callAction) String() string {
	switch a {
	case callActionHold:
		return "holding call"
	case callActionResume:
		return "resuming call"
	case callActionRemoteSessionModification:
		return "remote session modification"
	case callActionEndAfterMediaEvent:
		return "ending call after media event"
	case callActionExpireSessionTimer:
		return "expiring session timer"
	case callActionReleaseForked2xx:
		return "releasing forked call 2xx"
	case callActionReleaseCancelled2xx:
		return "releasing cancelled call 2xx"
	case callActionReleaseAcknowledgedFailure:
		return "releasing acknowledged failed call"
	case callActionHangUp:
		return "hanging up call"
	case callActionReadMedia:
		return "reading call media"
	case callActionReadRTCP:
		return "reading call rtcp"
	case callActionWriteRTCP:
		return "writing call rtcp"
	default:
		return "handling call"
	}
}
