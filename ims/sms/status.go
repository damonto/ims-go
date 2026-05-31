package sms

// ReportStatus is the TP-Status octet from an SMS-STATUS-REPORT.
//
// 3GPP TS 23.040 9.2.3.15 says reserved values must be stored as received
// but interpreted as Service Rejected with no further transfer attempts.
type ReportStatus byte

type ReportStatusClass byte

const (
	ReportStatusClassCompleted ReportStatusClass = iota
	ReportStatusClassTemporaryErrorRetrying
	ReportStatusClassPermanentError
	ReportStatusClassTemporaryErrorNoRetry
)

const (
	ReportStatusReceivedBySME           ReportStatus = 0x00
	ReportStatusForwardedUnconfirmed    ReportStatus = 0x01
	ReportStatusReplacedByServiceCenter ReportStatus = 0x02

	ReportStatusRetryingCongestion        ReportStatus = 0x20
	ReportStatusRetryingSMEBusy           ReportStatus = 0x21
	ReportStatusRetryingNoResponseFromSME ReportStatus = 0x22
	ReportStatusRetryingServiceRejected   ReportStatus = 0x23
	ReportStatusRetryingQoSUnavailable    ReportStatus = 0x24
	ReportStatusRetryingErrorInSME        ReportStatus = 0x25

	ReportStatusPermanentRemoteProcedureError    ReportStatus = 0x40
	ReportStatusPermanentIncompatibleDestination ReportStatus = 0x41
	ReportStatusPermanentConnectionRejectedBySME ReportStatus = 0x42
	ReportStatusPermanentNotObtainable           ReportStatus = 0x43
	ReportStatusPermanentQoSUnavailable          ReportStatus = 0x44
	ReportStatusPermanentNoInterworking          ReportStatus = 0x45
	ReportStatusPermanentValidityExpired         ReportStatus = 0x46
	ReportStatusPermanentDeletedByOriginatingSME ReportStatus = 0x47
	ReportStatusPermanentDeletedByServiceCenter  ReportStatus = 0x48
	ReportStatusPermanentSMDoesNotExist          ReportStatus = 0x49

	ReportStatusNoRetryCongestion        ReportStatus = 0x60
	ReportStatusNoRetrySMEBusy           ReportStatus = 0x61
	ReportStatusNoRetryNoResponseFromSME ReportStatus = 0x62
	ReportStatusNoRetryServiceRejected   ReportStatus = 0x63
	ReportStatusNoRetryQoSUnavailable    ReportStatus = 0x64
	ReportStatusNoRetryErrorInSME        ReportStatus = 0x65
)

func (s ReportStatus) Code() byte {
	return byte(s)
}

func (s ReportStatus) Effective() ReportStatus {
	if s.Reserved() {
		return ReportStatusNoRetryServiceRejected
	}
	return s
}

func (s ReportStatus) Class() ReportStatusClass {
	switch s.Effective() & 0x60 {
	case 0x00:
		return ReportStatusClassCompleted
	case 0x20:
		return ReportStatusClassTemporaryErrorRetrying
	case 0x40:
		return ReportStatusClassPermanentError
	default:
		return ReportStatusClassTemporaryErrorNoRetry
	}
}

func (s ReportStatus) Delivered() bool {
	return s == ReportStatusReceivedBySME
}

func (s ReportStatus) Completed() bool {
	return s.Class() == ReportStatusClassCompleted
}

func (s ReportStatus) Retrying() bool {
	return s.Class() == ReportStatusClassTemporaryErrorRetrying
}

func (s ReportStatus) PermanentError() bool {
	return s.Class() == ReportStatusClassPermanentError
}

func (s ReportStatus) TemporaryError() bool {
	class := s.Class()
	return class == ReportStatusClassTemporaryErrorRetrying || class == ReportStatusClassTemporaryErrorNoRetry
}

func (s ReportStatus) NoRetry() bool {
	class := s.Class()
	return class == ReportStatusClassPermanentError || class == ReportStatusClassTemporaryErrorNoRetry
}

func (s ReportStatus) Final() bool {
	return !s.Retrying()
}

func (s ReportStatus) Failed() bool {
	return s.PermanentError() || s.Class() == ReportStatusClassTemporaryErrorNoRetry
}

func (s ReportStatus) Reserved() bool {
	switch {
	case s >= 0x80:
		return true
	case s >= 0x03 && s <= 0x0f:
		return true
	case s >= 0x26 && s <= 0x2f:
		return true
	case s >= 0x4a && s <= 0x4f:
		return true
	case s >= 0x66 && s <= 0x6f:
		return true
	default:
		return false
	}
}

func (s ReportStatus) ServiceCenterSpecific() bool {
	switch {
	case s >= 0x10 && s <= 0x1f:
		return true
	case s >= 0x30 && s <= 0x3f:
		return true
	case s >= 0x50 && s <= 0x5f:
		return true
	case s >= 0x70 && s <= 0x7f:
		return true
	default:
		return false
	}
}

func (s ReportStatus) String() string {
	if s.Reserved() {
		return "reserved"
	}
	switch s {
	case ReportStatusReceivedBySME:
		return "received_by_sme"
	case ReportStatusForwardedUnconfirmed:
		return "forwarded_unconfirmed"
	case ReportStatusReplacedByServiceCenter:
		return "replaced_by_service_center"
	case ReportStatusRetryingCongestion:
		return "retrying_congestion"
	case ReportStatusRetryingSMEBusy:
		return "retrying_sme_busy"
	case ReportStatusRetryingNoResponseFromSME:
		return "retrying_no_response_from_sme"
	case ReportStatusRetryingServiceRejected:
		return "retrying_service_rejected"
	case ReportStatusRetryingQoSUnavailable:
		return "retrying_qos_unavailable"
	case ReportStatusRetryingErrorInSME:
		return "retrying_error_in_sme"
	case ReportStatusPermanentRemoteProcedureError:
		return "permanent_remote_procedure_error"
	case ReportStatusPermanentIncompatibleDestination:
		return "permanent_incompatible_destination"
	case ReportStatusPermanentConnectionRejectedBySME:
		return "permanent_connection_rejected_by_sme"
	case ReportStatusPermanentNotObtainable:
		return "permanent_not_obtainable"
	case ReportStatusPermanentQoSUnavailable:
		return "permanent_qos_unavailable"
	case ReportStatusPermanentNoInterworking:
		return "permanent_no_interworking"
	case ReportStatusPermanentValidityExpired:
		return "permanent_validity_expired"
	case ReportStatusPermanentDeletedByOriginatingSME:
		return "permanent_deleted_by_originating_sme"
	case ReportStatusPermanentDeletedByServiceCenter:
		return "permanent_deleted_by_service_center"
	case ReportStatusPermanentSMDoesNotExist:
		return "permanent_sm_does_not_exist"
	case ReportStatusNoRetryCongestion:
		return "no_retry_congestion"
	case ReportStatusNoRetrySMEBusy:
		return "no_retry_sme_busy"
	case ReportStatusNoRetryNoResponseFromSME:
		return "no_retry_no_response_from_sme"
	case ReportStatusNoRetryServiceRejected:
		return "no_retry_service_rejected"
	case ReportStatusNoRetryQoSUnavailable:
		return "no_retry_qos_unavailable"
	case ReportStatusNoRetryErrorInSME:
		return "no_retry_error_in_sme"
	default:
		return s.Class().String()
	}
}

func (c ReportStatusClass) String() string {
	switch c {
	case ReportStatusClassCompleted:
		return "completed"
	case ReportStatusClassTemporaryErrorRetrying:
		return "temporary_error_retrying"
	case ReportStatusClassPermanentError:
		return "permanent_error"
	case ReportStatusClassTemporaryErrorNoRetry:
		return "temporary_error_no_retry"
	default:
		return "unknown"
	}
}
