package sms

import "testing"

func TestReportStatusClassification(t *testing.T) {
	tests := []struct {
		name                  string
		status                ReportStatus
		wantClass             ReportStatusClass
		wantDelivered         bool
		wantRetrying          bool
		wantFailed            bool
		wantFinal             bool
		wantReserved          bool
		wantServiceCenterCode bool
		wantEffective         ReportStatus
	}{
		{
			name:          "delivered",
			status:        ReportStatusReceivedBySME,
			wantClass:     ReportStatusClassCompleted,
			wantDelivered: true,
			wantFinal:     true,
			wantEffective: ReportStatusReceivedBySME,
		},
		{
			name:          "temporary retrying",
			status:        ReportStatusRetryingSMEBusy,
			wantClass:     ReportStatusClassTemporaryErrorRetrying,
			wantRetrying:  true,
			wantEffective: ReportStatusRetryingSMEBusy,
		},
		{
			name:          "permanent failure",
			status:        ReportStatusPermanentIncompatibleDestination,
			wantClass:     ReportStatusClassPermanentError,
			wantFailed:    true,
			wantFinal:     true,
			wantEffective: ReportStatusPermanentIncompatibleDestination,
		},
		{
			name:          "temporary no retry",
			status:        ReportStatusNoRetryServiceRejected,
			wantClass:     ReportStatusClassTemporaryErrorNoRetry,
			wantFailed:    true,
			wantFinal:     true,
			wantEffective: ReportStatusNoRetryServiceRejected,
		},
		{
			name:          "reserved low value interpreted as service rejected",
			status:        ReportStatus(0x03),
			wantClass:     ReportStatusClassTemporaryErrorNoRetry,
			wantFailed:    true,
			wantFinal:     true,
			wantReserved:  true,
			wantEffective: ReportStatusNoRetryServiceRejected,
		},
		{
			name:          "reserved bit seven interpreted as service rejected",
			status:        ReportStatus(0x80),
			wantClass:     ReportStatusClassTemporaryErrorNoRetry,
			wantFailed:    true,
			wantFinal:     true,
			wantReserved:  true,
			wantEffective: ReportStatusNoRetryServiceRejected,
		},
		{
			name:                  "service centre specific completed",
			status:                ReportStatus(0x10),
			wantClass:             ReportStatusClassCompleted,
			wantFinal:             true,
			wantServiceCenterCode: true,
			wantEffective:         ReportStatus(0x10),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.status.Class(); got != tt.wantClass {
				t.Fatalf("Class() = %v, want %v", got, tt.wantClass)
			}
			if got := tt.status.Delivered(); got != tt.wantDelivered {
				t.Fatalf("Delivered() = %v, want %v", got, tt.wantDelivered)
			}
			if got := tt.status.Retrying(); got != tt.wantRetrying {
				t.Fatalf("Retrying() = %v, want %v", got, tt.wantRetrying)
			}
			if got := tt.status.Failed(); got != tt.wantFailed {
				t.Fatalf("Failed() = %v, want %v", got, tt.wantFailed)
			}
			if got := tt.status.Final(); got != tt.wantFinal {
				t.Fatalf("Final() = %v, want %v", got, tt.wantFinal)
			}
			if got := tt.status.Reserved(); got != tt.wantReserved {
				t.Fatalf("Reserved() = %v, want %v", got, tt.wantReserved)
			}
			if got := tt.status.ServiceCenterSpecific(); got != tt.wantServiceCenterCode {
				t.Fatalf("ServiceCenterSpecific() = %v, want %v", got, tt.wantServiceCenterCode)
			}
			if got := tt.status.Effective(); got != tt.wantEffective {
				t.Fatalf("Effective() = 0x%02X, want 0x%02X", got, tt.wantEffective)
			}
		})
	}
}

func TestReportStatusString(t *testing.T) {
	tests := []struct {
		name   string
		status ReportStatus
		want   string
	}{
		{"known", ReportStatusReceivedBySME, "received_by_sme"},
		{"reserved", ReportStatus(0x03), "reserved"},
		{"class fallback", ReportStatus(0x30), "temporary_error_retrying"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.status.String(); got != tt.want {
				t.Fatalf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}
