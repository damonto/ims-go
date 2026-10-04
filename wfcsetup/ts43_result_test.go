package wfcsetup

import (
	"testing"

	ts43 "github.com/damonto/ts43-go"
)

func TestTS43ResultByPurpose(t *testing.T) {
	for _, tt := range []struct {
		name   string
		status ts43.WFCStatus
		want   [4]Action
	}{
		{
			name:   "entitled",
			status: ts43.WFCStatus{EntitlementStatus: ts43.WFCEntitlementEnabled, TCStatus: ts43.WFCTCNotRequired, AddrStatus: ts43.WFCAddressNotRequired, ProvStatus: ts43.WFCProvisionNotRequired},
			want:   [4]Action{ActionAllowActivation, ActionNone, ActionOpenWebsheet, ActionNone},
		},
		{
			name:   "terms needed",
			status: ts43.WFCStatus{EntitlementStatus: ts43.WFCEntitlementDisabled, TCStatus: ts43.WFCTCNotAvailable},
			want:   [4]Action{ActionOpenWebsheet, ActionWait, ActionDenied, ActionDisableWFC},
		},
		{
			name:   "provisioning",
			status: ts43.WFCStatus{EntitlementStatus: ts43.WFCEntitlementProvisioning},
			want:   [4]Action{ActionWait, ActionWait, ActionWait, ActionWait},
		},
		{
			name:   "incompatible",
			status: ts43.WFCStatus{EntitlementStatus: ts43.WFCEntitlementIncompatible},
			want:   [4]Action{ActionDenied, ActionDenied, ActionDenied, ActionDenied},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			for _, purpose := range []struct {
				name  string
				value Purpose
			}{
				{"activation", PurposeActivation},
				{"activation recheck", PurposeActivationRecheck},
				{"address update", PurposeEmergencyAddressUpdate},
				{"address recheck", PurposeEmergencyAddressRecheck},
			} {
				t.Run(purpose.name, func(t *testing.T) {
					f := ts43Flow{req: Request{Purpose: purpose.value}, wfc: ts43.WFCConfig{ShowVoWiFiWebview: true}}
					status := tt.status
					status.ServiceFlowURL = "https://carrier.example/portal"
					got, err := f.result(status)
					if err != nil {
						t.Fatal(err)
					}
					want := tt.want[purpose.value]
					if got.Action != want || got.Pending != (want == ActionWait) || (got.Websheet != nil) != (want == ActionOpenWebsheet) {
						t.Errorf("result() = %+v, want action %v", got, want)
					}
				})
			}
		})
	}
}
