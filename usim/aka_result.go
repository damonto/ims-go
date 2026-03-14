package usim

type AKAResult struct {
	RES    []byte
	CK     []byte
	IK     []byte
	AUTS   []byte
	Reject bool
}

func (r AKAResult) IsSuccess() bool {
	return len(r.RES) != 0 && len(r.CK) != 0 && len(r.IK) != 0
}

func (r AKAResult) IsSynchronizationFailure() bool {
	return len(r.AUTS) != 0
}

func (r AKAResult) IsAuthenticationReject() bool {
	return r.Reject
}
