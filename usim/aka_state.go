package usim

type AKAIdentityState struct {
	Pseudonym      string
	ReauthIdentity string
	Counter        uint16
	MK             []byte
	KEncr          []byte
	KAut           []byte
}

func (s AKAIdentityState) clone() AKAIdentityState {
	return AKAIdentityState{
		Pseudonym:      s.Pseudonym,
		ReauthIdentity: s.ReauthIdentity,
		Counter:        s.Counter,
		MK:             append([]byte(nil), s.MK...),
		KEncr:          append([]byte(nil), s.KEncr...),
		KAut:           append([]byte(nil), s.KAut...),
	}
}

func (s AKAIdentityState) HasReauth() bool {
	return s.ReauthIdentity != "" && len(s.MK) != 0 && len(s.KEncr) != 0 && len(s.KAut) != 0
}

func (s AKAIdentityState) HasPseudonym() bool {
	return s.Pseudonym != ""
}
