package at

func (r CSIMResponse) MarshalBinary() ([]byte, error) {
	return append([]byte(nil), r...), nil
}

func (r *CSIMResponse) UnmarshalBinary(data []byte) error {
	*r = append((*r)[:0], data...)
	return nil
}
