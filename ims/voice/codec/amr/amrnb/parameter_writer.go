package amrnb

import "fmt"

type parameterWriter struct {
	values []int16
	offset int
}

func newParameterWriter(values []int16, offset int) (parameterWriter, error) {
	if offset < 0 || offset > len(values) {
		return parameterWriter{}, fmt.Errorf("writing AMR-NB parameters: offset %d outside 0..%d", offset, len(values))
	}
	return parameterWriter{values: values, offset: offset}, nil
}

func (w *parameterWriter) write(value int16) error {
	if w.offset >= len(w.values) {
		return fmt.Errorf("writing AMR-NB parameter %d: capacity %d", w.offset, len(w.values))
	}
	w.values[w.offset] = value
	w.offset++
	return nil
}

func (w *parameterWriter) writeSlice(values []int16) error {
	for _, value := range values {
		if err := w.write(value); err != nil {
			return err
		}
	}
	return nil
}

func (w *parameterWriter) reserve() (int, error) {
	index := w.offset
	if err := w.write(0); err != nil {
		return 0, err
	}
	return index, nil
}

func (w *parameterWriter) set(index int, value int16) error {
	if index < 0 || index >= w.offset || index >= len(w.values) {
		return fmt.Errorf("writing AMR-NB parameter %d: written count %d", index, w.offset)
	}
	w.values[index] = value
	return nil
}

func (w *parameterWriter) count() int {
	return w.offset
}
