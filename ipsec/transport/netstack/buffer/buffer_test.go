package buffer

import "testing"

func TestGrowToPreservesClonedBuffer(t *testing.T) {
	original := MakeWithData([]byte("abcd"))
	defer original.Release()
	clone := original.Clone()
	defer clone.Release()

	clone.Truncate(2)
	clone.GrowTo(4, true)
	if got := string(clone.Flatten()); got != "ab\x00\x00" {
		t.Errorf("grown clone = %q, want %q", got, "ab\x00\x00")
	}
	if got := string(original.Flatten()); got != "abcd" {
		t.Errorf("original = %q, want %q", got, "abcd")
	}
}
