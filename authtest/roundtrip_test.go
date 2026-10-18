package authtest

import "testing"

// A store may return nil for an empty slice, never empty for a non-empty one.
func TestDiffFields_NilAndEmptySlices(t *testing.T) {
	t.Parallel()
	type rec struct{ B []byte }
	for _, tc := range []struct {
		name string
		a, b rec
		want string
	}{
		{"nil and empty", rec{nil}, rec{[]byte{}}, ""},
		{"empty and nil", rec{[]byte{}}, rec{nil}, ""},
		{"empty and non-empty", rec{[]byte{}}, rec{[]byte{1}}, "B"},
		{"nil and non-empty", rec{nil}, rec{[]byte{1}}, "B"},
		{"non-empty and nil", rec{[]byte{1}}, rec{nil}, "B"},
	} {
		if got := diffFields(tc.a, tc.b); got != tc.want {
			t.Errorf("%s: diffFields = %q, want %q", tc.name, got, tc.want)
		}
	}
}
