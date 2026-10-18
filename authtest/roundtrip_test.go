package authtest

import (
	"testing"
	"time"
)

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

// A store keeps the microsecond and may truncate or round below it.
func TestDiffFields_TimesToTheMicrosecond(t *testing.T) {
	t.Parallel()
	type rec struct{ At time.Time }
	at := time.Date(2026, 1, 2, 3, 4, 5, 123_456_789, time.UTC)
	for _, tc := range []struct {
		name string
		got  time.Time
		want string
	}{
		{"truncated to the microsecond", at.Truncate(time.Microsecond), ""},
		{"rounded to the microsecond", at.Round(time.Microsecond), ""},
		{"in another location", at.In(time.FixedZone("+14", 14*3600)), ""},
		{"truncated to the millisecond", at.Truncate(time.Millisecond), "At"},
		{"truncated to the second", at.Truncate(time.Second), "At"},
		{"one microsecond later", at.Add(time.Microsecond), "At"},
	} {
		if got := diffFields(rec{tc.got}, rec{at}); got != tc.want {
			t.Errorf("%s: diffFields = %q, want %q", tc.name, got, tc.want)
		}
	}
}
