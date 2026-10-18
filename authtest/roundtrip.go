package authtest

import (
	"crypto/rand"
	"encoding/hex"
	"reflect"
	"testing"
	"time"
)

// randBytes returns n bytes from crypto/rand. The suites draw every flow id,
// credential id and user handle from it, so a harness whose stores share one
// database without truncation between subtests still sees unique keys.
func randBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("crypto/rand: %v", err)
	}
	return b
}

// randID returns prefix followed by 16 random bytes in hex.
func randID(t *testing.T, prefix string) string {
	t.Helper()
	return prefix + hex.EncodeToString(randBytes(t, 16))
}

// FillNonZero sets every exported field of the struct v points to a distinct
// non-zero value; signed integers are negative. Supported kinds are strings,
// byte and string slices, bools, signed and unsigned integers, byte arrays,
// *bool and [time.Time] (a UTC instant with a sub-microsecond remainder, which
// a store may drop). Any other kind fails the test, so a new field of a new
// kind forces the suites to learn it instead of silently skipping it.
func FillNonZero(t *testing.T, v any) {
	t.Helper()
	p := reflect.ValueOf(v)
	if p.Kind() != reflect.Pointer || p.IsNil() || p.Elem().Kind() != reflect.Struct {
		t.Fatalf("FillNonZero: need a non-nil pointer to a struct, got %T", v)
	}
	n := 0
	fillStruct(t, p.Elem(), &n)
}

var timeType = reflect.TypeFor[time.Time]()

func fillStruct(t *testing.T, s reflect.Value, n *int) {
	t.Helper()
	for i := range s.NumField() {
		f := s.Field(i)
		name := s.Type().Field(i).Name
		if !f.CanSet() {
			continue
		}
		*n++
		fillValue(t, f, name, *n)
	}
}

func fillValue(t *testing.T, f reflect.Value, name string, n int) {
	t.Helper()
	switch {
	case f.Type() == timeType:
		f.Set(reflect.ValueOf(time.Unix(1_700_000_000+int64(n)*3600, 123_456_789+int64(n)).UTC()))
		return
	case f.Kind() == reflect.String:
		f.SetString(name + "-" + string(rune('a'+n%26)) + string(rune('A'+n%7)))
	case f.Kind() == reflect.Bool:
		f.SetBool(true)
	case f.CanUint():
		f.SetUint(uint64(n)) // small enough for every unsigned width
	case f.CanInt():
		f.SetInt(-int64(n)) // negative, so a store that truncates or clamps a signed column is caught
	case f.Kind() == reflect.Slice && f.Type().Elem().Kind() == reflect.Uint8:
		f.SetBytes([]byte{byte(n), byte(n + 1), byte(n + 2)})
	case f.Kind() == reflect.Slice && f.Type().Elem().Kind() == reflect.String:
		s := reflect.MakeSlice(f.Type(), 2, 2)
		s.Index(0).SetString(name + "-1")
		s.Index(1).SetString(name + "-2")
		f.Set(s)
	case f.Kind() == reflect.Array && f.Type().Elem().Kind() == reflect.Uint8:
		for j := range f.Len() {
			f.Index(j).SetUint(uint64(n + j + 1))
		}
	case f.Kind() == reflect.Pointer && f.Type().Elem().Kind() == reflect.Bool:
		b := reflect.New(f.Type().Elem())
		b.Elem().SetBool(true)
		f.Set(b)
	default:
		t.Fatalf("FillNonZero: field %s has unsupported type %s; teach FillNonZero the kind", name, f.Type())
	}
}

// diffFields returns the name of the first exported field of a and b (structs
// of the same type) that differs. Two [time.Time] values match when they are
// the same instant to the microsecond, the precision a store must keep, in
// whatever location; a nil slice matches an empty one, which a store may
// return for it. It returns "" when they match.
func diffFields(a, b any) string {
	av, bv := reflect.ValueOf(a), reflect.ValueOf(b)
	for i := range av.NumField() {
		if !av.Type().Field(i).IsExported() {
			continue
		}
		name := av.Type().Field(i).Name
		x, y := av.Field(i), bv.Field(i)
		if x.Type() == timeType {
			xt, xok := x.Interface().(time.Time)
			yt, yok := y.Interface().(time.Time)
			if !xok || !yok || !sameInstant(xt, yt) {
				return name
			}
			continue
		}
		if x.Kind() == reflect.Slice && x.Len() == 0 && y.Len() == 0 {
			continue
		}
		if !reflect.DeepEqual(x.Interface(), y.Interface()) {
			return name
		}
	}
	return ""
}

// sameInstant reports whether a and b are the same instant to the
// microsecond: a store may truncate or round what lies below it.
func sameInstant(a, b time.Time) bool {
	d := a.Sub(b)
	return d > -time.Microsecond && d < time.Microsecond
}
