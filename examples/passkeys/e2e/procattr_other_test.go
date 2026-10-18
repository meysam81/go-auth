//go:build !linux

package e2e

import "os/exec"

// dieWithParent is a no-op where the kernel has no parent-death signal; the
// test's cleanup still stops the example on every normal exit.
func dieWithParent(*exec.Cmd) {}
