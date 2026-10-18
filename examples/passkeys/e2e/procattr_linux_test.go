package e2e

import (
	"os/exec"
	"syscall"
)

// dieWithParent has the kernel kill the example when the test binary dies, so
// a test killed by -timeout does not leave it listening on the port.
func dieWithParent(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
}
