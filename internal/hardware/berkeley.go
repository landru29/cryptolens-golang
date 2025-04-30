package hardware

import (
	"os"
	"os/exec"

	pkgerrors "github.com/pkg/errors"
)

func berkeleyID() (string, error) {
	if id, err := os.ReadFile("/etc/hostid"); err == nil && len(id) > 0 {
		return string(id), nil
	}

	cmd := exec.Command(
		"kenv",
		"-q",
		"smbios.system.uuid",
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", pkgerrors.WithMessage(err, "cannot execute kenv command")
	}

	if len(output) > 0 {
		return string(output), nil
	}

	return "", ErrUnknown
}
