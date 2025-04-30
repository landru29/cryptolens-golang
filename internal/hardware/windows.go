//go:build windows

package hardware

import (
	"os/exec"
	"strings"

	pkgerrors "github.com/pkg/errors"
	"golang.org/x/sys/windows/registry"
)

func identifier() (string, error) {
	if id, err := fromRegistry(); err == nil {
		return id, nil
	}

	if id, err := fromComputerSystemProduct(); err == nil {
		return id, nil
	}

	if id, err := fromCSProduct(); err == nil {
		return id, nil
	}

	return "", ErrUnknown
}

func fromRegistry() (string, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography\MachineGuid`, registry.READ)
	if err != nil {
		return "", pkgerrors.WithMessage(err, "cannot read windows registry")
	}

	defer func() {
		_ = key.Close()
	}()

	value, _, err := key.GetStringValue("MyValue")
	if err != nil {
		return "", pkgerrors.WithMessage(err, "cannot read value from windows registry")
	}

	return value, nil
}

func fromCSProduct() (string, error) {
	cmd := exec.Command(
		"wmic",
		"csproduct",
		"get",
		"uuid",
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", pkgerrors.WithMessage(err, "cannot execute powershell command")
	}

	splitter := strings.Split(string(output), "\n")
	if len(splitter) < 3 {
		return "", pkgerrors.WithMessage(ErrUnknown, "wmic command failed")
	}

	return string(strings.TrimSpace(splitter[2])), nil
}
