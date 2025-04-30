// Package hardware manage identifiers from the hardware.
package hardware

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net"
	"os/exec"
	"runtime"
	"sort"
	"strings"

	localerrors "github.com/landru29/cryptolens-golang/internal/errors"
	pkgerrors "github.com/pkg/errors"
)

const (
	// ErrOSNotSupported is when a OS is not supported.
	ErrOSNotSupported localerrors.Error = "Operating system not supported"

	// ErrUnknown is a miscellaneous error.
	ErrUnknown localerrors.Error = "Unknown error"
)

// FootPrint is a unique footprint of a machine (physical, virtual machine, docker)
type FootPrint struct {
	OperatingSystem string               `json:"operatingSystem" yaml:"operatingSystem"`
	Architecture    string               `json:"architecture"    yaml:"architecture"`
	ID              string               `json:"id"              yaml:"id"`
	Interfaces      map[string]Interface `json:"interfaces"      yaml:"interfaces"`
}

// Interface is a network interface.
type Interface struct {
	MAC   string   `json:"mac"`
	Name  string   `json:"name"`
	Addrs []string `json:"addrs"`
}

func GetMachineCode() (string, error) {
	code, err := machineCode()
	if err != nil {
		return "", err
	}

	var buffer bytes.Buffer
	if err := json.NewEncoder(&buffer).Encode(code); err != nil {
		return "", err
	}

	h := sha256.New()

	h.Write(buffer.Bytes())

	return base64.StdEncoding.EncodeToString(h.Sum(nil)), nil
}

func machineCode() (*FootPrint, error) {
	// Network
	machineInterfaces, err := interfaces()
	if err != nil {
		return nil, err
	}

	output := FootPrint{
		OperatingSystem: runtime.GOOS,
		Architecture:    runtime.GOARCH,
		Interfaces:      machineInterfaces,
	}

	// Berkeley Software Distribution
	if strings.HasPrefix(output.OperatingSystem, "openbsd") || strings.HasPrefix(output.OperatingSystem, "freebsd") {
		if id, err := berkeleyID(); err != nil {
			output.ID = id

			return &output, nil
		}
	}

	// Linux or Windows
	if !strings.HasPrefix(output.OperatingSystem, "linux") && !strings.HasPrefix(output.OperatingSystem, "win") {
		return nil, pkgerrors.WithMessage(ErrOSNotSupported, output.OperatingSystem+" is not supported")
	}

	id, err := identifier()
	if err != nil {
		return nil, err
	}

	output.ID = id

	return &output, nil
}

func fromComputerSystemProduct() (string, error) {
	cmd := exec.Command(
		"powershell.exe",
		"-ExecutionPolicy",
		"bypass",
		"-command",
		"(Get-CimInstance -Class Win32_ComputerSystemProduct).UUID",
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", pkgerrors.WithMessage(err, "cannot execute powershell command")
	}

	return string(output), nil
}

func interfaces() (map[string]Interface, error) {
	output := map[string]Interface{}

	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range interfaces {
		addresses := []string{}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			addresses = append(addresses, addr.String())
		}

		sort.Strings(addresses)

		output[iface.Name] = Interface{
			Name:  iface.Name,
			MAC:   iface.HardwareAddr.String(),
			Addrs: addresses,
		}
	}

	return output, nil
}
