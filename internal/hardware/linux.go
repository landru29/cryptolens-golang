//go:build !windows

package hardware

import (
	"os"
	"strings"
	"syscall"
)

func identifier() (string, error) {
	for _, file := range []string{
		"/var/lib/dbus/machine-id",
		"/etc/machine-id",
	} {
		if id, err := os.ReadFile(file); err == nil && len(id) > 0 {
			return string(id), nil
		}
	}

	// Docker
	if cgroup, err := os.ReadFile("/proc/self/cgroup"); err == nil && len(cgroup) > 0 {
		firstLine := strings.Split(string(cgroup), "\n")[0]

		splitter := strings.Split(firstLine, "/")
		if len(splitter) > 1 && strings.TrimSpace(splitter[1]) != "" {
			return strings.TrimSpace(splitter[1]), nil
		}
	}

	if mountInfo, err := os.ReadFile("/proc/self/mountinfo"); err == nil && len(mountInfo) > 0 {
		lines := strings.Split(string(mountInfo), "\n")
		for _, line := range lines {
			if splitter := strings.Split(line, "docker/containers/"); len(splitter) > 1 {
				return strings.Split(splitter[1], "/")[0], nil
			}
		}
	}

	var utsname syscall.Utsname
	if err := syscall.Uname(&utsname); err == nil {
		release := make([]byte, len(utsname.Release))

		for idx, val := range utsname.Release {
			release[idx] = byte(val)
		}

		if string(release) == "microsoft" {
			if id, err := fromComputerSystemProduct(); err == nil {
				return id, nil
			}
		}
	}

	return "", nil
}
