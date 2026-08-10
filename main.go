package main

import (
	"crypto/md5"
	"encoding/hex"
	"os"
	"os/exec"
	"strings"
)

const secret = "datagrand_license_copyright_9s^994f@)E"

func getUUID() string {
	uuid := getWindowsUUID()
	if uuid != "" {
		return uuid
	}
	uuid = getLinuxUUID()
	if uuid != "" {
		return uuid
	}
	uuid = getMacUUID()
	if uuid != "" {
		return uuid
	}
	return ""
}

func getWindowsUUID() string {
	cmd := `powershell -Command "Get-WmiObject -Class Win32_ComputerSystemProduct | Select -Expand UUID"`
	out, err := exec.Command("powershell", "-Command", cmd).Output()
	if err == nil {
		uuid := strings.TrimSpace(string(out))
		uuid = strings.ReplaceAll(uuid, "-", "")
		return strings.ToLower(uuid)
	}
	return ""
}

func getLinuxUUID() string {
	data, err := os.ReadFile("/sys/class/dmi/id/product_uuid")
	if err == nil {
		uuid := strings.TrimSpace(string(data))
		uuid = strings.ReplaceAll(uuid, "-", "")
		return strings.ToLower(uuid)
	}
	data, err = os.ReadFile("/etc/machine-id")
	if err == nil {
		uuid := strings.TrimSpace(string(data))
		uuid = strings.ReplaceAll(uuid, "-", "")
		return strings.ToLower(uuid)
	}
	return ""
}

func getMacUUID() string {
	out, err := exec.Command("sysctl", "-n", "hw.uuid").Output()
	if err == nil {
		uuid := strings.TrimSpace(string(out))
		uuid = strings.ReplaceAll(uuid, "-", "")
		return strings.ToLower(uuid)
	}
	cmd := `ioreg -rd1 -c IOPlatformExpertDevice | grep -E '(UUID)'`
	out, err = exec.Command("sh", "-c", cmd).Output()
	if err == nil {
		lines := strings.Split(string(out), "\n")
		for _, line := range lines {
			if strings.Contains(line, "UUID") {
				parts := strings.Split(line, "=")
				if len(parts) > 1 {
					uuid := strings.TrimSpace(strings.Trim(parts[1], "\""))
					uuid = strings.ReplaceAll(uuid, "-", "")
					return strings.ToLower(uuid)
				}
			}
		}
	}
	return ""
}

func main() {
	uuid := getUUID()
	if uuid == "" {
		os.Exit(1)
	}
	tmp := uuid + secret
	h := md5.Sum([]byte(tmp))
	for _, b := range h[:] {
		print(hex.EncodeToString([]byte{b}))
	}
}
