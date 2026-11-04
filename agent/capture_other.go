//go:build !linux

package main

import "errors"

func captureRequirements() map[string]any {
	return map[string]any{"linux": false, "message": "eBPF capture requires a Linux target host; snapshot collection is available"}
}
func capture(Config, *writer) error {
	return errors.New("eBPF capture requires Linux; the desktop client itself does not capture Linux kernel traffic")
}
