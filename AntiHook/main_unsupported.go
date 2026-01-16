//go:build !windows && !darwin
// +build !windows,!darwin

package main

import (
	"fmt"
)

func showMessageBox(title, message string, flags uint) {
	_ = flags
	fmt.Printf("%s: %s\n", title, message)
}

func addToPath(dir string) error {
	return fmt.Errorf("add to PATH is not supported on this platform: %s", dir)
}

func recoverOriginal() error {
	return fmt.Errorf("recover is only supported on Windows")
}

