//go:build !windows && !darwin
// +build !windows,!darwin

package registry

import (
	"fmt"
	"os"
	"path/filepath"
)

const (
	ProtocolName   = "kiro"
	ProtocolScheme = "kiro://"
)

type ProtocolHandler struct {
	Protocol    string
	ExePath     string
	Description string
}

func NewProtocolHandler(protocol, description string) (*ProtocolHandler, error) {
	exePath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("failed to get executable path: %w", err)
	}

	exePath, err = filepath.Abs(exePath)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path: %w", err)
	}

	return &ProtocolHandler{
		Protocol:    protocol,
		ExePath:     exePath,
		Description: description,
	}, nil
}

func (h *ProtocolHandler) Register() error {
	return fmt.Errorf("protocol handler register is not supported on this platform: %s", h.Protocol)
}

func (h *ProtocolHandler) Unregister() error {
	return fmt.Errorf("protocol handler unregister is not supported on this platform: %s", h.Protocol)
}

func (h *ProtocolHandler) IsRegistered() (bool, error) {
	return false, nil
}

func (h *ProtocolHandler) GetRegisteredHandler() (string, error) {
	return "", fmt.Errorf("get registered handler is not supported on this platform: %s", h.Protocol)
}

func (h *ProtocolHandler) Backup() (map[string]string, error) {
	return nil, nil
}

func (h *ProtocolHandler) Restore(backup map[string]string) error {
	_ = backup
	return fmt.Errorf("restore is not supported on this platform: %s", h.Protocol)
}

func (h *ProtocolHandler) IsSelfRegistered() (bool, error) {
	return false, nil
}

