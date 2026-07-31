//go:build !linux && !windows

package autostart

type platformManager struct{}

func (platformManager) Status() (bool, bool) { return false, false }
func (platformManager) Enable() error        { return nil }
func (platformManager) Disable() error       { return nil }
