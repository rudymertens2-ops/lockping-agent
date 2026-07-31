// Package autostart beheert "start mee met je sessie" per platform:
// systemd user unit (Linux) of de Run-registersleutel (Windows).
package autostart

// Manager is bewust een interface zodat de web-UI hem kan injecteren en
// tests een fake kunnen gebruiken.
type Manager interface {
	// Status: enabled = start mee; supported = platform kan het überhaupt.
	Status() (enabled bool, supported bool)
	Enable() error
	Disable() error
}

// New geeft de platform-implementatie.
func New() Manager { return platformManager{} }
