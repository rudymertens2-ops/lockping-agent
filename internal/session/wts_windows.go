//go:build windows

package session

import (
	"context"
	"fmt"
	"runtime"
	"sync/atomic"
	"syscall"
	"unsafe"
)

// Windows-implementatie: status via WTSQuerySessionInformation, events via
// een message-only venster + WTSRegisterSessionNotification (event-gedreven,
// geen polling), vergrendelen via LockWorkStation. Draait in de
// gebruikerssessie (console-app nu, tray-app later).

var (
	user32   = syscall.NewLazyDLL("user32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	wtsapi32 = syscall.NewLazyDLL("wtsapi32.dll")

	procLockWorkStation        = user32.NewProc("LockWorkStation")
	procRegisterClassExW       = user32.NewProc("RegisterClassExW")
	procCreateWindowExW        = user32.NewProc("CreateWindowExW")
	procDefWindowProcW         = user32.NewProc("DefWindowProcW")
	procDestroyWindow          = user32.NewProc("DestroyWindow")
	procGetMessageW            = user32.NewProc("GetMessageW")
	procTranslateMessage       = user32.NewProc("TranslateMessage")
	procDispatchMessageW       = user32.NewProc("DispatchMessageW")
	procPostMessageW           = user32.NewProc("PostMessageW")
	procPostQuitMessage        = user32.NewProc("PostQuitMessage")
	procGetModuleHandleW       = kernel32.NewProc("GetModuleHandleW")
	procWTSQuerySessionInfoW   = wtsapi32.NewProc("WTSQuerySessionInformationW")
	procWTSFreeMemory          = wtsapi32.NewProc("WTSFreeMemory")
	procWTSRegisterSession     = wtsapi32.NewProc("WTSRegisterSessionNotification")
	procWTSUnRegisterSession   = wtsapi32.NewProc("WTSUnRegisterSessionNotification")
)

const (
	wtsCurrentSession   = 0xFFFFFFFF
	wtsSessionInfoEx    = 25 // WTS_INFO_CLASS.WTSSessionInfoEx
	wmWtsSessionChange  = 0x02B1
	wmClose             = 0x0010
	wmDestroy           = 0x0002
	notifyForThisSession = 0
)

// hwndMessage is (HWND)-3: een message-only venster zonder UI.
var hwndMessage = ^uintptr(2)

// wtsInfoExHeader beslaat het begin van WTSINFOEX + LEVEL1; de rest van de
// struct (namen, tijden) hebben we niet nodig. De union is 8-byte-aligned
// door de LARGE_INTEGER-velden verderop, vandaar de expliciete padding.
type wtsInfoExHeader struct {
	Level        uint32
	_            uint32
	SessionID    uint32
	SessionState uint32
	SessionFlags int32
}

type winSession struct{}

// New bindt aan de interactieve sessie en faalt vroeg als WTS onbereikbaar is.
func New() (Controller, error) {
	s := &winSession{}
	if _, err := s.Locked(context.Background()); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *winSession) Locked(_ context.Context) (bool, error) {
	var buf unsafe.Pointer
	var size uint32
	r, _, callErr := procWTSQuerySessionInfoW.Call(
		0, wtsCurrentSession, wtsSessionInfoEx,
		uintptr(unsafe.Pointer(&buf)), uintptr(unsafe.Pointer(&size)),
	)
	if r == 0 {
		return false, fmt.Errorf("session: WTSQuerySessionInformation: %w", callErr)
	}
	defer procWTSFreeMemory.Call(uintptr(buf))
	if size < uint32(unsafe.Sizeof(wtsInfoExHeader{})) {
		return false, fmt.Errorf("session: WTSINFOEX te klein (%d bytes)", size)
	}
	info := (*wtsInfoExHeader)(buf)
	locked, known := lockedFromSessionFlags(info.SessionFlags)
	if !known {
		return false, fmt.Errorf("session: onbekende SessionFlags %d", info.SessionFlags)
	}
	return locked, nil
}

func (s *winSession) Lock(_ context.Context) error {
	r, _, callErr := procLockWorkStation.Call()
	if r == 0 {
		return fmt.Errorf("session: LockWorkStation: %w", callErr)
	}
	return nil
}

/* ---- Watch: message-only venster op een eigen OS-thread ---- */

// watchEvents is de brug tussen de C-callback (wndProc) en Watch. Eén
// watcher per proces; afgedwongen met watchActive.
var (
	watchEvents chan bool
	watchActive atomic.Bool
)

func (s *winSession) Watch(ctx context.Context, onChange func(locked bool)) error {
	if !watchActive.CompareAndSwap(false, true) {
		return fmt.Errorf("session: er draait al een watcher in dit proces")
	}
	defer watchActive.Store(false)

	last, err := s.Locked(ctx)
	if err != nil {
		return err
	}
	onChange(last)

	watchEvents = make(chan bool, 8)
	hwndCh := make(chan uintptr, 1)
	loopErr := make(chan error, 1)
	go messageLoop(hwndCh, loopErr)

	var hwnd uintptr
	select {
	case hwnd = <-hwndCh:
	case err := <-loopErr:
		return err
	}

	for {
		select {
		case <-ctx.Done():
			procPostMessageW.Call(hwnd, wmClose, 0, 0)
			return ctx.Err()
		case locked := <-watchEvents:
			if locked != last {
				last = locked
				onChange(locked)
			}
		case err := <-loopErr:
			return err
		}
	}
}

// messageLoop draait het venster + de Windows message pump; moet op één
// vaste OS-thread blijven (Win32-eis voor vensters).
func messageLoop(hwndCh chan<- uintptr, loopErr chan<- error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	hwnd, err := createMessageWindow()
	if err != nil {
		loopErr <- err
		return
	}
	if r, _, callErr := procWTSRegisterSession.Call(hwnd, notifyForThisSession); r == 0 {
		procDestroyWindow.Call(hwnd)
		loopErr <- fmt.Errorf("session: WTSRegisterSessionNotification: %w", callErr)
		return
	}
	hwndCh <- hwnd

	type msg struct {
		Hwnd    uintptr
		Message uint32
		WParam  uintptr
		LParam  uintptr
		Time    uint32
		Pt      struct{ X, Y int32 }
	}
	var m msg
	for {
		r, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 { // 0 = WM_QUIT, -1 = fout
			loopErr <- nil
			return
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
}

func wndProc(hwnd, message, wparam, lparam uintptr) uintptr {
	switch message {
	case wmWtsSessionChange:
		if locked, relevant := lockedFromSessionEvent(wparam); relevant {
			select {
			case watchEvents <- locked:
			default: // volle buffer: status wordt sowieso gededupliceerd
			}
		}
		return 0
	case wmClose:
		procDestroyWindow.Call(hwnd)
		return 0
	case wmDestroy:
		procWTSUnRegisterSession.Call(hwnd)
		procPostQuitMessage.Call(0)
		return 0
	}
	r, _, _ := procDefWindowProcW.Call(hwnd, message, wparam, lparam)
	return r
}

func createMessageWindow() (uintptr, error) {
	className, err := syscall.UTF16PtrFromString("LockPingAgentWatch")
	if err != nil {
		return 0, err
	}
	hInstance, _, _ := procGetModuleHandleW.Call(0)

	type wndClassEx struct {
		Size, Style                        uint32
		WndProc                            uintptr
		ClsExtra, WndExtra                 int32
		Instance, Icon, Cursor, Background uintptr
		MenuName, ClassName                *uint16
		IconSm                             uintptr
	}
	wc := wndClassEx{
		WndProc:   syscall.NewCallback(wndProc),
		Instance:  hInstance,
		ClassName: className,
	}
	wc.Size = uint32(unsafe.Sizeof(wc))
	if r, _, callErr := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc))); r == 0 {
		return 0, fmt.Errorf("session: RegisterClassEx: %w", callErr)
	}

	hwnd, _, callErr := procCreateWindowExW.Call(
		0, uintptr(unsafe.Pointer(className)), 0, 0,
		0, 0, 0, 0, hwndMessage, 0, hInstance, 0,
	)
	if hwnd == 0 {
		return 0, fmt.Errorf("session: CreateWindowEx: %w", callErr)
	}
	return hwnd, nil
}

func (s *winSession) Close() error { return nil }
