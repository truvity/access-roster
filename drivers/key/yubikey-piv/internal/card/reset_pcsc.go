//go:build sluis_card && (linux || darwin)

package card

// piv-go has no call for resetting the session of the card, and keeps its connection to itself, so the driver makes the
// reset with the PC/SC calls it needs: SCardConnect exclusively, then SCardDisconnect with SCARD_RESET_CARD. Reset is a
// warm reset of the card at the PC/SC layer (winscard.h: "Reset the card (warm reset)"): the card is powered on again and
// answers with its ATR, which deselects the PIV applet and ends the security state of the session, the PIN
// verification. It is not the applet's own reset (piv.YubiKey.Reset, INS 0xfb), which needs both the PIN and the PUK
// blocked and then wipes every key: that one is never called.

// #cgo darwin LDFLAGS: -framework PCSC
// #cgo linux pkg-config: libpcsclite
// #include <stdlib.h>
// #include <PCSC/winscard.h>
// #include <PCSC/wintypes.h>
import "C"

import (
	"fmt"
	"unsafe"
)

// scSharingViolation is SCARD_E_SHARING_VIOLATION: another connection to the reader is outstanding.
const scSharingViolation = 0x8010000B

// resetReader connects to the reader exclusively and disconnects with a reset of the card. The connection is exclusive,
// so it succeeds only when nobody else holds the card; it then leaves no connection of its own behind.
func resetReader(reader string) error {
	var ctx C.SCARDCONTEXT
	if rc := C.SCardEstablishContext(C.SCARD_SCOPE_SYSTEM, nil, nil, &ctx); rc != C.SCARD_S_SUCCESS {
		return fmt.Errorf("card: reset: connect to the smart card daemon: pcsc return code 0x%08x", uint32(rc))
	}
	defer C.SCardReleaseContext(ctx)
	name := C.CString(reader)
	defer C.free(unsafe.Pointer(name))
	var (
		handle C.SCARDHANDLE
		proto  C.DWORD
	)
	if rc := C.SCardConnect(ctx, name, C.SCARD_SHARE_EXCLUSIVE, C.SCARD_PROTOCOL_T1, &handle, &proto); rc != C.SCARD_S_SUCCESS {
		if uint32(rc) == scSharingViolation {
			return fmt.Errorf("%w: it cannot be connected to exclusively, so it cannot be reset", ErrSharing)
		}
		return fmt.Errorf("card: reset: connect: pcsc return code 0x%08x", uint32(rc))
	}
	if rc := C.SCardDisconnect(handle, C.SCARD_RESET_CARD); rc != C.SCARD_S_SUCCESS {
		return fmt.Errorf("card: reset: disconnect with reset: pcsc return code 0x%08x", uint32(rc))
	}
	return nil
}
