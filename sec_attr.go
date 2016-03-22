package npipe

import (
	"syscall"
	"unsafe"
)

const SDDL_REVISION_1 = 1
const AllowEveryone = `D:(A;;FA;;;WD)`
const AllowAnonymous = `D:(A;;FA;;;AN)`

var (
	advapi32 = syscall.NewLazyDLL("advapi32.dll")
	procConvertStringSecurityDescriptorToSecurityDescriptor = advapi32.NewProc(`ConvertStringSecurityDescriptorToSecurityDescriptorW`)
)

func initSecurityAttributes(SDDL string) (*syscall.SecurityAttributes, error) {
	var sa syscall.SecurityAttributes
	sa.Length = uint32(unsafe.Sizeof(sa))
	if `` != SDDL {
		u, err := syscall.UTF16PtrFromString(SDDL)
		if nil != err {
			return nil, err
		}
		r0, _, err := procConvertStringSecurityDescriptorToSecurityDescriptor.Call(
			uintptr(unsafe.Pointer(u)),
			SDDL_REVISION_1,
			uintptr(unsafe.Pointer(&sa.SecurityDescriptor)),
			uintptr(0))
		if 0 == r0 {
			return nil, err
		}
	}
	return &sa, nil
}
