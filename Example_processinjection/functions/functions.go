package functions

import (
	"fmt"
	"log"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")
	ntdll    = windows.NewLazySystemDLL("ntdll.dll")

	VirtualAlloc   = kernel32.NewProc("VirtualAlloc")
	VirtualProtect = kernel32.NewProc("VirtualProtect")
	RtlCopyMemory  = ntdll.NewProc("RtlCopyMemory")
)

func NtOpenProcessSyscall(syscallno byte, DesiredAccess uintptr, pid int) *syscall.Handle {
	/*
	   __kernel_entry NTSYSCALLAPI NTSTATUS NtOpenProcess(
	     [out]          PHANDLE            ProcessHandle,
	     [in]           ACCESS_MASK        DesiredAccess,
	     [in]           POBJECT_ATTRIBUTES ObjectAttributes,
	     [in, optional] PCLIENT_ID         ClientId
	   );
	*/
	type UnicodeString struct {
		Length        uint16
		MaximumLength uint16
		Buffer        *uint16
	}
	type ObjectAttributes struct {
		Length                   uint32
		RootDirectory            syscall.Handle
		ObjectName               *UnicodeString
		Attributes               uint32
		SecurityDescriptor       *byte
		SecurityQualityOfService *byte
	}
	type ClientId struct {
		UniqueProcess syscall.Handle
		UniqueThread  syscall.Handle
	}

	var Handle syscall.Handle
	//var AccessMask uint32
	var oa ObjectAttributes
	var cID ClientId
	cID.UniqueProcess = syscall.Handle(pid)

	// syscall for NtOpenProcess
	shellcode := []byte{
		//0xcc,
		0x4c, 0x8b, 0xd1,
		0xb8, syscallno, 0x00, 0x00, 0x00,
		0x0f, 0x05,
		0xc3,
	}

	addr, _, errVirtualAlloc := VirtualAlloc.Call(0, uintptr(len(shellcode)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)

	if errVirtualAlloc != nil && errVirtualAlloc.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling VirtualAlloc:\r\n%s", errVirtualAlloc.Error()))
	}

	if addr == 0 {
		log.Fatal("[!]VirtualAlloc failed and returned 0")
	}

	_, _, errRtlCopyMemory := RtlCopyMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))

	if errRtlCopyMemory != nil && errRtlCopyMemory.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling RtlCopyMemory:\r\n%s", errRtlCopyMemory.Error()))
	}

	oldProtect := windows.PAGE_READWRITE
	_, _, errVirtualProtect := VirtualProtect.Call(addr, uintptr(len(shellcode)), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
	if errVirtualProtect != nil && errVirtualProtect.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("Error calling VirtualProtect:\r\n%s", errVirtualProtect.Error()))
	}

	_, _, errSyscall := syscall.SyscallN(addr, uintptr(unsafe.Pointer(&Handle)), DesiredAccess, uintptr(unsafe.Pointer(&oa)), uintptr(unsafe.Pointer(&cID)))

	if errSyscall != 0 {
		log.Fatal(fmt.Sprintf("[!]Error executing shellcode syscall:\r\n%s", errSyscall.Error()))
	}

	fmt.Printf("Handle: %v\n", Handle)

	return &Handle
}
