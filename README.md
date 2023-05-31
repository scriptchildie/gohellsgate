# gohellsgate

A pure golang implementation of hellsgate. 

This library allows for both direct and indrect syscalls in golang. 

This is the best document out there to understand the technique https://github.com/am0nsec/HellsGate/blob/master/hells-gate.pdf

Also this is a great resource https://github.com/C-Sto/BananaPhone. Stolen the bpSyscall function from this repo. This is a great way to avoid using VirtuallAlloc and CreateThread.

## Caveats

It currently works only with Nt functions

## Usage
```
func gohellsgate.IndirectSyscall(ntapi string, argh ...uintptr) (errcode uint32, err error)
func gohellsgate.Syscall(ntapi string, argh ...uintptr) (errcode uint32, err error)
```

I like to wrap the syscall function in its own function but you don't have to. This is my implementation of NtAllocateVirtualMemorySyscall


In the main function
```
	addr, err := NtAllocateVirtualMemorySyscall("NtAllocateVirtualMemory", uintptr(pHandle), uintptr(len(sc)), windows.MEM_COMMIT|windows.MEM_RESERVE, flProtect, verbose)
	if err != nil {
		return fmt.Errorf("NtAllocateVirtualMemorySyscall: Failed to allocate memory %v\n", err)
	}
```

Wrapper function. If you would like to use a direct syscall instead of indirect simply change from gohellsgate.IndrectSyscall to gohellsgate.Syscall
```
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

```
