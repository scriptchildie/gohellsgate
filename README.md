# gohellsgate

A pure golang implementation of hellsgate. 

This is the best document out there to understand the technique https://github.com/am0nsec/HellsGate/blob/master/hells-gate.pdf

Also this is a great resource https://github.com/C-Sto/BananaPhone. Stolen the bpSyscall function from this repo. This is a great way to avoid using VirtuallAlloc and CreateThread.

## Functions of this Package

### func ListDllFromPEB() []dllstruct
Loops through loaded modules and prints the name and their base address in a slice of dllstruct

### func PrintModules() 
Uses ListDllFromPEB and then prints dll names and base addresses 

### func GetBaseAddrOfLoadedDll(name string) (uintptr, error)
Get the base address of dll by providing the dll name "ntdll.dll" for example.

### func getExportTableAddress(name string) (uintptr, error)
Get the ExportTable Address of the provided dll. 

### func GetImageExportDirectory(name string) (*IMAGE_EXPORT_DIRECTORY, error) 
Get the information of Image_export_directory and return the following struct

type IMAGE_EXPORT_DIRECTORY struct { //offsets
	Characteristics       uint32 // 0x0
	TimeDateStamp         uint32 // 0x4
	MajorVersion          uint16 // 0x8
	MinorVersion          uint16 // 0xa
	Name                  uint32 // 0xc
	Base                  uint32 // 0x10
	NumberOfFunctions     uint32 // 0x14
	NumberOfNames         uint32 // 0x18
	AddressOfFunctions    uint32 // 0x1c
	AddressOfNames        uint32 // 0x20
	AddressOfNameOrdinals uint32 // 0x24
}

### func GetModuleExports(name string) ([]exportfunc, error)
Loops through the exports and returns a slice of the following struct:
** It only returns the exports starting with Nt. If Zw functions are required please adjust the code accordingly

type exportfunc struct {
	funcRVA   uint32
	nameRVA   uint32
	name      string
	syscallno byte
}

### func GetSyscallNumbers(exports *[]exportfunc) error
Takes the slice from the GetModuleExports and adds the syscall byte. 
if a hook is detected it sets the syscall number to 0xff

### func UnhookSyscalls(exports *[]exportfunc) error
This is a quick and dirty code to unhook hooked functions. This doesn't touch any of the DLLs. All modifications are done on the slice. 
Please use with caution. This function was not really tested.

### func GetSyscallNoFromName(function string, exports *[]exportfunc) (byte, error) 
Takes the slice and function name as arguments to return the syscall number

### func bpSyscall(callid uint16, argh ...uintptr) (errcode uint32)
https://github.com/C-Sto/BananaPhone. Stolen the bpSyscall function from this repo. Uses goasm for the syscall. It is precompiled so no need to change memory permissions at runtime.

### func Syscall(callid uint16, argh ...uintptr) (errcode uint32, err error)
Provide syscall number and arguments and there you have it direct syscalls






