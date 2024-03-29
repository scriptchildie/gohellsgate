package gohellsgate

import (
	"fmt"
	"sort"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

type dllstruct struct {
	name    string
	address uintptr
}

type Exportfunc struct {
	funcRVA    uint32
	nameRVA    uint32
	name       string
	syscallno  byte
	tramboline uintptr
}

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

var exports []Exportfunc

func getSyscalls() (err error) {

	exports, err = GetModuleExports("ntdll.dll")
	if err != nil {
		return fmt.Errorf("Failed to get Exports: %v", err)
	}
	GetSyscallNumbers(&exports)
	UnhookSyscalls(&exports)
	return nil

}

func checkExports(verbose bool) error {
	if len(exports) == 0 {

		if verbose {
			fmt.Println("[!] Unable to find syscalls table. Resolving syscalls and Generating table...")
		}
		err := getSyscalls()
		if err != nil {
			return err
		}
	}
	return nil
}

// Syscall calls the system function specified by callid with n arguments. Works much the same as syscall.Syscall - return value is the call error code and optional error text. All args are uintptrs to make it easy.
func Syscall(ntapi string, argh ...uintptr) (errcode uint32, err error) {

	err = checkExports(true)
	if err != nil {
		return 0, err
	}
	callid, _, err := GetSyscallFromName(ntapi, &exports)
	if err != nil {
		return 0, fmt.Errorf("Failed to get syscall for %s %v\n", ntapi, err)
	}

	errcode = bpSyscall(uint16(callid), argh...)

	if errcode != 0 {
		err = fmt.Errorf("non-zero return from syscall")
	}
	return errcode, err
}

// Syscall calls the system function specified by callid with n arguments. Works much the same as syscall.Syscall - return value is the call error code and optional error text. All args are uintptrs to make it easy.
func bpSyscall(callid uint16, argh ...uintptr) (errcode uint32)

func IndirectSyscall(ntapi string, argh ...uintptr) (errcode uint32, err error) {
	err = checkExports(false)
	if err != nil {
		return 0, err
	}

	callid, tramboline, err := GetSyscallFromName(ntapi, &exports)
	if err != nil {
		return 0, fmt.Errorf("Failed to get syscall for %s %v\n", ntapi, err)
	}

	errcode = execIndirectSyscall(uint16(callid), tramboline, argh...)

	if errcode != 0 {
		err = fmt.Errorf("non-zero return from syscall")
	}
	return errcode, err
}

func execIndirectSyscall(callid uint16, tramboline uintptr, argh ...uintptr) (errcode uint32)

func GetSyscallFromName(function string, exports *[]Exportfunc) (byte, uintptr, error) {
	for _, exFunc := range *exports {
		if function == exFunc.name {
			return exFunc.syscallno, exFunc.tramboline, nil
		}
	}
	return 0x0, 0, fmt.Errorf("Unable to find Syscall Function")
}

// Beta Version, This needs a lot of testing. I only tested this on win11 x64 and limited AVs
func UnhookSyscalls(exports *[]Exportfunc) error {
	var lastGood byte
	lastGood = 0x0
	for i, exFunc := range *exports {
		//fmt.Printf("Func RVA: %x , nameRVA: %x , name: %s, syscallno : %x\n", exFunc.funcRVA, exFunc.nameRVA, exFunc.name, exFunc.syscallno)
		if exFunc.syscallno == 0xff {
			//fmt.Println("-------------------------------------------")
			if lastGood == 0x0 {
				exFunc.syscallno = lastGood
			} else {
				exFunc.syscallno = lastGood + 0x1
			}
			(*exports)[i] = exFunc
		} else {
			lastGood = exFunc.syscallno
		}
		//	fmt.Printf("Func RVA: %x , nameRVA: %x , name: %s, syscallno : %x\n", exFunc.funcRVA, exFunc.nameRVA, exFunc.name, exFunc.syscallno)
	}
	return nil
}

// Find address in ntdll with the following opcodes  "\x0F\x05\xC3" syscall;ret;
/*func GetSyscallAddr(exports *[]Exportfunc) (uintptr, error) {
	fAddress := (*exports)[1].funcRVA
	baddr, err := GetBaseAddrOfLoadedDll("ntdll.dll")
	if err != nil {
		return 0, err
	}

	for {
		if *(*byte)(unsafe.Pointer(baddr + uintptr(fAddress))) == 0x0F {
			if *(*byte)(unsafe.Pointer(baddr + uintptr(fAddress+1))) == 0x05 {
				if *(*byte)(unsafe.Pointer(baddr + uintptr(fAddress+2))) == 0xc3 {
					return baddr + uintptr(fAddress), nil
				}
			}
		}
		fAddress += 1
	}
	return baddr + uintptr(fAddress), nil
}*/

func GetSyscallNumbers(exports *[]Exportfunc) error {
	baddr, err := GetBaseAddrOfLoadedDll("ntdll.dll")
	if err != nil {
		return err
	}
	//derefslice := []exportfunc{}

	sort.SliceStable(*exports, func(i, j int) bool {
		return (*exports)[i].funcRVA < (*exports)[j].funcRVA
	})

	for i, exFunc := range *exports {
		funcAA := baddr + uintptr(exFunc.funcRVA)
		funcbytes := (*[5]byte)(unsafe.Pointer(funcAA))[:]

		if funcbytes[0] == 0x4c && funcbytes[1] == 0x8b && funcbytes[2] == 0xd1 && funcbytes[3] == 0xb8 { // Check if the function is hooked.
			exFunc.syscallno = funcbytes[4] // Get Syscall Number
		} else {
			exFunc.syscallno = 0xff // when hooked set the syscall number 0xff
		}
		(*exports)[i] = exFunc
		//fmt.Printf("Func RVA: %x , nameRVA: %x , name: %s, syscallno : %x\n", exFunc.funcRVA, exFunc.nameRVA, exFunc.name, exFunc.syscallno)

	}

	return nil
}

// Loops through the exports and returns it into a slice
// Any future queries or any unhooking will be happening on the slice and not the dll itself
func GetModuleExports(name string) ([]Exportfunc, error) {

	exp, err := GetImageExportDirectory(name)
	if err != nil {
		return nil, err
	}
	baddr, err := GetBaseAddrOfLoadedDll(name)
	if err != nil {
		return nil, err
	}
	funcSlice := []Exportfunc{}
	for i := 0; i < int(exp.NumberOfNames); i++ {
		funcRVA := *((*uint32)(unsafe.Pointer(baddr + (uintptr(exp.AddressOfFunctions) + uintptr((i+1)*0x4)))))
		nameRVA := *((*uint32)(unsafe.Pointer(baddr + (uintptr(exp.AddressOfNames) + uintptr(i*0x4)))))
		nameAddr := baddr + uintptr(nameRVA)
		nameRVAbyte := (*[4]byte)(unsafe.Pointer(nameAddr))[:]
		name := windows.BytePtrToString(&nameRVAbyte[0])

		var absAddress uintptr
		absAddress = baddr + uintptr(funcRVA)
		for j := 0; j < 100; j++ {
			if *(*byte)(unsafe.Pointer(absAddress)) == 0x0f {
				if *(*byte)(unsafe.Pointer(absAddress + 1)) == 0x05 {
					if *(*byte)(unsafe.Pointer(absAddress + 2)) == 0xc3 {
						break
					}
				}
			}
			absAddress += 1
		}

		if strings.HasPrefix(name, "Nt") { // || strings.HasPrefix(name, "Zw") <= Might use this to compare /unhook the NT functions
			funcSlice = append(funcSlice, Exportfunc{
				funcRVA:    funcRVA,
				nameRVA:    nameRVA,
				name:       name,
				tramboline: absAddress,
			})
			//fmt.Printf("Func RVA: %x , nameRVA: %x , name: %s, trambo: %x\n ", funcRVA, nameRVA, name, absAddress)

		}

	}
	return funcSlice, nil
}

// Get Image Export directory. We are interested in
// - AddressofFunctions
// - AddressOfNames
// - AddressOFNameOrdinals (maybe in the future)
// - Number of functions
func GetImageExportDirectory(name string) (*IMAGE_EXPORT_DIRECTORY, error) {
	var img_exp_dir IMAGE_EXPORT_DIRECTORY
	export, err := getExportTableAddress(name)
	if err != nil {
		return nil, err
	}
	img_exp_dir.Characteristics = *((*uint32)(unsafe.Pointer(export)))
	img_exp_dir.TimeDateStamp = *((*uint32)(unsafe.Pointer(export + 0x4)))
	img_exp_dir.MajorVersion = *((*uint16)(unsafe.Pointer(export + 0x8)))
	img_exp_dir.MinorVersion = *((*uint16)(unsafe.Pointer(export + 0xa)))
	img_exp_dir.Name = *((*uint32)(unsafe.Pointer(export + 0xc)))
	img_exp_dir.Base = *((*uint32)(unsafe.Pointer(export + 0x10)))
	img_exp_dir.NumberOfFunctions = *((*uint32)(unsafe.Pointer(export + 0x14)))
	img_exp_dir.NumberOfNames = *((*uint32)(unsafe.Pointer(export + 0x18)))
	img_exp_dir.AddressOfFunctions = *((*uint32)(unsafe.Pointer(export + 0x1c)))
	img_exp_dir.AddressOfNames = *((*uint32)(unsafe.Pointer(export + 0x20)))
	img_exp_dir.AddressOfNameOrdinals = *((*uint32)(unsafe.Pointer(export + 0x24)))
	return &img_exp_dir, nil
}

func getExportTableAddress(name string) (uintptr, error) {
	addr, err := GetBaseAddrOfLoadedDll(name)
	if err != nil {
		return 0, err
	}
	//fmt.Printf("%p\n", unsafe.Pointer(addr))
	e_lfanew := *((*uint32)(unsafe.Pointer(addr + 0x3c)))
	ntHeader := addr + uintptr(e_lfanew)
	fileHeader := ntHeader + 0x4
	// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_file_header
	optionalHeader := fileHeader + 0x14 // 0x14 is the size of the image_file_header struct
	exportDir := optionalHeader + 0x70  // offset to export table
	exportDirOffset := *((*uint32)(unsafe.Pointer(exportDir)))
	exportDirAbsolute := addr + uintptr(exportDirOffset)
	//fmt.Printf("%p\n", unsafe.Pointer(exportDirAddress))

	return exportDirAbsolute, nil
}

// returns address of a loaded module
// Example : addr, err := getBaseAddrOfLoadedDll("ntdll.dll")
func GetBaseAddrOfLoadedDll(name string) (uintptr, error) {
	modules := ListDllFromPEB()
	for _, module := range modules {
		if module.name == name {
			return module.address, nil
		}

	}
	return 0, fmt.Errorf("dll not Found")
}

// prints loaded modules in the current process
func PrintModules() {
	modules := ListDllFromPEB()
	for _, module := range modules {
		fmt.Printf("%s  -- %p \n", module.name, unsafe.Pointer(module.address))

	}

}

// adds all loaded modules and their base addresses in a slice
func ListDllFromPEB() []dllstruct {
	peb := windows.RtlGetCurrentPeb()
	moduleList := peb.Ldr.InMemoryOrderModuleList
	a := moduleList.Flink
	loadedModules := []dllstruct{}
	for {

		listentry := uintptr(unsafe.Pointer(a))
		// -0x10 beginning of the _LDR_DATA_TABLE_ENTRY_ structure
		// +0x30 Dllbase address
		// +0x58 +0x8 address holding the address pointing to base dllname
		// offsets different for 32-bit processes
		DllBase := uintptr(listentry) - 0x10 + 0x30
		BaseDllName := uintptr(listentry) - 0x10 + 0x58 + 0x8

		v := *((*uintptr)(unsafe.Pointer(BaseDllName)))
		//fmt.Printf("%p\n", (unsafe.Pointer(v))) // prints the address that holds the dll name

		s := ((*uint16)(unsafe.Pointer(v))) // turn uintptr to *uint16
		dllNameStr := windows.UTF16PtrToString(s)
		if dllNameStr == "" {
			break
		}
		//print(dllNameStr, " ")
		dllbaseaddr := *((*uintptr)(unsafe.Pointer(DllBase)))
		//fmt.Printf("%p\n", (unsafe.Pointer(dllbaseaddr))) // prints the dll base addr
		loadedModules = append(loadedModules, dllstruct{
			name:    dllNameStr,
			address: dllbaseaddr,
		})
		a = a.Flink
	}

	return loadedModules
}
