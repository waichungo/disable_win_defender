package main

import (
	_ "embed"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/KnicKnic/go-powershell/pkg/powershell"
	"golang.org/x/sys/windows"
)

var (
	kernel32        = syscall.NewLazyDLL("kernel32.dll")
	procCreateMutex = kernel32.NewProc("CreateMutexW")
	user32          = syscall.MustLoadDLL("user32.dll")
	MUTEX           = "Global defender"
)

func CheckErr(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

//go:embed psh_host.dll
var psDll []byte

func IsAdmin() bool {
	var sid *windows.SID

	// Although this looks scary, it is directly copied from the
	// official windows documentation. The Go API for this is a
	// direct wrap around the official C++ API.
	// See https://docs.microsoft.com/en-us/windows/desktop/api/securitybaseapi/nf-securitybaseapi-checktokenmembership
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid)
	if err != nil {

		return false
	}
	defer windows.FreeSid(sid)

	// This appears to cast a null pointer so I'm not sure why this
	// works, but this guy says it does and it Works for Me™:
	// https://github.com/golang/go/issues/28804#issuecomment-438838144
	token := windows.Token(0)

	admin, err := token.IsMember(sid)
	if err != nil {
		log.Fatalf("Token Membership Error: %s", err)
		return false
	}
	return admin
}
func CreateMutex(name string) (uintptr, error) {
	ret, _, err := procCreateMutex.Call(
		0,
		0,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(name))),
	)
	switch int(err.(syscall.Errno)) {
	case 0:
		return ret, nil
	default:
		return ret, err
	}
}
func FirstInstance() bool {
	mutex, err := CreateMutex(MUTEX)
	if err != nil {
		syscall.CloseHandle(syscall.Handle(mutex))
	}
	return err == nil
}
func RerunElevated() {
	verb := "runas"
	exe, _ := os.Executable()
	cwd, _ := os.Getwd()
	args := strings.Join(os.Args[1:], " ")

	verbPtr, _ := syscall.UTF16PtrFromString(verb)
	exePtr, _ := syscall.UTF16PtrFromString(exe)
	cwdPtr, _ := syscall.UTF16PtrFromString(cwd)
	argPtr, _ := syscall.UTF16PtrFromString(args)

	var showCmd int32 = 1 //SW_NORMAL

	err := windows.ShellExecute(0, verbPtr, exePtr, argPtr, cwdPtr, showCmd)
	if err != nil {
		fmt.Println(err)
	}
}
func Elevate() bool {
	res := MessageBoxPlain("Permissions", "Do you need admin permissions")
	return res == 6
}
func MessageBox(hwnd uintptr, caption, title string, flags uint) int {
	ret, _, _ := user32.MustFindProc("MessageBoxW").Call(
		uintptr(hwnd),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(caption))),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(title))),
		uintptr(flags))

	return int(ret)
}

// MessageBoxPlain of Win32 API.
func MessageBoxPlain(title, caption string) int {
	const (
		NULL     = 0
		MB_OK    = 0
		MB_YESNO = 4
	)
	return MessageBox(NULL, caption, title, MB_YESNO)
}
func IsDefenderRunning(runspace powershell.Runspace) bool {
	script := `Get-MpComputerStatus | ConvertTo-Json`
	results1 := runspace.ExecScript(script, false, nil)
	defer results1.Close()

	if results1.Success() && len(results1.Objects) > 0 {
		var values map[string]interface{}

		err := results1.Objects[0].JSONUnmarshal(&values)
		if err == nil {
			stat, f := values["RealTimeProtectionEnabled"]
			if f {
				if stat.(bool) {
					return true
				}
			}
		}
	}

	return false
}
func WriteFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0755)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(data)
	if err != nil {
		for i := 0; i < 10; i++ {
			_, err = f.Write(data)
			if err == nil {
				break
			}
			time.Sleep(time.Millisecond * 200)
		}
	}
	return err
}
func Exists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}
func Start() {
	exe, _ := os.Executable()
	dll := filepath.Join(filepath.Dir(exe), "psh_host.dll")
	if !Exists(dll) {
		WriteFile(dll, psDll)
	}
	runspace := powershell.CreateRunspaceSimple()
	// auto cleanup your runspace
	defer runspace.Close()
	fmt.Println(IsDefenderRunning(runspace))

}
func main() {
	if IsAdmin() {
		MUTEX += "_admin"
	}
	if FirstInstance() {
		if !IsAdmin() {
			if Elevate() {
				RerunElevated()
				os.Exit(0)
			}
		}
		Start()

	} else {
		fmt.Println("Another instance is running")
	}

}
