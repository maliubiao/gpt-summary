Response:
The user wants a summary of the functionality of the provided Go code snippet. The code is a test file (`os_windows_test.go`) for the `os` package in Go, specifically focusing on Windows-related functionalities.

Therefore, the summary should list the types of tests and functionalities being tested in the code.
这是 `go/src/os/os_windows_test.go` 文件的一部分，它主要用于测试 Go 语言 `os` 包在 Windows 操作系统下的特定功能实现。

**主要功能归纳:**

1. **文件和目录操作测试:**
    * 测试 `os.SameFile` 函数在不同路径表示下的行为 (如绝对路径、带盘符的相对路径)。
    * 测试目录链接 (junction point) 的创建和行为，包括使用 `mklink` 命令和直接调用 Windows API 创建。
    * 测试目录符号链接的创建和行为，包括使用 `mklink` 命令、`os.Symlink` 函数以及直接调用 Windows API 创建，并涵盖了相对路径的符号链接。
    * 测试网络共享路径下的符号链接操作。
    * 测试 WSL (Windows Subsystem for Linux) 创建的符号链接的 `Stat` 和 `Lstat` 行为。
    * 测试在只读属性下的文件删除操作。
    * 测试打开卷名 (例如 `C:\`) 并列出其内容。
    * 测试对 `NUL` 设备文件的操作和 `Stat` 信息。

2. **进程相关测试:**
    * 测试 `os.StartProcess` 函数在某些特定属性下的行为 (预期会失败的场景)。
    * 测试 `os.CommandLineToArgv` 函数，用于将命令行字符串解析为参数列表，并与 `syscall.CommandLineToArgv` 的结果进行比较。

3. **错误处理测试:**
    * 测试访问不存在的网络共享路径时 `os.Stat` 返回的错误类型 (`os.IsNotExist`)。
    * 测试 `syscall.ERROR_BAD_NETPATH` 是否被 `os.IsNotExist` 正确识别。

4. **其他系统特性测试:**
    * 测试获取 OneDrive 目录的功能，并验证其是否为目录而非符号链接。
    * 测试在根目录下创建临时目录 (需要辅助进程)。

总而言之，这段代码是 `os` 包在 Windows 平台下各种文件系统操作、进程创建和错误处理功能的集成测试集合。它覆盖了符号链接、目录连接、网络路径、设备文件等多种 Windows 特有的文件系统概念，并通过多种方式创建和操作这些对象来验证 `os` 包的相关 API 的正确性。

Prompt: 
```
这是路径为go/src/os/os_windows_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package os_test

import (
	"errors"
	"fmt"
	"internal/godebug"
	"internal/poll"
	"internal/syscall/windows"
	"internal/syscall/windows/registry"
	"internal/testenv"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"unicode/utf16"
	"unsafe"
)

var winsymlink = godebug.New("winsymlink")
var winreadlinkvolume = godebug.New("winreadlinkvolume")

// For TestRawConnReadWrite.
type syscallDescriptor = syscall.Handle

func TestSameWindowsFile(t *testing.T) {
	t.Chdir(t.TempDir())

	f, err := os.Create("a")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	ia1, err := os.Stat("a")
	if err != nil {
		t.Fatal(err)
	}

	path, err := filepath.Abs("a")
	if err != nil {
		t.Fatal(err)
	}
	ia2, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(ia1, ia2) {
		t.Errorf("files should be same")
	}

	p := filepath.VolumeName(path) + filepath.Base(path)
	if err != nil {
		t.Fatal(err)
	}
	ia3, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(ia1, ia3) {
		t.Errorf("files should be same")
	}
}

type dirLinkTest struct {
	name         string
	mklink       func(link, target string) error
	isMountPoint bool
}

func testDirLinks(t *testing.T, tests []dirLinkTest) {
	tmpdir := t.TempDir()
	t.Chdir(tmpdir)

	dir := filepath.Join(tmpdir, "dir")
	err := os.Mkdir(dir, 0777)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	err = os.WriteFile(filepath.Join(dir, "abc"), []byte("abc"), 0644)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range tests {
		link := filepath.Join(tmpdir, test.name+"_link")
		err := test.mklink(link, dir)
		if err != nil {
			t.Errorf("creating link for %q test failed: %v", test.name, err)
			continue
		}

		data, err := os.ReadFile(filepath.Join(link, "abc"))
		if err != nil {
			t.Errorf("failed to read abc file: %v", err)
			continue
		}
		if string(data) != "abc" {
			t.Errorf(`abc file is expected to have "abc" in it, but has %v`, data)
			continue
		}

		fi1, err := os.Stat(link)
		if err != nil {
			t.Errorf("failed to stat link %v: %v", link, err)
			continue
		}
		if tp := fi1.Mode().Type(); tp != fs.ModeDir {
			t.Errorf("Stat(%q) is type %v; want %v", link, tp, fs.ModeDir)
			continue
		}
		if fi1.Name() != filepath.Base(link) {
			t.Errorf("Stat(%q).Name() = %q, want %q", link, fi1.Name(), filepath.Base(link))
			continue
		}
		if !os.SameFile(fi, fi1) {
			t.Errorf("%q should point to %q", link, dir)
			continue
		}

		fi2, err := os.Lstat(link)
		if err != nil {
			t.Errorf("failed to lstat link %v: %v", link, err)
			continue
		}
		var wantType fs.FileMode
		if test.isMountPoint && winsymlink.Value() != "0" {
			// Mount points are reparse points, and we no longer treat them as symlinks.
			wantType = fs.ModeIrregular
		} else {
			// This is either a real symlink, or a mount point treated as a symlink.
			wantType = fs.ModeSymlink
		}
		if tp := fi2.Mode().Type(); tp != wantType {
			t.Errorf("Lstat(%q) is type %v; want %v", link, tp, wantType)
		}
	}
}

// reparseData is used to build reparse buffer data required for tests.
type reparseData struct {
	substituteName namePosition
	printName      namePosition
	pathBuf        []uint16
}

type namePosition struct {
	offset uint16
	length uint16
}

func (rd *reparseData) addUTF16s(s []uint16) (offset uint16) {
	off := len(rd.pathBuf) * 2
	rd.pathBuf = append(rd.pathBuf, s...)
	return uint16(off)
}

func (rd *reparseData) addString(s string) (offset, length uint16) {
	p := syscall.StringToUTF16(s)
	return rd.addUTF16s(p), uint16(len(p)-1) * 2 // do not include terminating NUL in the length (as per PrintNameLength and SubstituteNameLength documentation)
}

func (rd *reparseData) addSubstituteName(name string) {
	rd.substituteName.offset, rd.substituteName.length = rd.addString(name)
}

func (rd *reparseData) addPrintName(name string) {
	rd.printName.offset, rd.printName.length = rd.addString(name)
}

func (rd *reparseData) addStringNoNUL(s string) (offset, length uint16) {
	p := syscall.StringToUTF16(s)
	p = p[:len(p)-1]
	return rd.addUTF16s(p), uint16(len(p)) * 2
}

func (rd *reparseData) addSubstituteNameNoNUL(name string) {
	rd.substituteName.offset, rd.substituteName.length = rd.addStringNoNUL(name)
}

func (rd *reparseData) addPrintNameNoNUL(name string) {
	rd.printName.offset, rd.printName.length = rd.addStringNoNUL(name)
}

// pathBuffeLen returns length of rd pathBuf in bytes.
func (rd *reparseData) pathBuffeLen() uint16 {
	return uint16(len(rd.pathBuf)) * 2
}

// Windows REPARSE_DATA_BUFFER contains union member, and cannot be
// translated into Go directly. _REPARSE_DATA_BUFFER type is to help
// construct alternative versions of Windows REPARSE_DATA_BUFFER with
// union part of SymbolicLinkReparseBuffer or MountPointReparseBuffer type.
type _REPARSE_DATA_BUFFER struct {
	header windows.REPARSE_DATA_BUFFER_HEADER
	detail [syscall.MAXIMUM_REPARSE_DATA_BUFFER_SIZE]byte
}

func createDirLink(link string, rdb *_REPARSE_DATA_BUFFER) error {
	err := os.Mkdir(link, 0777)
	if err != nil {
		return err
	}

	linkp := syscall.StringToUTF16(link)
	fd, err := syscall.CreateFile(&linkp[0], syscall.GENERIC_WRITE, 0, nil, syscall.OPEN_EXISTING,
		syscall.FILE_FLAG_OPEN_REPARSE_POINT|syscall.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return err
	}
	defer syscall.CloseHandle(fd)

	buflen := uint32(rdb.header.ReparseDataLength) + uint32(unsafe.Sizeof(rdb.header))
	var bytesReturned uint32
	return syscall.DeviceIoControl(fd, windows.FSCTL_SET_REPARSE_POINT,
		(*byte)(unsafe.Pointer(&rdb.header)), buflen, nil, 0, &bytesReturned, nil)
}

func createMountPoint(link string, target *reparseData) error {
	var buf *windows.MountPointReparseBuffer
	buflen := uint16(unsafe.Offsetof(buf.PathBuffer)) + target.pathBuffeLen() // see ReparseDataLength documentation
	byteblob := make([]byte, buflen)
	buf = (*windows.MountPointReparseBuffer)(unsafe.Pointer(&byteblob[0]))
	buf.SubstituteNameOffset = target.substituteName.offset
	buf.SubstituteNameLength = target.substituteName.length
	buf.PrintNameOffset = target.printName.offset
	buf.PrintNameLength = target.printName.length
	pbuflen := len(target.pathBuf)
	copy((*[2048]uint16)(unsafe.Pointer(&buf.PathBuffer[0]))[:pbuflen:pbuflen], target.pathBuf)

	var rdb _REPARSE_DATA_BUFFER
	rdb.header.ReparseTag = windows.IO_REPARSE_TAG_MOUNT_POINT
	rdb.header.ReparseDataLength = buflen
	copy(rdb.detail[:], byteblob)

	return createDirLink(link, &rdb)
}

func TestDirectoryJunction(t *testing.T) {
	var tests = []dirLinkTest{
		{
			// Create link similar to what mklink does, by inserting \??\ at the front of absolute target.
			name:         "standard",
			isMountPoint: true,
			mklink: func(link, target string) error {
				var t reparseData
				t.addSubstituteName(`\??\` + target)
				t.addPrintName(target)
				return createMountPoint(link, &t)
			},
		},
		{
			// Do as junction utility https://learn.microsoft.com/en-us/sysinternals/downloads/junction does - set PrintNameLength to 0.
			name:         "have_blank_print_name",
			isMountPoint: true,
			mklink: func(link, target string) error {
				var t reparseData
				t.addSubstituteName(`\??\` + target)
				t.addPrintName("")
				return createMountPoint(link, &t)
			},
		},
	}
	output, _ := testenv.Command(t, "cmd", "/c", "mklink", "/?").Output()
	mklinkSupportsJunctionLinks := strings.Contains(string(output), " /J ")
	if mklinkSupportsJunctionLinks {
		tests = append(tests,
			dirLinkTest{
				name:         "use_mklink_cmd",
				isMountPoint: true,
				mklink: func(link, target string) error {
					output, err := testenv.Command(t, "cmd", "/c", "mklink", "/J", link, target).CombinedOutput()
					if err != nil {
						t.Errorf("failed to run mklink %v %v: %v %q", link, target, err, output)
					}
					return nil
				},
			},
		)
	} else {
		t.Log(`skipping "use_mklink_cmd" test, mklink does not supports directory junctions`)
	}
	testDirLinks(t, tests)
}

func enableCurrentThreadPrivilege(privilegeName string) error {
	ct, err := windows.GetCurrentThread()
	if err != nil {
		return err
	}
	var t syscall.Token
	err = windows.OpenThreadToken(ct, syscall.TOKEN_QUERY|windows.TOKEN_ADJUST_PRIVILEGES, false, &t)
	if err != nil {
		return err
	}
	defer syscall.CloseHandle(syscall.Handle(t))

	var tp windows.TOKEN_PRIVILEGES

	privStr, err := syscall.UTF16PtrFromString(privilegeName)
	if err != nil {
		return err
	}
	err = windows.LookupPrivilegeValue(nil, privStr, &tp.Privileges[0].Luid)
	if err != nil {
		return err
	}
	tp.PrivilegeCount = 1
	tp.Privileges[0].Attributes = windows.SE_PRIVILEGE_ENABLED
	return windows.AdjustTokenPrivileges(t, false, &tp, 0, nil, nil)
}

func createSymbolicLink(link string, target *reparseData, isrelative bool) error {
	var buf *windows.SymbolicLinkReparseBuffer
	buflen := uint16(unsafe.Offsetof(buf.PathBuffer)) + target.pathBuffeLen() // see ReparseDataLength documentation
	byteblob := make([]byte, buflen)
	buf = (*windows.SymbolicLinkReparseBuffer)(unsafe.Pointer(&byteblob[0]))
	buf.SubstituteNameOffset = target.substituteName.offset
	buf.SubstituteNameLength = target.substituteName.length
	buf.PrintNameOffset = target.printName.offset
	buf.PrintNameLength = target.printName.length
	if isrelative {
		buf.Flags = windows.SYMLINK_FLAG_RELATIVE
	}
	pbuflen := len(target.pathBuf)
	copy((*[2048]uint16)(unsafe.Pointer(&buf.PathBuffer[0]))[:pbuflen:pbuflen], target.pathBuf)

	var rdb _REPARSE_DATA_BUFFER
	rdb.header.ReparseTag = syscall.IO_REPARSE_TAG_SYMLINK
	rdb.header.ReparseDataLength = buflen
	copy(rdb.detail[:], byteblob)

	return createDirLink(link, &rdb)
}

func TestDirectorySymbolicLink(t *testing.T) {
	var tests []dirLinkTest
	output, _ := testenv.Command(t, "cmd", "/c", "mklink", "/?").Output()
	mklinkSupportsDirectorySymbolicLinks := strings.Contains(string(output), " /D ")
	if mklinkSupportsDirectorySymbolicLinks {
		tests = append(tests,
			dirLinkTest{
				name: "use_mklink_cmd",
				mklink: func(link, target string) error {
					output, err := testenv.Command(t, "cmd", "/c", "mklink", "/D", link, target).CombinedOutput()
					if err != nil {
						t.Errorf("failed to run mklink %v %v: %v %q", link, target, err, output)
					}
					return nil
				},
			},
		)
	} else {
		t.Log(`skipping "use_mklink_cmd" test, mklink does not supports directory symbolic links`)
	}

	// The rest of these test requires SeCreateSymbolicLinkPrivilege to be held.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	err := windows.ImpersonateSelf(windows.SecurityImpersonation)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.RevertToSelf()

	err = enableCurrentThreadPrivilege("SeCreateSymbolicLinkPrivilege")
	if err != nil {
		t.Skipf(`skipping some tests, could not enable "SeCreateSymbolicLinkPrivilege": %v`, err)
	}
	tests = append(tests,
		dirLinkTest{
			name: "use_os_pkg",
			mklink: func(link, target string) error {
				return os.Symlink(target, link)
			},
		},
		dirLinkTest{
			// Create link similar to what mklink does, by inserting \??\ at the front of absolute target.
			name: "standard",
			mklink: func(link, target string) error {
				var t reparseData
				t.addPrintName(target)
				t.addSubstituteName(`\??\` + target)
				return createSymbolicLink(link, &t, false)
			},
		},
		dirLinkTest{
			name: "relative",
			mklink: func(link, target string) error {
				var t reparseData
				t.addSubstituteNameNoNUL(filepath.Base(target))
				t.addPrintNameNoNUL(filepath.Base(target))
				return createSymbolicLink(link, &t, true)
			},
		},
	)
	testDirLinks(t, tests)
}

func mustHaveWorkstation(t *testing.T) {
	mar, err := windows.OpenSCManager(nil, nil, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return
	}
	defer syscall.CloseHandle(mar)
	//LanmanWorkstation is the service name, and Workstation is the display name.
	srv, err := windows.OpenService(mar, syscall.StringToUTF16Ptr("LanmanWorkstation"), windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return
	}
	defer syscall.CloseHandle(srv)
	var state windows.SERVICE_STATUS
	err = windows.QueryServiceStatus(srv, &state)
	if err != nil {
		return
	}
	if state.CurrentState != windows.SERVICE_RUNNING {
		t.Skip("Requires the Windows service Workstation, but it is detected that it is not enabled.")
	}
}

func TestNetworkSymbolicLink(t *testing.T) {
	testenv.MustHaveSymlink(t)

	const _NERR_ServerNotStarted = syscall.Errno(2114)

	dir := t.TempDir()
	t.Chdir(dir)

	pid := os.Getpid()
	shareName := fmt.Sprintf("GoSymbolicLinkTestShare%d", pid)
	sharePath := filepath.Join(dir, shareName)
	testDir := "TestDir"

	err := os.MkdirAll(filepath.Join(sharePath, testDir), 0777)
	if err != nil {
		t.Fatal(err)
	}

	wShareName, err := syscall.UTF16PtrFromString(shareName)
	if err != nil {
		t.Fatal(err)
	}
	wSharePath, err := syscall.UTF16PtrFromString(sharePath)
	if err != nil {
		t.Fatal(err)
	}

	// Per https://learn.microsoft.com/en-us/windows/win32/api/lmshare/ns-lmshare-share_info_2:
	//
	// “[The shi2_permissions field] indicates the shared resource's permissions
	// for servers running with share-level security. A server running user-level
	// security ignores this member.
	// …
	// Note that Windows does not support share-level security.”
	//
	// So it shouldn't matter what permissions we set here.
	const permissions = 0

	p := windows.SHARE_INFO_2{
		Netname:     wShareName,
		Type:        windows.STYPE_DISKTREE | windows.STYPE_TEMPORARY,
		Remark:      nil,
		Permissions: permissions,
		MaxUses:     1,
		CurrentUses: 0,
		Path:        wSharePath,
		Passwd:      nil,
	}

	err = windows.NetShareAdd(nil, 2, (*byte)(unsafe.Pointer(&p)), nil)
	if err != nil {
		if err == syscall.ERROR_ACCESS_DENIED || err == _NERR_ServerNotStarted {
			t.Skipf("skipping: NetShareAdd: %v", err)
		}
		t.Fatal(err)
	}
	defer func() {
		err := windows.NetShareDel(nil, wShareName, 0)
		if err != nil {
			t.Fatal(err)
		}
	}()

	UNCPath := `\\localhost\` + shareName + `\`

	fi1, err := os.Stat(sharePath)
	if err != nil {
		t.Fatal(err)
	}
	fi2, err := os.Stat(UNCPath)
	if err != nil {
		mustHaveWorkstation(t)
		t.Fatal(err)
	}
	if !os.SameFile(fi1, fi2) {
		t.Fatalf("%q and %q should be the same directory, but not", sharePath, UNCPath)
	}

	target := filepath.Join(UNCPath, testDir)
	link := "link"

	err = os.Symlink(target, link)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(link)

	got, err := os.Readlink(link)
	if err != nil {
		t.Fatal(err)
	}
	if got != target {
		t.Errorf(`os.Readlink(%#q): got %v, want %v`, link, got, target)
	}

	got, err = filepath.EvalSymlinks(link)
	if err != nil {
		t.Fatal(err)
	}
	if got != target {
		t.Errorf(`filepath.EvalSymlinks(%#q): got %v, want %v`, link, got, target)
	}
}

func TestStatLxSymLink(t *testing.T) {
	if _, err := exec.LookPath("wsl"); err != nil {
		t.Skip("skipping: WSL not detected")
	}

	t.Chdir(t.TempDir())

	const target = "target"
	const link = "link"

	_, err := testenv.Command(t, "wsl", "/bin/mkdir", target).Output()
	if err != nil {
		// This normally happens when WSL still doesn't have a distro installed to run on.
		t.Skipf("skipping: WSL is not correctly installed: %v", err)
	}

	_, err = testenv.Command(t, "wsl", "/bin/ln", "-s", target, link).Output()
	if err != nil {
		t.Fatal(err)
	}

	fi, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if m := fi.Mode(); m&fs.ModeSymlink != 0 {
		// This can happen depending on newer WSL versions when running as admin or in developer mode.
		t.Skip("skipping: WSL created reparse tag IO_REPARSE_TAG_SYMLINK instead of an IO_REPARSE_TAG_LX_SYMLINK")
	}
	// Stat'ing a IO_REPARSE_TAG_LX_SYMLINK from outside WSL always return ERROR_CANT_ACCESS_FILE.
	// We check this condition to validate that os.Stat has tried to follow the link.
	_, err = os.Stat(link)
	const ERROR_CANT_ACCESS_FILE = syscall.Errno(1920)
	if err == nil || !errors.Is(err, ERROR_CANT_ACCESS_FILE) {
		t.Fatalf("os.Stat(%q): got %v, want ERROR_CANT_ACCESS_FILE", link, err)
	}
}

func TestStartProcessAttr(t *testing.T) {
	t.Parallel()

	p, err := os.StartProcess(os.Getenv("COMSPEC"), []string{"/c", "cd"}, new(os.ProcAttr))
	if err != nil {
		return
	}
	defer p.Wait()
	t.Fatalf("StartProcess expected to fail, but succeeded.")
}

func TestShareNotExistError(t *testing.T) {
	if testing.Short() {
		t.Skip("slow test that uses network; skipping")
	}
	t.Parallel()

	_, err := os.Stat(`\\no_such_server\no_such_share\no_such_file`)
	if err == nil {
		t.Fatal("stat succeeded, but expected to fail")
	}
	if !os.IsNotExist(err) {
		t.Fatalf("os.Stat failed with %q, but os.IsNotExist(err) is false", err)
	}
}

func TestBadNetPathError(t *testing.T) {
	const ERROR_BAD_NETPATH = syscall.Errno(53)
	if !os.IsNotExist(ERROR_BAD_NETPATH) {
		t.Fatal("os.IsNotExist(syscall.Errno(53)) is false, but want true")
	}
}

func TestStatDir(t *testing.T) {
	t.Chdir(t.TempDir())

	f, err := os.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}

	err = os.Chdir("..")
	if err != nil {
		t.Fatal(err)
	}

	fi2, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}

	if !os.SameFile(fi, fi2) {
		t.Fatal("race condition occurred")
	}
}

func TestOpenVolumeName(t *testing.T) {
	tmpdir := t.TempDir()
	t.Chdir(tmpdir)

	want := []string{"file1", "file2", "file3", "gopher.txt"}
	slices.Sort(want)
	for _, name := range want {
		err := os.WriteFile(filepath.Join(tmpdir, name), nil, 0777)
		if err != nil {
			t.Fatal(err)
		}
	}

	f, err := os.Open(filepath.VolumeName(tmpdir))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	have, err := f.Readdirnames(-1)
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(have)

	if strings.Join(want, "/") != strings.Join(have, "/") {
		t.Fatalf("unexpected file list %q, want %q", have, want)
	}
}

func TestDeleteReadOnly(t *testing.T) {
	t.Parallel()

	tmpdir := t.TempDir()
	p := filepath.Join(tmpdir, "a")
	// This sets FILE_ATTRIBUTE_READONLY.
	f, err := os.OpenFile(p, os.O_CREATE, 0400)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	if err = os.Chmod(p, 0400); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(p); err != nil {
		t.Fatal(err)
	}
}

func TestReadStdin(t *testing.T) {
	old := poll.ReadConsole
	defer func() {
		poll.ReadConsole = old
	}()

	p, err := syscall.GetCurrentProcess()
	if err != nil {
		t.Fatalf("Unable to get handle to current process: %v", err)
	}
	var stdinDuplicate syscall.Handle
	err = syscall.DuplicateHandle(p, syscall.Handle(syscall.Stdin), p, &stdinDuplicate, 0, false, syscall.DUPLICATE_SAME_ACCESS)
	if err != nil {
		t.Fatalf("Unable to duplicate stdin: %v", err)
	}
	testConsole := os.NewConsoleFile(stdinDuplicate, "test")

	var tests = []string{
		"abc",
		"äöü",
		"\u3042",
		"“hi”™",
		"hello\x1aworld",
		"\U0001F648\U0001F649\U0001F64A",
	}

	for _, consoleSize := range []int{1, 2, 3, 10, 16, 100, 1000} {
		for _, readSize := range []int{1, 2, 3, 4, 5, 8, 10, 16, 20, 50, 100} {
			for _, s := range tests {
				t.Run(fmt.Sprintf("c%d/r%d/%s", consoleSize, readSize, s), func(t *testing.T) {
					s16 := utf16.Encode([]rune(s))
					poll.ReadConsole = func(h syscall.Handle, buf *uint16, toread uint32, read *uint32, inputControl *byte) error {
						if inputControl != nil {
							t.Fatalf("inputControl not nil")
						}
						n := int(toread)
						if n > consoleSize {
							n = consoleSize
						}
						n = copy((*[10000]uint16)(unsafe.Pointer(buf))[:n:n], s16)
						s16 = s16[n:]
						*read = uint32(n)
						t.Logf("read %d -> %d", toread, *read)
						return nil
					}

					var all []string
					var buf []byte
					chunk := make([]byte, readSize)
					for {
						n, err := testConsole.Read(chunk)
						buf = append(buf, chunk[:n]...)
						if err == io.EOF {
							all = append(all, string(buf))
							if len(all) >= 5 {
								break
							}
							buf = buf[:0]
						} else if err != nil {
							t.Fatalf("reading %q: error: %v", s, err)
						}
						if len(buf) >= 2000 {
							t.Fatalf("reading %q: stuck in loop: %q", s, buf)
						}
					}

					want := strings.Split(s, "\x1a")
					for len(want) < 5 {
						want = append(want, "")
					}
					if !slices.Equal(all, want) {
						t.Errorf("reading %q:\nhave %x\nwant %x", s, all, want)
					}
				})
			}
		}
	}
}

func TestStatPagefile(t *testing.T) {
	t.Parallel()

	const path = `c:\pagefile.sys`
	fi, err := os.Stat(path)
	if err == nil {
		if fi.Name() == "" {
			t.Fatalf("Stat(%q).Name() is empty", path)
		}
		t.Logf("Stat(%q).Size() = %v", path, fi.Size())
		return
	}
	if os.IsNotExist(err) {
		t.Skip(`skipping because c:\pagefile.sys is not found`)
	}
	t.Fatal(err)
}

// syscallCommandLineToArgv calls syscall.CommandLineToArgv
// and converts returned result into []string.
func syscallCommandLineToArgv(cmd string) ([]string, error) {
	var argc int32
	argv, err := syscall.CommandLineToArgv(&syscall.StringToUTF16(cmd)[0], &argc)
	if err != nil {
		return nil, err
	}
	defer syscall.LocalFree(syscall.Handle(uintptr(unsafe.Pointer(argv))))

	var args []string
	for _, v := range (*argv)[:argc] {
		args = append(args, syscall.UTF16ToString((*v)[:]))
	}
	return args, nil
}

// compareCommandLineToArgvWithSyscall ensures that
// os.CommandLineToArgv(cmd) and syscall.CommandLineToArgv(cmd)
// return the same result.
func compareCommandLineToArgvWithSyscall(t *testing.T, cmd string) {
	syscallArgs, err := syscallCommandLineToArgv(cmd)
	if err != nil {
		t.Fatal(err)
	}
	args := os.CommandLineToArgv(cmd)
	if want, have := fmt.Sprintf("%q", syscallArgs), fmt.Sprintf("%q", args); want != have {
		t.Errorf("testing os.commandLineToArgv(%q) failed: have %q want %q", cmd, args, syscallArgs)
		return
	}
}

func TestCmdArgs(t *testing.T) {
	if testing.Short() {
		t.Skipf("in short mode; skipping test that builds a binary")
	}
	t.Parallel()

	tmpdir := t.TempDir()

	const prog = `
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Printf("%q", os.Args)
}
`
	src := filepath.Join(tmpdir, "main.go")
	if err := os.WriteFile(src, []byte(prog), 0666); err != nil {
		t.Fatal(err)
	}

	exe := filepath.Join(tmpdir, "main.exe")
	cmd := testenv.Command(t, testenv.GoToolPath(t), "build", "-o", exe, src)
	cmd.Dir = tmpdir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("building main.exe failed: %v\n%s", err, out)
	}

	var cmds = []string{
		``,
		` a b c`,
		` "`,
		` ""`,
		` """`,
		` "" a`,
		` "123"`,
		` \"123\"`,
		` \"123 456\"`,
		` \\"`,
		` \\\"`,
		` \\\\\"`,
		` \\\"x`,
		` """"\""\\\"`,
		` abc`,
		` \\\\\""x"""y z`,
		"\tb\t\"x\ty\"",
		` "Брад" d e`,
		// examples from https://learn.microsoft.com/en-us/cpp/cpp/main-function-command-line-args
		` "abc" d e`,
		` a\\b d"e f"g h`,
		` a\\\"b c d`,
		` a\\\\"b c" d e`,
		// http://daviddeley.com/autohotkey/parameters/parameters.htm#WINARGV
		// from 5.4  Examples
		` CallMeIshmael`,
		` "Call Me Ishmael"`,
		` Cal"l Me I"shmael`,
		` CallMe\"Ishmael`,
		` "CallMe\"Ishmael"`,
		` "Call Me Ishmael\\"`,
		` "CallMe\\\"Ishmael"`,
		` a\\\b`,
		` "a\\\b"`,
		// from 5.5  Some Common Tasks
		` "\"Call Me Ishmael\""`,
		` "C:\TEST A\\"`,
		` "\"C:\TEST A\\\""`,
		// from 5.6  The Microsoft Examples Explained
		` "a b c"  d  e`,
		` "ab\"c"  "\\"  d`,
		` a\\\b d"e f"g h`,
		` a\\\"b c d`,
		` a\\\\"b c" d e`,
		// from 5.7  Double Double Quote Examples (pre 2008)
		` "a b c""`,
		` """CallMeIshmael"""  b  c`,
		` """Call Me Ishmael"""`,
		` """"Call Me Ishmael"" b c`,
	}
	for _, cmd := range cmds {
		compareCommandLineToArgvWithSyscall(t, "test"+cmd)
		compareCommandLineToArgvWithSyscall(t, `"cmd line"`+cmd)
		compareCommandLineToArgvWithSyscall(t, exe+cmd)

		// test both syscall.EscapeArg and os.commandLineToArgv
		args := os.CommandLineToArgv(exe + cmd)
		out, err := testenv.Command(t, args[0], args[1:]...).CombinedOutput()
		if err != nil {
			t.Fatalf("running %q failed: %v\n%v", args, err, string(out))
		}
		if want, have := fmt.Sprintf("%q", args), string(out); want != have {
			t.Errorf("wrong output of executing %q: have %q want %q", args, have, want)
			continue
		}
	}
}

func findOneDriveDir() (string, error) {
	// as per https://stackoverflow.com/questions/42519624/how-to-determine-location-of-onedrive-on-windows-7-and-8-in-c
	const onedrivekey = `SOFTWARE\Microsoft\OneDrive`
	k, err := registry.OpenKey(registry.CURRENT_USER, onedrivekey, registry.READ)
	if err != nil {
		return "", fmt.Errorf("OpenKey(%q) failed: %v", onedrivekey, err)
	}
	defer k.Close()

	path, valtype, err := k.GetStringValue("UserFolder")
	if err != nil {
		return "", fmt.Errorf("reading UserFolder failed: %v", err)
	}

	// REG_SZ values may also contain environment variables that need to be expanded.
	// It's recommended but not required to use REG_EXPAND_SZ for paths that contain environment variables.
	if valtype == registry.EXPAND_SZ || valtype == registry.SZ {
		expanded, err := registry.ExpandString(path)
		if err != nil {
			return "", fmt.Errorf("expanding UserFolder failed: %v", err)
		}
		path = expanded
	}

	return path, nil
}

// TestOneDrive verifies that OneDrive folder is a directory and not a symlink.
func TestOneDrive(t *testing.T) {
	t.Parallel()

	dir, err := findOneDriveDir()
	if err != nil {
		t.Skipf("Skipping, because we did not find OneDrive directory: %v", err)
	}
	testDirStats(t, dir)
}

func TestWindowsDevNullFile(t *testing.T) {
	t.Parallel()

	f1, err := os.Open("NUL")
	if err != nil {
		t.Fatal(err)
	}
	defer f1.Close()

	fi1, err := f1.Stat()
	if err != nil {
		t.Fatal(err)
	}

	f2, err := os.Open("nul")
	if err != nil {
		t.Fatal(err)
	}
	defer f2.Close()

	fi2, err := f2.Stat()
	if err != nil {
		t.Fatal(err)
	}

	if !os.SameFile(fi1, fi2) {
		t.Errorf(`"NUL" and "nul" are not the same file`)
	}
}

func TestFileStatNUL(t *testing.T) {
	t.Parallel()

	f, err := os.Open("NUL")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := fi.Mode(), os.ModeDevice|os.ModeCharDevice|0666; got != want {
		t.Errorf("Open(%q).Stat().Mode() = %v, want %v", "NUL", got, want)
	}
}

func TestStatNUL(t *testing.T) {
	t.Parallel()

	fi, err := os.Stat("NUL")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := fi.Mode(), os.ModeDevice|os.ModeCharDevice|0666; got != want {
		t.Errorf("Stat(%q).Mode() = %v, want %v", "NUL", got, want)
	}
}

// TestSymlinkCreation verifies that creating a symbolic link
// works on Windows when developer mode is active.
// This is supported starting Windows 10 (1703, v10.0.14972).
func TestSymlinkCreation(t *testing.T) {
	if !testenv.HasSymlink() {
		t.Skip("skipping test; no symlink support")
	}
	t.Parallel()

	temp := t.TempDir()
	dummyFile := filepath.Join(temp, "file")
	if err := os.WriteFile(dummyFile, []byte(""), 0644); err != nil {
		t.Fatal(err)
	}

	linkFile := filepath.Join(temp, "link")
	if err := os.Symlink(dummyFile, linkFile); err != nil {
		t.Fatal(err)
	}
}

// TestRootRelativeDirSymlink verifies that symlinks to paths relative to the
// drive root (beginning with "\" but no volume name) are created with the
// correct symlink type.
// (See https://golang.org/issue/39183#issuecomment-632175728.)
func TestRootRelativeDirSymlink(t *testing.T) {
	testenv.MustHaveSymlink(t)
	t.Parallel()

	temp := t.TempDir()
	dir := filepath.Join(temp, "dir")
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Fatal(err)
	}

	volumeRelDir := strings.TrimPrefix(dir, filepath.VolumeName(dir)) // leaves leading backslash

	link := filepath.Join(temp, "link")
	err := os.Symlink(volumeRelDir, link)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Symlink(%#q, %#q)", volumeRelDir, link)

	f, err := os.Open(link)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil {
		t.Fatal(err)
	} else if !fi.IsDir() {
		t.Errorf("Open(%#q).Stat().IsDir() = false; want true", f.Name())
	}
}

// TestWorkingDirectoryRelativeSymlink verifies that symlinks to paths relative
// to the current working directory for the drive, such as "C:File.txt", are
// correctly converted to absolute links of the correct symlink type (per
// https://docs.microsoft.com/en-us/windows/win32/fileio/creating-symbolic-links).
func TestWorkingDirectoryRelativeSymlink(t *testing.T) {
	testenv.MustHaveSymlink(t)

	// Construct a directory to be symlinked.
	temp := t.TempDir()
	if v := filepath.VolumeName(temp); len(v) < 2 || v[1] != ':' {
		t.Skipf("Can't test relative symlinks: t.TempDir() (%#q) does not begin with a drive letter.", temp)
	}

	absDir := filepath.Join(temp, `dir\sub`)
	if err := os.MkdirAll(absDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Change to the temporary directory and construct a
	// working-directory-relative symlink.
	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(temp)
	t.Logf("Chdir(%#q)", temp)

	wdRelDir := filepath.VolumeName(temp) + `dir\sub` // no backslash after volume.
	absLink := filepath.Join(temp, "link")
	err = os.Symlink(wdRelDir, absLink)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Symlink(%#q, %#q)", wdRelDir, absLink)

	// Now change back to the original working directory and verify that the
	// symlink still refers to its original path and is correctly marked as a
	// directory.
	if err := os.Chdir(oldwd); err != nil {
		t.Fatal(err)
	}
	t.Logf("Chdir(%#q)", oldwd)

	resolved, err := os.Readlink(absLink)
	if err != nil {
		t.Errorf("Readlink(%#q): %v", absLink, err)
	} else if resolved != absDir {
		t.Errorf("Readlink(%#q) = %#q; want %#q", absLink, resolved, absDir)
	}

	linkFile, err := os.Open(absLink)
	if err != nil {
		t.Fatal(err)
	}
	defer linkFile.Close()

	linkInfo, err := linkFile.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if !linkInfo.IsDir() {
		t.Errorf("Open(%#q).Stat().IsDir() = false; want true", absLink)
	}

	absInfo, err := os.Stat(absDir)
	if err != nil {
		t.Fatal(err)
	}

	if !os.SameFile(absInfo, linkInfo) {
		t.Errorf("SameFile(Stat(%#q), Open(%#q).Stat()) = false; want true", absDir, absLink)
	}
}

// TestStatOfInvalidName is regression test for issue #24999.
func TestStatOfInvalidName(t *testing.T) {
	t.Parallel()

	_, err := os.Stat("*.go")
	if err == nil {
		t.Fatal(`os.Stat("*.go") unexpectedly succeeded`)
	}
}

// findUnusedDriveLetter searches mounted drive list on the system
// (starting from Z: and ending at D:) for unused drive letter.
// It returns path to the found drive root directory (like Z:\) or error.
func findUnusedDriveLetter() (string, error) {
	// Do not use A: and B:, because they are reserved for floppy drive.
	// Do not use C:, because it is normally used for main drive.
	for l := 'Z'; l >= 'D'; l-- {
		p := string(l) + `:\`
		_, err := os.Stat(p)
		if os.IsNotExist(err) {
			return p, nil
		}
	}
	return "", errors.New("Could not find unused drive letter.")
}

func TestRootDirAsTemp(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") == "1" {
		fmt.Print(os.TempDir())
		os.Exit(0)
	}

	testenv.MustHaveExec(t)
	t.Parallel()

	exe := testenv.Executable(t)

	newtmp, err := findUnusedDriveLetter()
	if err != nil {
		t.Skip(err)
	}

	cmd := testenv.Command(t, exe, "-test.run=^TestRootDirAsTemp$")
	cmd.Env = cmd.Environ()
	cmd.Env = append(cmd.Env, "GO_WANT_HELPER_PROCESS=1")
	cmd.Env = append(cmd.Env, "TMP="+newtmp)
	cmd.Env = append(cmd.Env, "TEMP="+newtmp)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to spawn child process: %v %q", err, string(output))
	}
	if want, have := newtmp, string(output); have != want {
		t.Fatalf("unexpected child process output %q, want %q", have, want)
	}
}

// replaceDriveWithVolumeID returns path with its volume name replaced with
// the mounted volume ID. E.g. C:\foo -> \\?\Volume{GUID}\foo.
func replaceDriveWithVolumeID(t *testing.T, path string) string {
	t.Helper()
	cmd := testenv.Command(t, "cmd", "/c", "mountvol", filepath.VolumeName(path), "/L")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %v\n%s", cmd, err, out)
	}
	vol := strings.Trim(string(out), " \n\r")
	return filepath.Join(vol, path[len(filepath.VolumeName(path)):])
}

func TestReadlink(t *testing.T) {
	tests := []struct {
		junction bool
		dir      bool
		drive    bool
		relative bool
	}{
		{junction: true, dir: true, drive: true, relative: false},
		{junction: true, dir: true, drive: false, relative: false},
		{junction: true, dir: true, drive: false, relative: true},
		{junction: false, dir: true, drive: true, relative: false},
		{junction: false, dir: true, drive: false, relative: false},
		{junction: false, dir: true, drive: false, relative: true},
		{junction: false, dir: false, drive: true, relative: false},
		{junction: false, dir: false, drive: false, relative: fal
"""




```