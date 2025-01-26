Response:
这个 Go 语言文件 `exec_linux_test.go` 是 Go 标准库 `syscall` 包的一部分，主要用于测试 Linux 系统调用相关的功能。它包含了一系列的测试函数，用于验证 Go 语言在 Linux 环境下对系统调用的封装是否正确工作。以下是该文件的主要功能和测试内容：

### 1. **用户命名空间（User Namespace）测试**
   - **功能**: 测试在 Linux 中使用 `CLONE_NEWUSER` 标志创建新的用户命名空间，并验证用户和组的映射是否正确。
   - **代码示例**:
     ```go
     func whoamiNEWUSER(t *testing.T, uid, gid int, setgroups bool) *exec.Cmd {
         cmd := testenv.Command(t, "whoami")
         cmd.SysProcAttr = &syscall.SysProcAttr{
             Cloneflags: syscall.CLONE_NEWUSER,
             UidMappings: []syscall.SysProcIDMap{
                 {ContainerID: 0, HostID: uid, Size: 1},
             },
             GidMappings: []syscall.SysProcIDMap{
                 {ContainerID: 0, HostID: gid, Size: 1},
             },
             GidMappingsEnableSetgroups: setgroups,
         }
         return cmd
     }
     ```
   - **输入与输出**:
     - 输入: 当前用户的 UID 和 GID。
     - 输出: 在用户命名空间中运行 `whoami` 命令，预期输出为 `root`，因为 UID 0 被映射到当前用户的 UID。

### 2. **网络命名空间（Network Namespace）测试**
   - **功能**: 测试在 Linux 中使用 `CLONE_NEWNET` 标志创建新的网络命名空间，并验证网络接口的隔离效果。
   - **代码示例**:
     ```go
     func TestUnshare(t *testing.T) {
         cmd := testenv.Command(t, "cat", "/proc/net/dev")
         cmd.SysProcAttr = &syscall.SysProcAttr{
             Unshareflags: syscall.CLONE_NEWNET,
         }
         out, err := cmd.CombinedOutput()
         if err != nil {
             t.Fatalf("Cmd failed with err %v, output: %s", err, out)
         }
     }
     ```
   - **输入与输出**:
     - 输入: `/proc/net/dev` 文件路径。
     - 输出: 在网络命名空间中运行 `cat /proc/net/dev`，预期输出只包含本地网络接口 `lo`。

### 3. **挂载命名空间（Mount Namespace）测试**
   - **功能**: 测试在 Linux 中使用 `CLONE_NEWNS` 标志创建新的挂载命名空间，并验证挂载点的隔离效果。
   - **代码示例**:
     ```go
     func TestUnshareMountNameSpace(t *testing.T) {
         cmd := testenv.Command(t, exe, "-test.run=^TestUnshareMountNameSpace$", d)
         cmd.Env = append(cmd.Environ(), "GO_WANT_HELPER_PROCESS=1")
         cmd.SysProcAttr = &syscall.SysProcAttr{Unshareflags: syscall.CLONE_NEWNS}
         out, err := cmd.CombinedOutput()
         if err != nil {
             t.Fatalf("unshare failed: %v\n%s", err, out)
         }
     }
     ```
   - **输入与输出**:
     - 输入: 临时目录路径。
     - 输出: 在挂载命名空间中运行命令，预期输出为成功创建并卸载挂载点。

### 4. **PID 文件描述符（PID FD）测试**
   - **功能**: 测试在 Linux 中使用 `pidfd` 来管理进程，并验证通过 `pidfd` 发送信号的功能。
   - **代码示例**:
     ```go
     func testPidFD(t *testing.T, userns bool) error {
         var pidfd int
         cmd := testenv.Command(t, exe, "-test.run=^TestPidFD$")
         cmd.Env = append(cmd.Environ(), "GO_WANT_HELPER_PROCESS=1")
         cmd.SysProcAttr = &syscall.SysProcAttr{
             PidFD: &pidfd,
         }
         if err := cmd.Start(); err != nil {
             return err
         }
         defer cmd.Process.Kill()
         defer cmd.Wait()
         if pidfd == -1 {
             t.Skip("pidfd not supported")
         }
         defer syscall.Close(pidfd)
         if err := unix.PidFDSendSignal(uintptr(pidfd), syscall.SIGINT); err != nil {
             t.Fatal("pidfd_send_signal syscall failed:", err)
         }
         return nil
     }
     ```
   - **输入与输出**:
     - 输入: 无。
     - 输出: 通过 `pidfd` 发送 `SIGINT` 信号，预期子进程会接收到信号并退出。

### 5. **时间命名空间（Time Namespace）测试**
   - **功能**: 测试在 Linux 中使用 `CLONE_NEWTIME` 标志创建新的时间命名空间，并验证时间命名空间的隔离效果。
   - **代码示例**:
     ```go
     func TestCloneTimeNamespace(t *testing.T) {
         cmd := testenv.Command(t, exe, "-test.run=^TestCloneTimeNamespace$")
         cmd.Env = append(cmd.Environ(), "GO_WANT_HELPER_PROCESS=1")
         cmd.SysProcAttr = &syscall.SysProcAttr{
             Cloneflags: syscall.CLONE_NEWTIME,
         }
         out, err := cmd.CombinedOutput()
         if err != nil {
             t.Fatalf("Cmd failed with err %v, output: %s", err, out)
         }
     }
     ```
   - **输入与输出**:
     - 输入: 无。
     - 输出: 在时间命名空间中运行命令，预期输出为不同的时间命名空间 inode 号。

### 6. **Cgroup 文件描述符（Cgroup FD）测试**
   - **功能**: 测试在 Linux 中使用 `Cgroup FD` 来管理进程的 cgroup，并验证进程是否被正确放入指定的 cgroup。
   - **代码示例**:
     ```go
     func TestUseCgroupFD(t *testing.T) {
         fd, suffix := prepareCgroupFD(t)
         cmd := testenv.Command(t, exe, "-test.run=^TestUseCgroupFD$")
         cmd.Env = append(cmd.Environ(), "GO_WANT_HELPER_PROCESS=1")
         cmd.SysProcAttr = &syscall.SysProcAttr{
             UseCgroupFD: true,
             CgroupFD:    fd,
         }
         out, err := cmd.CombinedOutput()
         if err != nil {
             t.Fatalf("Cmd failed with err %v, output: %s", err, out)
         }
     }
     ```
   - **输入与输出**:
     - 输入: 无。
     - 输出: 进程的 cgroup 路径应与指定的 cgroup 路径匹配。

### 7. **环境能力（Ambient Capabilities）测试**
   - **功能**: 测试在 Linux 中设置环境能力（Ambient Capabilities），并验证子进程是否继承了这些能力。
   - **代码示例**:
     ```go
     func testAmbientCaps(t *testing.T, userns bool) {
         cmd := testenv.Command(t, f.Name(), "-test.run=^"+t.Name()+"$")
         cmd.Env = append(cmd.Environ(), "GO_WANT_HELPER_PROCESS=1")
         cmd.SysProcAttr = &syscall.SysProcAttr{
             AmbientCaps: []uintptr{CAP_SYS_TIME, CAP_SYSLOG},
         }
         if err := cmd.Run(); err != nil {
             t.Fatal(err.Error())
         }
     }
     ```
   - **输入与输出**:
     - 输入: 无。
     - 输出: 子进程应具有 `CAP_SYS_TIME` 和 `CAP_SYSLOG` 能力。

### 8. **命令行参数处理**
   - **功能**: 该文件中的测试函数通过命令行参数来控制子进程的行为。例如，`GO_WANT_HELPER_PROCESS` 环境变量用于区分主进程和子进程。
   - **代码示例**:
     ```go
     if os.Getenv("GO_WANT_HELPER_PROCESS") == "1" {
         // 子进程逻辑
         os.Exit(0)
     }
     ```
   - **详细处理**:
     - 主进程通过设置 `GO_WANT_HELPER_PROCESS=1` 来启动子进程，子进程根据该环境变量执行特定的测试逻辑。

### 9. **易犯错的点**
   - **权限问题**: 许多测试需要特定的权限（如 `CAP_SYS_ADMIN`）或 root 权限才能运行。如果测试在没有足够权限的环境中运行，可能会导致测试失败或跳过。
   - **内核版本兼容性**: 某些测试依赖于较新的 Linux 内核功能（如 `pidfd`、`CLONE_NEWTIME`），如果内核版本较旧，测试可能会跳过。
   - **环境隔离**: 测试中使用了命名空间（如用户、网络、挂载命名空间），如果测试环境本身已经处于某个命名空间中，可能会导致测试结果不符合预期。

### 总结
该文件主要用于测试 Go 语言在 Linux 环境下对系统调用的封装，特别是与命名空间、cgroup、能力管理等相关的高级功能。通过这些测试，可以确保 Go 语言在 Linux 系统上的系统调用封装是正确且可靠的。
Prompt: 
```
这是路径为go/src/syscall/exec_linux_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux

package syscall_test

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"internal/platform"
	"internal/syscall/unix"
	"internal/testenv"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// whoamiNEWUSER returns a command that runs "whoami" with CLONE_NEWUSER,
// mapping uid and gid 0 to the actual uid and gid of the test.
func whoamiNEWUSER(t *testing.T, uid, gid int, setgroups bool) *exec.Cmd {
	t.Helper()
	testenv.MustHaveExecPath(t, "whoami")
	cmd := testenv.Command(t, "whoami")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER,
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: uid, Size: 1},
		},
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: gid, Size: 1},
		},
		GidMappingsEnableSetgroups: setgroups,
	}
	return cmd
}

func TestCloneNEWUSERAndRemap(t *testing.T) {
	for _, setgroups := range []bool{false, true} {
		setgroups := setgroups
		t.Run(fmt.Sprintf("setgroups=%v", setgroups), func(t *testing.T) {
			uid := os.Getuid()
			gid := os.Getgid()

			cmd := whoamiNEWUSER(t, uid, gid, setgroups)
			out, err := cmd.CombinedOutput()
			t.Logf("%v: %v", cmd, err)

			if uid != 0 && setgroups {
				t.Logf("as non-root, expected permission error due to unprivileged gid_map")
				if !os.IsPermission(err) {
					if err == nil {
						t.Skipf("unexpected success: probably old kernel without security fix?")
					}
					if testenv.SyscallIsNotSupported(err) {
						t.Skipf("skipping: CLONE_NEWUSER appears to be unsupported")
					}
					t.Fatalf("got non-permission error") // Already logged above.
				}
				return
			}

			if err != nil {
				if testenv.SyscallIsNotSupported(err) {
					// May be inside a container that disallows CLONE_NEWUSER.
					t.Skipf("skipping: CLONE_NEWUSER appears to be unsupported")
				}
				t.Fatalf("unexpected command failure; output:\n%s", out)
			}

			sout := strings.TrimSpace(string(out))
			want := "root"
			if sout != want {
				t.Fatalf("whoami = %q; want %q", out, want)
			}
		})
	}
}

func TestEmptyCredGroupsDisableSetgroups(t *testing.T) {
	cmd := whoamiNEWUSER(t, os.Getuid(), os.Getgid(), false)
	cmd.SysProcAttr.Credential = &syscall.Credential{}
	if err := cmd.Run(); err != nil {
		if testenv.SyscallIsNotSupported(err) {
			t.Skipf("skipping: %v: %v", cmd, err)
		}
		t.Fatal(err)
	}
}

func TestUnshare(t *testing.T) {
	path := "/proc/net/dev"
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			t.Skip("kernel doesn't support proc filesystem")
		}
		if os.IsPermission(err) {
			t.Skip("unable to test proc filesystem due to permissions")
		}
		t.Fatal(err)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	orig := strings.TrimSpace(string(b))
	if strings.Contains(orig, "lo:") && strings.Count(orig, ":") == 1 {
		// This test expects there to be at least 1 more network interface
		// in addition to the local network interface, so that it can tell
		// that unshare worked.
		t.Skip("not enough network interfaces to test unshare with")
	}

	cmd := testenv.Command(t, "cat", path)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Unshareflags: syscall.CLONE_NEWNET,
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		if testenv.SyscallIsNotSupported(err) {
			// CLONE_NEWNET does not appear to be supported.
			t.Skipf("skipping due to permission error: %v", err)
		}
		t.Fatalf("Cmd failed with err %v, output: %s", err, out)
	}

	// Check there is only the local network interface.
	sout := strings.TrimSpace(string(out))
	if !strings.Contains(sout, "lo:") {
		t.Fatalf("Expected lo network interface to exist, got %s", sout)
	}

	origLines := strings.Split(orig, "\n")
	lines := strings.Split(sout, "\n")
	if len(lines) >= len(origLines) {
		t.Logf("%s before unshare:\n%s", path, orig)
		t.Logf("%s after unshare:\n%s", path, sout)
		t.Fatalf("Got %d lines of output, want < %d", len(lines), len(origLines))
	}
}

func TestGroupCleanup(t *testing.T) {
	testenv.MustHaveExecPath(t, "id")
	cmd := testenv.Command(t, "id")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid: 0,
			Gid: 0,
		},
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		if testenv.SyscallIsNotSupported(err) {
			t.Skipf("skipping: %v: %v", cmd, err)
		}
		t.Fatalf("Cmd failed with err %v, output: %s", err, out)
	}
	strOut := strings.TrimSpace(string(out))
	t.Logf("id: %s", strOut)

	expected := "uid=0(root) gid=0(root)"
	// Just check prefix because some distros reportedly output a
	// context parameter; see https://golang.org/issue/16224.
	// Alpine does not output groups; see https://golang.org/issue/19938.
	if !strings.HasPrefix(strOut, expected) {
		t.Errorf("expected prefix: %q", expected)
	}
}

func TestGroupCleanupUserNamespace(t *testing.T) {
	testenv.MustHaveExecPath(t, "id")
	cmd := testenv.Command(t, "id")
	uid, gid := os.Getuid(), os.Getgid()
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER,
		Credential: &syscall.Credential{
			Uid: uint32(uid),
			Gid: uint32(gid),
		},
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: uid, Size: 1},
		},
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: gid, Size: 1},
		},
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		if testenv.SyscallIsNotSupported(err) {
			t.Skipf("skipping: %v: %v", cmd, err)
		}
		t.Fatalf("Cmd failed with err %v, output: %s", err, out)
	}
	strOut := strings.TrimSpace(string(out))
	t.Logf("id: %s", strOut)

	// As in TestGroupCleanup, just check prefix.
	// The actual groups and contexts seem to vary from one distro to the next.
	expected := "uid=0(root) gid=0(root) groups=0(root)"
	if !strings.HasPrefix(strOut, expected) {
		t.Errorf("expected prefix: %q", expected)
	}
}

// Test for https://go.dev/issue/19661: unshare fails because systemd
// has forced / to be shared
func TestUnshareMountNameSpace(t *testing.T) {
	const mountNotSupported = "mount is not supported: " // Output prefix indicating a test skip.
	if os.Getenv("GO_WANT_HELPER_PROCESS") == "1" {
		dir := flag.Args()[0]
		err := syscall.Mount("none", dir, "proc", 0, "")
		if testenv.SyscallIsNotSupported(err) {
			fmt.Print(mountNotSupported, err)
		} else if err != nil {
			fmt.Fprintf(os.Stderr, "unshare: mount %s: %v\n", dir, err)
			os.Exit(2)
		}
		os.Exit(0)
	}

	exe := testenv.Executable(t)
	d := t.TempDir()
	t.Cleanup(func() {
		// If the subprocess fails to unshare the parent directory, force-unmount it
		// so that the test can clean it up.
		if _, err := os.Stat(d); err == nil {
			syscall.Unmount(d, syscall.MNT_FORCE)
		}
	})
	cmd := testenv.Command(t, exe, "-test.run=^TestUnshareMountNameSpace$", d)
	cmd.Env = append(cmd.Environ(), "GO_WANT_HELPER_PROCESS=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Unshareflags: syscall.CLONE_NEWNS}

	out, err := cmd.CombinedOutput()
	if err != nil {
		if testenv.SyscallIsNotSupported(err) {
			t.Skipf("skipping: could not start process with CLONE_NEWNS: %v", err)
		}
		t.Fatalf("unshare failed: %v\n%s", err, out)
	} else if len(out) != 0 {
		if bytes.HasPrefix(out, []byte(mountNotSupported)) {
			t.Skipf("skipping: helper process reported %s", out)
		}
		t.Fatalf("unexpected output from helper process: %s", out)
	}

	// How do we tell if the namespace was really unshared? It turns out
	// to be simple: just try to remove the directory. If it's still mounted
	// on the rm will fail with EBUSY.
	if err := os.Remove(d); err != nil {
		t.Errorf("rmdir failed on %v: %v", d, err)
	}
}

// Test for Issue 20103: unshare fails when chroot is used
func TestUnshareMountNameSpaceChroot(t *testing.T) {
	const mountNotSupported = "mount is not supported: " // Output prefix indicating a test skip.
	if os.Getenv("GO_WANT_HELPER_PROCESS") == "1" {
		dir := flag.Args()[0]
		err := syscall.Mount("none", dir, "proc", 0, "")
		if testenv.SyscallIsNotSupported(err) {
			fmt.Print(mountNotSupported, err)
		} else if err != nil {
			fmt.Fprintf(os.Stderr, "unshare: mount %s: %v\n", dir, err)
			os.Exit(2)
		}
		os.Exit(0)
	}

	d := t.TempDir()

	// Since we are doing a chroot, we need the binary there,
	// and it must be statically linked.
	testenv.MustHaveGoBuild(t)
	if platform.MustLinkExternal(runtime.GOOS, runtime.GOARCH, false) {
		t.Skipf("skipping: can't build static binary because %s/%s requires external linking", runtime.GOOS, runtime.GOARCH)
	}
	x := filepath.Join(d, "syscall.test")
	t.Cleanup(func() {
		// If the subprocess fails to unshare the parent directory, force-unmount it
		// so that the test can clean it up.
		if _, err := os.Stat(d); err == nil {
			syscall.Unmount(d, syscall.MNT_FORCE)
		}
	})

	cmd := testenv.Command(t, testenv.GoToolPath(t), "test", "-c", "-o", x, "syscall")
	cmd.Env = append(cmd.Environ(), "CGO_ENABLED=0")
	if o, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v: %v\n%s", cmd, err, o)
	}

	cmd = testenv.Command(t, "/syscall.test", "-test.run=^TestUnshareMountNameSpaceChroot$", "/")
	cmd.Env = append(cmd.Environ(), "GO_WANT_HELPER_PROCESS=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Chroot: d, Unshareflags: syscall.CLONE_NEWNS}

	out, err := cmd.CombinedOutput()
	if err != nil {
		if testenv.SyscallIsNotSupported(err) {
			t.Skipf("skipping: could not start process with CLONE_NEWNS and Chroot %q: %v", d, err)
		}
		t.Fatalf("unshare failed: %v\n%s", err, out)
	} else if len(out) != 0 {
		if bytes.HasPrefix(out, []byte(mountNotSupported)) {
			t.Skipf("skipping: helper process reported %s", out)
		}
		t.Fatalf("unexpected output from helper process: %s", out)
	}

	// How do we tell if the namespace was really unshared? It turns out
	// to be simple: just try to remove the executable. If it's still mounted
	// on, the rm will fail.
	if err := os.Remove(x); err != nil {
		t.Errorf("rm failed on %v: %v", x, err)
	}
	if err := os.Remove(d); err != nil {
		t.Errorf("rmdir failed on %v: %v", d, err)
	}
}

// Test for Issue 29789: unshare fails when uid/gid mapping is specified
func TestUnshareUidGidMapping(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") == "1" {
		defer os.Exit(0)
		if err := syscall.Chroot(os.TempDir()); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	}

	if os.Getuid() == 0 {
		t.Skip("test exercises unprivileged user namespace, fails with privileges")
	}

	exe := testenv.Executable(t)
	cmd := testenv.Command(t, exe, "-test.run=^TestUnshareUidGidMapping$")
	cmd.Env = append(cmd.Environ(), "GO_WANT_HELPER_PROCESS=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Unshareflags:               syscall.CLONE_NEWNS | syscall.CLONE_NEWUSER,
		GidMappingsEnableSetgroups: false,
		UidMappings: []syscall.SysProcIDMap{
			{
				ContainerID: 0,
				HostID:      syscall.Getuid(),
				Size:        1,
			},
		},
		GidMappings: []syscall.SysProcIDMap{
			{
				ContainerID: 0,
				HostID:      syscall.Getgid(),
				Size:        1,
			},
		},
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		if testenv.SyscallIsNotSupported(err) {
			t.Skipf("skipping: could not start process with CLONE_NEWNS and CLONE_NEWUSER: %v", err)
		}
		t.Fatalf("Cmd failed with err %v, output: %s", err, out)
	}
}

func prepareCgroupFD(t *testing.T) (int, string) {
	t.Helper()

	const O_PATH = 0x200000 // Same for all architectures, but for some reason not defined in syscall for 386||amd64.

	// Requires cgroup v2.
	const prefix = "/sys/fs/cgroup"
	selfCg, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		if os.IsNotExist(err) || os.IsPermission(err) {
			t.Skip(err)
		}
		t.Fatal(err)
	}

	// Expect a single line like this:
	// 0::/user.slice/user-1000.slice/user@1000.service/app.slice/vte-spawn-891992a2-efbb-4f28-aedb-b24f9e706770.scope
	// Otherwise it's either cgroup v1 or a hybrid hierarchy.
	if bytes.Count(selfCg, []byte("\n")) > 1 {
		t.Skip("cgroup v2 not available")
	}
	cg := bytes.TrimPrefix(selfCg, []byte("0::"))
	if len(cg) == len(selfCg) { // No prefix found.
		t.Skipf("cgroup v2 not available (/proc/self/cgroup contents: %q)", selfCg)
	}

	// Need an ability to create a sub-cgroup.
	subCgroup, err := os.MkdirTemp(prefix+string(bytes.TrimSpace(cg)), "subcg-")
	if err != nil {
		// ErrPermission or EROFS (#57262) when running in an unprivileged container.
		// ErrNotExist when cgroupfs is not mounted in chroot/schroot.
		if os.IsNotExist(err) || testenv.SyscallIsNotSupported(err) {
			t.Skipf("skipping: %v", err)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { syscall.Rmdir(subCgroup) })

	cgroupFD, err := syscall.Open(subCgroup, O_PATH, 0)
	if err != nil {
		t.Fatal(&os.PathError{Op: "open", Path: subCgroup, Err: err})
	}
	t.Cleanup(func() { syscall.Close(cgroupFD) })

	return cgroupFD, "/" + path.Base(subCgroup)
}

func TestUseCgroupFD(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") == "1" {
		// Read and print own cgroup path.
		selfCg, err := os.ReadFile("/proc/self/cgroup")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		fmt.Print(string(selfCg))
		os.Exit(0)
	}

	exe := testenv.Executable(t)
	fd, suffix := prepareCgroupFD(t)

	cmd := testenv.Command(t, exe, "-test.run=^TestUseCgroupFD$")
	cmd.Env = append(cmd.Environ(), "GO_WANT_HELPER_PROCESS=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		UseCgroupFD: true,
		CgroupFD:    fd,
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		if testenv.SyscallIsNotSupported(err) && !errors.Is(err, syscall.EINVAL) {
			// Can be one of:
			// - clone3 not supported (old kernel);
			// - clone3 not allowed (by e.g. seccomp);
			// - lack of CAP_SYS_ADMIN.
			t.Skipf("clone3 with CLONE_INTO_CGROUP not available: %v", err)
		}
		t.Fatalf("Cmd failed with err %v, output: %s", err, out)
	}
	// NB: this wouldn't work with cgroupns.
	if !bytes.HasSuffix(bytes.TrimSpace(out), []byte(suffix)) {
		t.Fatalf("got: %q, want: a line that ends with %q", out, suffix)
	}
}

func TestCloneTimeNamespace(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") == "1" {
		timens, err := os.Readlink("/proc/self/ns/time")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		fmt.Print(string(timens))
		os.Exit(0)
	}

	exe := testenv.Executable(t)
	cmd := testenv.Command(t, exe, "-test.run=^TestCloneTimeNamespace$")
	cmd.Env = append(cmd.Environ(), "GO_WANT_HELPER_PROCESS=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWTIME,
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		if testenv.SyscallIsNotSupported(err) {
			// CLONE_NEWTIME does not appear to be supported.
			t.Skipf("skipping, CLONE_NEWTIME not supported: %v", err)
		}
		t.Fatalf("Cmd failed with err %v, output: %s", err, out)
	}

	// Inode number of the time namespaces should be different.
	// Based on https://man7.org/linux/man-pages/man7/time_namespaces.7.html#EXAMPLES
	timens, err := os.Readlink("/proc/self/ns/time")
	if err != nil {
		t.Fatal(err)
	}

	parentTimeNS := timens
	childTimeNS := string(out)
	if childTimeNS == parentTimeNS {
		t.Fatalf("expected child time namespace to be different from parent time namespace: %s", parentTimeNS)
	}
}

func testPidFD(t *testing.T, userns bool) error {
	if os.Getenv("GO_WANT_HELPER_PROCESS") == "1" {
		// Child: wait for a signal.
		time.Sleep(time.Hour)
	}

	exe := testenv.Executable(t)
	var pidfd int
	cmd := testenv.Command(t, exe, "-test.run=^TestPidFD$")
	cmd.Env = append(cmd.Environ(), "GO_WANT_HELPER_PROCESS=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		PidFD: &pidfd,
	}
	if userns {
		cmd.SysProcAttr.Cloneflags = syscall.CLONE_NEWUSER
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	defer func() {
		cmd.Process.Kill()
		cmd.Wait()
	}()
	t.Log("got pidfd:", pidfd)
	// If pidfd is not supported by the kernel, -1 is returned.
	if pidfd == -1 {
		t.Skip("pidfd not supported")
	}
	defer syscall.Close(pidfd)

	// Use pidfd to send a signal to the child.
	sig := syscall.SIGINT
	if err := unix.PidFDSendSignal(uintptr(pidfd), sig); err != nil {
		if err != syscall.EINVAL && testenv.SyscallIsNotSupported(err) {
			t.Skip("pidfd_send_signal syscall not supported:", err)
		}
		t.Fatal("pidfd_send_signal syscall failed:", err)
	}
	// Check if the child received our signal.
	err := cmd.Wait()
	if cmd.ProcessState == nil || cmd.ProcessState.Sys().(syscall.WaitStatus).Signal() != sig {
		t.Fatal("unexpected child error:", err)
	}
	return nil
}

func TestPidFD(t *testing.T) {
	if err := testPidFD(t, false); err != nil {
		t.Fatal("can't start a process:", err)
	}
}

func TestPidFDWithUserNS(t *testing.T) {
	if err := testPidFD(t, true); err != nil {
		if testenv.SyscallIsNotSupported(err) {
			t.Skip("userns not supported:", err)
		}
		t.Fatal("can't start a process:", err)
	}
}

func TestPidFDClone3(t *testing.T) {
	*syscall.ForceClone3 = true
	defer func() { *syscall.ForceClone3 = false }()

	if err := testPidFD(t, false); err != nil {
		if testenv.SyscallIsNotSupported(err) {
			t.Skip("clone3 not supported:", err)
		}
		t.Fatal("can't start a process:", err)
	}
}

type capHeader struct {
	version uint32
	pid     int32
}

type capData struct {
	effective   uint32
	permitted   uint32
	inheritable uint32
}

const CAP_SYS_TIME = 25
const CAP_SYSLOG = 34

type caps struct {
	hdr  capHeader
	data [2]capData
}

func getCaps() (caps, error) {
	var c caps

	// Get capability version
	if _, _, errno := syscall.Syscall(syscall.SYS_CAPGET, uintptr(unsafe.Pointer(&c.hdr)), uintptr(unsafe.Pointer(nil)), 0); errno != 0 {
		return c, fmt.Errorf("SYS_CAPGET: %v", errno)
	}

	// Get current capabilities
	if _, _, errno := syscall.Syscall(syscall.SYS_CAPGET, uintptr(unsafe.Pointer(&c.hdr)), uintptr(unsafe.Pointer(&c.data[0])), 0); errno != 0 {
		return c, fmt.Errorf("SYS_CAPGET: %v", errno)
	}

	return c, nil
}

func TestAmbientCaps(t *testing.T) {
	testAmbientCaps(t, false)
}

func TestAmbientCapsUserns(t *testing.T) {
	b, err := os.ReadFile("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
	if err == nil && strings.TrimSpace(string(b)) == "1" {
		t.Skip("AppArmor restriction for unprivileged user namespaces is enabled")
	}
	testAmbientCaps(t, true)
}

func testAmbientCaps(t *testing.T, userns bool) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") == "1" {
		caps, err := getCaps()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		if caps.data[0].effective&(1<<uint(CAP_SYS_TIME)) == 0 {
			fmt.Fprintln(os.Stderr, "CAP_SYS_TIME unexpectedly not in the effective capability mask")
			os.Exit(2)
		}
		if caps.data[1].effective&(1<<uint(CAP_SYSLOG&31)) == 0 {
			fmt.Fprintln(os.Stderr, "CAP_SYSLOG unexpectedly not in the effective capability mask")
			os.Exit(2)
		}
		os.Exit(0)
	}

	// skip on android, due to lack of lookup support
	if runtime.GOOS == "android" {
		t.Skip("skipping test on android; see Issue 27327")
	}

	u, err := user.Lookup("nobody")
	if err != nil {
		t.Fatal(err)
	}
	uid, err := strconv.ParseInt(u.Uid, 0, 32)
	if err != nil {
		t.Fatal(err)
	}
	gid, err := strconv.ParseInt(u.Gid, 0, 32)
	if err != nil {
		t.Fatal(err)
	}

	// Copy the test binary to a temporary location which is readable by nobody.
	f, err := os.CreateTemp("", "gotest")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.Close()
		os.Remove(f.Name())
	})

	exe := testenv.Executable(t)
	e, err := os.Open(exe)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if _, err := io.Copy(f, e); err != nil {
		t.Fatal(err)
	}
	if err := f.Chmod(0755); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	cmd := testenv.Command(t, f.Name(), "-test.run=^"+t.Name()+"$")
	cmd.Env = append(cmd.Environ(), "GO_WANT_HELPER_PROCESS=1")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid: uint32(uid),
			Gid: uint32(gid),
		},
		AmbientCaps: []uintptr{CAP_SYS_TIME, CAP_SYSLOG},
	}
	if userns {
		cmd.SysProcAttr.Cloneflags = syscall.CLONE_NEWUSER
		const nobody = 65534
		uid := os.Getuid()
		gid := os.Getgid()
		cmd.SysProcAttr.UidMappings = []syscall.SysProcIDMap{{
			ContainerID: int(nobody),
			HostID:      uid,
			Size:        int(1),
		}}
		cmd.SysProcAttr.GidMappings = []syscall.SysProcIDMap{{
			ContainerID: int(nobody),
			HostID:      gid,
			Size:        int(1),
		}}

		// Set credentials to run as user and group nobody.
		cmd.SysProcAttr.Credential = &syscall.Credential{
			Uid: nobody,
			Gid: nobody,
		}
	}
	if err := cmd.Run(); err != nil {
		if testenv.SyscallIsNotSupported(err) {
			t.Skipf("skipping: %v: %v", cmd, err)
		}
		t.Fatal(err.Error())
	}
}

"""



```