Response:
Let's break down the thought process for analyzing the provided Go code.

1. **Understand the Goal:** The request asks for the functionality of a Go test file (`syscall_linux_test.go`), explanations of specific Go features it demonstrates, code examples, command-line argument handling, and common pitfalls. The key is to understand that this is *test* code, meaning it's designed to verify the behavior of the `syscall` package on Linux.

2. **Initial Scan and Keyword Spotting:**  Read through the code, looking for familiar Go testing patterns and syscall-related functions. Keywords like `Test...`, `syscall.`, `os.`, `exec.Command`, constants like `_AT_FDCWD`, and specific syscall names (e.g., `Faccessat`, `Fchmodat`, `Prlimit`, `Setuid`, `Getrlimit`) jump out. This gives a high-level overview of the tested areas.

3. **Function-by-Function Analysis:**  Go through each `func Test...` and other top-level functions systematically. For each function:

    * **Identify the Core Syscall:** What syscall is being tested?  The function name often gives this away (e.g., `TestFaccessat` tests `syscall.Faccessat`).
    * **Understand the Test Logic:** What is the test doing?  Is it checking for success, failure, specific error codes, or side effects? Look at the setup (creating files, symlinks), the syscall invocation, and the assertions (using `t.Errorf`, `t.Fatalf`).
    * **Note Constants and Variables:** Pay attention to constants like `_AT_SYMLINK_NOFOLLOW` and variables used as arguments to syscalls. Their values often provide context about the test scenarios.
    * **Infer the Go Feature:** Based on the syscall being tested, what Go functionality is being demonstrated?  For example, `TestFaccessat` shows how Go wraps the `faccessat` syscall for checking file access permissions.
    * **Look for Edge Cases and Error Handling:** Does the test explicitly check for specific error conditions? This can reveal important aspects of how the syscall behaves.

4. **Specific Feature Extraction:**  After analyzing the individual tests, consolidate the information to answer the specific questions in the prompt:

    * **Functionality Listing:**  Summarize the purpose of each test function. Group related tests (e.g., all the `Setuid` family tests).
    * **Go Feature Explanation and Examples:** For each identified Go feature, provide a concise explanation and a simple, illustrative Go code example. The example should clearly demonstrate how to use the feature. Think about the necessary imports and basic usage patterns. Consider including input/output if it helps clarify the behavior.
    * **Code Reasoning:** For tests involving more complex logic (like `TestSyscallNoError` or `TestPrlimitFileLimit`), explain the steps involved, the expected outcomes, and any assumptions made.
    * **Command-Line Arguments:** Look for the `TestMain` function. It's often used for setting up test environments or handling special test cases. In this case, it checks environment variables like `GO_DEATHSIG_PARENT`, `GO_DEATHSIG_CHILD`, and `GO_SYSCALL_NOERROR`. Explain the purpose of each.
    * **Common Mistakes:** Think about potential errors a user might make when using the tested syscalls or Go features. This might involve incorrect flags, insufficient permissions, or misunderstanding the behavior of certain syscalls (e.g., `Fchmodat` on symlinks).

5. **Refine and Structure:** Organize the collected information into a clear and structured answer, addressing each point in the original request. Use headings and bullet points to improve readability. Ensure the language is precise and easy to understand.

**Self-Correction/Refinement during the Process:**

* **Initial Overgeneralization:**  At first, I might broadly categorize the file as "testing various syscalls related to file operations and process management."  However, as I delve deeper, I need to be more specific about *which* file operations and *which* aspects of process management are being tested.
* **Missing Details:**  I might initially miss the significance of constants like `_AT_SYMLINK_NOFOLLOW`. I need to research or deduce their meaning and incorporate that into the explanation of the relevant tests.
* **Inaccurate Feature Mapping:** I might incorrectly associate a test with a specific high-level Go feature. For example, I might initially think `TestAllThreadsSyscall` is solely about concurrency, but it's specifically testing syscalls that affect all threads.
* **Vague Explanations:**  My initial explanations might be too technical or assume too much prior knowledge. I need to rephrase them in a way that is accessible to a wider audience.
* **Insufficient Examples:**  My first examples might be too simplistic or not clearly illustrate the intended point. I need to refine them to be more demonstrative.

By iteratively analyzing the code, extracting information, and refining my understanding, I can arrive at a comprehensive and accurate answer like the example you provided. The key is to be systematic and to continually check my understanding against the actual code.
这个文件 `go/src/syscall/syscall_linux_test.go` 是 Go 语言标准库 `syscall` 包在 Linux 平台上的单元测试文件。它包含了多个测试函数，用于验证 `syscall` 包中与 Linux 系统调用相关的函数的正确性和行为。

以下是该文件的一些主要功能和测试的方面：

**1. 文件和目录操作相关的系统调用：**

* **`TestFaccessat`:** 测试 `syscall.Faccessat` 函数。这个函数允许在相对于目录文件描述符的情况下检查文件的访问权限。它测试了不同的标志，例如 `_AT_EACCESS` 和 `_AT_SYMLINK_NOFOLLOW`。
    * **Go 代码示例:**
    ```go
    package main

    import (
        "fmt"
        "syscall"
    )

    func main() {
        // 假设当前目录下有名为 "test.txt" 的可读文件
        err := syscall.Faccessat(syscall.AT_FDCWD, "test.txt", syscall.R_OK, 0)
        if err == nil {
            fmt.Println("文件可读")
        } else {
            fmt.Println("文件不可读:", err)
        }
    }
    ```
    * **假设输入与输出:** 假设当前目录下存在一个名为 "test.txt" 且当前用户有读取权限的文件。则输出为 "文件可读"。如果文件不存在或不可读，则输出相应的错误信息。

* **`TestFchmodat`:** 测试 `syscall.Fchmodat` 函数。这个函数允许在相对于目录文件描述符的情况下修改文件的权限。它测试了修改普通文件和符号链接权限的行为。
    * **Go 代码示例:**
    ```go
    package main

    import (
        "fmt"
        "os"
        "syscall"
    )

    func main() {
        // 假设当前目录下有名为 "test.txt" 的文件
        err := syscall.Fchmodat(syscall.AT_FDCWD, "test.txt", 0644, 0)
        if err != nil {
            fmt.Println("修改权限失败:", err)
        } else {
            fmt.Println("修改权限成功")
            fi, _ := os.Stat("test.txt")
            fmt.Printf("文件权限: %o\n", fi.Mode().Perm())
        }
    }
    ```
    * **假设输入与输出:** 假设当前目录下存在一个名为 "test.txt" 的文件。执行后，该文件的权限将被修改为 0644。输出会显示 "修改权限成功" 和修改后的文件权限。

**2. 进程和线程相关的系统调用：**

* **`TestMain`:**  虽然名字是 `TestMain`，但在这个上下文中，它更像是一个辅助函数，用于根据环境变量执行不同的子测试逻辑，例如模拟进程收到信号 (`GO_DEATHSIG_PARENT`, `GO_DEATHSIG_CHILD`) 或测试系统调用无错误返回 (`GO_SYSCALL_NOERROR`)。

* **`TestSyscallNoError`:**  测试 `syscall.RawSyscallNoError` 函数。这个函数用于执行不会失败的系统调用，并确保返回值不会被误判为错误。
    * **Go 代码示例 (基于推断):**
    ```go
    package main

    import (
        "fmt"
        "syscall"
    )

    func main() {
        // GETEUID 通常不会失败
        euid, _ := syscall.RawSyscallNoError(syscall.SYS_GETEUID, 0, 0, 0)
        fmt.Println("Effective User ID:", euid)
    }
    ```
    * **假设输入与输出:**  该系统调用不需要输入。输出将会是当前进程的有效用户 ID。

* **`TestAllThreadsSyscall`:** 测试 `syscall.AllThreadsSyscall` 和 `syscall.AllThreadsSyscall6` 函数。这些函数用于在所有操作系统线程上执行系统调用，这对于需要同步所有线程状态的系统调用（如修改进程的 keep-capabilities）非常重要。

* **`TestSetuidEtc`:**  测试一系列与用户和组 ID 相关的系统调用，如 `Setuid`, `Setgid`, `Setegid`, `Setgroups`, `Setregid`, `Setreuid`, `Setresgid`, `Setresuid`。它通过修改进程的用户和组 ID，并检查 `/proc/<pid>/status` 文件来验证这些调用的效果。

* **`TestAllThreadsSyscallError`:** 验证当 `syscall.AllThreadsSyscall` 在原始线程上执行失败时，能够正确返回错误。

* **`TestAllThreadsSyscallBlockedSyscall`:** 测试 `syscall.AllThreadsSyscall` 是否可以中断正在阻塞的系统调用。

**3. 资源限制相关的系统调用：**

* **`TestPrlimitSelf`:** 测试 `syscall.Prlimit` 函数，用于获取和设置当前进程的资源限制。
* **`TestPrlimitOtherProcess`:** 测试 `syscall.Prlimit` 函数，用于获取和设置其他进程的资源限制。
* **`TestPrlimitFileLimit`:**  一个更复杂的测试，用于验证通过 `prlimit` 修改文件描述符限制后，子进程能否继承并感知到这个修改后的限制。

**4. 网络相关的系统调用：**

* **`TestParseNetlinkMessage`:** 测试 `syscall.ParseNetlinkMessage` 函数。这个函数用于解析 Linux Netlink 协议的消息。
    * **代码推理:**  该测试用例提供了几个 byte 数组作为输入，并期望 `syscall.ParseNetlinkMessage` 返回 `syscall.EINVAL` 错误，以及 `nil` 的消息。这暗示了这些输入的 byte 数组并非有效的 Netlink 消息格式，因此测试验证了错误处理机制。

**命令行参数处理:**

该文件本身主要是测试代码，并不直接处理命令行参数。然而，`TestMain` 函数会根据环境变量的值来决定执行不同的测试分支。例如：

* **`GO_DEATHSIG_PARENT=1`**: 运行模拟父进程收到信号的逻辑。
* **`GO_DEATHSIG_CHILD=1`**: 运行模拟子进程收到信号的逻辑。
* **`GO_SYSCALL_NOERROR=1`**: 运行测试 `syscall.RawSyscallNoError` 的逻辑。

这些环境变量可以被 `go test` 命令设置，例如：

```bash
GO_DEATHSIG_PARENT=1 go test ./syscall
```

**使用者易犯错的点 (基于代码推断):**

* **`Faccessat` 和路径问题:** 使用 `Faccessat` 时，如果没有正确理解 `dirfd` 参数（例如使用 `_AT_FDCWD` 表示当前工作目录），可能会导致路径解析错误，从而得到意外的权限检查结果。
* **`Fchmodat` 和符号链接:**  容易忘记 `Fchmodat` 默认情况下会修改符号链接指向的目标文件的权限，而不是符号链接自身的权限。要修改符号链接的权限需要使用 `_AT_SYMLINK_NOFOLLOW` 标志，但并非所有文件系统都支持修改符号链接的权限。
* **权限问题:**  很多系统调用（如修改用户/组 ID，修改资源限制等）都需要 root 权限才能执行成功。在非 root 用户下运行这些测试或使用相关的系统调用会遇到权限错误。
* **`AllThreadsSyscall` 的使用:**  不理解 `AllThreadsSyscall` 的适用场景，可能会在不需要同步所有线程状态的情况下使用，或者在 CGO 环境下使用可能受到限制。
* **`Prlimit` 的进程 ID:**  使用 `Prlimit` 修改其他进程的资源限制时，需要提供正确的进程 ID，否则会操作失败。

总的来说，`go/src/syscall/syscall_linux_test.go` 是一个非常重要的测试文件，它覆盖了 `syscall` 包中大量与 Linux 系统调用相关的函数，确保了这些函数在 Go 语言中的封装和使用是正确可靠的。通过分析这个文件，可以深入了解 Go 语言如何与底层操作系统进行交互，以及各种 Linux 系统调用的具体功能和使用方法。

Prompt: 
```
这是路径为go/src/syscall/syscall_linux_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package syscall_test

import (
	"context"
	"fmt"
	"internal/testenv"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"unsafe"
)

func touch(t *testing.T, name string) {
	f, err := os.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

const (
	_AT_SYMLINK_NOFOLLOW = 0x100
	_AT_FDCWD            = -0x64
	_AT_EACCESS          = 0x200
	_F_OK                = 0
	_R_OK                = 4
)

func TestFaccessat(t *testing.T) {
	t.Chdir(t.TempDir())
	touch(t, "file1")

	err := syscall.Faccessat(_AT_FDCWD, "file1", _R_OK, 0)
	if err != nil {
		t.Errorf("Faccessat: unexpected error: %v", err)
	}

	err = syscall.Faccessat(_AT_FDCWD, "file1", _R_OK, 2)
	if err != syscall.EINVAL {
		t.Errorf("Faccessat: unexpected error: %v, want EINVAL", err)
	}

	err = syscall.Faccessat(_AT_FDCWD, "file1", _R_OK, _AT_EACCESS)
	if err != nil {
		t.Errorf("Faccessat: unexpected error: %v", err)
	}

	err = os.Symlink("file1", "symlink1")
	if err != nil {
		t.Fatal(err)
	}

	err = syscall.Faccessat(_AT_FDCWD, "symlink1", _R_OK, _AT_SYMLINK_NOFOLLOW)
	if err != nil {
		t.Errorf("Faccessat SYMLINK_NOFOLLOW: unexpected error %v", err)
	}

	// We can't really test _AT_SYMLINK_NOFOLLOW, because there
	// doesn't seem to be any way to change the mode of a symlink.
	// We don't test _AT_EACCESS because such tests are only
	// meaningful if run as root.

	err = syscall.Fchmodat(_AT_FDCWD, "file1", 0, 0)
	if err != nil {
		t.Errorf("Fchmodat: unexpected error %v", err)
	}

	err = syscall.Faccessat(_AT_FDCWD, "file1", _F_OK, _AT_SYMLINK_NOFOLLOW)
	if err != nil {
		t.Errorf("Faccessat: unexpected error: %v", err)
	}

	err = syscall.Faccessat(_AT_FDCWD, "file1", _R_OK, _AT_SYMLINK_NOFOLLOW)
	if err != syscall.EACCES {
		if syscall.Getuid() != 0 {
			t.Errorf("Faccessat: unexpected error: %v, want EACCES", err)
		}
	}
}

func TestFchmodat(t *testing.T) {
	t.Chdir(t.TempDir())

	touch(t, "file1")
	os.Symlink("file1", "symlink1")

	err := syscall.Fchmodat(_AT_FDCWD, "symlink1", 0444, 0)
	if err != nil {
		t.Fatalf("Fchmodat: unexpected error: %v", err)
	}

	fi, err := os.Stat("file1")
	if err != nil {
		t.Fatal(err)
	}

	if fi.Mode() != 0444 {
		t.Errorf("Fchmodat: failed to change mode: expected %v, got %v", 0444, fi.Mode())
	}

	err = syscall.Fchmodat(_AT_FDCWD, "symlink1", 0444, _AT_SYMLINK_NOFOLLOW)
	if err != syscall.EOPNOTSUPP {
		t.Fatalf("Fchmodat: unexpected error: %v, expected EOPNOTSUPP", err)
	}
}

func TestMain(m *testing.M) {
	if os.Getenv("GO_DEATHSIG_PARENT") == "1" {
		deathSignalParent()
	} else if os.Getenv("GO_DEATHSIG_CHILD") == "1" {
		deathSignalChild()
	} else if os.Getenv("GO_SYSCALL_NOERROR") == "1" {
		syscallNoError()
	}

	os.Exit(m.Run())
}

func TestParseNetlinkMessage(t *testing.T) {
	for i, b := range [][]byte{
		{103, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 2, 11, 0, 1, 0, 0, 0, 0, 5, 8, 0, 3,
			0, 8, 0, 6, 0, 0, 0, 0, 1, 63, 0, 10, 0, 69, 16, 0, 59, 39, 82, 64, 0, 64, 6, 21, 89, 127, 0, 0,
			1, 127, 0, 0, 1, 230, 228, 31, 144, 32, 186, 155, 211, 185, 151, 209, 179, 128, 24, 1, 86,
			53, 119, 0, 0, 1, 1, 8, 10, 0, 17, 234, 12, 0, 17, 189, 126, 107, 106, 108, 107, 106, 13, 10,
		},
		{106, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 2, 11, 0, 1, 0, 0, 0, 0, 3, 8, 0, 3,
			0, 8, 0, 6, 0, 0, 0, 0, 1, 66, 0, 10, 0, 69, 0, 0, 62, 230, 255, 64, 0, 64, 6, 85, 184, 127, 0, 0,
			1, 127, 0, 0, 1, 237, 206, 31, 144, 73, 197, 128, 65, 250, 60, 192, 97, 128, 24, 1, 86, 253, 21, 0,
			0, 1, 1, 8, 10, 0, 51, 106, 89, 0, 51, 102, 198, 108, 104, 106, 108, 107, 104, 108, 107, 104, 10,
		},
		{102, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 2, 11, 0, 1, 0, 0, 0, 0, 1, 8, 0, 3, 0,
			8, 0, 6, 0, 0, 0, 0, 1, 62, 0, 10, 0, 69, 0, 0, 58, 231, 2, 64, 0, 64, 6, 85, 185, 127, 0, 0, 1, 127,
			0, 0, 1, 237, 206, 31, 144, 73, 197, 128, 86, 250, 60, 192, 97, 128, 24, 1, 86, 104, 64, 0, 0, 1, 1, 8,
			10, 0, 52, 198, 200, 0, 51, 135, 232, 101, 115, 97, 103, 103, 10,
		},
	} {
		m, err := syscall.ParseNetlinkMessage(b)
		if err != syscall.EINVAL {
			t.Errorf("#%d: got %v; want EINVAL", i, err)
		}
		if m != nil {
			t.Errorf("#%d: got %v; want nil", i, m)
		}
	}
}

func TestSyscallNoError(t *testing.T) {
	// On Linux there are currently no syscalls which don't fail and return
	// a value larger than 0xfffffffffffff001 so we could test RawSyscall
	// vs. RawSyscallNoError on 64bit architectures.
	if unsafe.Sizeof(uintptr(0)) != 4 {
		t.Skip("skipping on non-32bit architecture")
	}

	// See https://golang.org/issue/35422
	// On MIPS, Linux returns whether the syscall had an error in a separate
	// register (R7), not using a negative return value as on other
	// architectures.
	if runtime.GOARCH == "mips" || runtime.GOARCH == "mipsle" {
		t.Skipf("skipping on %s", runtime.GOARCH)
	}

	if os.Getuid() != 0 {
		t.Skip("skipping root only test")
	}
	if testing.Short() && testenv.Builder() != "" && os.Getenv("USER") == "swarming" {
		// The Go build system's swarming user is known not to be root.
		// Unfortunately, it sometimes appears as root due the current
		// implementation of a no-network check using 'unshare -n -r'.
		// Since this test does need root to work, we need to skip it.
		t.Skip("skipping root only test on a non-root builder")
	}

	if runtime.GOOS == "android" {
		t.Skip("skipping on rooted android, see issue 27364")
	}

	// Copy the test binary to a location that a non-root user can read/execute
	// after we drop privileges.
	tempDir := t.TempDir()
	os.Chmod(tempDir, 0755)

	tmpBinary := filepath.Join(tempDir, filepath.Base(os.Args[0]))

	src, err := os.Open(os.Args[0])
	if err != nil {
		t.Fatalf("cannot open binary %q, %v", os.Args[0], err)
	}
	defer src.Close()

	dst, err := os.OpenFile(tmpBinary, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		t.Fatalf("cannot create temporary binary %q, %v", tmpBinary, err)
	}
	if _, err := io.Copy(dst, src); err != nil {
		t.Fatalf("failed to copy test binary to %q, %v", tmpBinary, err)
	}
	err = dst.Close()
	if err != nil {
		t.Fatalf("failed to close test binary %q, %v", tmpBinary, err)
	}

	uid := uint32(0xfffffffe)
	err = os.Chown(tmpBinary, int(uid), -1)
	if err != nil {
		t.Fatalf("failed to chown test binary %q, %v", tmpBinary, err)
	}

	err = os.Chmod(tmpBinary, 0755|fs.ModeSetuid)
	if err != nil {
		t.Fatalf("failed to set setuid bit on test binary %q, %v", tmpBinary, err)
	}

	cmd := exec.Command(tmpBinary)
	cmd.Env = append(os.Environ(), "GO_SYSCALL_NOERROR=1")

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to start first child process: %v", err)
	}

	got := strings.TrimSpace(string(out))
	want := strconv.FormatUint(uint64(uid)+1, 10) + " / " +
		strconv.FormatUint(uint64(-uid), 10) + " / " +
		strconv.FormatUint(uint64(uid), 10)
	if got != want {
		if filesystemIsNoSUID(tmpBinary) {
			t.Skip("skipping test when temp dir is mounted nosuid")
		}
		// formatted so the values are aligned for easier comparison
		t.Errorf("expected %s,\ngot      %s", want, got)
	}
}

// filesystemIsNoSUID reports whether the filesystem for the given
// path is mounted nosuid.
func filesystemIsNoSUID(path string) bool {
	var st syscall.Statfs_t
	if syscall.Statfs(path, &st) != nil {
		return false
	}
	return st.Flags&syscall.MS_NOSUID != 0
}

func syscallNoError() {
	// Test that the return value from SYS_GETEUID32 (which cannot fail)
	// doesn't get treated as an error (see https://golang.org/issue/22924)
	euid1, _, e := syscall.RawSyscall(syscall.Sys_GETEUID, 0, 0, 0)
	euid2, _ := syscall.RawSyscallNoError(syscall.Sys_GETEUID, 0, 0, 0)

	fmt.Println(uintptr(euid1), "/", int(e), "/", uintptr(euid2))
	os.Exit(0)
}

// reference uapi/linux/prctl.h
const (
	PR_GET_KEEPCAPS uintptr = 7
	PR_SET_KEEPCAPS         = 8
)

// TestAllThreadsSyscall tests that the go runtime can perform
// syscalls that execute on all OSThreads - with which to support
// POSIX semantics for security state changes.
func TestAllThreadsSyscall(t *testing.T) {
	if _, _, err := syscall.AllThreadsSyscall(syscall.SYS_PRCTL, PR_SET_KEEPCAPS, 0, 0); err == syscall.ENOTSUP {
		t.Skip("AllThreadsSyscall disabled with cgo")
	}

	fns := []struct {
		label string
		fn    func(uintptr) error
	}{
		{
			label: "prctl<3-args>",
			fn: func(v uintptr) error {
				_, _, e := syscall.AllThreadsSyscall(syscall.SYS_PRCTL, PR_SET_KEEPCAPS, v, 0)
				if e != 0 {
					return e
				}
				return nil
			},
		},
		{
			label: "prctl<6-args>",
			fn: func(v uintptr) error {
				_, _, e := syscall.AllThreadsSyscall6(syscall.SYS_PRCTL, PR_SET_KEEPCAPS, v, 0, 0, 0, 0)
				if e != 0 {
					return e
				}
				return nil
			},
		},
	}

	waiter := func(q <-chan uintptr, r chan<- uintptr, once bool) {
		for x := range q {
			runtime.LockOSThread()
			v, _, e := syscall.Syscall(syscall.SYS_PRCTL, PR_GET_KEEPCAPS, 0, 0)
			if e != 0 {
				t.Errorf("tid=%d prctl(PR_GET_KEEPCAPS) failed: %v", syscall.Gettid(), e)
			} else if x != v {
				t.Errorf("tid=%d prctl(PR_GET_KEEPCAPS) mismatch: got=%d want=%d", syscall.Gettid(), v, x)
			}
			r <- v
			if once {
				break
			}
			runtime.UnlockOSThread()
		}
	}

	// launches per fns member.
	const launches = 11
	question := make(chan uintptr)
	response := make(chan uintptr)
	defer close(question)

	routines := 0
	for i, v := range fns {
		for j := 0; j < launches; j++ {
			// Add another goroutine - the closest thing
			// we can do to encourage more OS thread
			// creation - while the test is running.  The
			// actual thread creation may or may not be
			// needed, based on the number of available
			// unlocked OS threads at the time waiter
			// calls runtime.LockOSThread(), but the goal
			// of doing this every time through the loop
			// is to race thread creation with v.fn(want)
			// being executed. Via the once boolean we
			// also encourage one in 5 waiters to return
			// locked after participating in only one
			// question response sequence. This allows the
			// test to race thread destruction too.
			once := routines%5 == 4
			go waiter(question, response, once)

			// Keep a count of how many goroutines are
			// going to participate in the
			// question/response test. This will count up
			// towards 2*launches minus the count of
			// routines that have been invoked with
			// once=true.
			routines++

			// Decide what value we want to set the
			// process-shared KEEPCAPS. Note, there is
			// an explicit repeat of 0 when we change the
			// variant of the syscall being used.
			want := uintptr(j & 1)

			// Invoke the AllThreadsSyscall* variant.
			if err := v.fn(want); err != nil {
				t.Errorf("[%d,%d] %s(PR_SET_KEEPCAPS, %d, ...): %v", i, j, v.label, j&1, err)
			}

			// At this point, we want all launched Go
			// routines to confirm that they see the
			// wanted value for KEEPCAPS.
			for k := 0; k < routines; k++ {
				question <- want
			}

			// At this point, we should have a large
			// number of locked OS threads all wanting to
			// reply.
			for k := 0; k < routines; k++ {
				if got := <-response; got != want {
					t.Errorf("[%d,%d,%d] waiter result got=%d, want=%d", i, j, k, got, want)
				}
			}

			// Provide an explicit opportunity for this Go
			// routine to change Ms.
			runtime.Gosched()

			if once {
				// One waiter routine will have exited.
				routines--
			}

			// Whatever M we are now running on, confirm
			// we see the wanted value too.
			if v, _, e := syscall.Syscall(syscall.SYS_PRCTL, PR_GET_KEEPCAPS, 0, 0); e != 0 {
				t.Errorf("[%d,%d] prctl(PR_GET_KEEPCAPS) failed: %v", i, j, e)
			} else if v != want {
				t.Errorf("[%d,%d] prctl(PR_GET_KEEPCAPS) gave wrong value: got=%v, want=1", i, j, v)
			}
		}
	}
}

// compareStatus is used to confirm the contents of the thread
// specific status files match expectations.
func compareStatus(filter, expect string) error {
	expected := filter + expect
	pid := syscall.Getpid()
	fs, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	if err != nil {
		return fmt.Errorf("unable to find %d tasks: %v", pid, err)
	}
	expectedProc := fmt.Sprintf("Pid:\t%d", pid)
	foundAThread := false
	for _, f := range fs {
		tf := fmt.Sprintf("/proc/%s/status", f.Name())
		d, err := os.ReadFile(tf)
		if err != nil {
			// There are a surprising number of ways this
			// can error out on linux.  We've seen all of
			// the following, so treat any error here as
			// equivalent to the "process is gone":
			//    os.IsNotExist(err),
			//    "... : no such process",
			//    "... : bad file descriptor.
			continue
		}
		lines := strings.Split(string(d), "\n")
		for _, line := range lines {
			// Different kernel vintages pad differently.
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "Pid:\t") {
				// On loaded systems, it is possible
				// for a TID to be reused really
				// quickly. As such, we need to
				// validate that the thread status
				// info we just read is a task of the
				// same process PID as we are
				// currently running, and not a
				// recently terminated thread
				// resurfaced in a different process.
				if line != expectedProc {
					break
				}
				// Fall through in the unlikely case
				// that filter at some point is
				// "Pid:\t".
			}
			if strings.HasPrefix(line, filter) {
				if line == expected {
					foundAThread = true
					break
				}
				if filter == "Groups:" && strings.HasPrefix(line, "Groups:\t") {
					// https://github.com/golang/go/issues/46145
					// Containers don't reliably output this line in sorted order so manually sort and compare that.
					a := strings.Split(line[8:], " ")
					slices.Sort(a)
					got := strings.Join(a, " ")
					if got == expected[8:] {
						foundAThread = true
						break
					}

				}
				return fmt.Errorf("%q got:%q want:%q (bad) [pid=%d file:'%s' %v]\n", tf, line, expected, pid, string(d), expectedProc)
			}
		}
	}
	if !foundAThread {
		return fmt.Errorf("found no thread /proc/<TID>/status files for process %q", expectedProc)
	}
	return nil
}

// killAThread locks the goroutine to an OS thread and exits; this
// causes an OS thread to terminate.
func killAThread(c <-chan struct{}) {
	runtime.LockOSThread()
	<-c
	return
}

// TestSetuidEtc performs tests on all of the wrapped system calls
// that mirror to the 9 glibc syscalls with POSIX semantics. The test
// here is considered authoritative and should compile and run
// CGO_ENABLED=0 or 1. Note, there is an extended copy of this same
// test in ../../misc/cgo/test/issue1435.go which requires
// CGO_ENABLED=1 and launches pthreads from C that run concurrently
// with the Go code of the test - and the test validates that these
// pthreads are also kept in sync with the security state changed with
// the syscalls. Care should be taken to mirror any enhancements to
// this test here in that file too.
func TestSetuidEtc(t *testing.T) {
	if syscall.Getuid() != 0 {
		t.Skip("skipping root only test")
	}
	if syscall.Getgid() != 0 {
		t.Skip("skipping the test when root's gid is not default value 0")
	}
	if testing.Short() && testenv.Builder() != "" && os.Getenv("USER") == "swarming" {
		// The Go build system's swarming user is known not to be root.
		// Unfortunately, it sometimes appears as root due the current
		// implementation of a no-network check using 'unshare -n -r'.
		// Since this test does need root to work, we need to skip it.
		t.Skip("skipping root only test on a non-root builder")
	}
	if _, err := os.Stat("/etc/alpine-release"); err == nil {
		t.Skip("skipping glibc test on alpine - go.dev/issue/19938")
	}
	vs := []struct {
		call           string
		fn             func() error
		filter, expect string
	}{
		{call: "Setegid(1)", fn: func() error { return syscall.Setegid(1) }, filter: "Gid:", expect: "\t0\t1\t0\t1"},
		{call: "Setegid(0)", fn: func() error { return syscall.Setegid(0) }, filter: "Gid:", expect: "\t0\t0\t0\t0"},

		{call: "Seteuid(1)", fn: func() error { return syscall.Seteuid(1) }, filter: "Uid:", expect: "\t0\t1\t0\t1"},
		{call: "Setuid(0)", fn: func() error { return syscall.Setuid(0) }, filter: "Uid:", expect: "\t0\t0\t0\t0"},

		{call: "Setgid(1)", fn: func() error { return syscall.Setgid(1) }, filter: "Gid:", expect: "\t1\t1\t1\t1"},
		{call: "Setgid(0)", fn: func() error { return syscall.Setgid(0) }, filter: "Gid:", expect: "\t0\t0\t0\t0"},

		{call: "Setgroups([]int{0,1,2,3})", fn: func() error { return syscall.Setgroups([]int{0, 1, 2, 3}) }, filter: "Groups:", expect: "\t0 1 2 3"},
		{call: "Setgroups(nil)", fn: func() error { return syscall.Setgroups(nil) }, filter: "Groups:", expect: ""},
		{call: "Setgroups([]int{0})", fn: func() error { return syscall.Setgroups([]int{0}) }, filter: "Groups:", expect: "\t0"},

		{call: "Setregid(101,0)", fn: func() error { return syscall.Setregid(101, 0) }, filter: "Gid:", expect: "\t101\t0\t0\t0"},
		{call: "Setregid(0,102)", fn: func() error { return syscall.Setregid(0, 102) }, filter: "Gid:", expect: "\t0\t102\t102\t102"},
		{call: "Setregid(0,0)", fn: func() error { return syscall.Setregid(0, 0) }, filter: "Gid:", expect: "\t0\t0\t0\t0"},

		{call: "Setreuid(1,0)", fn: func() error { return syscall.Setreuid(1, 0) }, filter: "Uid:", expect: "\t1\t0\t0\t0"},
		{call: "Setreuid(0,2)", fn: func() error { return syscall.Setreuid(0, 2) }, filter: "Uid:", expect: "\t0\t2\t2\t2"},
		{call: "Setreuid(0,0)", fn: func() error { return syscall.Setreuid(0, 0) }, filter: "Uid:", expect: "\t0\t0\t0\t0"},

		{call: "Setresgid(101,0,102)", fn: func() error { return syscall.Setresgid(101, 0, 102) }, filter: "Gid:", expect: "\t101\t0\t102\t0"},
		{call: "Setresgid(0,102,101)", fn: func() error { return syscall.Setresgid(0, 102, 101) }, filter: "Gid:", expect: "\t0\t102\t101\t102"},
		{call: "Setresgid(0,0,0)", fn: func() error { return syscall.Setresgid(0, 0, 0) }, filter: "Gid:", expect: "\t0\t0\t0\t0"},

		{call: "Setresuid(1,0,2)", fn: func() error { return syscall.Setresuid(1, 0, 2) }, filter: "Uid:", expect: "\t1\t0\t2\t0"},
		{call: "Setresuid(0,2,1)", fn: func() error { return syscall.Setresuid(0, 2, 1) }, filter: "Uid:", expect: "\t0\t2\t1\t2"},
		{call: "Setresuid(0,0,0)", fn: func() error { return syscall.Setresuid(0, 0, 0) }, filter: "Uid:", expect: "\t0\t0\t0\t0"},
	}

	for i, v := range vs {
		// Generate some thread churn as we execute the tests.
		c := make(chan struct{})
		go killAThread(c)
		close(c)

		if err := v.fn(); err != nil {
			t.Errorf("[%d] %q failed: %v", i, v.call, err)
			continue
		}
		if err := compareStatus(v.filter, v.expect); err != nil {
			t.Errorf("[%d] %q comparison: %v", i, v.call, err)
		}
	}
}

// TestAllThreadsSyscallError verifies that errors are properly returned when
// the syscall fails on the original thread.
func TestAllThreadsSyscallError(t *testing.T) {
	// SYS_CAPGET takes pointers as the first two arguments. Since we pass
	// 0, we expect to get EFAULT back.
	r1, r2, err := syscall.AllThreadsSyscall(syscall.SYS_CAPGET, 0, 0, 0)
	if err == syscall.ENOTSUP {
		t.Skip("AllThreadsSyscall disabled with cgo")
	}
	if err != syscall.EFAULT {
		t.Errorf("AllThreadSyscall(SYS_CAPGET) got %d, %d, %v, want err %v", r1, r2, err, syscall.EFAULT)
	}
}

// TestAllThreadsSyscallBlockedSyscall confirms that AllThreadsSyscall
// can interrupt threads in long-running system calls. This test will
// deadlock if this doesn't work correctly.
func TestAllThreadsSyscallBlockedSyscall(t *testing.T) {
	if _, _, err := syscall.AllThreadsSyscall(syscall.SYS_PRCTL, PR_SET_KEEPCAPS, 0, 0); err == syscall.ENOTSUP {
		t.Skip("AllThreadsSyscall disabled with cgo")
	}

	rd, wr, err := os.Pipe()
	if err != nil {
		t.Fatalf("unable to obtain a pipe: %v", err)
	}

	// Perform a blocking read on the pipe.
	var wg sync.WaitGroup
	ready := make(chan bool)
	wg.Add(1)
	go func() {
		data := make([]byte, 1)

		// To narrow the window we have to wait for this
		// goroutine to block in read, synchronize just before
		// calling read.
		ready <- true

		// We use syscall.Read directly to avoid the poller.
		// This will return when the write side is closed.
		n, err := syscall.Read(int(rd.Fd()), data)
		if !(n == 0 && err == nil) {
			t.Errorf("expected read to return 0, got %d, %s", n, err)
		}

		// Clean up rd and also ensure rd stays reachable so
		// it doesn't get closed by GC.
		rd.Close()
		wg.Done()
	}()
	<-ready

	// Loop here to give the goroutine more time to block in read.
	// Generally this will trigger on the first iteration anyway.
	pid := syscall.Getpid()
	for i := 0; i < 100; i++ {
		if id, _, e := syscall.AllThreadsSyscall(syscall.SYS_GETPID, 0, 0, 0); e != 0 {
			t.Errorf("[%d] getpid failed: %v", i, e)
		} else if int(id) != pid {
			t.Errorf("[%d] getpid got=%d, want=%d", i, id, pid)
		}
		// Provide an explicit opportunity for this goroutine
		// to change Ms.
		runtime.Gosched()
	}
	wr.Close()
	wg.Wait()
}

func TestPrlimitSelf(t *testing.T) {
	origLimit := syscall.OrigRlimitNofile()
	origRlimitNofile := syscall.GetInternalOrigRlimitNofile()

	if origLimit == nil {
		defer origRlimitNofile.Store(origLimit)
		origRlimitNofile.Store(&syscall.Rlimit{
			Cur: 1024,
			Max: 65536,
		})
	}

	// Get current process's nofile limit
	var lim syscall.Rlimit
	if err := syscall.Prlimit(0, syscall.RLIMIT_NOFILE, nil, &lim); err != nil {
		t.Fatalf("Failed to get the current nofile limit: %v", err)
	}
	// Set current process's nofile limit through prlimit
	if err := syscall.Prlimit(0, syscall.RLIMIT_NOFILE, &lim, nil); err != nil {
		t.Fatalf("Prlimit self failed: %v", err)
	}

	rlimLater := origRlimitNofile.Load()
	if rlimLater != nil {
		t.Fatalf("origRlimitNofile got=%v, want=nil", rlimLater)
	}
}

func TestPrlimitOtherProcess(t *testing.T) {
	origLimit := syscall.OrigRlimitNofile()
	origRlimitNofile := syscall.GetInternalOrigRlimitNofile()

	if origLimit == nil {
		defer origRlimitNofile.Store(origLimit)
		origRlimitNofile.Store(&syscall.Rlimit{
			Cur: 1024,
			Max: 65536,
		})
	}
	rlimOrig := origRlimitNofile.Load()

	// Start a child process firstly,
	// so we can use Prlimit to set it's nofile limit.
	cmd := exec.Command("sleep", "infinity")
	cmd.Start()
	defer func() {
		cmd.Process.Kill()
		cmd.Process.Wait()
	}()

	// Get child process's current nofile limit
	var lim syscall.Rlimit
	if err := syscall.Prlimit(cmd.Process.Pid, syscall.RLIMIT_NOFILE, nil, &lim); err != nil {
		t.Fatalf("Failed to get the current nofile limit: %v", err)
	}
	// Set child process's nofile rlimit through prlimit
	if err := syscall.Prlimit(cmd.Process.Pid, syscall.RLIMIT_NOFILE, &lim, nil); err != nil {
		t.Fatalf("Prlimit(%d) failed: %v", cmd.Process.Pid, err)
	}

	rlimLater := origRlimitNofile.Load()
	if rlimLater != rlimOrig {
		t.Fatalf("origRlimitNofile got=%v, want=%v", rlimLater, rlimOrig)
	}
}

const magicRlimitValue = 42

// TestPrlimitFileLimit tests that we can start a Go program, use
// prlimit to change its NOFILE limit, and have that updated limit be
// seen by children. See issue #66797.
func TestPrlimitFileLimit(t *testing.T) {
	switch os.Getenv("GO_WANT_HELPER_PROCESS") {
	case "prlimit1":
		testPrlimitFileLimitHelper1(t)
		return
	case "prlimit2":
		testPrlimitFileLimitHelper2(t)
		return
	}

	origRlimitNofile := syscall.GetInternalOrigRlimitNofile()
	defer origRlimitNofile.Store(origRlimitNofile.Load())

	// Set our rlimit to magic+1/max.
	// That will also become the rlimit of the child.

	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		t.Fatal(err)
	}
	max := lim.Max

	lim = syscall.Rlimit{
		Cur: magicRlimitValue + 1,
		Max: max,
	}
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	r1, w1, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r1.Close()
	defer w1.Close()

	r2, w2, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Close()
	defer w2.Close()

	var output strings.Builder

	const arg = "-test.run=^TestPrlimitFileLimit$"
	cmd := testenv.CommandContext(t, ctx, exe, arg, "-test.v")
	cmd = testenv.CleanCmdEnv(cmd)
	cmd.Env = append(cmd.Env, "GO_WANT_HELPER_PROCESS=prlimit1")
	cmd.ExtraFiles = []*os.File{r1, w2}
	cmd.Stdout = &output
	cmd.Stderr = &output

	t.Logf("running %s %s", exe, arg)

	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	// Wait for the child to start.
	b := make([]byte, 1)
	if n, err := r2.Read(b); err != nil {
		t.Fatal(err)
	} else if n != 1 {
		t.Fatalf("read %d bytes, want 1", n)
	}

	// Set the child's prlimit.
	lim = syscall.Rlimit{
		Cur: magicRlimitValue,
		Max: max,
	}
	if err := syscall.Prlimit(cmd.Process.Pid, syscall.RLIMIT_NOFILE, &lim, nil); err != nil {
		t.Fatalf("Prlimit failed: %v", err)
	}

	// Tell the child to continue.
	if n, err := w1.Write(b); err != nil {
		t.Fatal(err)
	} else if n != 1 {
		t.Fatalf("wrote %d bytes, want 1", n)
	}

	err = cmd.Wait()
	if output.Len() > 0 {
		t.Logf("%s", output.String())
	}

	if err != nil {
		t.Errorf("child failed: %v", err)
	}
}

// testPrlimitFileLimitHelper1 is run by TestPrlimitFileLimit.
func testPrlimitFileLimitHelper1(t *testing.T) {
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		t.Fatal(err)
	}
	t.Logf("helper1 rlimit is %v", lim)
	t.Logf("helper1 cached rlimit is %v", syscall.OrigRlimitNofile())

	// Tell the parent that we are ready.
	b := []byte{0}
	if n, err := syscall.Write(4, b); err != nil {
		t.Fatal(err)
	} else if n != 1 {
		t.Fatalf("wrote %d bytes, want 1", n)
	}

	// Wait for the parent to tell us that prlimit was used.
	if n, err := syscall.Read(3, b); err != nil {
		t.Fatal(err)
	} else if n != 1 {
		t.Fatalf("read %d bytes, want 1", n)
	}

	if err := syscall.Close(3); err != nil {
		t.Errorf("Close(3): %v", err)
	}
	if err := syscall.Close(4); err != nil {
		t.Errorf("Close(4): %v", err)
	}

	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		t.Fatal(err)
	}
	t.Logf("after prlimit helper1 rlimit is %v", lim)
	t.Logf("after prlimit helper1 cached rlimit is %v", syscall.OrigRlimitNofile())

	// Start the grandchild, which should see the rlimit
	// set by the prlimit called by the parent.

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	const arg = "-test.run=^TestPrlimitFileLimit$"
	cmd := testenv.CommandContext(t, ctx, exe, arg, "-test.v")
	cmd = testenv.CleanCmdEnv(cmd)
	cmd.Env = append(cmd.Env, "GO_WANT_HELPER_PROCESS=prlimit2")
	t.Logf("running %s %s", exe, arg)
	out, err := cmd.CombinedOutput()
	if len(out) > 0 {
		t.Logf("%s", out)
	}
	if err != nil {
		t.Errorf("grandchild failed: %v", err)
	} else {
		fmt.Println("OK")
	}
}

// testPrlimitFileLimitHelper2 is run by testPrlimitFileLimit1.
func testPrlimitFileLimitHelper2(t *testing.T) {
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		t.Fatal(err)
	}

	t.Logf("helper2 rlimit is %v", lim)
	cached := syscall.OrigRlimitNofile()
	t.Logf("helper2 cached rlimit is %v", cached)

	// The value return by Getrlimit will have been adjusted.
	// We should have cached the value set by prlimit called by the parent.

	if cached == nil {
		t.Fatal("no cached rlimit")
	} else if cached.Cur != magicRlimitValue {
		t.Fatalf("cached rlimit is %d, want %d", cached.Cur, magicRlimitValue)
	}

	fmt.Println("OK")
}

"""



```