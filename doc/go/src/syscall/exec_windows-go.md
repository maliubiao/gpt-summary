Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Understanding of the Request:**

The request asks for the functionality of a specific Go file (`exec_windows.go`), what Go feature it implements, examples of its usage, handling of command-line arguments, and potential pitfalls. The language is Chinese, so the answer should also be in Chinese.

**2. High-Level Analysis of the Code:**

A quick skim reveals keywords and function names related to process creation and manipulation on Windows: `CreateProcess`, `CreateProcessAsUser`, `STARTUPINFOEXW`, `ProcAttr`, `SysProcAttr`, `EscapeArg`, `makeCmdLine`, `createEnvBlock`, etc. This strongly suggests the file deals with the `os/exec` package's underlying implementation on Windows.

**3. Function-by-Function Breakdown and Purpose Identification:**

* **`ForkLock sync.RWMutex`:**  This is a mutex, but the comment says it's not used on Windows. This is a crucial piece of information - it suggests this code is specific to Windows and differs from Unix-like systems.

* **`EscapeArg(s string) string`:** The comment and the code clearly explain its purpose: escaping special characters in command-line arguments for Windows according to Microsoft's guidelines. This is vital for correctly passing arguments to child processes.

* **`appendEscapeArg(b []byte, s string) []byte`:**  A helper function for `EscapeArg`.

* **`makeCmdLine(args []string) string`:**  This function takes a slice of arguments and uses `appendEscapeArg` to create a single command-line string suitable for `CreateProcess`. This directly relates to the `os/exec` package's argument handling.

* **`createEnvBlock(envv []string) ([]uint16, error)`:**  The comment explains its role: converting Go's string-based environment variables into the format Windows `CreateProcess` expects (null-terminated UTF-16 strings). This is another essential piece for process creation.

* **`CloseOnExec(fd Handle)`:** This function sets the `HANDLE_FLAG_INHERIT` flag to 0, preventing the specified file descriptor from being inherited by child processes. This is a common requirement for security and proper resource management.

* **`SetNonblock(fd Handle, nonblocking bool) error`:**  The code simply returns `nil`. This suggests that setting non-blocking mode for file descriptors might be handled differently or not directly in this specific part of the Windows syscall implementation.

* **`FullPath(name string) (path string, err error)`:** This retrieves the full, canonical path of a file. This is often needed to resolve relative paths before starting a process.

* **`isSlash(c uint8) bool`:** A simple helper to check for forward or backslashes.

* **`normalizeDir(dir string) (name string, err error)`:**  This appears to normalize a directory path, potentially resolving it to an absolute path and handling special Windows path formats.

* **`volToUpper(ch int) int`:** Converts a lowercase drive letter to uppercase.

* **`joinExeDirAndFName(dir, p string) (name string, err error)`:**  This is a crucial function for resolving the path of the executable (`argv0`) based on the working directory (`dir`). It handles different path types (absolute, relative, with drive letters). This is a key part of how `os/exec` figures out *what* to execute.

* **`type ProcAttr struct` and `type SysProcAttr struct`:** These structures define the attributes that can be set when starting a new process. `ProcAttr` is the user-facing structure in `os/exec`, and `SysProcAttr` is platform-specific and contains Windows-specific options.

* **`StartProcess(argv0 string, argv []string, attr *ProcAttr) (pid int, handle uintptr, err error)`:** This is the core function. It takes the executable path, arguments, and attributes, and uses the underlying Windows API (`CreateProcess` or `CreateProcessAsUser`) to create a new process. This is the direct link to the operating system. The code carefully handles argument escaping, environment variables, standard file descriptors, and other process attributes.

* **`Exec(argv0 string, argv []string, envv []string) error`:** This function simply returns `EWINDOWS`. This strongly implies that the `Exec` system call (which replaces the current process) is not directly implemented in this way on Windows. Instead, `StartProcess` is likely used, possibly followed by terminating the current process.

**4. Identifying the Go Feature:**

Based on the function names and the overall structure, it's clear that this file is part of the implementation of the `os/exec` package on Windows. Specifically, it's responsible for the low-level details of creating new processes.

**5. Creating Go Code Examples:**

Now, based on the identified functions, create examples demonstrating their use. Focus on `EscapeArg`, `makeCmdLine`, and `StartProcess` (as it's the most central). For `StartProcess`, demonstrate setting different attributes (working directory, environment variables, hiding the window).

**6. Inferring Command-Line Argument Handling:**

The code explicitly uses `EscapeArg` and `makeCmdLine`. Explain how these functions work to escape and combine arguments. Highlight that `os/exec` handles this automatically, but understanding these functions is crucial for grasping how arguments are passed to Windows processes.

**7. Identifying Potential Pitfalls:**

Think about common mistakes when using `os/exec` on Windows. A major one is incorrect handling of paths and escaping of special characters. Illustrate this with examples of commands that might fail if not escaped correctly. Also consider the differences between how Windows and Unix-like systems handle arguments.

**8. Structuring the Answer in Chinese:**

Translate the findings into clear and concise Chinese. Use appropriate terminology and formatting to make the answer easy to understand. Ensure the code examples are also in Go and the explanations are accurate.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Maybe this file handles signals as well?  *Correction:*  A closer look reveals no signal-related code. Signals are likely handled in a different part of the `syscall` package or even higher up in the `os` package.

* **Initial thought:**  The `Exec` function seems strange. *Correction:*  Realize that `Exec` has a specific meaning (replacing the current process) and that Windows handles this differently. The `EWINDOWS` return makes sense in this context.

* **Ensuring clarity of examples:**  Make sure the input and expected output for `EscapeArg` are clear. For `StartProcess`, provide complete, runnable examples.

By following these steps, we can systematically analyze the code and provide a comprehensive and accurate answer to the request. The key is to break down the code into smaller pieces, understand the purpose of each piece, and then connect those pieces back to the overall functionality and the related Go features.
这段代码是 Go 语言 `syscall` 包中用于在 Windows 操作系统上执行外部命令的一部分。它提供了创建、启动和管理新进程的基础功能。

以下是其主要功能点的详细说明：

**1. 命令行参数转义 (`EscapeArg`, `appendEscapeArg`)：**

* **功能:** 这两个函数负责根据 Windows 的命令行参数转义规则（详细见 MSDN 文档：[https://msdn.microsoft.com/en-us/library/ms880421](https://msdn.microsoft.com/en-us/library/ms880421)）对命令行参数进行转义。这确保了包含特殊字符（如空格、制表符、双引号、反斜杠）的参数能被正确传递给新进程。
* **规则:**
    * 空字符串转义为 `""`。
    * 反斜杠 (`\`) 只有紧跟双引号 (`"`) 时才会被加倍（`\\"`）。
    * 双引号 (`"`) 会被反斜杠转义 (`\"`)。
    * 如果字符串中包含空格或制表符，则整个字符串会被双引号包裹。
* **Go 代码示例:**

```go
package main

import (
	"fmt"
	"syscall"
)

func main() {
	args := []string{"command", "argument with space", "argument\"with\"quotes", `argument\with\backslashes`}
	for _, arg := range args {
		escapedArg := syscall.EscapeArg(arg)
		fmt.Printf("Original: %q, Escaped: %q\n", arg, escapedArg)
	}

	emptyArg := ""
	escapedEmptyArg := syscall.EscapeArg(emptyArg)
	fmt.Printf("Original: %q, Escaped: %q\n", emptyArg, escapedEmptyArg)
}
```

* **假设输入与输出:**

```
Original: "command", Escaped: "command"
Original: "argument with space", Escaped: "\"argument with space\""
Original: "argument\"with\"quotes", Escaped: "argument\\\"with\\\"quotes"
Original: "argument\with\backslashes", Escaped: "argument\\with\\backslashes"
Original: "", Escaped: "\"\""
```

**2. 构建命令行字符串 (`makeCmdLine`)：**

* **功能:** 该函数接收一个字符串切片作为参数，这些字符串代表要执行命令的各个部分（命令名和参数）。它会遍历这些参数，使用 `appendEscapeArg` 对每个参数进行转义，然后用空格将它们连接成一个单一的命令行字符串，这个字符串可以直接传递给 Windows 的 `CreateProcess` 函数。

* **Go 代码示例:**

```go
package main

import (
	"fmt"
	"syscall"
)

func main() {
	args := []string{"cmd", "/c", "echo", "Hello World!"}
	cmdLine := syscall.MakeCmdLine(args)
	fmt.Println(cmdLine)
}
```

* **假设输出:**  `cmd /c echo "Hello World!"`

**3. 创建环境变量块 (`createEnvBlock`)：**

* **功能:**  Windows 的 `CreateProcess` 函数期望环境变量以一种特定的格式传递：一个以 NULL 结尾的字符串序列，最后以两个 NULL 结尾（或四个 NULL 字节，因为使用 UTF-16）。`createEnvBlock` 函数将 Go 中字符串切片形式的环境变量转换为这种格式。
* **错误处理:** 如果任何一个环境变量字符串中包含 NULL 字符，该函数会返回 `EINVAL` 错误。
* **Go 代码示例:**

```go
package main

import (
	"fmt"
	"syscall"
)

func main() {
	env := []string{"MY_VAR=my_value", "ANOTHER_VAR=another_value"}
	envBlock, err := syscall.CreateEnvBlock(env)
	if err != nil {
		fmt.Println("Error creating environment block:", err)
		return
	}
	fmt.Printf("Environment block (length: %d): %+v\n", len(envBlock), envBlock)
	// 注意：直接打印 uint16 切片可能不是你期望的字符串形式，这里仅用于展示数据结构。
}
```

* **假设输出 (可能因系统编码而异，这里仅展示结构):**  `Environment block (length: 34): [77 0 89 0 ... 117 0 101 0 0 0]` (实际上是 UTF-16 编码的字符串)

**4. 关闭执行时继承 (`CloseOnExec`)：**

* **功能:**  此函数用于设置文件句柄的属性，使其在子进程执行时不会被继承。在 Windows 中，通过 `SetHandleInformation` 函数并设置 `HANDLE_FLAG_INHERIT` 标志为 0 来实现。
* **适用场景:**  当你希望父进程打开的文件或管道不被子进程意外访问时使用。

**5. 设置非阻塞模式 (`SetNonblock`)：**

* **功能:**  在提供的代码中，`SetNonblock` 函数只是简单地返回 `nil`。这表明在 Windows 上，设置文件句柄为非阻塞模式可能不在这个特定的 `exec_windows.go` 文件中处理，或者可能有其他机制来实现。

**6. 获取完整路径 (`FullPath`)：**

* **功能:**  `FullPath` 函数用于获取指定文件的完整路径。它使用 Windows API 函数 `GetFullPathName` 来实现。这对于解析相对路径非常有用。

**7. 规范化目录 (`normalizeDir`)：**

* **功能:**  该函数用于规范化给定的目录路径。它首先使用 `FullPath` 获取完整路径，并检查路径是否是 `\\server\share\path` 这种 UNC 路径，如果是则返回错误。

**8. 连接执行目录和文件名 (`joinExeDirAndFName`)：**

* **功能:**  这个函数用于将执行目录和文件名连接成一个完整的可执行文件路径。它会处理各种情况，包括绝对路径、相对路径、带有驱动器号的路径等。这在 `StartProcess` 中用于确定要执行的程序的位置。

**9. 进程属性结构 (`ProcAttr`, `SysProcAttr`)：**

* **功能:**  这两个结构体定义了创建新进程时可以设置的各种属性。
    * `ProcAttr` 是更通用的属性结构，包含了工作目录、环境变量和文件描述符等。
    * `SysProcAttr` 包含了特定于 Windows 的进程属性，例如是否隐藏窗口 (`HideWindow`)、自定义命令行 (`CmdLine`)、创建标志 (`CreationFlags`)、用户令牌 (`Token`) 等。

**10. 启动进程 (`StartProcess`)：**

* **功能:**  这是核心函数，用于在 Windows 上启动一个新的进程。它接收可执行文件的路径 (`argv0`)、命令行参数 (`argv`) 和进程属性 (`attr`) 作为输入。
* **主要步骤:**
    * 检查参数有效性。
    * 处理工作目录，如果指定了工作目录，则将 `argv0` 转换为相对于该目录的绝对路径。
    * 构建命令行字符串，如果 `SysProcAttr.CmdLine` 为空，则使用 `makeCmdLine` 函数根据 `argv` 构建。
    * 创建环境变量块。
    * 处理文件描述符的继承。
    * 设置 `STARTUPINFOEXW` 结构体，包含窗口显示方式、标准句柄等信息。
    * 如果指定了父进程，则设置父进程属性。
    * 调用 `CreateProcess` 或 `CreateProcessAsUser` Windows API 函数来创建进程。
* **命令行参数处理:**  `StartProcess` 函数会检查 `attr.Sys.CmdLine` 是否为空。如果为空，它会使用 `makeCmdLine(argv)` 来构建命令行。这意味着传递给 `StartProcess` 的 `argv` 切片会被自动转义并组合成一个单一的命令行字符串。

**11. 执行程序 (`Exec`)：**

* **功能:**  在提供的代码中，`Exec` 函数直接返回 `EWINDOWS` 错误。这表明在 Windows 上，Go 的 `syscall` 包并没有提供一个与 Unix 系统中 `execve` 类似的直接替换当前进程的 `Exec` 函数。在 Windows 上启动新进程通常是通过 `CreateProcess` 实现的，它会创建一个新的进程。如果要达到类似 `execve` 的效果，可能需要在新进程启动后结束当前进程。

**使用者易犯错的点 (与命令行参数处理相关):**

* **手动拼接命令行字符串:**  使用者可能会尝试自己拼接命令行字符串，而没有使用 `EscapeArg` 或依赖 `StartProcess` 自动处理，这可能导致包含特殊字符的参数无法正确传递。

    ```go
    // 错误示例
    package main

    import (
        "fmt"
        "os/exec"
    )

    func main() {
        command := "myprogram.exe argument with space \"quoted argument\""
        cmd := exec.Command("cmd", "/c", command) // 错误地将整个字符串作为单个参数传递
        output, err := cmd.CombinedOutput()
        if err != nil {
            fmt.Println("Error:", err)
        }
        fmt.Println(string(output))
    }
    ```

    **应该使用 `exec.Command` 并将参数作为单独的字符串传递，`os/exec` 会在底层调用 `syscall.StartProcess` 并正确处理转义:**

    ```go
    // 正确示例
    package main

    import (
        "fmt"
        "os/exec"
    )

    func main() {
        cmd := exec.Command("myprogram.exe", "argument with space", `"quoted argument"`)
        output, err := cmd.CombinedOutput()
        if err != nil {
            fmt.Println("Error:", err)
        }
        fmt.Println(string(output))
    }
    ```

* **不理解 Windows 的转义规则:**  即使使用 `exec.Command`，了解 Windows 的转义规则也有助于理解为什么某些参数需要用引号包裹，以及反斜杠在某些情况下的特殊含义。

总而言之，`go/src/syscall/exec_windows.go` 这部分代码是 Go 语言在 Windows 平台上实现进程创建和管理的核心，它封装了底层的 Windows API 调用，并提供了方便的函数来处理命令行参数、环境变量和进程属性。使用者通常不需要直接调用这些 `syscall` 包的函数，而是使用更高级别的 `os/exec` 包，该包会在底层使用这些函数来执行外部命令。理解这些底层实现有助于更好地理解 `os/exec` 的行为以及在 Windows 上执行命令的机制。

Prompt: 
```
这是路径为go/src/syscall/exec_windows.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Fork, exec, wait, etc.

package syscall

import (
	"internal/bytealg"
	"runtime"
	"sync"
	"unicode/utf16"
	"unsafe"
)

// ForkLock is not used on Windows.
var ForkLock sync.RWMutex

// EscapeArg rewrites command line argument s as prescribed
// in https://msdn.microsoft.com/en-us/library/ms880421.
// This function returns "" (2 double quotes) if s is empty.
// Alternatively, these transformations are done:
//   - every back slash (\) is doubled, but only if immediately
//     followed by double quote (");
//   - every double quote (") is escaped by back slash (\);
//   - finally, s is wrapped with double quotes (arg -> "arg"),
//     but only if there is space or tab inside s.
func EscapeArg(s string) string {
	if len(s) == 0 {
		return `""`
	}
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"', '\\', ' ', '\t':
			// Some escaping required.
			b := make([]byte, 0, len(s)+2)
			b = appendEscapeArg(b, s)
			return string(b)
		}
	}
	return s
}

// appendEscapeArg escapes the string s, as per escapeArg,
// appends the result to b, and returns the updated slice.
func appendEscapeArg(b []byte, s string) []byte {
	if len(s) == 0 {
		return append(b, `""`...)
	}

	needsBackslash := false
	hasSpace := false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"', '\\':
			needsBackslash = true
		case ' ', '\t':
			hasSpace = true
		}
	}

	if !needsBackslash && !hasSpace {
		// No special handling required; normal case.
		return append(b, s...)
	}
	if !needsBackslash {
		// hasSpace is true, so we need to quote the string.
		b = append(b, '"')
		b = append(b, s...)
		return append(b, '"')
	}

	if hasSpace {
		b = append(b, '"')
	}
	slashes := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		default:
			slashes = 0
		case '\\':
			slashes++
		case '"':
			for ; slashes > 0; slashes-- {
				b = append(b, '\\')
			}
			b = append(b, '\\')
		}
		b = append(b, c)
	}
	if hasSpace {
		for ; slashes > 0; slashes-- {
			b = append(b, '\\')
		}
		b = append(b, '"')
	}

	return b
}

// makeCmdLine builds a command line out of args by escaping "special"
// characters and joining the arguments with spaces.
func makeCmdLine(args []string) string {
	var b []byte
	for _, v := range args {
		if len(b) > 0 {
			b = append(b, ' ')
		}
		b = appendEscapeArg(b, v)
	}
	return string(b)
}

// createEnvBlock converts an array of environment strings into
// the representation required by CreateProcess: a sequence of NUL
// terminated strings followed by a nil.
// Last bytes are two UCS-2 NULs, or four NUL bytes.
// If any string contains a NUL, it returns (nil, EINVAL).
func createEnvBlock(envv []string) ([]uint16, error) {
	if len(envv) == 0 {
		return utf16.Encode([]rune("\x00\x00")), nil
	}
	var length int
	for _, s := range envv {
		if bytealg.IndexByteString(s, 0) != -1 {
			return nil, EINVAL
		}
		length += len(s) + 1
	}
	length += 1

	b := make([]uint16, 0, length)
	for _, s := range envv {
		for _, c := range s {
			b = utf16.AppendRune(b, c)
		}
		b = utf16.AppendRune(b, 0)
	}
	b = utf16.AppendRune(b, 0)
	return b, nil
}

func CloseOnExec(fd Handle) {
	SetHandleInformation(Handle(fd), HANDLE_FLAG_INHERIT, 0)
}

func SetNonblock(fd Handle, nonblocking bool) (err error) {
	return nil
}

// FullPath retrieves the full path of the specified file.
func FullPath(name string) (path string, err error) {
	p, err := UTF16PtrFromString(name)
	if err != nil {
		return "", err
	}
	n := uint32(100)
	for {
		buf := make([]uint16, n)
		n, err = GetFullPathName(p, uint32(len(buf)), &buf[0], nil)
		if err != nil {
			return "", err
		}
		if n <= uint32(len(buf)) {
			return UTF16ToString(buf[:n]), nil
		}
	}
}

func isSlash(c uint8) bool {
	return c == '\\' || c == '/'
}

func normalizeDir(dir string) (name string, err error) {
	ndir, err := FullPath(dir)
	if err != nil {
		return "", err
	}
	if len(ndir) > 2 && isSlash(ndir[0]) && isSlash(ndir[1]) {
		// dir cannot have \\server\share\path form
		return "", EINVAL
	}
	return ndir, nil
}

func volToUpper(ch int) int {
	if 'a' <= ch && ch <= 'z' {
		ch += 'A' - 'a'
	}
	return ch
}

func joinExeDirAndFName(dir, p string) (name string, err error) {
	if len(p) == 0 {
		return "", EINVAL
	}
	if len(p) > 2 && isSlash(p[0]) && isSlash(p[1]) {
		// \\server\share\path form
		return p, nil
	}
	if len(p) > 1 && p[1] == ':' {
		// has drive letter
		if len(p) == 2 {
			return "", EINVAL
		}
		if isSlash(p[2]) {
			return p, nil
		} else {
			d, err := normalizeDir(dir)
			if err != nil {
				return "", err
			}
			if volToUpper(int(p[0])) == volToUpper(int(d[0])) {
				return FullPath(d + "\\" + p[2:])
			} else {
				return FullPath(p)
			}
		}
	} else {
		// no drive letter
		d, err := normalizeDir(dir)
		if err != nil {
			return "", err
		}
		if isSlash(p[0]) {
			return FullPath(d[:2] + p)
		} else {
			return FullPath(d + "\\" + p)
		}
	}
}

type ProcAttr struct {
	Dir   string
	Env   []string
	Files []uintptr
	Sys   *SysProcAttr
}

type SysProcAttr struct {
	HideWindow                 bool
	CmdLine                    string // used if non-empty, else the windows command line is built by escaping the arguments passed to StartProcess
	CreationFlags              uint32
	Token                      Token               // if set, runs new process in the security context represented by the token
	ProcessAttributes          *SecurityAttributes // if set, applies these security attributes as the descriptor for the new process
	ThreadAttributes           *SecurityAttributes // if set, applies these security attributes as the descriptor for the main thread of the new process
	NoInheritHandles           bool                // if set, no handles are inherited by the new process, not even the standard handles, contained in ProcAttr.Files, nor the ones contained in AdditionalInheritedHandles
	AdditionalInheritedHandles []Handle            // a list of additional handles, already marked as inheritable, that will be inherited by the new process
	ParentProcess              Handle              // if non-zero, the new process regards the process given by this handle as its parent process, and AdditionalInheritedHandles, if set, should exist in this parent process
}

var zeroProcAttr ProcAttr
var zeroSysProcAttr SysProcAttr

func StartProcess(argv0 string, argv []string, attr *ProcAttr) (pid int, handle uintptr, err error) {
	if len(argv0) == 0 {
		return 0, 0, EWINDOWS
	}
	if attr == nil {
		attr = &zeroProcAttr
	}
	sys := attr.Sys
	if sys == nil {
		sys = &zeroSysProcAttr
	}

	if len(attr.Files) > 3 {
		return 0, 0, EWINDOWS
	}
	if len(attr.Files) < 3 {
		return 0, 0, EINVAL
	}

	if len(attr.Dir) != 0 {
		// StartProcess assumes that argv0 is relative to attr.Dir,
		// because it implies Chdir(attr.Dir) before executing argv0.
		// Windows CreateProcess assumes the opposite: it looks for
		// argv0 relative to the current directory, and, only once the new
		// process is started, it does Chdir(attr.Dir). We are adjusting
		// for that difference here by making argv0 absolute.
		var err error
		argv0, err = joinExeDirAndFName(attr.Dir, argv0)
		if err != nil {
			return 0, 0, err
		}
	}
	argv0p, err := UTF16PtrFromString(argv0)
	if err != nil {
		return 0, 0, err
	}

	var cmdline string
	// Windows CreateProcess takes the command line as a single string:
	// use attr.CmdLine if set, else build the command line by escaping
	// and joining each argument with spaces
	if sys.CmdLine != "" {
		cmdline = sys.CmdLine
	} else {
		cmdline = makeCmdLine(argv)
	}

	var argvp *uint16
	if len(cmdline) != 0 {
		argvp, err = UTF16PtrFromString(cmdline)
		if err != nil {
			return 0, 0, err
		}
	}

	var dirp *uint16
	if len(attr.Dir) != 0 {
		dirp, err = UTF16PtrFromString(attr.Dir)
		if err != nil {
			return 0, 0, err
		}
	}

	p, _ := GetCurrentProcess()
	parentProcess := p
	if sys.ParentProcess != 0 {
		parentProcess = sys.ParentProcess
	}
	fd := make([]Handle, len(attr.Files))
	for i := range attr.Files {
		if attr.Files[i] > 0 {
			err := DuplicateHandle(p, Handle(attr.Files[i]), parentProcess, &fd[i], 0, true, DUPLICATE_SAME_ACCESS)
			if err != nil {
				return 0, 0, err
			}
			defer DuplicateHandle(parentProcess, fd[i], 0, nil, 0, false, DUPLICATE_CLOSE_SOURCE)
		}
	}
	si := new(_STARTUPINFOEXW)
	si.ProcThreadAttributeList, err = newProcThreadAttributeList(2)
	if err != nil {
		return 0, 0, err
	}
	defer deleteProcThreadAttributeList(si.ProcThreadAttributeList)
	si.Cb = uint32(unsafe.Sizeof(*si))
	si.Flags = STARTF_USESTDHANDLES
	if sys.HideWindow {
		si.Flags |= STARTF_USESHOWWINDOW
		si.ShowWindow = SW_HIDE
	}
	if sys.ParentProcess != 0 {
		err = updateProcThreadAttribute(si.ProcThreadAttributeList, 0, _PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, unsafe.Pointer(&sys.ParentProcess), unsafe.Sizeof(sys.ParentProcess), nil, nil)
		if err != nil {
			return 0, 0, err
		}
	}
	si.StdInput = fd[0]
	si.StdOutput = fd[1]
	si.StdErr = fd[2]

	fd = append(fd, sys.AdditionalInheritedHandles...)

	// The presence of a NULL handle in the list is enough to cause PROC_THREAD_ATTRIBUTE_HANDLE_LIST
	// to treat the entire list as empty, so remove NULL handles.
	j := 0
	for i := range fd {
		if fd[i] != 0 {
			fd[j] = fd[i]
			j++
		}
	}
	fd = fd[:j]

	willInheritHandles := len(fd) > 0 && !sys.NoInheritHandles

	// Do not accidentally inherit more than these handles.
	if willInheritHandles {
		err = updateProcThreadAttribute(si.ProcThreadAttributeList, 0, _PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&fd[0]), uintptr(len(fd))*unsafe.Sizeof(fd[0]), nil, nil)
		if err != nil {
			return 0, 0, err
		}
	}

	envBlock, err := createEnvBlock(attr.Env)
	if err != nil {
		return 0, 0, err
	}

	pi := new(ProcessInformation)
	flags := sys.CreationFlags | CREATE_UNICODE_ENVIRONMENT | _EXTENDED_STARTUPINFO_PRESENT
	if sys.Token != 0 {
		err = CreateProcessAsUser(sys.Token, argv0p, argvp, sys.ProcessAttributes, sys.ThreadAttributes, willInheritHandles, flags, &envBlock[0], dirp, &si.StartupInfo, pi)
	} else {
		err = CreateProcess(argv0p, argvp, sys.ProcessAttributes, sys.ThreadAttributes, willInheritHandles, flags, &envBlock[0], dirp, &si.StartupInfo, pi)
	}
	if err != nil {
		return 0, 0, err
	}
	defer CloseHandle(Handle(pi.Thread))
	runtime.KeepAlive(fd)
	runtime.KeepAlive(sys)

	return int(pi.ProcessId), uintptr(pi.Process), nil
}

func Exec(argv0 string, argv []string, envv []string) (err error) {
	return EWINDOWS
}

"""



```