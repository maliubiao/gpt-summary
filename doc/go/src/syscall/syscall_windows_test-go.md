Response:
我的思考过程如下：

1. **理解目标：** 目标是分析一个 Go 语言测试文件 `syscall_windows_test.go`，并解释其功能，最好能推断出它测试的 Go 语言特性。

2. **代码结构观察：** 我首先浏览代码，注意到几个关键点：
    * `package syscall_test`:  这是一个测试包，说明它在测试 `syscall` 包的功能。
    * `import` 语句：引入了 `fmt`, `internal/testenv`, `os`, `os/exec`, `path/filepath`, `strings`, `syscall`, `testing` 这些包。  这暗示了测试可能涉及文件操作、系统调用、进程执行、字符串处理等。
    * 大量的 `func Test...` 函数：这表明这是一个单元测试文件，每个 `Test` 开头的函数都在测试特定的功能。

3. **逐个分析测试函数：**  我开始逐个分析每个 `Test` 函数的功能：
    * `TestOpen`:  测试 `syscall.Open` 函数，涉及到打开文件和目录的不同模式 (`O_RDONLY`, `O_CREAT`, `O_TRUNC`, `O_APPEND` 等)，以及期望的错误 (`syscall.ERROR_ACCESS_DENIED`, `syscall.EISDIR`)。这显然是在测试 Windows 下文件打开操作的各种情况。
    * `TestComputerName`: 测试 `syscall.ComputerName` 函数，验证能否获取计算机名。
    * `TestWin32finddata`:  测试 `syscall.FindFirstFile` 和 `syscall.FindClose` 函数，以及 `syscall.Win32finddata` 结构体。  看起来是在测试 Windows 下查找文件的功能，并检查返回的数据结构是否正确。其中还包含了一个内存损坏检测的技巧。
    * `ExampleLoadLibrary`:  这是一个示例函数，演示如何使用 `syscall.LoadLibrary` 加载 DLL，以及 `syscall.GetProcAddress` 获取函数地址，然后通过 `syscall.Syscall` 调用。这直接展示了如何调用 Windows API。
    * `TestTOKEN_ALL_ACCESS`:  简单的常量测试，检查 `syscall.TOKEN_ALL_ACCESS` 的值是否正确。
    * `TestStdioAreInheritable`:  这是一个比较复杂的集成测试，涉及到编译 Go DLL 和 C 可执行文件，并验证标准输入/输出是否可以被子进程继承。它使用了 `os/exec` 包来执行编译和运行命令，并使用了 `internal/testenv` 中的辅助函数。
    * `TestGetwd_DoesNotPanicWhenPathIsLong`:  这是一个回归测试，用于确保在当前工作目录路径很长时 `syscall.Getwd` 不会崩溃。它涉及到创建很深的目录结构。
    * `TestGetStartupInfo`:  测试 `syscall.GetStartupInfo` 函数，获取进程启动信息。
    * `TestSyscallAllocations`:  测试 `syscall.SyscallN` 和 `syscall.Syscall` 函数的内存分配情况，确保没有不必要的内存逃逸。这涉及到性能优化方面的测试。
    * `FuzzUTF16FromString`:  使用模糊测试来测试 `syscall.UTF16FromString` 函数，该函数将 Go 字符串转换为 UTF-16 编码。它提供了各种不同的输入，包括 ASCII、非 ASCII、无效字节等。

4. **总结功能：** 基于对每个测试函数的分析，我总结出该文件的主要功能是测试 Go 语言 `syscall` 包在 Windows 平台上的实现。  具体包括：文件操作、系统信息获取、动态库加载、进程启动信息、内存分配以及字符串转换等。

5. **推断 Go 语言功能：** 我开始思考这些测试对应的 Go 语言特性。 显然，`syscall` 包是 Go 语言与操作系统底层交互的关键部分。 这个测试文件侧重于 Windows 平台的系统调用，例如文件操作 (open, close)、进程管理 (load library, get proc address, startup info)、以及一些特定的 Windows API 交互 (find first file, computer name)。

6. **提供代码示例：**  对于 `syscall.Open` 和 `syscall.LoadLibrary`/`GetProcAddress`/`Syscall` 提供了代码示例，因为这些功能比较典型，而且示例代码可以直接从测试文件中提取并稍作修改。

7. **推理代码及假设：** 对于 `TestWin32finddata`，我解释了它是在测试 `FindFirstFile`，并指出了内存损坏检测的技巧。我假设用户想要查找的文件确实存在。

8. **命令行参数处理：**  `TestStdioAreInheritable` 中涉及到 `go build` 和 `gcc` 命令，我解释了这些命令及其参数的作用。

9. **易犯错的点：** 我主要关注了 `syscall.Open` 的错误处理，强调了需要检查返回值以确定操作是否成功。

10. **语言和格式：**  我使用中文进行回答，并注意了排版和清晰度。

通过以上步骤，我对代码进行了由表及里的分析，最终得到了最终的答案。  关键在于理解测试代码的目的，以及它所覆盖的 Go 语言功能。

这个 Go 语言源文件 `go/src/syscall/syscall_windows_test.go` 是 `syscall` 包在 Windows 操作系统上的单元测试文件。它的主要功能是：

1. **测试 `syscall` 包中与 Windows 系统调用相关的函数是否正常工作。** 这包括文件操作、进程管理、系统信息获取等方面的功能。

下面我将根据代码中的测试函数，逐一列举其测试的功能，并尝试推理出它所测试的 Go 语言功能，并提供代码示例。

**1. `TestOpen` 函数：测试 `syscall.Open` 函数**

* **功能：** 测试在 Windows 系统下使用 `syscall.Open` 函数打开文件和目录的不同模式是否能正确工作，并返回预期的错误。
* **测试的 Go 语言功能：**  `syscall.Open` 函数是 Go 语言 `syscall` 包提供的用于执行 Windows 系统调用 `CreateFileW` 的封装。它允许程序以特定的模式打开或创建文件和目录。
* **代码示例：**
```go
package main

import (
	"fmt"
	"os"
	"syscall"
)

func main() {
	// 创建一个临时文件
	file, err := os.CreateTemp("", "example")
	if err != nil {
		fmt.Println("创建临时文件失败:", err)
		return
	}
	filePath := file.Name()
	file.Close()
	defer os.Remove(filePath) // 清理临时文件

	// 尝试以只读模式打开文件
	handle, err := syscall.Open(filePath, syscall.O_RDONLY, 0)
	if err != nil {
		fmt.Println("只读打开文件失败:", err)
	} else {
		fmt.Println("只读打开文件成功，句柄:", handle)
		syscall.CloseHandle(handle)
	}

	// 尝试以读写模式打开文件 (文件已存在)
	handle, err = syscall.Open(filePath, syscall.O_RDWR, 0)
	if err != nil {
		fmt.Println("读写打开文件失败:", err)
	} else {
		fmt.Println("读写打开文件成功，句柄:", handle)
		syscall.CloseHandle(handle)
	}

	// 尝试创建新文件 (如果不存在)
	newFilePath := "new_example.txt"
	handle, err = syscall.Open(newFilePath, syscall.O_RDWR|syscall.O_CREAT|syscall.O_EXCL, 0o666)
	if err != nil {
		fmt.Println("创建新文件失败:", err)
	} else {
		fmt.Println("创建新文件成功，句柄:", handle)
		syscall.CloseHandle(handle)
		os.Remove(newFilePath) // 清理新文件
	}
}
```
* **假设的输入与输出：**
    * **输入：**  执行上述代码。
    * **输出：**  如果操作系统允许文件操作，输出可能如下（具体输出可能因环境而异）：
      ```
      只读打开文件成功，句柄: 5
      读写打开文件成功，句柄: 6
      创建新文件成功，句柄: 7
      ```
      如果发生错误，则会输出相应的错误信息。

**2. `TestComputerName` 函数：测试 `syscall.ComputerName` 函数**

* **功能：** 测试获取 Windows 计算机名称的功能。
* **测试的 Go 语言功能：** `syscall.ComputerName` 函数封装了 Windows API `GetComputerNameExW` 或 `GetComputerNameW`，用于获取计算机的名称。
* **代码示例：**
```go
package main

import (
	"fmt"
	"syscall"
)

func main() {
	name, err := syscall.ComputerName()
	if err != nil {
		fmt.Println("获取计算机名失败:", err)
		return
	}
	fmt.Println("计算机名:", name)
}
```
* **假设的输入与输出：**
    * **输入：** 执行上述代码。
    * **输出：**  当前 Windows 系统的计算机名称，例如：
      ```
      计算机名: MY-PC
      ```

**3. `TestWin32finddata` 函数：测试 `syscall.FindFirstFile` 和 `syscall.FindClose` 函数，以及 `syscall.Win32finddata` 结构体**

* **功能：** 测试在 Windows 下查找文件的功能，并验证返回的 `syscall.Win32finddata` 结构体中的数据是否正确。该测试还隐含地检查了内存是否被意外修改。
* **测试的 Go 语言功能：** `syscall.FindFirstFile` 封装了 Windows API `FindFirstFileW`，用于开始查找与指定模式匹配的文件或子目录。 `syscall.FindClose` 用于关闭查找句柄。 `syscall.Win32finddata` 结构体对应 Windows API 中的 `WIN32_FIND_DATAW` 结构。
* **代码示例：**
```go
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

func main() {
	dir, err := os.MkdirTemp("", "findtest")
	if err != nil {
		fmt.Println("创建临时目录失败:", err)
		return
	}
	defer os.RemoveAll(dir)

	filePath := filepath.Join(dir, "testfile.txt")
	_, err = os.Create(filePath)
	if err != nil {
		fmt.Println("创建测试文件失败:", err)
		return
	}

	pathPtr, err := syscall.UTF16PtrFromString(filePath)
	if err != nil {
		fmt.Println("转换路径失败:", err)
		return
	}

	var findData syscall.Win32finddata
	handle, err := syscall.FindFirstFile(pathPtr, &findData)
	if err != nil {
		fmt.Println("FindFirstFile 失败:", err)
		return
	}
	defer syscall.FindClose(handle)

	fileName := syscall.UTF16ToString(findData.FileName[:])
	fmt.Println("找到的文件名:", fileName)
}
```
* **假设的输入与输出：**
    * **输入：** 执行上述代码。
    * **输出：**
      ```
      找到的文件名: testfile.txt
      ```

**4. `ExampleLoadLibrary` 函数：演示 `syscall.LoadLibrary` 和 `syscall.GetProcAddress` 的用法**

* **功能：** 展示如何加载 Windows DLL (动态链接库) 并获取其中函数的地址。
* **测试的 Go 语言功能：** `syscall.LoadLibrary` 封装了 Windows API `LoadLibraryW`，用于加载指定的 DLL 到进程地址空间。 `syscall.GetProcAddress` 封装了 Windows API `GetProcAddress`，用于获取 DLL 中导出函数的地址。 `syscall.Syscall` 用于执行系统调用，这里用来调用获取到的函数地址。
* **代码示例（与测试代码中的示例相同）：**
```go
package main

import (
	"fmt"
	"syscall"
)

func abort(funcname string, err error) {
	panic(funcname + " failed: " + err.Error())
}

func main() {
	h, err := syscall.LoadLibrary("kernel32.dll")
	if err != nil {
		abort("LoadLibrary", err)
	}
	defer syscall.FreeLibrary(h)
	proc, err := syscall.GetProcAddress(h, "GetVersion")
	if err != nil {
		abort("GetProcAddress", err)
	}
	r, _, _ := syscall.Syscall(uintptr(proc), 0, 0, 0, 0)
	major := byte(r)
	minor := uint8(r >> 8)
	build := uint16(r >> 16)
	fmt.Printf("windows version %d.%d (Build %d)\n", major, minor, build)
}
```
* **假设的输入与输出：**
    * **输入：** 执行上述代码。
    * **输出：**  当前 Windows 系统的版本信息，例如：
      ```
      windows version 10.0 (Build 19045)
      ```

**5. `TestTOKEN_ALL_ACCESS` 函数：检查常量 `syscall.TOKEN_ALL_ACCESS` 的值**

* **功能：** 验证 `syscall.TOKEN_ALL_ACCESS` 常量是否定义了正确的值。
* **测试的 Go 语言功能：**  这部分测试主要关注 `syscall` 包中定义的与 Windows 访问令牌相关的常量。
* **代码示例：**  这个测试本身就是一个简单的断言，没有独立运行的必要。

**6. `TestStdioAreInheritable` 函数：测试标准 I/O 是否可被子进程继承**

* **功能：**  通过创建一个 Go DLL 和一个 C 可执行文件，验证子进程是否能够继承父进程的标准输入、输出和错误流。
* **测试的 Go 语言功能：**  这涉及到 Go 的 `os/exec` 包，用于执行外部命令，以及 Go 对 DLL 的支持（通过 `//export` 注释）。它也间接测试了 Windows 进程创建时的句柄继承机制。
* **命令行参数处理：**
    * 该测试使用 `go build` 命令编译 Go DLL，使用了 `-o` 参数指定输出文件名，`-buildmode c-shared` 参数指定编译为 C 共享库。例如：
      ```bash
      go build -o helloworld.dll -buildmode c-shared helloworld.go
      ```
    * 该测试使用 `gcc` 命令编译 C 可执行文件，使用了 `-o` 参数指定输出文件名，`-xc` 参数表示从标准输入读取源代码。例如：
      ```bash
      gcc -o helloworld.exe -xc -
      ```
* **代码推理与假设：** 测试假设系统中安装了 `go` 和 `gcc`。它创建了一个简单的 Go DLL，其中导出了一个 `HelloWorld` 函数。然后，它编译了一个 C 程序，该程序加载该 DLL 并调用 `HelloWorld` 函数。通过在调用前后执行 `hostname` 命令，可以判断标准输出是否被正确继承。
* **假设的输入与输出：**
    * **输入：** 系统中存在 `go` 和 `gcc` 编译器，且代码构建和执行过程中没有错误。
    * **输出：**  C 程序的输出应该包含两次主机名，中间是 "Hello World"，例如（假设主机名为 "myhost"）：
      ```
      myhost
      Hello World
      myhost
      ```

**7. `TestGetwd_DoesNotPanicWhenPathIsLong` 函数：测试当路径很长时 `syscall.Getwd` 不会 panic**

* **功能：**  这是一个回归测试，用于确保在当前工作目录路径很长的情况下，`syscall.Getwd` 函数不会崩溃。
* **测试的 Go 语言功能：** `syscall.Getwd` 函数封装了 Windows API `GetCurrentDirectoryW`，用于获取当前进程的工作目录。
* **代码推理与假设：** 测试通过创建多层嵌套的目录来模拟一个很长的路径。它假设操作系统允许创建如此深度的目录结构。

**8. `TestGetStartupInfo` 函数：测试 `syscall.GetStartupInfo` 函数**

* **功能：** 测试获取进程启动信息的功能。
* **测试的 Go 语言功能：** `syscall.GetStartupInfo` 函数封装了 Windows API `GetStartupInfoW`，用于检索启动此进程时指定的信息。
* **代码示例：**
```go
package main

import (
	"fmt"
	"syscall"
)

func main() {
	var si syscall.StartupInfo
	err := syscall.GetStartupInfo(&si)
	if err != nil {
		fmt.Println("GetStartupInfo 失败:", err)
		return
	}
	fmt.Printf("标准输出句柄: %v\n", si.StdOutput)
	// 可以访问 si 结构体的其他字段来获取启动信息
}
```
* **假设的输入与输出：**
    * **输入：** 执行上述代码。
    * **输出：**  会打印出 `StartupInfo` 结构体中的一些信息，例如标准输出的句柄值。

**9. `TestSyscallAllocations` 函数：测试 `syscall.SyscallN` 的内存分配**

* **功能：**  测试 `syscall.SyscallN` 和 `syscall.Syscall` 在调用过程中是否会产生不必要的内存分配。这通常是性能优化的考虑。
* **测试的 Go 语言功能：**  测试直接进行系统调用的性能特性。

**10. `FuzzUTF16FromString` 函数：模糊测试 `syscall.UTF16FromString` 函数**

* **功能：**  使用模糊测试来检查 `syscall.UTF16FromString` 函数的健壮性，该函数将 Go 字符串转换为 UTF-16 编码。
* **测试的 Go 语言功能：**  测试字符串和 UTF-16 之间的转换，这是与 Windows API 交互时常见的操作。
* **代码推理与假设：** 模糊测试会提供各种各样的字符串作为输入，包括有效的、无效的和边界情况的字符串，以检测潜在的错误或崩溃。

**使用者易犯错的点（以 `syscall.Open` 为例）：**

* **没有检查错误返回值：**  调用 `syscall.Open` 后，必须检查返回的 `error` 值。如果 `err` 不为 `nil`，则表示打开操作失败。直接使用返回的句柄可能会导致程序崩溃或其他不可预测的行为。
    ```go
    handle, err := syscall.Open("nonexistent.txt", syscall.O_RDONLY, 0)
    if err != nil {
        fmt.Println("打开文件失败:", err)
        // 正确处理错误，例如返回或退出
        return
    }
    defer syscall.CloseHandle(handle) // 如果打开失败，handle 可能无效
    // ... 使用 handle
    ```
* **忘记关闭句柄：**  通过 `syscall.Open` 打开的文件或其他内核对象，需要在使用完毕后通过 `syscall.CloseHandle` 关闭，否则可能导致资源泄漏。推荐使用 `defer` 语句来确保句柄被关闭。

总而言之，这个测试文件全面地测试了 `syscall` 包在 Windows 平台上的核心功能，确保 Go 语言能够正确地与 Windows 操作系统进行交互。

Prompt: 
```
这是路径为go/src/syscall/syscall_windows_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package syscall_test

import (
	"fmt"
	"internal/testenv"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestOpen(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	file := filepath.Join(dir, "a")
	f, err := os.Create(file)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	tests := []struct {
		path string
		flag int
		err  error
	}{
		{dir, syscall.O_RDONLY, nil},
		{dir, syscall.O_CREAT, nil},
		{dir, syscall.O_RDONLY | syscall.O_CREAT, nil},
		{file, syscall.O_APPEND | syscall.O_WRONLY | os.O_CREATE, nil},
		{file, syscall.O_APPEND | syscall.O_WRONLY | os.O_CREATE | os.O_TRUNC, nil},
		{dir, syscall.O_RDONLY | syscall.O_TRUNC, syscall.ERROR_ACCESS_DENIED},
		{dir, syscall.O_WRONLY | syscall.O_RDWR, syscall.EISDIR},
		{dir, syscall.O_WRONLY, syscall.EISDIR},
		{dir, syscall.O_RDWR, syscall.EISDIR},
	}
	for i, tt := range tests {
		h, err := syscall.Open(tt.path, tt.flag, 0o660)
		if err == nil {
			syscall.CloseHandle(h)
		}
		if err != tt.err {
			t.Errorf("%d: Open got %q, want %q", i, err, tt.err)
		}
	}
}

func TestComputerName(t *testing.T) {
	name, err := syscall.ComputerName()
	if err != nil {
		t.Fatalf("ComputerName failed: %v", err)
	}
	if len(name) == 0 {
		t.Error("ComputerName returned empty string")
	}
}

func TestWin32finddata(t *testing.T) {
	dir := t.TempDir()

	path := filepath.Join(dir, "long_name.and_extension")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("failed to create %v: %v", path, err)
	}
	f.Close()

	type X struct {
		fd  syscall.Win32finddata
		got byte
		pad [10]byte // to protect ourselves

	}
	var want byte = 2 // it is unlikely to have this character in the filename
	x := X{got: want}

	pathp, _ := syscall.UTF16PtrFromString(path)
	h, err := syscall.FindFirstFile(pathp, &(x.fd))
	if err != nil {
		t.Fatalf("FindFirstFile failed: %v", err)
	}
	err = syscall.FindClose(h)
	if err != nil {
		t.Fatalf("FindClose failed: %v", err)
	}

	if x.got != want {
		t.Fatalf("memory corruption: want=%d got=%d", want, x.got)
	}
}

func abort(funcname string, err error) {
	panic(funcname + " failed: " + err.Error())
}

func ExampleLoadLibrary() {
	h, err := syscall.LoadLibrary("kernel32.dll")
	if err != nil {
		abort("LoadLibrary", err)
	}
	defer syscall.FreeLibrary(h)
	proc, err := syscall.GetProcAddress(h, "GetVersion")
	if err != nil {
		abort("GetProcAddress", err)
	}
	r, _, _ := syscall.Syscall(uintptr(proc), 0, 0, 0, 0)
	major := byte(r)
	minor := uint8(r >> 8)
	build := uint16(r >> 16)
	print("windows version ", major, ".", minor, " (Build ", build, ")\n")
}

func TestTOKEN_ALL_ACCESS(t *testing.T) {
	if syscall.TOKEN_ALL_ACCESS != 0xF01FF {
		t.Errorf("TOKEN_ALL_ACCESS = %x, want 0xF01FF", syscall.TOKEN_ALL_ACCESS)
	}
}

func TestStdioAreInheritable(t *testing.T) {
	testenv.MustHaveGoBuild(t)
	testenv.MustHaveCGO(t)
	testenv.MustHaveExecPath(t, "gcc")

	tmpdir := t.TempDir()

	// build go dll
	const dlltext = `
package main

import "C"
import (
	"fmt"
)

//export HelloWorld
func HelloWorld() {
	fmt.Println("Hello World")
}

func main() {}
`
	dllsrc := filepath.Join(tmpdir, "helloworld.go")
	err := os.WriteFile(dllsrc, []byte(dlltext), 0644)
	if err != nil {
		t.Fatal(err)
	}
	dll := filepath.Join(tmpdir, "helloworld.dll")
	cmd := exec.Command(testenv.GoToolPath(t), "build", "-o", dll, "-buildmode", "c-shared", dllsrc)
	out, err := testenv.CleanCmdEnv(cmd).CombinedOutput()
	if err != nil {
		t.Fatalf("failed to build go library: %s\n%s", err, out)
	}

	// build c exe
	const exetext = `
#include <stdlib.h>
#include <windows.h>
int main(int argc, char *argv[])
{
	system("hostname");
	((void(*)(void))GetProcAddress(LoadLibraryA(%q), "HelloWorld"))();
	system("hostname");
	return 0;
}
`
	exe := filepath.Join(tmpdir, "helloworld.exe")
	cmd = exec.Command("gcc", "-o", exe, "-xc", "-")
	cmd.Stdin = strings.NewReader(fmt.Sprintf(exetext, dll))
	out, err = testenv.CleanCmdEnv(cmd).CombinedOutput()
	if err != nil {
		t.Fatalf("failed to build c executable: %s\n%s", err, out)
	}
	out, err = exec.Command(exe).Output()
	if err != nil {
		t.Fatalf("c program execution failed: %v: %v", err, string(out))
	}

	hostname, err := os.Hostname()
	if err != nil {
		t.Fatal(err)
	}

	have := strings.ReplaceAll(string(out), "\n", "")
	have = strings.ReplaceAll(have, "\r", "")
	want := fmt.Sprintf("%sHello World%s", hostname, hostname)
	if have != want {
		t.Fatalf("c program output is wrong: got %q, want %q", have, want)
	}
}

func TestGetwd_DoesNotPanicWhenPathIsLong(t *testing.T) {
	// Regression test for https://github.com/golang/go/issues/60051.
	tmp := t.TempDir()
	t.Chdir(tmp)

	// The length of a filename is also limited, so we can't reproduce the
	// crash by creating a single directory with a very long name; we need two
	// layers.
	a200 := strings.Repeat("a", 200)
	dirname := filepath.Join(tmp, a200, a200)

	err := os.MkdirAll(dirname, 0o700)
	if err != nil {
		t.Skipf("MkdirAll failed: %v", err)
	}
	err = os.Chdir(dirname)
	if err != nil {
		t.Skipf("Chdir failed: %v", err)
	}

	syscall.Getwd()
}

func TestGetStartupInfo(t *testing.T) {
	var si syscall.StartupInfo
	err := syscall.GetStartupInfo(&si)
	if err != nil {
		// see https://go.dev/issue/31316
		t.Fatalf("GetStartupInfo: got error %v, want nil", err)
	}
}

func TestSyscallAllocations(t *testing.T) {
	testenv.SkipIfOptimizationOff(t)

	// Test that syscall.SyscallN arguments do not escape.
	// The function used (in this case GetVersion) doesn't matter
	// as long as it is always available and doesn't panic.
	h, err := syscall.LoadLibrary("kernel32.dll")
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.FreeLibrary(h)
	proc, err := syscall.GetProcAddress(h, "GetVersion")
	if err != nil {
		t.Fatal(err)
	}

	testAllocs := func(t *testing.T, name string, fn func() error) {
		t.Run(name, func(t *testing.T) {
			n := int(testing.AllocsPerRun(10, func() {
				if err := fn(); err != nil {
					t.Fatalf("%s: %v", name, err)
				}
			}))
			if n > 0 {
				t.Errorf("allocs = %d, want 0", n)
			}
		})
	}

	testAllocs(t, "SyscallN", func() error {
		r0, _, e1 := syscall.SyscallN(proc, 0, 0, 0)
		if r0 == 0 {
			return syscall.Errno(e1)
		}
		return nil
	})
	testAllocs(t, "Syscall", func() error {
		r0, _, e1 := syscall.Syscall(proc, 3, 0, 0, 0)
		if r0 == 0 {
			return syscall.Errno(e1)
		}
		return nil
	})
}

func FuzzUTF16FromString(f *testing.F) {
	f.Add("hi")           // ASCII
	f.Add("â")            // latin1
	f.Add("ねこ")           // plane 0
	f.Add("😃")            // extra Plane 0
	f.Add("\x90")         // invalid byte
	f.Add("\xe3\x81")     // truncated
	f.Add("\xe3\xc1\x81") // invalid middle byte

	f.Fuzz(func(t *testing.T, tst string) {
		res, err := syscall.UTF16FromString(tst)
		if err != nil {
			if strings.Contains(tst, "\x00") {
				t.Skipf("input %q contains a NUL byte", tst)
			}
			t.Fatalf("UTF16FromString(%q): %v", tst, err)
		}
		t.Logf("UTF16FromString(%q) = %04x", tst, res)

		if len(res) < 1 || res[len(res)-1] != 0 {
			t.Fatalf("missing NUL terminator")
		}
		if len(res) > len(tst)+1 {
			t.Fatalf("len(%04x) > len(%q)+1", res, tst)
		}
	})
}

"""



```