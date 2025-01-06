Response:
The user wants to understand the functionality of the Go code provided in `go/src/cmd/cgo/internal/testcshared/cshared_test.go`.

Here's a breakdown of how to approach this:

1. **Identify the purpose of the file:** The file name and package name suggest it's a test suite for the `cgo` command, specifically focusing on the `c-shared` build mode. This mode allows building Go packages as shared libraries that can be called from C code.

2. **Analyze the `TestMain` function:** This function is the entry point for the tests. Pay attention to what it initializes and sets up. This includes environment variables, compiler settings, and test data.

3. **Examine individual test functions:** Look at the names of the test functions (e.g., `TestExportedSymbols`, `TestUnexportedSymbols`) to understand what specific aspects of `c-shared` functionality they are testing.

4. **Analyze helper functions:** Functions like `run`, `runCC`, `createHeaders`, and `copyFile` provide essential utilities for running the tests. Understand their roles.

5. **Infer functionality from the tests:** By looking at how the tests are structured (compiling Go code with `-buildmode=c-shared`, compiling C code that interacts with the shared library, and running the resulting executables), we can deduce the features being tested.

6. **Look for specific scenarios:**  Pay attention to tests that handle different operating systems (e.g., Windows, Linux, macOS) or specific architectures.

7. **Identify potential pitfalls:** Look for comments or test logic that indicates common mistakes users might make when working with `c-shared`.

8. **Provide illustrative Go code examples:** Based on the identified functionalities, create simple Go code snippets demonstrating how these features are used.

9. **Explain command-line arguments:**  Focus on how the tests use `go build` with the `-buildmode=c-shared` flag and other related flags.

**Pre-computation/Analysis:**

* **`TestMain`:** Initializes the testing environment, including setting up `GOPATH`, copying test data, and configuring the C compiler (`cc`). It also handles skipping tests based on environment and OS.
* **Helper functions:**
    * `run`: Executes a command and returns the output.
    * `runCC`: Executes the C compiler with pre-configured flags.
    * `createHeaders`:  Builds Go packages in `c-shared` mode to generate header files (`.h`) and shared library files (`.a` or `.dll`).
* **Test functions:**
    * `TestExportedSymbols`: Verifies that symbols exported from a Go shared library are accessible from C code.
    * `TestNumberOfExportedFunctions`: Specifically for Windows, checks the number of exported symbols, ensuring only explicitly exported functions are included by default.
    * `TestExportedSymbolsWithDynamicLoad`: Tests loading a Go shared library dynamically from C code.
    * `TestUnexportedSymbols`: Tests linking against a Go shared library that doesn't export any Go functions, ensuring it works.
    * `TestMainExportedOnAndroid`: Verifies that the `main.main` function is exported on Android when building a shared library.
    * `TestSignalHandlers`: Tests signal handling when a Go shared library is used.
    * `TestSignalHandlersWithNotify`: Similar to the above but uses `os/signal.Notify`.
    * `TestPIE`: Checks if the generated shared library is Position Independent Executable (PIE) on Linux and Android.
    * `TestCachedInstall`: Tests that reinstalling a shared library recreates the header file.
    * `TestGo2C2Go`: Tests linking a Go shared library into another Go program via C.
    * `TestIssue36233`: Tests that the generated header file uses `GoComplex64` and `GoComplex128` for complex types.

**Potential User Errors:** Forgetting to set `LD_LIBRARY_PATH` (or its equivalent on other OSs) when running executables that depend on dynamically loaded shared libraries.

By following this thought process, I can structure the response to address all aspects of the user's request.
这个go语言文件 `go/src/cmd/cgo/internal/testcshared/cshared_test.go` 是 `cgo` 工具的一个测试文件，专门用于测试 **`-buildmode=c-shared`** 这个功能。这个构建模式允许将 Go 代码编译成一个共享库（`.so` 在 Linux 上，`.dylib` 在 macOS 上，`.dll` 在 Windows 上），可以被其他语言（主要是 C）调用。

下面列举一下这个测试文件的主要功能：

1. **测试导出符号的访问:** 验证使用 `-buildmode=c-shared` 构建的 Go 共享库中导出的 Go 函数可以在 C 代码中被正确调用。
2. **测试动态加载共享库:** 验证 C 代码可以动态加载 Go 共享库，并调用其中导出的函数。
3. **测试未导出符号的处理:** 验证当 Go 共享库没有导出任何 Go 函数时，C 代码可以正确链接和运行。
4. **测试 Android 平台 `main.main` 的导出:**  验证在 Android 平台上使用 `-buildmode=c-shared` 构建共享库时，`main.main` 函数会被导出。
5. **测试信号处理:** 验证当 Go 代码被编译成共享库并被 C 代码调用时，信号处理机制是否正常工作。包括使用 `os/signal.Notify` 的情况。
6. **测试生成共享库的 PIE (Position Independent Executable) 特性:**  在 Linux 和 Android 平台上，验证生成的共享库是否是 PIE，这是一种安全特性。
7. **测试头文件的缓存机制:** 验证重新安装一个共享库后，其对应的头文件是否会被重新生成。
8. **测试 Go 互相调用场景 (Go2C2Go):** 测试将一个使用 `-buildmode=c-shared` 构建的 Go 共享库链接到另一个 Go 程序中，并通过 C 接口进行调用。
9. **测试导出头文件中复数类型的表示:** 验证使用 `-buildmode=c-shared` 生成的头文件中，Go 的 `complex64` 和 `complex128` 类型会被正确映射为 `GoComplex64` 和 `GoComplex128`。
10. **测试 Windows 平台上导出函数的数量:** 验证在 Windows 平台上，默认情况下只有显式导出的 Go 函数才会被包含在导出的符号表中。

**它是什么go语言功能的实现？**

这个测试文件主要测试的是 Go 语言通过 `cgo` 工具提供的将 Go 代码编译成 C 共享库的功能，即 **`-buildmode=c-shared`** 构建模式。

**go代码举例说明:**

假设我们有以下 Go 代码 `libgo.go`：

```go
package main

import "C"

//export SayHello
func SayHello() {
	println("Hello from Go shared library!")
}

//export Add
func Add(a int, b int) int {
	return a + b
}

func main() {}
```

我们可以使用以下命令将其编译成共享库：

```bash
go build -buildmode=c-shared -o libgo.so libgo.go  # Linux
go build -buildmode=c-shared -o libgo.dylib libgo.go # macOS
go build -buildmode=c-shared -o libgo.dll libgo.go # Windows
```

然后，我们可以编写 C 代码 `main.c` 来调用这个共享库：

```c
#include <stdio.h>
#include "libgo.h" // 假设生成了 libgo.h 头文件

extern void SayHello();
extern GoInt Add(GoInt a, GoInt b);

int main() {
    SayHello();
    GoInt result = Add(5, 3);
    printf("Result of addition: %lld\n", result);
    return 0;
}
```

编译和运行 C 代码（假设 `libgo.so` 与 `main.c` 在同一目录下）：

```bash
gcc -o main main.c -L. -lgo
LD_LIBRARY_PATH=. ./main  # Linux/macOS
```

**假设的输入与输出:**

**输入 (编译 Go 代码):** `go build -buildmode=c-shared -o libgo.so libgo.go`
**输出 (生成共享库):**  生成 `libgo.so` 文件 (或其他平台对应的共享库文件) 和 `libgo.h` 头文件。

**输入 (运行 C 代码):** `LD_LIBRARY_PATH=. ./main`
**输出 (C 代码的输出):**
```
Hello from Go shared library!
Result of addition: 8
```

**命令行参数的具体处理:**

这个测试文件本身不直接处理用户输入的命令行参数。但是它大量使用了 `go` 命令及其子命令，特别是 `go build` 和 `go tool cgo`。

* **`go build -buildmode=c-shared -o <output_file> <go_package>`:**  这是最核心的命令，用于将指定的 Go 包编译成 C 共享库。
    * `-buildmode=c-shared`:  指定构建模式为 C 共享库。
    * `-o <output_file>`:  指定输出文件的名称。
    * `<go_package>`:  指定要编译的 Go 包的路径。
* **`go tool cgo -exportheader <header_file> <go_files>`:** 用于生成 C 头文件，其中包含了 Go 代码中导出的函数和类型的声明。
    * `-exportheader <header_file>`: 指定生成的头文件名称。

测试代码中还使用了一些其他的 `go build` 参数，例如：

* `-installsuffix`:  用于在测试环境中创建隔离的安装目录。
* `-ldflags`:  用于传递链接器标志。
* `-x`:  显示构建过程中的详细命令。

**使用者易犯错的点:**

1. **忘记设置动态链接库路径:**  在运行依赖于 Go 共享库的 C 程序时，需要确保操作系统能够找到该共享库。这通常通过设置环境变量 `LD_LIBRARY_PATH` (Linux), `DYLD_LIBRARY_PATH` (macOS) 或将 DLL 放在可执行文件相同的目录下 (Windows) 来实现。
    * **错误示例:**  直接运行 `./main` 而没有设置 `LD_LIBRARY_PATH`。
    * **正确示例:** `LD_LIBRARY_PATH=. ./main`

2. **头文件包含错误:**  在 C 代码中调用 Go 共享库的函数时，需要正确包含生成的头文件。
    * **错误示例:**  `#include "mylib.h"`，但实际生成的头文件是 `libgo.h`。
    * **正确示例:** `#include "libgo.h"`

3. **类型不匹配:** C 代码中使用的类型需要与 Go 代码中导出的类型相匹配。`cgo` 会将 Go 的基本类型映射到 C 的类型 (例如 `int` 到 `GoInt`)，但需要注意这些映射关系。
    * **错误示例:** Go 函数 `Add` 接受 `int`，但在 C 代码中传递了 `long long`。
    * **正确示例:** 使用 `GoInt` 类型。

4. **Windows 平台 DLL 导入库:** 在 Windows 上，链接到 DLL 通常需要一个导入库 (`.lib` 文件)。虽然 `-buildmode=c-shared` 主要生成 DLL，但有时候可能需要额外的步骤来生成或指定导入库。测试代码中展示了一些处理 Windows 导入库的复杂情况。

5. **CGO 的使用限制:**  需要理解 `cgo` 的工作原理和限制，例如在 Go 代码中嵌入 C 代码块时需要遵守特定的语法。

总而言之，这个测试文件覆盖了使用 Go 的 `-buildmode=c-shared` 功能时可能遇到的各种场景和问题，为确保该功能的正确性和稳定性提供了保障。

Prompt: 
```
这是路径为go/src/cmd/cgo/internal/testcshared/cshared_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cshared_test

import (
	"bufio"
	"bytes"
	"cmd/cgo/internal/cgotest"
	"debug/elf"
	"debug/pe"
	"encoding/binary"
	"flag"
	"fmt"
	"internal/testenv"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"unicode"
)

var globalSkip = func(t *testing.T) {}

// C compiler with args (from $(go env CC) $(go env GOGCCFLAGS)).
var cc []string

// ".exe" on Windows.
var exeSuffix string

var GOOS, GOARCH, GOROOT string
var installdir string
var libgoname string

func TestMain(m *testing.M) {
	os.Exit(testMain(m))
}

func testMain(m *testing.M) int {
	log.SetFlags(log.Lshortfile)
	flag.Parse()
	if testing.Short() && os.Getenv("GO_BUILDER_NAME") == "" {
		globalSkip = func(t *testing.T) { t.Skip("short mode and $GO_BUILDER_NAME not set") }
		return m.Run()
	}
	if runtime.GOOS == "linux" {
		if _, err := os.Stat("/etc/alpine-release"); err == nil {
			globalSkip = func(t *testing.T) { t.Skip("skipping failing test on alpine - go.dev/issue/19938") }
			return m.Run()
		}
	}
	if !testenv.HasGoBuild() {
		// Checking for "go build" is a proxy for whether or not we can run "go env".
		globalSkip = func(t *testing.T) { t.Skip("no go build") }
		return m.Run()
	}

	GOOS = goEnv("GOOS")
	GOARCH = goEnv("GOARCH")
	GOROOT = goEnv("GOROOT")

	if _, err := os.Stat(GOROOT); os.IsNotExist(err) {
		log.Fatalf("Unable able to find GOROOT at '%s'", GOROOT)
	}

	cc = []string{goEnv("CC")}

	out := goEnv("GOGCCFLAGS")
	quote := '\000'
	start := 0
	lastSpace := true
	backslash := false
	s := string(out)
	for i, c := range s {
		if quote == '\000' && unicode.IsSpace(c) {
			if !lastSpace {
				cc = append(cc, s[start:i])
				lastSpace = true
			}
		} else {
			if lastSpace {
				start = i
				lastSpace = false
			}
			if quote == '\000' && !backslash && (c == '"' || c == '\'') {
				quote = c
				backslash = false
			} else if !backslash && quote == c {
				quote = '\000'
			} else if (quote == '\000' || quote == '"') && !backslash && c == '\\' {
				backslash = true
			} else {
				backslash = false
			}
		}
	}
	if !lastSpace {
		cc = append(cc, s[start:])
	}

	switch GOOS {
	case "darwin", "ios":
		// For Darwin/ARM.
		// TODO(crawshaw): can we do better?
		cc = append(cc, []string{"-framework", "CoreFoundation", "-framework", "Foundation"}...)
	case "android":
		cc = append(cc, "-pie")
	}
	libgodir := GOOS + "_" + GOARCH
	switch GOOS {
	case "darwin", "ios":
		if GOARCH == "arm64" {
			libgodir += "_shared"
		}
	case "dragonfly", "freebsd", "linux", "netbsd", "openbsd", "solaris", "illumos":
		libgodir += "_shared"
	}
	cc = append(cc, "-I", filepath.Join("pkg", libgodir))

	// Force reallocation (and avoid aliasing bugs) for parallel tests that append to cc.
	cc = cc[:len(cc):len(cc)]

	if GOOS == "windows" {
		exeSuffix = ".exe"
	}

	// Copy testdata into GOPATH/src/testcshared, along with a go.mod file
	// declaring the same path.

	GOPATH, err := os.MkdirTemp("", "cshared_test")
	if err != nil {
		log.Panic(err)
	}
	defer os.RemoveAll(GOPATH)
	os.Setenv("GOPATH", GOPATH)

	modRoot := filepath.Join(GOPATH, "src", "testcshared")
	if err := cgotest.OverlayDir(modRoot, "testdata"); err != nil {
		log.Panic(err)
	}
	if err := os.Chdir(modRoot); err != nil {
		log.Panic(err)
	}
	os.Setenv("PWD", modRoot)
	if err := os.WriteFile("go.mod", []byte("module testcshared\n"), 0666); err != nil {
		log.Panic(err)
	}

	defer func() {
		if installdir != "" {
			err := os.RemoveAll(installdir)
			if err != nil {
				log.Panic(err)
			}
		}
	}()

	return m.Run()
}

func goEnv(key string) string {
	out, err := exec.Command("go", "env", key).Output()
	if err != nil {
		log.Printf("go env %s failed:\n%s", key, err)
		log.Panicf("%s", err.(*exec.ExitError).Stderr)
	}
	return strings.TrimSpace(string(out))
}

func cmdToRun(name string) string {
	return "./" + name + exeSuffix
}

func run(t *testing.T, extraEnv []string, args ...string) string {
	t.Helper()
	cmd := exec.Command(args[0], args[1:]...)
	if len(extraEnv) > 0 {
		cmd.Env = append(os.Environ(), extraEnv...)
	}
	stderr := new(strings.Builder)
	cmd.Stderr = stderr

	if GOOS != "windows" {
		// TestUnexportedSymbols relies on file descriptor 30
		// being closed when the program starts, so enforce
		// that in all cases. (The first three descriptors are
		// stdin/stdout/stderr, so we just need to make sure
		// that cmd.ExtraFiles[27] exists and is nil.)
		cmd.ExtraFiles = make([]*os.File, 28)
	}

	t.Logf("run: %v", args)
	out, err := cmd.Output()
	if stderr.Len() > 0 {
		t.Logf("stderr:\n%s", stderr)
	}
	if err != nil {
		t.Fatalf("command failed: %v\n%v\n%s\n", args, err, out)
	}
	return string(out)
}

func runExe(t *testing.T, extraEnv []string, args ...string) string {
	t.Helper()
	return run(t, extraEnv, args...)
}

func runCC(t *testing.T, args ...string) string {
	t.Helper()
	// This function is run in parallel, so append to a copy of cc
	// rather than cc itself.
	return run(t, nil, append(append([]string(nil), cc...), args...)...)
}

func createHeaders() error {
	// The 'cgo' command generates a number of additional artifacts,
	// but we're only interested in the header.
	// Shunt the rest of the outputs to a temporary directory.
	objDir, err := os.MkdirTemp("", "testcshared_obj")
	if err != nil {
		return err
	}
	defer os.RemoveAll(objDir)

	// Generate a C header file for p, which is a non-main dependency
	// of main package libgo.
	//
	// TODO(golang.org/issue/35715): This should be simpler.
	args := []string{"go", "tool", "cgo",
		"-objdir", objDir,
		"-exportheader", "p.h",
		filepath.Join(".", "p", "p.go")}
	cmd := exec.Command(args[0], args[1:]...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("command failed: %v\n%v\n%s\n", args, err, out)
	}

	// Generate a C header file for libgo itself.
	installdir, err = os.MkdirTemp("", "testcshared")
	if err != nil {
		return err
	}
	libgoname = "libgo.a"

	args = []string{"go", "build", "-buildmode=c-shared", "-o", filepath.Join(installdir, libgoname), "./libgo"}
	cmd = exec.Command(args[0], args[1:]...)
	out, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("command failed: %v\n%v\n%s\n", args, err, out)
	}

	args = []string{"go", "build", "-buildmode=c-shared",
		"-installsuffix", "testcshared",
		"-o", libgoname,
		filepath.Join(".", "libgo", "libgo.go")}
	if GOOS == "windows" && strings.HasSuffix(args[6], ".a") {
		args[6] = strings.TrimSuffix(args[6], ".a") + ".dll"
	}
	cmd = exec.Command(args[0], args[1:]...)
	out, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("command failed: %v\n%v\n%s\n", args, err, out)
	}
	if GOOS == "windows" {
		// We can't simply pass -Wl,--out-implib, because this relies on having imports from multiple packages,
		// which results in the linkers output implib getting overwritten at each step. So instead build the
		// import library the traditional way, using a def file.
		err = os.WriteFile("libgo.def",
			[]byte("LIBRARY libgo.dll\nEXPORTS\n\tDidInitRun\n\tDidMainRun\n\tDivu\n\tFromPkg\n\t_cgo_dummy_export\n"),
			0644)
		if err != nil {
			return fmt.Errorf("unable to write def file: %v", err)
		}
		out, err = exec.Command(cc[0], append(cc[1:], "-print-prog-name=dlltool")...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("unable to find dlltool path: %v\n%s\n", err, out)
		}
		dlltoolpath := strings.TrimSpace(string(out))
		if filepath.Ext(dlltoolpath) == "" {
			// Some compilers report slash-separated paths without extensions
			// instead of ordinary Windows paths.
			// Try to find the canonical name for the path.
			if lp, err := exec.LookPath(dlltoolpath); err == nil {
				dlltoolpath = lp
			}
		}

		args := []string{dlltoolpath, "-D", args[6], "-l", libgoname, "-d", "libgo.def"}

		if filepath.Ext(dlltoolpath) == "" {
			// This is an unfortunate workaround for
			// https://github.com/mstorsjo/llvm-mingw/issues/205 in which
			// we basically reimplement the contents of the dlltool.sh
			// wrapper: https://git.io/JZFlU.
			// TODO(thanm): remove this workaround once we can upgrade
			// the compilers on the windows-arm64 builder.
			dlltoolContents, err := os.ReadFile(args[0])
			if err != nil {
				return fmt.Errorf("unable to read dlltool: %v\n", err)
			}
			if bytes.HasPrefix(dlltoolContents, []byte("#!/bin/sh")) && bytes.Contains(dlltoolContents, []byte("llvm-dlltool")) {
				base, name := filepath.Split(args[0])
				args[0] = filepath.Join(base, "llvm-dlltool")
				var machine string
				switch prefix, _, _ := strings.Cut(name, "-"); prefix {
				case "i686":
					machine = "i386"
				case "x86_64":
					machine = "i386:x86-64"
				case "armv7":
					machine = "arm"
				case "aarch64":
					machine = "arm64"
				}
				if len(machine) > 0 {
					args = append(args, "-m", machine)
				}
			}
		}

		out, err = exec.Command(args[0], args[1:]...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("unable to run dlltool to create import library: %v\n%s\n", err, out)
		}
	}

	return nil
}

var (
	headersOnce sync.Once
	headersErr  error
)

func createHeadersOnce(t *testing.T) {
	testenv.MustHaveGoBuild(t)
	testenv.MustHaveCGO(t)
	testenv.MustHaveBuildMode(t, "c-shared")

	headersOnce.Do(func() {
		headersErr = createHeaders()
	})
	if headersErr != nil {
		t.Helper()
		t.Fatal(headersErr)
	}
}

// test0: exported symbols in shared lib are accessible.
func TestExportedSymbols(t *testing.T) {
	globalSkip(t)
	testenv.MustHaveCGO(t)
	testenv.MustHaveExec(t)

	t.Parallel()

	cmd := "testp0"
	bin := cmdToRun(cmd)

	createHeadersOnce(t)

	runCC(t, "-I", installdir, "-o", cmd, "main0.c", libgoname)

	defer os.Remove(bin)

	out := runExe(t, []string{"LD_LIBRARY_PATH=."}, bin)
	if strings.TrimSpace(out) != "PASS" {
		t.Error(out)
	}
}

func checkNumberOfExportedFunctionsWindows(t *testing.T, exportAllSymbols bool) {
	const prog = `
package main

import "C"

//export GoFunc
func GoFunc() {
	println(42)
}

//export GoFunc2
func GoFunc2() {
	println(24)
}

func main() {
}
`

	tmpdir := t.TempDir()

	srcfile := filepath.Join(tmpdir, "test.go")
	objfile := filepath.Join(tmpdir, "test.dll")
	if err := os.WriteFile(srcfile, []byte(prog), 0666); err != nil {
		t.Fatal(err)
	}
	argv := []string{"build", "-buildmode=c-shared"}
	if exportAllSymbols {
		argv = append(argv, "-ldflags", "-extldflags=-Wl,--export-all-symbols")
	}
	argv = append(argv, "-o", objfile, srcfile)
	out, err := exec.Command("go", argv...).CombinedOutput()
	if err != nil {
		t.Fatalf("build failure: %s\n%s\n", err, string(out))
	}

	f, err := pe.Open(objfile)
	if err != nil {
		t.Fatalf("pe.Open failed: %v", err)
	}
	defer f.Close()
	section := f.Section(".edata")
	if section == nil {
		t.Skip(".edata section is not present")
	}

	// TODO: deduplicate this struct from cmd/link/internal/ld/pe.go
	type IMAGE_EXPORT_DIRECTORY struct {
		_                 [2]uint32
		_                 [2]uint16
		_                 [2]uint32
		NumberOfFunctions uint32
		NumberOfNames     uint32
		_                 [3]uint32
	}
	var e IMAGE_EXPORT_DIRECTORY
	if err := binary.Read(section.Open(), binary.LittleEndian, &e); err != nil {
		t.Fatalf("binary.Read failed: %v", err)
	}

	// Only the two exported functions and _cgo_dummy_export should be exported
	expectedNumber := uint32(3)

	if exportAllSymbols {
		if e.NumberOfFunctions <= expectedNumber {
			t.Fatalf("missing exported functions: %v", e.NumberOfFunctions)
		}
		if e.NumberOfNames <= expectedNumber {
			t.Fatalf("missing exported names: %v", e.NumberOfNames)
		}
	} else {
		if e.NumberOfFunctions != expectedNumber {
			t.Fatalf("got %d exported functions; want %d", e.NumberOfFunctions, expectedNumber)
		}
		if e.NumberOfNames != expectedNumber {
			t.Fatalf("got %d exported names; want %d", e.NumberOfNames, expectedNumber)
		}
	}
}

func TestNumberOfExportedFunctions(t *testing.T) {
	if GOOS != "windows" {
		t.Skip("skipping windows only test")
	}
	globalSkip(t)
	testenv.MustHaveGoBuild(t)
	testenv.MustHaveCGO(t)
	testenv.MustHaveBuildMode(t, "c-shared")

	t.Parallel()

	t.Run("OnlyExported", func(t *testing.T) {
		checkNumberOfExportedFunctionsWindows(t, false)
	})
	t.Run("All", func(t *testing.T) {
		checkNumberOfExportedFunctionsWindows(t, true)
	})
}

// test1: shared library can be dynamically loaded and exported symbols are accessible.
func TestExportedSymbolsWithDynamicLoad(t *testing.T) {
	if GOOS == "windows" {
		t.Skipf("Skipping on %s", GOOS)
	}
	globalSkip(t)
	testenv.MustHaveCGO(t)
	testenv.MustHaveExec(t)

	t.Parallel()

	cmd := "testp1"
	bin := cmdToRun(cmd)

	createHeadersOnce(t)

	if GOOS != "freebsd" {
		runCC(t, "-o", cmd, "main1.c", "-ldl")
	} else {
		runCC(t, "-o", cmd, "main1.c")
	}

	defer os.Remove(bin)

	out := runExe(t, nil, bin, "./"+libgoname)
	if strings.TrimSpace(out) != "PASS" {
		t.Error(out)
	}
}

// test2: tests libgo2 which does not export any functions.
func TestUnexportedSymbols(t *testing.T) {
	if GOOS == "windows" {
		t.Skipf("Skipping on %s", GOOS)
	}
	globalSkip(t)
	testenv.MustHaveGoBuild(t)
	testenv.MustHaveCGO(t)
	testenv.MustHaveBuildMode(t, "c-shared")

	t.Parallel()

	cmd := "testp2"
	bin := cmdToRun(cmd)
	libname := "libgo2.a"

	run(t,
		nil,
		"go", "build",
		"-buildmode=c-shared",
		"-installsuffix", "testcshared",
		"-o", libname, "./libgo2",
	)

	linkFlags := "-Wl,--no-as-needed"
	if GOOS == "darwin" || GOOS == "ios" {
		linkFlags = ""
	}

	runCC(t, "-o", cmd, "main2.c", linkFlags, libname)

	defer os.Remove(libname)
	defer os.Remove(bin)

	out := runExe(t, []string{"LD_LIBRARY_PATH=."}, bin)

	if strings.TrimSpace(out) != "PASS" {
		t.Error(out)
	}
}

// test3: tests main.main is exported on android.
func TestMainExportedOnAndroid(t *testing.T) {
	globalSkip(t)
	testenv.MustHaveCGO(t)
	testenv.MustHaveExec(t)

	t.Parallel()

	switch GOOS {
	case "android":
		break
	default:
		t.Logf("Skipping on %s", GOOS)
		return
	}

	cmd := "testp3"
	bin := cmdToRun(cmd)

	createHeadersOnce(t)

	runCC(t, "-o", cmd, "main3.c", "-ldl")

	defer os.Remove(bin)

	out := runExe(t, nil, bin, "./"+libgoname)
	if strings.TrimSpace(out) != "PASS" {
		t.Error(out)
	}
}

func testSignalHandlers(t *testing.T, pkgname, cfile, cmd string) {
	if GOOS == "windows" {
		t.Skipf("Skipping on %s", GOOS)
	}
	globalSkip(t)
	testenv.MustHaveGoBuild(t)
	testenv.MustHaveCGO(t)
	testenv.MustHaveBuildMode(t, "c-shared")

	libname := pkgname + ".a"
	run(t,
		nil,
		"go", "build",
		"-buildmode=c-shared",
		"-installsuffix", "testcshared",
		"-o", libname, pkgname,
	)
	if GOOS != "freebsd" {
		runCC(t, "-pthread", "-o", cmd, cfile, "-ldl")
	} else {
		runCC(t, "-pthread", "-o", cmd, cfile)
	}

	bin := cmdToRun(cmd)

	defer os.Remove(libname)
	defer os.Remove(bin)
	defer os.Remove(pkgname + ".h")

	args := []string{bin, "./" + libname}
	if testing.Verbose() {
		args = append(args, "verbose")
	}
	out := runExe(t, nil, args...)
	if strings.TrimSpace(out) != "PASS" {
		t.Errorf("%v%s", args, out)
	}
}

// test4: test signal handlers
func TestSignalHandlers(t *testing.T) {
	t.Parallel()
	testSignalHandlers(t, "./libgo4", "main4.c", "testp4")
}

// test5: test signal handlers with os/signal.Notify
func TestSignalHandlersWithNotify(t *testing.T) {
	t.Parallel()
	testSignalHandlers(t, "./libgo5", "main5.c", "testp5")
}

func TestPIE(t *testing.T) {
	switch GOOS {
	case "linux", "android":
		break
	default:
		t.Skipf("Skipping on %s", GOOS)
	}
	globalSkip(t)

	t.Parallel()

	createHeadersOnce(t)

	f, err := elf.Open(libgoname)
	if err != nil {
		t.Fatalf("elf.Open failed: %v", err)
	}
	defer f.Close()

	ds := f.SectionByType(elf.SHT_DYNAMIC)
	if ds == nil {
		t.Fatalf("no SHT_DYNAMIC section")
	}
	d, err := ds.Data()
	if err != nil {
		t.Fatalf("can't read SHT_DYNAMIC contents: %v", err)
	}
	for len(d) > 0 {
		var tag elf.DynTag
		switch f.Class {
		case elf.ELFCLASS32:
			tag = elf.DynTag(f.ByteOrder.Uint32(d[:4]))
			d = d[8:]
		case elf.ELFCLASS64:
			tag = elf.DynTag(f.ByteOrder.Uint64(d[:8]))
			d = d[16:]
		}
		if tag == elf.DT_TEXTREL {
			t.Fatalf("%s has DT_TEXTREL flag", libgoname)
		}
	}
}

// Test that installing a second time recreates the header file.
func TestCachedInstall(t *testing.T) {
	globalSkip(t)
	testenv.MustHaveGoBuild(t)
	testenv.MustHaveCGO(t)
	testenv.MustHaveBuildMode(t, "c-shared")

	tmpdir, err := os.MkdirTemp("", "cshared")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)

	copyFile(t, filepath.Join(tmpdir, "src", "testcshared", "go.mod"), "go.mod")
	copyFile(t, filepath.Join(tmpdir, "src", "testcshared", "libgo", "libgo.go"), filepath.Join("libgo", "libgo.go"))
	copyFile(t, filepath.Join(tmpdir, "src", "testcshared", "p", "p.go"), filepath.Join("p", "p.go"))

	buildcmd := []string{"go", "install", "-x", "-buildmode=c-shared", "-installsuffix", "testcshared", "./libgo"}

	cmd := exec.Command(buildcmd[0], buildcmd[1:]...)
	cmd.Dir = filepath.Join(tmpdir, "src", "testcshared")
	env := append(cmd.Environ(),
		"GOPATH="+tmpdir,
		"GOBIN="+filepath.Join(tmpdir, "bin"),
		"GO111MODULE=off", // 'go install' only works in GOPATH mode
	)
	cmd.Env = env
	t.Log(buildcmd)
	out, err := cmd.CombinedOutput()
	t.Logf("%s", out)
	if err != nil {
		t.Fatal(err)
	}

	var libgoh, ph string

	walker := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			t.Fatal(err)
		}
		var ps *string
		switch filepath.Base(path) {
		case "libgo.h":
			ps = &libgoh
		case "p.h":
			ps = &ph
		}
		if ps != nil {
			if *ps != "" {
				t.Fatalf("%s found again", *ps)
			}
			*ps = path
		}
		return nil
	}

	if err := filepath.Walk(tmpdir, walker); err != nil {
		t.Fatal(err)
	}

	if libgoh == "" {
		t.Fatal("libgo.h not installed")
	}

	if err := os.Remove(libgoh); err != nil {
		t.Fatal(err)
	}

	cmd = exec.Command(buildcmd[0], buildcmd[1:]...)
	cmd.Dir = filepath.Join(tmpdir, "src", "testcshared")
	cmd.Env = env
	t.Log(buildcmd)
	out, err = cmd.CombinedOutput()
	t.Logf("%s", out)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(libgoh); err != nil {
		t.Errorf("libgo.h not installed in second run: %v", err)
	}
}

// copyFile copies src to dst.
func copyFile(t *testing.T, dst, src string) {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0777); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, data, 0666); err != nil {
		t.Fatal(err)
	}
}

func TestGo2C2Go(t *testing.T) {
	switch GOOS {
	case "darwin", "ios", "windows":
		// Non-ELF shared libraries don't support the multiple
		// copies of the runtime package implied by this test.
		t.Skipf("linking c-shared into Go programs not supported on %s; issue 29061, 49457", GOOS)
	case "android":
		t.Skip("test fails on android; issue 29087")
	}
	globalSkip(t)
	testenv.MustHaveGoBuild(t)
	testenv.MustHaveCGO(t)
	testenv.MustHaveBuildMode(t, "c-shared")

	t.Parallel()

	tmpdir, err := os.MkdirTemp("", "cshared-TestGo2C2Go")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)

	lib := filepath.Join(tmpdir, "libtestgo2c2go.a")
	var env []string
	if GOOS == "windows" && strings.HasSuffix(lib, ".a") {
		env = append(env, "CGO_LDFLAGS=-Wl,--out-implib,"+lib, "CGO_LDFLAGS_ALLOW=.*")
		lib = strings.TrimSuffix(lib, ".a") + ".dll"
	}
	run(t, env, "go", "build", "-buildmode=c-shared", "-o", lib, "./go2c2go/go")

	cgoCflags := os.Getenv("CGO_CFLAGS")
	if cgoCflags != "" {
		cgoCflags += " "
	}
	cgoCflags += "-I" + tmpdir

	cgoLdflags := os.Getenv("CGO_LDFLAGS")
	if cgoLdflags != "" {
		cgoLdflags += " "
	}
	cgoLdflags += "-L" + tmpdir + " -ltestgo2c2go"

	goenv := []string{"CGO_CFLAGS=" + cgoCflags, "CGO_LDFLAGS=" + cgoLdflags}

	ldLibPath := os.Getenv("LD_LIBRARY_PATH")
	if ldLibPath != "" {
		ldLibPath += ":"
	}
	ldLibPath += tmpdir

	runenv := []string{"LD_LIBRARY_PATH=" + ldLibPath}

	bin := filepath.Join(tmpdir, "m1") + exeSuffix
	run(t, goenv, "go", "build", "-o", bin, "./go2c2go/m1")
	runExe(t, runenv, bin)

	bin = filepath.Join(tmpdir, "m2") + exeSuffix
	run(t, goenv, "go", "build", "-o", bin, "./go2c2go/m2")
	runExe(t, runenv, bin)
}

func TestIssue36233(t *testing.T) {
	globalSkip(t)
	testenv.MustHaveCGO(t)

	t.Parallel()

	// Test that the export header uses GoComplex64 and GoComplex128
	// for complex types.

	tmpdir, err := os.MkdirTemp("", "cshared-TestIssue36233")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)

	const exportHeader = "issue36233.h"

	run(t, nil, "go", "tool", "cgo", "-exportheader", exportHeader, "-objdir", tmpdir, "./issue36233/issue36233.go")
	data, err := os.ReadFile(exportHeader)
	if err != nil {
		t.Fatal(err)
	}

	funcs := []struct{ name, signature string }{
		{"exportComplex64", "GoComplex64 exportComplex64(GoComplex64 v)"},
		{"exportComplex128", "GoComplex128 exportComplex128(GoComplex128 v)"},
		{"exportComplexfloat", "GoComplex64 exportComplexfloat(GoComplex64 v)"},
		{"exportComplexdouble", "GoComplex128 exportComplexdouble(GoComplex128 v)"},
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	var found int
	for scanner.Scan() {
		b := scanner.Bytes()
		for _, fn := range funcs {
			if bytes.Contains(b, []byte(fn.name)) {
				found++
				if !bytes.Contains(b, []byte(fn.signature)) {
					t.Errorf("function signature mismatch; got %q, want %q", b, fn.signature)
				}
			}
		}
	}
	if err = scanner.Err(); err != nil {
		t.Errorf("scanner encountered error: %v", err)
	}
	if found != len(funcs) {
		t.Error("missing functions")
	}
}

"""



```