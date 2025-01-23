Response:
My thinking process to analyze the Go code and fulfill the request goes like this:

1. **Understand the Goal:** The request asks for a functional overview of the `carchive_test.go` file, along with explanations of the Go features it utilizes, code examples, command-line argument handling, and potential pitfalls.

2. **High-Level Scan:**  I first skim the code to get a general sense of its purpose. Keywords like `test`, `cgo`, `buildmode`, `c-archive`, `signal`, `elf`, and the import paths (`cmd/cgo/internal/cgotest`, `debug/elf`, `syscall`) immediately suggest that this file is testing the `c-archive` build mode of the `cgo` tool. This build mode allows compiling Go code into a static C library archive (`.a` file).

3. **Identify Core Functionality:** Based on the imports and the test function names (e.g., `TestInstall`, `TestEarlySignalHandler`, `TestSignalForwarding`), I can deduce the key areas being tested:
    * **Installation/Building of C Archives:**  Verifying the process of creating `.a` and `.h` files using `go build -buildmode=c-archive`.
    * **Interaction with C Code:**  Testing how the generated C archive interacts with C code (e.g., linking, calling Go functions from C).
    * **Signal Handling:** Specifically testing signal handling in the context of a C archive (early signal handlers, signal forwarding from C to Go and vice-versa).
    * **ELF Archive Structure:** Checking the structure of the generated `.a` files (especially on Linux-like systems).
    * **Other `cgo` Features:** Exploring features like `-extar`, PIE (Position Independent Executables), and more advanced scenarios like deep stacks and many calls.

4. **Analyze Key Functions:** I then dive deeper into the important functions:
    * `TestMain`:  Handles setup like creating a temporary `GOPATH`, setting environment variables, and parsing flags. The `-testwork` flag is a key element here.
    * `testInstall`: This function seems to be a helper for the common scenario of building a C archive, compiling a C program that links against it, and then running the resulting executable.
    * `genHeader`: Clearly responsible for generating the C header file from Go source code using `go tool cgo`.
    * `checkArchive` and `checkELFArchive`: These functions validate the structure of the generated archive file. The ELF-specific checks confirm the correct section types within the object files in the archive.
    * The various `Test...` functions each focus on a specific aspect of `c-archive`.

5. **Infer Go Feature Usage:**  Based on the identified functionalities, I can pinpoint the Go features being exercised:
    * **`cgo`:**  The central feature under test. The `//go:build unix || windows` constraint and the import of `cmd/cgo/internal/cgotest` confirm this.
    * **`buildmode=c-archive`:**  The core build mode being validated.
    * **`go build` and `go install`:** Used to build the C archives.
    * **`os/exec`:**  Essential for running Go and C compiler commands.
    * **`syscall`:**  Used extensively for signal testing.
    * **`debug/elf`:**  For inspecting the structure of ELF archive files.
    * **Testing Framework:** The `testing` package provides the structure for the tests.

6. **Construct Code Examples:** For the identified Go features, I craft simple code examples to illustrate their use in the context of `c-archive`. For instance, demonstrating how `go build -buildmode=c-archive` generates the `.a` and `.h` files.

7. **Identify Command-Line Arguments:**  I carefully examine the `TestMain` function to find how command-line arguments are parsed. The `-testwork` flag is the main one here. I explain its purpose and how it affects the test execution. I also note the use of `go env` to fetch compiler and environment settings.

8. **Deduce Input/Output and Make Assumptions:**  For code examples involving compilation and execution, I make reasonable assumptions about the input Go and C source files (e.g., `libgo/libgo.go`, `main.c`). I then describe the expected output, such as the creation of `.a`, `.h`, and executable files.

9. **Identify Potential Pitfalls:** Based on my understanding of `cgo` and the test code, I consider common issues developers might encounter:
    * **Incorrect `GOPATH` setup:** `cgo` relies on a correctly configured `GOPATH`.
    * **Missing C compiler:**  A C compiler is required to link against the generated archive.
    * **Platform-specific issues:** The code explicitly skips tests on certain platforms, indicating potential platform dependencies.
    * **Signal handling complexities:** Signal handling can be tricky, especially when mixing C and Go. The tests themselves highlight these complexities.

10. **Structure the Output:** Finally, I organize my findings into the requested sections: Functionality, Go Feature Implementation, Code Examples, Command-Line Arguments, and Potential Pitfalls. I use clear and concise language, providing specific details and examples where needed.

By following these steps, I can systematically analyze the provided Go code, extract the relevant information, and present it in a comprehensive and easy-to-understand manner. This process involves a combination of code reading, understanding Go concepts, and making logical inferences based on the code's structure and behavior.
这段代码是 Go 语言标准库中 `cmd/cgo` 工具的一个测试文件，专门用于测试 `c-archive` 构建模式的功能。 `c-archive` 构建模式允许将 Go 代码编译成一个 C 静态库（`.a` 文件）。

下面详细列举一下它的功能：

**主要功能：测试 `go build -buildmode=c-archive` 的各种场景和特性。**

**具体测试点包括：**

1. **基本的 C 静态库生成和安装:**
   - 测试能否使用 `go install -buildmode=c-archive` 命令将 Go 代码编译成 C 静态库 (`.a`) 和对应的头文件 (`.h`)。
   - 测试使用 `go build -buildmode=c-archive` 命令构建 C 静态库。
   - 测试使用 `-o` 参数指定输出文件名。

2. **生成的头文件内容检查:**
   - 检查生成的头文件 (`.h`) 中 `#line` 指令是否包含绝对路径。避免因 GOPATH 的不同导致头文件内容变化。

3. **生成的静态库内容检查:**
   - 对于支持 ELF 格式的操作系统（Linux 等），检查生成的静态库 (`.a`) 的内部结构，包括 magic number、文件头、以及包含的 ELF 目标文件的 section 类型是否正确（如 `.text`, `.data`, `.bss`, `.symtab`, `.strtab` 等）。

4. **C 代码与 Go 静态库的链接和交互:**
   - 测试 C 代码能否链接到生成的 Go 静态库。
   - 测试 C 代码能否调用 Go 语言导出的函数。
   - 通过运行链接了 Go 静态库的 C 可执行文件，验证其功能是否正常。

5. **信号处理 (Signal Handling):**
   - **早期信号处理 (Early Signal Handler):** 测试在 C 代码中设置的信号处理函数能否在 Go runtime 初始化之前被调用。
   - **信号转发 (Signal Forwarding):** 测试从 C 代码发送的信号能否正确地传递到 Go runtime，并导致 Go 程序终止。
   - **外部信号转发 (Signal Forwarding External):** 测试从外部进程发送的信号能否被 Go runtime 正确处理。
   - **Go 发送信号 (Signal Forwarding Go):** 测试在 Go 代码中触发信号，能否被 C 代码捕获或导致程序终止。
   - **`os/signal` 包的使用:** 测试在 C 静态库中集成使用 Go 的 `os/signal` 包的功能。
   - **`sigaltstack` 的使用:** 测试在 C 静态库中使用 `sigaltstack` 设置备用信号栈的功能。

6. **外部链接器 (External Linker) 的使用:**
   - 测试使用 `-ldflags=-extar=...` 参数指定外部链接器来处理静态库的链接过程。

7. **PIE (Position Independent Executable) 支持:**
   - 测试生成的 C 静态库能否用于构建 PIE 可执行文件，并验证生成的可执行文件不包含 `DT_TEXTREL` 标志。

8. **性能测试:**
   - 通过 Benchmark 测量从 C 主线程回调 Go 函数的性能。

9. **共享对象 (Shared Object) 的构建:**
   - 测试能否将生成的 Go `c-archive` 静态库打包到 C 的共享对象 (`.so` 或 `.dylib`) 中。

10. **编译时不使用 `-shared` 选项:**
    - 测试在不使用 `-shared` 选项的情况下编译 Go 代码，然后将其放入静态库中是否可行。这模拟了 Bazel 等构建工具的行为。

11. **缓存安装测试:**
    - 测试多次安装同一个 `c-archive` 库，确保头文件被正确地重新生成。

12. **压力测试:**
    - 测试大量 C 调用 Go 函数的场景。
    - 测试 Go 程序的抢占式调度在作为 C 静态库时是否正常工作。

13. **栈空间测试:**
    - 测试在 C 代码中以较大的栈空间调用 Go 函数是否会导致问题。

**Go 语言功能实现举例 (以 `go build -buildmode=c-archive` 为例):**

假设有以下 Go 代码文件 `libgo/libgo.go`:

```go
package libgo

import "C"

//export SayHello
func SayHello() {
	println("Hello from Go!")
}

//export Add
func Add(a, b int) int {
	return a + b
}
```

要将其编译成 C 静态库，可以在 `libgo` 目录的父级目录执行命令：

```bash
go build -buildmode=c-archive -o libgo.a ./libgo
```

**假设输入：** 包含上述 `libgo.go` 文件的 `libgo` 目录。

**输出：**

- 在当前目录下生成 `libgo.a` 文件 (C 静态库)。
- 在当前目录下生成 `libgo.h` 文件 (C 头文件)，内容可能如下：

```c
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

extern void SayHello(void);
extern int32_t Add(int32_t a, int32_t b);

#ifdef __cplusplus
}
#endif
```

**命令行参数的具体处理：**

该测试文件本身主要关注 `go build` 和 `go install` 命令的 `-buildmode=c-archive` 选项。

- **`-buildmode=c-archive`:** 这是核心选项，指示 `go build` 将 Go 代码编译成 C 静态库。
- **`-o <filename>`:**  用于指定输出的静态库文件名（例如 `libgo.a`）。
- **`go install`:**  在 `-buildmode=c-archive` 模式下，会将生成的静态库和头文件安装到 `$GOPATH/pkg/<GOOS>_<GOARCH>/<package_path>` 目录下。
- **`-ldflags=-extar=<path>`:** 用于指定外部链接器的路径。
- **`-gcflags=-shared=false`:**  用于覆盖默认的 `-shared` 编译选项。
- **`-testwork` flag:**  该测试文件自身定义了一个 `-testwork` 标志，用于控制是否保留测试过程中创建的临时目录。如果设置为 true，测试完成后不会删除临时目录，方便调试。

**使用者易犯错的点：**

1. **缺少 C 编译器:**  使用 `c-archive` 构建模式生成的静态库需要使用 C 编译器（如 gcc 或 clang）进行链接。如果系统中没有安装 C 编译器，链接过程会失败。

   **示例：** 如果尝试链接 `libgo.a` 但系统中没有 gcc，可能会出现类似 "gcc: command not found" 的错误。

2. **`GOPATH` 设置不正确:** `go build` 和 `go install` 命令依赖于正确的 `GOPATH` 环境变量。如果 `GOPATH` 未设置或设置不正确，可能导致找不到依赖包或安装路径错误。

   **示例：** 如果 `GOPATH` 没有设置，执行 `go install -buildmode=c-archive ./libgo` 可能会报错，提示找不到 `libgo` 包。

3. **平台兼容性问题:**  生成的 C 静态库通常是平台相关的（与操作系统和 CPU 架构有关）。在一个平台上生成的静态库可能无法在另一个平台上使用。

   **示例：** 在 Linux 上生成的 `libgo.a` 文件不能直接在 Windows 上链接使用。

4. **头文件路径问题:**  在 C 代码中包含 Go 生成的头文件时，需要确保头文件的路径设置正确。C 编译器可能无法找到头文件。

   **示例：** 如果生成的 `libgo.h` 不在 C 代码的 include 路径中，编译 C 代码时会报错，提示找不到 `libgo.h` 文件。

5. **信号处理的复杂性:**  在混合使用 C 和 Go 的程序中处理信号可能比较复杂，需要理解 C 和 Go runtime 的信号处理机制，避免冲突或意外行为。

   **示例：**  如果在 C 代码和 Go 代码中都注册了同一个信号的处理函数，可能会出现未定义的行为。

总而言之，`carchive_test.go` 是一个非常全面的测试文件，它涵盖了 `go build -buildmode=c-archive` 功能的各个方面，确保该功能的稳定性和正确性，并帮助开发者理解其工作原理和潜在的使用场景。

### 提示词
```
这是路径为go/src/cmd/cgo/internal/testcarchive/carchive_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This test uses various syscall.SIG* constants that are defined on Unix
// platforms and Windows.

//go:build unix || windows

package carchive_test

import (
	"bufio"
	"bytes"
	"cmd/cgo/internal/cgotest"
	"debug/elf"
	"flag"
	"fmt"
	"internal/testenv"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unicode"
)

var globalSkip = func(t testing.TB) {}

// Program to run.
var bin []string

// C compiler with args (from $(go env CC) $(go env GOGCCFLAGS)).
var cc []string

// ".exe" on Windows.
var exeSuffix string

var GOOS, GOARCH, GOPATH string
var libgodir string

var testWork bool // If true, preserve temporary directories.

func TestMain(m *testing.M) {
	flag.BoolVar(&testWork, "testwork", false, "if true, log and preserve the test's temporary working directory")
	flag.Parse()

	log.SetFlags(log.Lshortfile)
	os.Exit(testMain(m))
}

func testMain(m *testing.M) int {
	if testing.Short() && os.Getenv("GO_BUILDER_NAME") == "" {
		globalSkip = func(t testing.TB) { t.Skip("short mode and $GO_BUILDER_NAME not set") }
		return m.Run()
	}
	if runtime.GOOS == "linux" {
		if _, err := os.Stat("/etc/alpine-release"); err == nil {
			globalSkip = func(t testing.TB) { t.Skip("skipping failing test on alpine - go.dev/issue/19938") }
			return m.Run()
		}
	}

	// We need a writable GOPATH in which to run the tests.
	// Construct one in a temporary directory.
	var err error
	GOPATH, err = os.MkdirTemp("", "carchive_test")
	if err != nil {
		log.Panic(err)
	}
	if testWork {
		log.Println(GOPATH)
	} else {
		defer os.RemoveAll(GOPATH)
	}
	os.Setenv("GOPATH", GOPATH)

	// Copy testdata into GOPATH/src/testarchive, along with a go.mod file
	// declaring the same path.
	modRoot := filepath.Join(GOPATH, "src", "testcarchive")
	if err := cgotest.OverlayDir(modRoot, "testdata"); err != nil {
		log.Panic(err)
	}
	if err := os.Chdir(modRoot); err != nil {
		log.Panic(err)
	}
	os.Setenv("PWD", modRoot)
	if err := os.WriteFile("go.mod", []byte("module testcarchive\n"), 0666); err != nil {
		log.Panic(err)
	}

	GOOS = goEnv("GOOS")
	GOARCH = goEnv("GOARCH")
	bin = cmdToRun("./testp")

	ccOut := goEnv("CC")
	cc = []string{string(ccOut)}

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

	if GOOS == "aix" {
		// -Wl,-bnoobjreorder is mandatory to keep the same layout
		// in .text section.
		cc = append(cc, "-Wl,-bnoobjreorder")
	}
	if GOOS == "ios" {
		// Linking runtime/cgo on ios requires the CoreFoundation framework because
		// x_cgo_init uses CoreFoundation APIs to switch directory to the app root.
		//
		// TODO(#58225): This special case probably should not be needed.
		// runtime/cgo is a very low-level package, and should not provide
		// high-level behaviors like changing the current working directory at init.
		cc = append(cc, "-framework", "CoreFoundation")
	}
	libbase := GOOS + "_" + GOARCH
	if runtime.Compiler == "gccgo" {
		libbase = "gccgo_" + libgodir + "_fPIC"
	} else {
		switch GOOS {
		case "darwin", "ios":
			if GOARCH == "arm64" {
				libbase += "_shared"
			}
		case "dragonfly", "freebsd", "linux", "netbsd", "openbsd", "solaris", "illumos":
			libbase += "_shared"
		}
	}
	libgodir = filepath.Join(GOPATH, "pkg", libbase, "testcarchive")
	cc = append(cc, "-I", libgodir)

	// Force reallocation (and avoid aliasing bugs) for parallel tests that append to cc.
	cc = cc[:len(cc):len(cc)]

	if GOOS == "windows" {
		exeSuffix = ".exe"
	}

	return m.Run()
}

func goEnv(key string) string {
	out, err := exec.Command("go", "env", key).Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			fmt.Fprintf(os.Stderr, "%s", ee.Stderr)
		}
		log.Panicf("go env %s failed:\n%s\n", key, err)
	}
	return strings.TrimSpace(string(out))
}

func cmdToRun(name string) []string {
	execScript := "go_" + goEnv("GOOS") + "_" + goEnv("GOARCH") + "_exec"
	executor, err := exec.LookPath(execScript)
	if err != nil {
		return []string{name}
	}
	return []string{executor, name}
}

// genHeader writes a C header file for the C-exported declarations found in .go
// source files in dir.
//
// TODO(golang.org/issue/35715): This should be simpler.
func genHeader(t *testing.T, header, dir string) {
	t.Helper()

	// The 'cgo' command generates a number of additional artifacts,
	// but we're only interested in the header.
	// Shunt the rest of the outputs to a temporary directory.
	objDir, err := os.MkdirTemp(GOPATH, "_obj")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(objDir)

	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("go", "tool", "cgo",
		"-objdir", objDir,
		"-exportheader", header)
	cmd.Args = append(cmd.Args, files...)
	t.Log(cmd.Args)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Logf("%s", out)
		t.Fatal(err)
	}
}

func testInstall(t *testing.T, exe, libgoa, libgoh string, buildcmd ...string) {
	t.Helper()
	cmd := exec.Command(buildcmd[0], buildcmd[1:]...)
	cmd.Env = append(cmd.Environ(), "GO111MODULE=off") // 'go install' only works in GOPATH mode
	t.Log(buildcmd)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Logf("%s", out)
		t.Fatal(err)
	}
	if !testWork {
		defer func() {
			os.Remove(libgoa)
			os.Remove(libgoh)
		}()
	}

	ccArgs := append(cc, "-o", exe, "main.c")
	if GOOS == "windows" {
		ccArgs = append(ccArgs, "main_windows.c", libgoa, "-lntdll", "-lws2_32", "-lwinmm")
	} else {
		ccArgs = append(ccArgs, "main_unix.c", libgoa)
	}
	if runtime.Compiler == "gccgo" {
		ccArgs = append(ccArgs, "-lgo")
	}
	t.Log(ccArgs)
	if out, err := exec.Command(ccArgs[0], ccArgs[1:]...).CombinedOutput(); err != nil {
		t.Logf("%s", out)
		t.Fatal(err)
	}
	if !testWork {
		defer os.Remove(exe)
	}

	binArgs := append(cmdToRun(exe), "arg1", "arg2")
	cmd = exec.Command(binArgs[0], binArgs[1:]...)
	if runtime.Compiler == "gccgo" {
		cmd.Env = append(cmd.Environ(), "GCCGO=1")
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Logf("%s", out)
		t.Fatal(err)
	}

	checkLineComments(t, libgoh)
}

var badLineRegexp = regexp.MustCompile(`(?m)^#line [0-9]+ "/.*$`)

// checkLineComments checks that the export header generated by
// -buildmode=c-archive doesn't have any absolute paths in the #line
// comments. We don't want those paths because they are unhelpful for
// the user and make the files change based on details of the location
// of GOPATH.
func checkLineComments(t *testing.T, hdrname string) {
	hdr, err := os.ReadFile(hdrname)
	if err != nil {
		if !os.IsNotExist(err) {
			t.Error(err)
		}
		return
	}
	if line := badLineRegexp.Find(hdr); line != nil {
		t.Errorf("bad #line directive with absolute path in %s: %q", hdrname, line)
	}
}

// checkArchive verifies that the created library looks OK.
// We just check a couple of things now, we can add more checks as needed.
func checkArchive(t *testing.T, arname string) {
	t.Helper()

	switch GOOS {
	case "aix", "darwin", "ios", "windows":
		// We don't have any checks for non-ELF libraries yet.
		if _, err := os.Stat(arname); err != nil {
			t.Errorf("archive %s does not exist: %v", arname, err)
		}
	default:
		checkELFArchive(t, arname)
	}
}

// checkELFArchive checks an ELF archive.
func checkELFArchive(t *testing.T, arname string) {
	t.Helper()

	f, err := os.Open(arname)
	if err != nil {
		t.Errorf("archive %s does not exist: %v", arname, err)
		return
	}
	defer f.Close()

	// TODO(iant): put these in a shared package?  But where?
	const (
		magic = "!<arch>\n"
		fmag  = "`\n"

		namelen = 16
		datelen = 12
		uidlen  = 6
		gidlen  = 6
		modelen = 8
		sizelen = 10
		fmaglen = 2
		hdrlen  = namelen + datelen + uidlen + gidlen + modelen + sizelen + fmaglen
	)

	type arhdr struct {
		name string
		date string
		uid  string
		gid  string
		mode string
		size string
		fmag string
	}

	var magbuf [len(magic)]byte
	if _, err := io.ReadFull(f, magbuf[:]); err != nil {
		t.Errorf("%s: archive too short", arname)
		return
	}
	if string(magbuf[:]) != magic {
		t.Errorf("%s: incorrect archive magic string %q", arname, magbuf)
	}

	off := int64(len(magic))
	for {
		if off&1 != 0 {
			var b [1]byte
			if _, err := f.Read(b[:]); err != nil {
				if err == io.EOF {
					break
				}
				t.Errorf("%s: error skipping alignment byte at %d: %v", arname, off, err)
			}
			off++
		}

		var hdrbuf [hdrlen]byte
		if _, err := io.ReadFull(f, hdrbuf[:]); err != nil {
			if err == io.EOF {
				break
			}
			t.Errorf("%s: error reading archive header at %d: %v", arname, off, err)
			return
		}

		var hdr arhdr
		hdrslice := hdrbuf[:]
		set := func(len int, ps *string) {
			*ps = string(bytes.TrimSpace(hdrslice[:len]))
			hdrslice = hdrslice[len:]
		}
		set(namelen, &hdr.name)
		set(datelen, &hdr.date)
		set(uidlen, &hdr.uid)
		set(gidlen, &hdr.gid)
		set(modelen, &hdr.mode)
		set(sizelen, &hdr.size)
		hdr.fmag = string(hdrslice[:fmaglen])
		hdrslice = hdrslice[fmaglen:]
		if len(hdrslice) != 0 {
			t.Fatalf("internal error: len(hdrslice) == %d", len(hdrslice))
		}

		if hdr.fmag != fmag {
			t.Errorf("%s: invalid fmagic value %q at %d", arname, hdr.fmag, off)
			return
		}

		size, err := strconv.ParseInt(hdr.size, 10, 64)
		if err != nil {
			t.Errorf("%s: error parsing size %q at %d: %v", arname, hdr.size, off, err)
			return
		}

		off += hdrlen

		switch hdr.name {
		case "__.SYMDEF", "/", "/SYM64/":
			// The archive symbol map.
		case "//", "ARFILENAMES/":
			// The extended name table.
		default:
			// This should be an ELF object.
			checkELFArchiveObject(t, arname, off, io.NewSectionReader(f, off, size))
		}

		off += size
		if _, err := f.Seek(off, io.SeekStart); err != nil {
			t.Errorf("%s: failed to seek to %d: %v", arname, off, err)
		}
	}
}

// checkELFArchiveObject checks an object in an ELF archive.
func checkELFArchiveObject(t *testing.T, arname string, off int64, obj io.ReaderAt) {
	t.Helper()

	ef, err := elf.NewFile(obj)
	if err != nil {
		t.Errorf("%s: failed to open ELF file at %d: %v", arname, off, err)
		return
	}
	defer ef.Close()

	// Verify section types.
	for _, sec := range ef.Sections {
		want := elf.SHT_NULL
		switch sec.Name {
		case ".text", ".data":
			want = elf.SHT_PROGBITS
		case ".bss":
			want = elf.SHT_NOBITS
		case ".symtab":
			want = elf.SHT_SYMTAB
		case ".strtab":
			want = elf.SHT_STRTAB
		case ".init_array":
			want = elf.SHT_INIT_ARRAY
		case ".fini_array":
			want = elf.SHT_FINI_ARRAY
		case ".preinit_array":
			want = elf.SHT_PREINIT_ARRAY
		}
		if want != elf.SHT_NULL && sec.Type != want {
			t.Errorf("%s: incorrect section type in elf file at %d for section %q: got %v want %v", arname, off, sec.Name, sec.Type, want)
		}
	}
}

func TestInstall(t *testing.T) {
	globalSkip(t)
	testenv.MustHaveGoBuild(t)
	testenv.MustHaveCGO(t)
	testenv.MustHaveBuildMode(t, "c-archive")

	if !testWork {
		defer os.RemoveAll(filepath.Join(GOPATH, "pkg"))
	}

	libgoa := "libgo.a"
	if runtime.Compiler == "gccgo" {
		libgoa = "liblibgo.a"
	}

	// Generate the p.h header file.
	//
	// 'go install -i -buildmode=c-archive ./libgo' would do that too, but that
	// would also attempt to install transitive standard-library dependencies to
	// GOROOT, and we cannot assume that GOROOT is writable. (A non-root user may
	// be running this test in a GOROOT owned by root.)
	genHeader(t, "p.h", "./p")

	testInstall(t, "./testp1"+exeSuffix,
		filepath.Join(libgodir, libgoa),
		filepath.Join(libgodir, "libgo.h"),
		"go", "install", "-buildmode=c-archive", "./libgo")

	// Test building libgo other than installing it.
	// Header files are now present.
	testInstall(t, "./testp2"+exeSuffix, "libgo.a", "libgo.h",
		"go", "build", "-buildmode=c-archive", filepath.Join(".", "libgo", "libgo.go"))

	testInstall(t, "./testp3"+exeSuffix, "libgo.a", "libgo.h",
		"go", "build", "-buildmode=c-archive", "-o", "libgo.a", "./libgo")
}

func TestEarlySignalHandler(t *testing.T) {
	switch GOOS {
	case "darwin", "ios":
		switch GOARCH {
		case "arm64":
			t.Skipf("skipping on %s/%s; see https://golang.org/issue/13701", GOOS, GOARCH)
		}
	case "windows":
		t.Skip("skipping signal test on Windows")
	}
	globalSkip(t)
	testenv.MustHaveGoBuild(t)
	testenv.MustHaveCGO(t)
	testenv.MustHaveBuildMode(t, "c-archive")

	if !testWork {
		defer func() {
			os.Remove("libgo2.a")
			os.Remove("libgo2.h")
			os.Remove("testp" + exeSuffix)
			os.RemoveAll(filepath.Join(GOPATH, "pkg"))
		}()
	}

	cmd := exec.Command("go", "build", "-buildmode=c-archive", "-o", "libgo2.a", "./libgo2")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Logf("%s", out)
		t.Fatal(err)
	}
	checkLineComments(t, "libgo2.h")
	checkArchive(t, "libgo2.a")

	ccArgs := append(cc, "-o", "testp"+exeSuffix, "main2.c", "libgo2.a")
	if runtime.Compiler == "gccgo" {
		ccArgs = append(ccArgs, "-lgo")
	}
	if out, err := exec.Command(ccArgs[0], ccArgs[1:]...).CombinedOutput(); err != nil {
		t.Logf("%s", out)
		t.Fatal(err)
	}

	darwin := "0"
	if runtime.GOOS == "darwin" {
		darwin = "1"
	}
	cmd = exec.Command(bin[0], append(bin[1:], darwin)...)

	if out, err := cmd.CombinedOutput(); err != nil {
		t.Logf("%s", out)
		t.Fatal(err)
	}
}

func TestSignalForwarding(t *testing.T) {
	globalSkip(t)
	checkSignalForwardingTest(t)
	buildSignalForwardingTest(t)

	cmd := exec.Command(bin[0], append(bin[1:], "1")...)

	out, err := cmd.CombinedOutput()
	t.Logf("%v\n%s", cmd.Args, out)
	expectSignal(t, err, syscall.SIGSEGV, 0)

	// SIGPIPE is never forwarded on darwin. See golang.org/issue/33384.
	if runtime.GOOS != "darwin" && runtime.GOOS != "ios" {
		// Test SIGPIPE forwarding
		cmd = exec.Command(bin[0], append(bin[1:], "3")...)

		out, err = cmd.CombinedOutput()
		if len(out) > 0 {
			t.Logf("%s", out)
		}
		expectSignal(t, err, syscall.SIGPIPE, 0)
	}
}

func TestSignalForwardingExternal(t *testing.T) {
	if GOOS == "freebsd" || GOOS == "aix" {
		t.Skipf("skipping on %s/%s; signal always goes to the Go runtime", GOOS, GOARCH)
	} else if GOOS == "darwin" && GOARCH == "amd64" {
		t.Skipf("skipping on %s/%s: runtime does not permit SI_USER SIGSEGV", GOOS, GOARCH)
	}
	globalSkip(t)
	checkSignalForwardingTest(t)
	buildSignalForwardingTest(t)

	// We want to send the process a signal and see if it dies.
	// Normally the signal goes to the C thread, the Go signal
	// handler picks it up, sees that it is running in a C thread,
	// and the program dies. Unfortunately, occasionally the
	// signal is delivered to a Go thread, which winds up
	// discarding it because it was sent by another program and
	// there is no Go handler for it. To avoid this, run the
	// program several times in the hopes that it will eventually
	// fail.
	const tries = 20
	for i := 0; i < tries; i++ {
		err := runSignalForwardingTest(t, "2")
		if err == nil {
			continue
		}

		// If the signal is delivered to a C thread, as expected,
		// the Go signal handler will disable itself and re-raise
		// the signal, causing the program to die with SIGSEGV.
		//
		// It is also possible that the signal will be
		// delivered to a Go thread, such as a GC thread.
		// Currently when the Go runtime sees that a SIGSEGV was
		// sent from a different program, it first tries to send
		// the signal to the os/signal API. If nothing is looking
		// for (or explicitly ignoring) SIGSEGV, then it crashes.
		// Because the Go runtime is invoked via a c-archive,
		// it treats this as GOTRACEBACK=crash, meaning that it
		// dumps a stack trace for all goroutines, which it does
		// by raising SIGQUIT. The effect is that we will see the
		// program die with SIGQUIT in that case, not SIGSEGV.
		if expectSignal(t, err, syscall.SIGSEGV, syscall.SIGQUIT) {
			return
		}
	}

	t.Errorf("program succeeded unexpectedly %d times", tries)
}

func TestSignalForwardingGo(t *testing.T) {
	// This test fails on darwin-amd64 because of the special
	// handling of user-generated SIGSEGV signals in fixsigcode in
	// runtime/signal_darwin_amd64.go.
	if runtime.GOOS == "darwin" && runtime.GOARCH == "amd64" {
		t.Skip("not supported on darwin-amd64")
	}
	globalSkip(t)

	checkSignalForwardingTest(t)
	buildSignalForwardingTest(t)
	err := runSignalForwardingTest(t, "4")

	// Occasionally the signal will be delivered to a C thread,
	// and the program will crash with SIGSEGV.
	expectSignal(t, err, syscall.SIGQUIT, syscall.SIGSEGV)
}

// checkSignalForwardingTest calls t.Skip if the SignalForwarding test
// doesn't work on this platform.
func checkSignalForwardingTest(t *testing.T) {
	switch GOOS {
	case "darwin", "ios":
		switch GOARCH {
		case "arm64":
			t.Skipf("skipping on %s/%s; see https://golang.org/issue/13701", GOOS, GOARCH)
		}
	case "windows":
		t.Skip("skipping signal test on Windows")
	}
	testenv.MustHaveGoBuild(t)
	testenv.MustHaveCGO(t)
	testenv.MustHaveBuildMode(t, "c-archive")
}

// buildSignalForwardingTest builds the executable used by the various
// signal forwarding tests.
func buildSignalForwardingTest(t *testing.T) {
	if !testWork {
		t.Cleanup(func() {
			os.Remove("libgo2.a")
			os.Remove("libgo2.h")
			os.Remove("testp" + exeSuffix)
			os.RemoveAll(filepath.Join(GOPATH, "pkg"))
		})
	}

	t.Log("go build -buildmode=c-archive -o libgo2.a ./libgo2")
	cmd := exec.Command("go", "build", "-buildmode=c-archive", "-o", "libgo2.a", "./libgo2")
	out, err := cmd.CombinedOutput()
	if len(out) > 0 {
		t.Logf("%s", out)
	}
	if err != nil {
		t.Fatal(err)
	}

	checkLineComments(t, "libgo2.h")
	checkArchive(t, "libgo2.a")

	ccArgs := append(cc, "-o", "testp"+exeSuffix, "main5.c", "libgo2.a")
	if runtime.Compiler == "gccgo" {
		ccArgs = append(ccArgs, "-lgo")
	}
	t.Log(ccArgs)
	out, err = exec.Command(ccArgs[0], ccArgs[1:]...).CombinedOutput()
	if len(out) > 0 {
		t.Logf("%s", out)
	}
	if err != nil {
		t.Fatal(err)
	}
}

func runSignalForwardingTest(t *testing.T, arg string) error {
	t.Logf("%v %s", bin, arg)
	cmd := exec.Command(bin[0], append(bin[1:], arg)...)

	var out strings.Builder
	cmd.Stdout = &out

	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stderr.Close()

	r := bufio.NewReader(stderr)

	err = cmd.Start()
	if err != nil {
		t.Fatal(err)
	}

	// Wait for trigger to ensure that process is started.
	ok, err := r.ReadString('\n')

	// Verify trigger.
	if err != nil || ok != "OK\n" {
		t.Fatal("Did not receive OK signal")
	}

	var wg sync.WaitGroup
	wg.Add(1)
	var errsb strings.Builder
	go func() {
		defer wg.Done()
		io.Copy(&errsb, r)
	}()

	// Give the program a chance to enter the function.
	// If the program doesn't get there the test will still
	// pass, although it doesn't quite test what we intended.
	// This is fine as long as the program normally makes it.
	time.Sleep(time.Millisecond)

	cmd.Process.Signal(syscall.SIGSEGV)

	err = cmd.Wait()

	s := out.String()
	if len(s) > 0 {
		t.Log(s)
	}
	wg.Wait()
	s = errsb.String()
	if len(s) > 0 {
		t.Log(s)
	}

	return err
}

// expectSignal checks that err, the exit status of a test program,
// shows a failure due to a specific signal or two. Returns whether we
// found an expected signal.
func expectSignal(t *testing.T, err error, sig1, sig2 syscall.Signal) bool {
	t.Helper()
	if err == nil {
		t.Error("test program succeeded unexpectedly")
	} else if ee, ok := err.(*exec.ExitError); !ok {
		t.Errorf("error (%v) has type %T; expected exec.ExitError", err, err)
	} else if ws, ok := ee.Sys().(syscall.WaitStatus); !ok {
		t.Errorf("error.Sys (%v) has type %T; expected syscall.WaitStatus", ee.Sys(), ee.Sys())
	} else if !ws.Signaled() || (ws.Signal() != sig1 && ws.Signal() != sig2) {
		if sig2 == 0 {
			t.Errorf("got %q; expected signal %q", ee, sig1)
		} else {
			t.Errorf("got %q; expected signal %q or %q", ee, sig1, sig2)
		}
	} else {
		return true
	}
	return false
}

func TestOsSignal(t *testing.T) {
	switch GOOS {
	case "windows":
		t.Skip("skipping signal test on Windows")
	}
	globalSkip(t)
	testenv.MustHaveGoBuild(t)
	testenv.MustHaveCGO(t)
	testenv.MustHaveBuildMode(t, "c-archive")

	if !testWork {
		defer func() {
			os.Remove("libgo3.a")
			os.Remove("libgo3.h")
			os.Remove("testp" + exeSuffix)
			os.RemoveAll(filepath.Join(GOPATH, "pkg"))
		}()
	}

	cmd := exec.Command("go", "build", "-buildmode=c-archive", "-o", "libgo3.a", "./libgo3")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Logf("%s", out)
		t.Fatal(err)
	}
	checkLineComments(t, "libgo3.h")
	checkArchive(t, "libgo3.a")

	ccArgs := append(cc, "-o", "testp"+exeSuffix, "main3.c", "libgo3.a")
	if runtime.Compiler == "gccgo" {
		ccArgs = append(ccArgs, "-lgo")
	}
	if out, err := exec.Command(ccArgs[0], ccArgs[1:]...).CombinedOutput(); err != nil {
		t.Logf("%s", out)
		t.Fatal(err)
	}

	if out, err := exec.Command(bin[0], bin[1:]...).CombinedOutput(); err != nil {
		t.Logf("%s", out)
		t.Fatal(err)
	}
}

func TestSigaltstack(t *testing.T) {
	switch GOOS {
	case "windows":
		t.Skip("skipping signal test on Windows")
	}
	globalSkip(t)
	testenv.MustHaveGoBuild(t)
	testenv.MustHaveCGO(t)
	testenv.MustHaveBuildMode(t, "c-archive")

	if !testWork {
		defer func() {
			os.Remove("libgo4.a")
			os.Remove("libgo4.h")
			os.Remove("testp" + exeSuffix)
			os.RemoveAll(filepath.Join(GOPATH, "pkg"))
		}()
	}

	cmd := exec.Command("go", "build", "-buildmode=c-archive", "-o", "libgo4.a", "./libgo4")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Logf("%s", out)
		t.Fatal(err)
	}
	checkLineComments(t, "libgo4.h")
	checkArchive(t, "libgo4.a")

	ccArgs := append(cc, "-o", "testp"+exeSuffix, "main4.c", "libgo4.a")
	if runtime.Compiler == "gccgo" {
		ccArgs = append(ccArgs, "-lgo")
	}
	if out, err := exec.Command(ccArgs[0], ccArgs[1:]...).CombinedOutput(); err != nil {
		t.Logf("%s", out)
		t.Fatal(err)
	}

	if out, err := exec.Command(bin[0], bin[1:]...).CombinedOutput(); err != nil {
		t.Logf("%s", out)
		t.Fatal(err)
	}
}

const testar = `#!/usr/bin/env bash
while [[ $1 == -* ]] >/dev/null; do
  shift
done
echo "testar" > $1
echo "testar" > PWD/testar.ran
`

func TestExtar(t *testing.T) {
	switch GOOS {
	case "windows":
		t.Skip("skipping signal test on Windows")
	}
	if runtime.Compiler == "gccgo" {
		t.Skip("skipping -extar test when using gccgo")
	}
	globalSkip(t)
	testenv.MustHaveGoBuild(t)
	testenv.MustHaveCGO(t)
	testenv.MustHaveBuildMode(t, "c-archive")
	testenv.MustHaveExecPath(t, "bash") // This test uses a bash script

	if !testWork {
		defer func() {
			os.Remove("libgo4.a")
			os.Remove("libgo4.h")
			os.Remove("testar")
			os.Remove("testar.ran")
			os.RemoveAll(filepath.Join(GOPATH, "pkg"))
		}()
	}

	os.Remove("testar")
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	s := strings.Replace(testar, "PWD", dir, 1)
	if err := os.WriteFile("testar", []byte(s), 0777); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("go", "build", "-buildmode=c-archive", "-ldflags=-extar="+filepath.Join(dir, "testar"), "-o", "libgo4.a", "./libgo4")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Logf("%s", out)
		t.Fatal(err)
	}
	checkLineComments(t, "libgo4.h")

	if _, err := os.Stat("testar.ran"); err != nil {
		if os.IsNotExist(err) {
			t.Error("testar does not exist after go build")
		} else {
			t.Errorf("error checking testar: %v", err)
		}
	}
}

func TestPIE(t *testing.T) {
	switch GOOS {
	case "windows", "darwin", "ios", "plan9":
		t.Skipf("skipping PIE test on %s", GOOS)
	}
	globalSkip(t)
	testenv.MustHaveGoBuild(t)
	testenv.MustHaveCGO(t)
	testenv.MustHaveBuildMode(t, "c-archive")

	libgoa := "libgo.a"
	if runtime.Compiler == "gccgo" {
		libgoa = "liblibgo.a"
	}

	if !testWork {
		defer func() {
			os.Remove("testp" + exeSuffix)
			os.Remove(libgoa)
			os.RemoveAll(filepath.Join(GOPATH, "pkg"))
		}()
	}

	// Generate the p.h header file.
	//
	// 'go install -i -buildmode=c-archive ./libgo' would do that too, but that
	// would also attempt to install transitive standard-library dependencies to
	// GOROOT, and we cannot assume that GOROOT is writable. (A non-root user may
	// be running this test in a GOROOT owned by root.)
	genHeader(t, "p.h", "./p")

	cmd := exec.Command("go", "build", "-buildmode=c-archive", "./libgo")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Logf("%s", out)
		t.Fatal(err)
	}

	ccArgs := append(cc, "-fPIE", "-pie", "-o", "testp"+exeSuffix, "main.c", "main_unix.c", libgoa)
	if runtime.Compiler == "gccgo" {
		ccArgs = append(ccArgs, "-lgo")
	}
	if out, err := exec.Command(ccArgs[0], ccArgs[1:]...).CombinedOutput(); err != nil {
		t.Logf("%s", out)
		t.Fatal(err)
	}

	binArgs := append(bin, "arg1", "arg2")
	cmd = exec.Command(binArgs[0], binArgs[1:]...)
	if runtime.Compiler == "gccgo" {
		cmd.Env = append(os.Environ(), "GCCGO=1")
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Logf("%s", out)
		t.Fatal(err)
	}

	if GOOS != "aix" {
		f, err := elf.Open("testp" + exeSuffix)
		if err != nil {
			t.Fatal("elf.Open failed: ", err)
		}
		defer f.Close()
		if hasDynTag(t, f, elf.DT_TEXTREL) {
			t.Errorf("%s has DT_TEXTREL flag", "testp"+exeSuffix)
		}
	}
}

func hasDynTag(t *testing.T, f *elf.File, tag elf.DynTag) bool {
	ds := f.SectionByType(elf.SHT_DYNAMIC)
	if ds == nil {
		t.Error("no SHT_DYNAMIC section")
		return false
	}
	d, err := ds.Data()
	if err != nil {
		t.Errorf("can't read SHT_DYNAMIC contents: %v", err)
		return false
	}
	for len(d) > 0 {
		var t elf.DynTag
		switch f.Class {
		case elf.ELFCLASS32:
			t = elf.DynTag(f.ByteOrder.Uint32(d[:4]))
			d = d[8:]
		case elf.ELFCLASS64:
			t = elf.DynTag(f.ByteOrder.Uint64(d[:8]))
			d = d[16:]
		}
		if t == tag {
			return true
		}
	}
	return false
}

func TestSIGPROF(t *testing.T) {
	switch GOOS {
	case "windows", "plan9":
		t.Skipf("skipping SIGPROF test on %s", GOOS)
	case "darwin", "ios":
		t.Skipf("skipping SIGPROF test on %s; see https://golang.org/issue/19320", GOOS)
	}
	globalSkip(t)
	testenv.MustHaveGoBuild(t)
	testenv.MustHaveCGO(t)
	testenv.MustHaveBuildMode(t, "c-archive")

	t.Parallel()

	if !testWork {
		defer func() {
			os.Remove("testp6" + exeSuffix)
			os.Remove("libgo6.a")
			os.Remove("libgo6.h")
		}()
	}

	cmd := exec.Command("go", "build", "-buildmode=c-archive", "-o", "libgo6.a", "./libgo6")
	out, err := cmd.CombinedOutput()
	t.Logf("%v\n%s", cmd.Args, out)
	if err != nil {
		t.Fatal(err)
	}
	checkLineComments(t, "libgo6.h")
	checkArchive(t, "libgo6.a")

	ccArgs := append(cc, "-o", "testp6"+exeSuffix, "main6.c", "libgo6.a")
	if runtime.Compiler == "gccgo" {
		ccArgs = append(ccArgs, "-lgo")
	}
	out, err = exec.Command(ccArgs[0], ccArgs[1:]...).CombinedOutput()
	t.Logf("%v\n%s", ccArgs, out)
	if err != nil {
		t.Fatal(err)
	}

	argv := cmdToRun("./testp6")
	cmd = exec.Command(argv[0], argv[1:]...)
	out, err = cmd.CombinedOutput()
	t.Logf("%v\n%s", argv, out)
	if err != nil {
		t.Fatal(err)
	}
}

// TestCompileWithoutShared tests that if we compile code without the
// -shared option, we can put it into an archive. When we use the go
// tool with -buildmode=c-archive, it passes -shared to the compiler,
// so we override that. The go tool doesn't work this way, but Bazel
// will likely do it in the future. And it ought to work. This test
// was added because at one time it did not work on PPC Linux.
func TestCompileWithoutShared(t *testing.T) {
	globalSkip(t)
	// For simplicity, reuse the signal forwarding test.
	checkSignalForwardingTest(t)
	testenv.MustHaveGoBuild(t)

	if !testWork {
		defer func() {
			os.Remove("libgo2.a")
			os.Remove("libgo2.h")
		}()
	}

	cmd := exec.Command("go", "build", "-buildmode=c-archive", "-gcflags=-shared=false", "-o", "libgo2.a", "./libgo2")
	out, err := cmd.CombinedOutput()
	t.Logf("%v\n%s", cmd.Args, out)
	if err != nil {
		t.Fatal(err)
	}
	checkLineComments(t, "libgo2.h")
	checkArchive(t, "libgo2.a")

	exe := "./testnoshared" + exeSuffix

	// In some cases, -no-pie is needed here, but not accepted everywhere. First try
	// if -no-pie is accepted. See #22126.
	ccArgs := append(cc, "-o", exe, "-no-pie", "main5.c", "libgo2.a")
	if runtime.Compiler == "gccgo" {
		ccArgs = append(ccArgs, "-lgo")
	}
	out, err = exec.Command(ccArgs[0], ccArgs[1:]...).CombinedOutput()
	t.Logf("%v\n%s", ccArgs, out)

	// If -no-pie unrecognized, try -nopie if this is possibly clang
	if err != nil && bytes.Contains(out, []byte("unknown")) && !strings.Contains(cc[0], "gcc") {
		ccArgs = append(cc, "-o", exe, "-nopie", "main5.c", "libgo2.a")
		out, err = exec.Command(ccArgs[0], ccArgs[1:]...).CombinedOutput()
		t.Logf("%v\n%s", ccArgs, out)
	}

	// Don't use either -no-pie or -nopie
	if err != nil && bytes.Contains(out, []byte("unrecognized")) {
		ccArgs = append(cc, "-o", exe, "main5.c", "libgo2.a")
		out, err = exec.Command(ccArgs[0], ccArgs[1:]...).CombinedOutput()
		t.Logf("%v\n%s", ccArgs, out)
	}
	if err != nil {
		t.Fatal(err)
	}
	if !testWork {
		defer os.Remove(exe)
	}

	binArgs := append(cmdToRun(exe), "1")
	out, err = exec.Command(binArgs[0], binArgs[1:]...).CombinedOutput()
	t.Logf("%v\n%s", binArgs, out)
	expectSignal(t, err, syscall.SIGSEGV, 0)

	// SIGPIPE is never forwarded on darwin. See golang.org/issue/33384.
	if runtime.GOOS != "darwin" && runtime.GOOS != "ios" {
		binArgs := append(cmdToRun(exe), "3")
		out, err = exec.Command(binArgs[0], binArgs[1:]...).CombinedOutput()
		t.Logf("%v\n%s", binArgs, out)
		expectSignal(t, err, syscall.SIGPIPE, 0)
	}
}

// Test that installing a second time recreates the header file.
func TestCachedInstall(t *testing.T) {
	globalSkip(t)
	testenv.MustHaveGoBuild(t)
	testenv.MustHaveCGO(t)
	testenv.MustHaveBuildMode(t, "c-archive")

	if !testWork {
		defer os.RemoveAll(filepath.Join(GOPATH, "pkg"))
	}

	h := filepath.Join(libgodir, "libgo.h")

	buildcmd := []string{"go", "install", "-buildmode=c-archive", "./libgo"}

	cmd := exec.Command(buildcmd[0], buildcmd[1:]...)
	cmd.Env = append(cmd.Environ(), "GO111MODULE=off") // 'go install' only works in GOPATH mode
	t.Log(buildcmd)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Logf("%s", out)
		t.Fatal(err)
	}

	if _, err := os.Stat(h); err != nil {
		t.Errorf("libgo.h not installed: %v", err)
	}

	if err := os.Remove(h); err != nil {
		t.Fatal(err)
	}

	cmd = exec.Command(buildcmd[0], buildcmd[1:]...)
	cmd.Env = append(cmd.Environ(), "GO111MODULE=off")
	t.Log(buildcmd)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Logf("%s", out)
		t.Fatal(err)
	}

	if _, err := os.Stat(h); err != nil {
		t.Errorf("libgo.h not installed in second run: %v", err)
	}
}

// Issue 35294.
func TestManyCalls(t *testing.T) {
	globalSkip(t)
	testenv.MustHaveGoBuild(t)
	testenv.MustHaveCGO(t)
	testenv.MustHaveBuildMode(t, "c-archive")

	t.Parallel()

	if !testWork {
		defer func() {
			os.Remove("testp7" + exeSuffix)
			os.Remove("libgo7.a")
			os.Remove("libgo7.h")
		}()
	}

	cmd := exec.Command("go", "build", "-buildmode=c-archive", "-o", "libgo7.a", "./libgo7")
	out, err := cmd.CombinedOutput()
	t.Logf("%v\n%s", cmd.Args, out)
	if err != nil {
		t.Fatal(err)
	}
	checkLineComments(t, "libgo7.h")
	checkArchive(t, "libgo7.a")

	ccArgs := append(cc, "-o", "testp7"+exeSuffix, "main7.c", "libgo7.a")
	if runtime.Compiler == "gccgo" {
		ccArgs = append(ccArgs, "-lgo")
	}
	out, err = exec.Command(ccArgs[0], ccArgs[1:]...).CombinedOutput()
	t.Logf("%v\n%s", ccArgs, out)
	if err != nil {
		t.Fatal(err)
	}

	argv := cmdToRun("./testp7")
	cmd = testenv.Command(t, argv[0], argv[1:]...)
	sb := new(strings.Builder)
	cmd.Stdout = sb
	cmd.Stderr = sb
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	err = cmd.Wait()
	t.Logf("%v\n%s", cmd.Args, sb)
	if err != nil {
		t.Error(err)
	}
}

// Issue 49288.
func TestPreemption(t *testing.T) {
	if runtime.Compiler == "gccgo" {
		t.Skip("skipping asynchronous preemption test with gccgo")
	}
	globalSkip(t)
	testenv.MustHaveGoBuild(t)
	testenv.MustHaveCGO(t)
	testenv.MustHaveBuildMode(t, "c-archive")

	t.Parallel()

	if !testWork {
		defer func() {
			os.Remove("testp8" + exeSuffix)
			os.Remove("libgo8.a")
			os.Remove("libgo8.h")
		}()
	}

	cmd := exec.Command("go", "build", "-buildmode=c-archive", "-o", "libgo8.a", "./libgo8")
	out, err := cmd.CombinedOutput()
	t.Logf("%v\n%s", cmd.Args, out)
	if err != nil {
		t.Fatal(err)
	}
	checkLineComments(t, "libgo8.h")
	checkArchive(t, "libgo8.a")

	ccArgs := append(cc, "-o", "testp8"+exeSuffix, "main8.c", "libgo8.a")
	out, err = exec.Command(ccArgs[0], ccArgs[1:]...).CombinedOutput()
	t.Logf("%v\n%s", ccArgs, out)
	if err != nil {
		t.Fatal(err)
	}

	argv := cmdToRun("./testp8")
	cmd = testenv.Command(t, argv[0], argv[1:]...)
	sb := new(strings.Builder)
	cmd.Stdout = sb
	cmd.Stderr = sb
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	err = cmd.Wait()
	t.Logf("%v\n%s", cmd.Args, sb)
	if err != nil {
		t.Error(err)
	}
}

// Issue 59294 and 68285. Test calling Go function from C after with
// various stack space.
func TestDeepStack(t *testing.T) {
	globalSkip(t)
	testenv.MustHaveGoBuild(t)
	testenv.MustHaveCGO(t)
	testenv.MustHaveBuildMode(t, "c-archive")

	t.Parallel()

	if !testWork {
		defer func() {
			os.Remove("testp9" + exeSuffix)
			os.Remove("libgo9.a")
			os.Remove("libgo9.h")
		}()
	}

	cmd := exec.Command("go", "build", "-buildmode=c-archive", "-o", "libgo9.a", "./libgo9")
	out, err := cmd.CombinedOutput()
	t.Logf("%v\n%s", cmd.Args, out)
	if err != nil {
		t.Fatal(err)
	}
	checkLineComments(t, "libgo9.h")
	checkArchive(t, "libgo9.a")

	// build with -O0 so the C compiler won't optimize out the large stack frame
	ccArgs := append(cc, "-O0", "-o", "testp9"+exeSuffix, "main9.c", "libgo9.a")
	out, err = exec.Command(ccArgs[0], ccArgs[1:]...).CombinedOutput()
	t.Logf("%v\n%s", ccArgs, out)
	if err != nil {
		t.Fatal(err)
	}

	argv := cmdToRun("./testp9")
	cmd = exec.Command(argv[0], argv[1:]...)
	sb := new(strings.Builder)
	cmd.Stdout = sb
	cmd.Stderr = sb
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	timer := time.AfterFunc(time.Minute,
		func() {
			t.Error("test program timed out")
			cmd.Process.Kill()
		},
	)
	defer timer.Stop()

	err = cmd.Wait()
	t.Logf("%v\n%s", cmd.Args, sb)
	if err != nil {
		t.Error(err)
	}
}

func BenchmarkCgoCallbackMainThread(b *testing.B) {
	// Benchmark for calling into Go fron C main thread.
	// See issue #68587.
	//
	// It uses a subprocess, which is a C binary that calls
	// Go on the main thread b.N times. There is some overhead
	// for launching the subprocess. It is probably fine when
	// b.N is large.

	globalSkip(b)
	testenv.MustHaveGoBuild(b)
	testenv.MustHaveCGO(b)
	testenv.MustHaveBuildMode(b, "c-archive")

	if !testWork {
		defer func() {
			os.Remove("testp10" + exeSuffix)
			os.Remove("libgo10.a")
			os.Remove("libgo10.h")
		}()
	}

	cmd := exec.Command("go", "build", "-buildmode=c-archive", "-o", "libgo10.a", "./libgo10")
	out, err := cmd.CombinedOutput()
	b.Logf("%v\n%s", cmd.Args, out)
	if err != nil {
		b.Fatal(err)
	}

	ccArgs := append(cc, "-o", "testp10"+exeSuffix, "main10.c", "libgo10.a")
	out, err = exec.Command(ccArgs[0], ccArgs[1:]...).CombinedOutput()
	b.Logf("%v\n%s", ccArgs, out)
	if err != nil {
		b.Fatal(err)
	}

	argv := cmdToRun("./testp10")
	argv = append(argv, fmt.Sprint(b.N))
	cmd = exec.Command(argv[0], argv[1:]...)

	b.ResetTimer()
	err = cmd.Run()
	if err != nil {
		b.Fatal(err)
	}
}

func TestSharedObject(t *testing.T) {
	// Test that we can put a Go c-archive into a C shared object.
	globalSkip(t)
	testenv.MustHaveGoBuild(t)
	testenv.MustHaveCGO(t)
	testenv.MustHaveBuildMode(t, "c-archive")

	t.Parallel()

	if !testWork {
		defer func() {
			os.Remove("libgo_s.a")
			os.Remove("libgo_s.h")
			os.Remove("libgo_s.so")
		}()
	}

	cmd := exec.Command("go", "build", "-buildmode=c-archive", "-o", "libgo_s.a", "./libgo")
	out, err := cmd.CombinedOutput()
	t.Logf("%v\n%s", cmd.Args, out)
	if err != nil {
		t.Fatal(err)
	}

	ccArgs := append(cc, "-shared", "-o", "libgo_s.so", "libgo_s.a")
	out, err = exec.Command(ccArgs[0], ccArgs[1:]...).CombinedOutput()
	t.Logf("%v\n%s", ccArgs, out)
	if err != nil {
		t.Fatal(err)
	}
}
```