Response:
Let's break down the thought process for analyzing the provided Go code.

**1. Initial Scan and Goal Identification:**

The first step is to quickly scan the import statements and the function names. This immediately gives a high-level understanding of what the code *might* be doing. We see imports like `debug/pe`, `internal/testenv`, `os`, `path/filepath`, `runtime`, `strings`, and `testing`. This strongly suggests it's a set of integration tests for the Go linker (`cmd/link`). The `Test...` function names confirm this. The specific names like `TestUndefinedRelocErrors`, `TestArchiveBuildInvokeWithExec`, etc., hint at the particular linking scenarios being tested. The goal is to analyze what aspects of the linker each test function verifies.

**2. Function-by-Function Analysis:**

Now, we go through each `Test...` function in detail.

* **`TestUndefinedRelocErrors`:**
    * **Key Imports/Functions:** `testenv.MustHaveGoBuild`, `testenv.MustInternalLink`, `testenv.Command`. These clearly indicate it's running a Go build process.
    * **Code Logic:**  It builds a program (`./testdata/issue10978`) that is *expected* to fail due to undefined symbols. It then parses the error output to verify the specific error messages related to undefined relocations.
    * **Inference:** This test verifies the linker's ability to correctly identify and report undefined symbols during the linking process, specifically in an internal linking scenario.
    * **Go Feature:** Undefined symbol detection during linking.
    * **Example:**  A simple example would involve two Go files where one references a function or variable defined in the other, but the definition is missing.
    * **Command-Line:**  It implicitly uses the `go build` command.
    * **Common Errors:**  Forgetting to define a function or variable that is referenced elsewhere.

* **`TestArchiveBuildInvokeWithExec`:**
    * **Key Imports/Functions:** `testenv.MustHaveGoBuild`, `testenv.MustHaveCGO`, `testenv.Command`, `runtime.GOOS`, `runtime.GOARCH`. The `carchiveSrcText` constant is also important.
    * **Code Logic:**  It builds a C archive (`-buildmode=c-archive`). The test checks the `-v` (verbose) output of the build command to ensure the linker is using `syscall.Exec` to invoke the archiver. It also limits the platforms on which it runs.
    * **Inference:** This test focuses on verifying the mechanism used to create C archives, specifically that the linker uses `syscall.Exec` for this process on certain platforms.
    * **Go Feature:** Building C archives (`-buildmode=c-archive`).
    * **Example:** The `carchiveSrcText` provides a basic example of a Go file that can be compiled into a C archive.
    * **Command-Line:**  Uses `go build -buildmode=c-archive`.
    * **Common Errors:** Platform limitations are built into the test itself.

* **`TestLargeTextSectionSplitting`:**
    * **Key Imports/Functions:** `testenv.MustHaveGoBuild`, `testenv.MustHaveCGO`, `testenv.Command`, `runtime.GOOS`, `runtime.GOARCH`, `bytes.Contains`.
    * **Code Logic:**  It builds `cmd/go` with `-ldflags=-linkmode=external -debugtextsize=1048576`. It then uses `go tool nm` to check if the output binary contains a symbol like `runtime.text.1`, indicating that the text section was split. Finally, it runs the built `go` executable to ensure it's functional.
    * **Inference:** This test verifies the linker's ability to split large text sections into smaller chunks, particularly when external linking is enabled. The `-debugtextsize` flag controls the splitting threshold.
    * **Go Feature:** Text section splitting for large binaries, often relevant for embedded systems or specific architectures.
    * **Example:** Building a sufficiently large Go program (like `cmd/go`) will trigger this behavior when the `-debugtextsize` flag is used.
    * **Command-Line:** Uses `go build -ldflags="-linkmode=external -debugtextsize=..."` and `go tool nm`.
    * **Common Errors:** Misunderstanding when text section splitting is necessary.

* **`TestWindowsBuildmodeCSharedASLR`:**
    * **Key Imports/Functions:** `testenv.MustHaveGoBuild`, `testenv.MustHaveCGO`, `testenv.Command`, `runtime.GOOS`, `runtime.GOARCH`, `debug/pe`.
    * **Code Logic:** It tests building a C shared library (`-buildmode=c-shared`) on Windows with and without Address Space Layout Randomization (ASLR) enabled using the `-ldflags=-aslr=false` flag. It then uses the `debug/pe` package to inspect the generated DLL and verify the presence (or absence) of the `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE` and `IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA` flags in the PE header.
    * **Inference:** This test focuses on verifying the linker's ability to control ASLR settings when building C shared libraries on Windows.
    * **Go Feature:** Controlling ASLR for shared libraries on Windows.
    * **Example:** Building a simple Go program with `-buildmode=c-shared` and then inspecting the resulting DLL.
    * **Command-Line:** Uses `go build -buildmode=c-shared` and optionally `-ldflags=-aslr=false`.
    * **Common Errors:** Incorrectly assuming ASLR is always enabled or disabled.

* **`TestMemProfileCheck`:**
    * **Key Imports/Functions:** `testenv.MustHaveGoBuild`, `testenv.Command`, `runtime`.
    * **Code Logic:** It runs several small Go programs. Some of these programs directly or indirectly reference functions related to memory profiling (like `runtime.MemProfile`, `runtime/pprof` functions, or importing `net/http/pprof`). It then checks the value of `runtime.MemProfileRate`. The test aims to verify that if memory profiling functions are reachable, the default `MemProfileRate` is set to a non-zero value (524288), otherwise it's 0.
    * **Inference:** This test verifies that the linker performs dead code elimination and correctly determines whether memory profiling is being used. This influences the default setting of `runtime.MemProfileRate`.
    * **Go Feature:** Memory profiling and dead code elimination.
    * **Example:** The provided test cases themselves serve as good examples.
    * **Command-Line:** Uses `go run`.
    * **Common Errors:**  Misunderstanding how the linker's dead code elimination affects runtime behavior.

* **`TestRISCVTrampolines`:**
    * **Key Imports/Functions:** `testenv.MustHaveGoBuild`, `testenv.Command`, `os`, `path/filepath`, `bytes.Contains`, `fmt`.
    * **Code Logic:** This test is specific to the `riscv64` architecture. It creates an assembly file with functions that are far apart in memory. It then builds a Go program that calls these assembly functions. The test uses `go tool nm` to check if the linker has created trampolines (small intermediary functions) to handle calls between distant code sections.
    * **Inference:** This test verifies the linker's ability to generate trampolines on RISC-V architecture when direct calls between functions exceed the allowed range.
    * **Go Feature:** Trampoline generation for long jumps on specific architectures.
    * **Example:** The assembly code within the test demonstrates the scenario requiring trampolines.
    * **Command-Line:** Uses `go build -ldflags=-linkmode=internal` and `go tool nm`. Environment variables `GOARCH=riscv64` and `GOOS=linux` are crucial.
    * **Common Errors:** Not understanding the limitations of direct calls on certain architectures.

**3. Synthesizing the Overall Purpose:**

After analyzing each function, we can synthesize the overall purpose of the `ld_test.go` file. It's a comprehensive suite of integration tests for the Go linker, specifically focusing on various aspects of the linking process, including:

* Error handling (undefined symbols)
* Build modes (C archives, C shared libraries)
* Platform-specific features (ASLR on Windows, trampolines on RISC-V)
* Optimization and code generation (text section splitting, dead code elimination related to memory profiling)
* Correct invocation of external tools during the build process.

**4. Refining Explanations and Examples:**

Finally, we refine the explanations and examples to be clear, concise, and accurate. We focus on providing practical examples that illustrate the concepts being tested. For common errors, we think about what mistakes developers might make that would cause these tests to fail or lead to unexpected behavior.

This systematic approach helps to thoroughly understand the functionality of the given Go code and explain it in a comprehensive and structured manner.
这个文件 `go/src/cmd/link/internal/ld/ld_test.go` 是 Go 语言链接器 (`cmd/link`) 内部 `ld` 包的测试文件。它的主要功能是**测试链接器的各种功能和特性，确保链接器在不同场景下能够正确地工作**。

下面对每个测试函数进行功能解释和可能的 Go 语言功能实现推理：

**1. `TestUndefinedRelocErrors(t *testing.T)`**

* **功能:** 测试链接器在遇到未定义的符号引用时的错误处理机制。
* **推理的 Go 语言功能:**  链接器需要能够识别出在链接过程中，某个符号（函数、变量等）被引用了，但是没有在任何输入的目标文件中找到其定义。
* **代码举例:**

```go
// testdata/issue10978/a.go
package main

var defined1 int
var defined2 int

func main() {
	_ = undefined // 引用了未定义的变量
}
```

```go
// testdata/issue10978/b.go
package main

func definedFunc() {}
```

* **假设的输入与输出:**
    * **输入:** 两个 Go 源文件 `a.go` 和 `b.go`，其中 `a.go` 中引用了一个未定义的变量 `undefined`。
    * **输出:**  链接器应该报错，并且错误信息中包含类似 "relocation target main.undefined not defined" 的内容。
* **命令行参数:** 这个测试本身不涉及直接的命令行参数，但是它测试的是 `go build` 命令在遇到链接错误时的行为。当使用内部链接器（`-linkmode=internal`，这也是此测试的前提 `testenv.MustInternalLink(t, false)`) 时，链接器会直接报错。
* **使用者易犯错的点:**  在编写 Go 代码时，忘记定义被引用的全局变量或函数。

**2. `TestArchiveBuildInvokeWithExec(t *testing.T)`**

* **功能:** 测试在使用 `c-archive` 构建模式时，链接器是否通过 `syscall.Exec` 来调用归档工具（如 `ar`）。这通常是为了避免在同一个进程中执行外部命令时可能出现的问题。
* **推理的 Go 语言功能:** Go 语言的 `buildmode=c-archive` 允许将 Go 代码编译成一个 C 静态库。这个过程通常需要调用底层的归档工具。
* **代码举例:**

```go
// 假设有一个 test.go 文件
package main

//export GoFunc
func GoFunc() {
	println(42)
}

func main() {
}
```

* **假设的输入与输出:**
    * **输入:** 一个包含 `//export` 注释的 Go 源文件。
    * **输出:** 在使用了 `-v` 选项的构建输出中，应该包含 "invoking archiver with syscall.Exec" 这样的信息。
* **命令行参数:**
    * `go build -buildmode=c-archive -o <output_file> <input_file>`
    * `-ldflags=-v`  这个 `-v` 标志会使链接器输出详细的执行信息。
    * `-tmpdir=<directory>`  指定临时目录。
* **使用者易犯错的点:**  对于构建 C 归档文件，需要确保系统中安装了相应的归档工具。

**3. `TestLargeTextSectionSplitting(t *testing.T)`**

* **功能:** 测试链接器是否能够将大的 `.text` 代码段分割成多个小的段。这在某些架构上可以提高加载性能或绕过某些限制。
* **推理的 Go 语言功能:** 链接器需要在生成目标文件时，根据配置或架构的限制，将代码段进行分割。
* **代码举例:**  这个测试更多关注链接器的行为，而不是具体的 Go 代码。它通过构建一个较大的程序（`cmd/go`）来触发代码段分割。
* **假设的输入与输出:**
    * **输入:** 编译 `cmd/go` 并且指定 `-ldflags=-linkmode=external -debugtextsize=1048576`。
    * **输出:** 使用 `go tool nm` 查看生成的可执行文件，应该能看到类似 `runtime.text.1` 这样的符号，表明 `.text` 段被分割了。
* **命令行参数:**
    * `go build -o <output_file> -ldflags="-linkmode=external -debugtextsize=1048576" cmd/go`
    * `-linkmode=external`: 使用外部链接器。
    * `-debugtextsize=1048576`:  设置代码段分割的大小阈值为 1MB。
    * `go tool nm <executable_file>`: 用于查看目标文件中的符号。
* **使用者易犯错的点:**  `debugtextsize` 通常不需要手动设置，链接器会根据架构自动处理。但理解这个选项可以帮助理解链接器如何处理大型代码段。

**4. `TestWindowsBuildmodeCSharedASLR(t *testing.T)`**

* **功能:** 测试在 Windows 上使用 `c-shared` 构建模式时，链接器是否能够正确地设置 Address Space Layout Randomization (ASLR) 相关的 PE 文件头标志。
* **推理的 Go 语言功能:**  当构建动态链接库 (`.dll`) 时，链接器需要能够控制是否启用 ASLR，这是一种安全特性，可以防止某些类型的攻击。
* **代码举例:**

```go
// test.go
package main

func main() {
	print("hello")
}
```

* **假设的输入与输出:**
    * **输入:**  在 Windows 上编译 `test.go`，使用 `-buildmode=c-shared`，并分别使用或不使用 `-ldflags=-aslr=false`。
    * **输出:** 使用 `debug/pe` 包打开生成的 `.dll` 文件，检查其 Optional Header 中的 `DllCharacteristics` 字段，验证 `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE` 和 `IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA` 标志是否被正确设置。
* **命令行参数:**
    * `go build -buildmode=c-shared -o <output_file> <input_file>`
    * `go build -buildmode=c-shared -ldflags=-aslr=false -o <output_file> <input_file>`
* **使用者易犯错的点:**  在构建共享库时，理解 ASLR 的作用以及如何通过链接器标志来控制它是很重要的。

**5. `TestMemProfileCheck(t *testing.T)`**

* **功能:** 测试链接器是否能够正确地检测到 `runtime.MemProfile` 符号是否可达，并根据情况设置 `runtime.disableMemoryProfiling`。这会影响 `runtime.MemProfileRate` 的默认值。
* **推理的 Go 语言功能:** 链接器执行死代码消除时，会分析哪些符号是程序实际用到的。如果 `runtime.MemProfile` 没有被直接或间接调用，链接器可能会将其标记为不可达。
* **代码举例:**  测试用例中包含了多种场景，展示了 `runtime.MemProfile` 的不同使用方式，包括直接调用、间接调用、以及通过 `runtime/pprof` 包的使用。
* **假设的输入与输出:**
    * **输入:** 不同的 Go 程序，有些会调用 `runtime.MemProfile` 或 `runtime/pprof` 相关函数，有些则不会。
    * **输出:**  运行这些程序，观察 `runtime.MemProfileRate` 的输出。如果 `runtime.MemProfile` 可达，则 `runtime.MemProfileRate` 应该是非零的（通常是 524288），否则为 0。
* **命令行参数:**  这个测试主要使用 `go run` 命令来执行不同的测试程序。
* **使用者易犯错的点:**  对 Go 的内存 profiling 机制不熟悉，不理解链接器的死代码消除如何影响运行时行为。

**6. `TestRISCVTrampolines(t *testing.T)`**

* **功能:** 测试在 RISC-V 架构上，当函数调用距离过远时，链接器是否能够正确地生成 trampoline 代码。
* **推理的 Go 语言功能:** 在某些架构上，直接函数调用的目标地址可能超出指令的寻址范围。为了解决这个问题，链接器会插入一个小的跳转代码段（trampoline），使得调用能够成功跳转到目标函数。
* **代码举例:**  这个测试创建了一个包含汇编代码的文件，其中定义了距离较远的函数 `a` 和 `d`，以及中间的函数 `b` 和 `c`。
* **假设的输入与输出:**
    * **输入:** 一个包含汇编代码的文件，以及一个调用这些汇编函数的 Go 程序。
    * **输出:** 使用 `go tool nm` 查看生成的可执行文件，应该能看到类似 `a-tramp0` 这样的符号，表示为函数 `a` 生成了一个 trampoline。而对于不需要 trampoline 的函数 `b`，则不应该有 `b-tramp0` 这样的符号。
* **命令行参数:**
    * `go build -ldflags=-linkmode=internal`
    * `go tool nm <executable_file>`
    * 需要设置环境变量 `GOARCH=riscv64` 和 `GOOS=linux` 来指定目标架构。
* **使用者易犯错的点:**  这通常是架构特定的问题，开发者在编写通用 Go 代码时不需要特别关注。但是，当涉及到低级别编程或特定架构优化时，理解 trampoline 的作用很重要。

**总结:**

总的来说，`ld_test.go` 文件通过各种测试用例，覆盖了 Go 语言链接器的核心功能，包括：

* **符号解析和重定位:**  测试链接器如何处理符号的定义和引用。
* **目标文件和库的处理:**  测试链接器如何处理不同的输入文件类型（如 `.o` 文件、静态库、共享库）。
* **代码生成和优化:**  测试链接器如何进行代码布局、代码段分割以及死代码消除。
* **平台特定的功能:**  测试链接器在不同操作系统和 CPU 架构下的特定行为，如 Windows 的 ASLR 和 RISC-V 的 trampoline。
* **构建模式的支持:**  测试链接器对不同构建模式（如 `c-archive`、`c-shared`）的支持。
* **错误处理:**  测试链接器在遇到错误时的报告机制。

这些测试用例是确保 Go 语言工具链稳定性和可靠性的重要组成部分。它们帮助开发者理解链接器的工作原理，并及时发现和修复链接器中的 bug。

### 提示词
```
这是路径为go/src/cmd/link/internal/ld/ld_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ld

import (
	"bytes"
	"debug/pe"
	"fmt"
	"internal/testenv"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestUndefinedRelocErrors(t *testing.T) {
	testenv.MustHaveGoBuild(t)

	// When external linking, symbols may be defined externally, so we allow
	// undefined symbols and let external linker resolve. Skip the test.
	testenv.MustInternalLink(t, false)

	t.Parallel()

	out, err := testenv.Command(t, testenv.GoToolPath(t), "build", "./testdata/issue10978").CombinedOutput()
	if err == nil {
		t.Fatal("expected build to fail")
	}

	wantErrors := map[string]int{
		// Main function has dedicated error message.
		"function main is undeclared in the main package": 1,

		// Single error reporting per each symbol.
		// This way, duplicated messages are not reported for
		// multiple relocations with a same name.
		"main.defined1: relocation target main.undefined not defined": 1,
		"main.defined2: relocation target main.undefined not defined": 1,
	}
	unexpectedErrors := map[string]int{}

	for _, l := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(l, "#") || l == "" {
			continue
		}
		matched := ""
		for want := range wantErrors {
			if strings.Contains(l, want) {
				matched = want
				break
			}
		}
		if matched != "" {
			wantErrors[matched]--
		} else {
			unexpectedErrors[l]++
		}
	}

	for want, n := range wantErrors {
		switch {
		case n > 0:
			t.Errorf("unmatched error: %s (x%d)", want, n)
		case n < 0:
			if runtime.GOOS == "android" && runtime.GOARCH == "arm64" {
				testenv.SkipFlaky(t, 58807)
			}
			t.Errorf("extra errors: %s (x%d)", want, -n)
		}
	}
	for unexpected, n := range unexpectedErrors {
		t.Errorf("unexpected error: %s (x%d)", unexpected, n)
	}
}

const carchiveSrcText = `
package main

//export GoFunc
func GoFunc() {
	println(42)
}

func main() {
}
`

func TestArchiveBuildInvokeWithExec(t *testing.T) {
	t.Parallel()
	testenv.MustHaveGoBuild(t)
	testenv.MustHaveCGO(t)

	// run this test on just a small set of platforms (no need to test it
	// across the board given the nature of the test).
	pair := runtime.GOOS + "-" + runtime.GOARCH
	switch pair {
	case "darwin-amd64", "darwin-arm64", "linux-amd64", "freebsd-amd64":
	default:
		t.Skip("no need for test on " + pair)
	}
	switch runtime.GOOS {
	case "openbsd", "windows":
		t.Skip("c-archive unsupported")
	}
	dir := t.TempDir()

	srcfile := filepath.Join(dir, "test.go")
	arfile := filepath.Join(dir, "test.a")
	if err := os.WriteFile(srcfile, []byte(carchiveSrcText), 0666); err != nil {
		t.Fatal(err)
	}

	ldf := fmt.Sprintf("-ldflags=-v -tmpdir=%s", dir)
	argv := []string{"build", "-buildmode=c-archive", "-o", arfile, ldf, srcfile}
	out, err := testenv.Command(t, testenv.GoToolPath(t), argv...).CombinedOutput()
	if err != nil {
		t.Fatalf("build failure: %s\n%s\n", err, string(out))
	}

	found := false
	const want = "invoking archiver with syscall.Exec"
	for _, l := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(l, want) {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("expected '%s' in -v output, got:\n%s\n", want, string(out))
	}
}

func TestLargeTextSectionSplitting(t *testing.T) {
	switch runtime.GOARCH {
	case "ppc64", "ppc64le", "arm":
	case "arm64":
		if runtime.GOOS == "darwin" {
			break
		}
		fallthrough
	default:
		t.Skipf("text section splitting is not done in %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	testenv.MustHaveGoBuild(t)
	testenv.MustHaveCGO(t)
	t.Parallel()
	dir := t.TempDir()

	// NB: the use of -ldflags=-debugtextsize=1048576 tells the linker to
	// split text sections at a size threshold of 1M instead of the
	// architected limit of 67M or larger. The choice of building cmd/go
	// is arbitrary; we just need something sufficiently large that uses
	// external linking.
	exe := filepath.Join(dir, "go.exe")
	out, err := testenv.Command(t, testenv.GoToolPath(t), "build", "-o", exe, "-ldflags=-linkmode=external -debugtextsize=1048576", "cmd/go").CombinedOutput()
	if err != nil {
		t.Fatalf("build failure: %s\n%s\n", err, string(out))
	}

	// Check that we did split text sections.
	out, err = testenv.Command(t, testenv.GoToolPath(t), "tool", "nm", exe).CombinedOutput()
	if err != nil {
		t.Fatalf("nm failure: %s\n%s\n", err, string(out))
	}
	if !bytes.Contains(out, []byte("runtime.text.1")) {
		t.Errorf("runtime.text.1 not found, text section not split?")
	}

	// Result should be runnable.
	_, err = testenv.Command(t, exe, "version").CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
}

func TestWindowsBuildmodeCSharedASLR(t *testing.T) {
	platform := fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)
	switch platform {
	case "windows/amd64", "windows/386":
	default:
		t.Skip("skipping windows amd64/386 only test")
	}

	testenv.MustHaveCGO(t)

	t.Run("aslr", func(t *testing.T) {
		testWindowsBuildmodeCSharedASLR(t, true)
	})
	t.Run("no-aslr", func(t *testing.T) {
		testWindowsBuildmodeCSharedASLR(t, false)
	})
}

func testWindowsBuildmodeCSharedASLR(t *testing.T, useASLR bool) {
	t.Parallel()
	testenv.MustHaveGoBuild(t)

	dir := t.TempDir()

	srcfile := filepath.Join(dir, "test.go")
	objfile := filepath.Join(dir, "test.dll")
	if err := os.WriteFile(srcfile, []byte(`package main; func main() { print("hello") }`), 0666); err != nil {
		t.Fatal(err)
	}
	argv := []string{"build", "-buildmode=c-shared"}
	if !useASLR {
		argv = append(argv, "-ldflags", "-aslr=false")
	}
	argv = append(argv, "-o", objfile, srcfile)
	out, err := testenv.Command(t, testenv.GoToolPath(t), argv...).CombinedOutput()
	if err != nil {
		t.Fatalf("build failure: %s\n%s\n", err, string(out))
	}

	f, err := pe.Open(objfile)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var dc uint16
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		dc = oh.DllCharacteristics
	case *pe.OptionalHeader64:
		dc = oh.DllCharacteristics
		hasHEVA := (dc & pe.IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA) != 0
		if useASLR && !hasHEVA {
			t.Error("IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA flag is not set")
		} else if !useASLR && hasHEVA {
			t.Error("IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA flag should not be set")
		}
	default:
		t.Fatalf("unexpected optional header type of %T", f.OptionalHeader)
	}
	hasASLR := (dc & pe.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0
	if useASLR && !hasASLR {
		t.Error("IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE flag is not set")
	} else if !useASLR && hasASLR {
		t.Error("IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE flag should not be set")
	}
}

// TestMemProfileCheck tests that cmd/link sets
// runtime.disableMemoryProfiling if the runtime.MemProfile
// symbol is unreachable after deadcode (and not dynlinking).
// The runtime then uses that to set the default value of
// runtime.MemProfileRate, which this test checks.
func TestMemProfileCheck(t *testing.T) {
	testenv.MustHaveGoBuild(t)
	t.Parallel()

	tests := []struct {
		name    string
		prog    string
		wantOut string
	}{
		{
			"no_memprofile",
			`
package main
import "runtime"
func main() {
	println(runtime.MemProfileRate)
}
`,
			"0",
		},
		{
			"with_memprofile",
			`
package main
import "runtime"
func main() {
	runtime.MemProfile(nil, false)
	println(runtime.MemProfileRate)
}
`,
			"524288",
		},
		{
			"with_memprofile_indirect",
			`
package main
import "runtime"
var f = runtime.MemProfile
func main() {
	if f == nil {
		panic("no f")
	}
	println(runtime.MemProfileRate)
}
`,
			"524288",
		},
		{
			"with_memprofile_runtime_pprof",
			`
package main
import "runtime"
import "runtime/pprof"
func main() {
	_ = pprof.Profiles()
	println(runtime.MemProfileRate)
}
`,
			"524288",
		},
		{
			"with_memprofile_runtime_pprof_writeheap",
			`
package main
import "io"
import "runtime"
import "runtime/pprof"
func main() {
	_ = pprof.WriteHeapProfile(io.Discard)
	println(runtime.MemProfileRate)
}
`,
			"524288",
		},
		{
			"with_memprofile_runtime_pprof_lookupheap",
			`
package main
import "runtime"
import "runtime/pprof"
func main() {
	_ = pprof.Lookup("heap")
	println(runtime.MemProfileRate)
}
`,
			"524288",
		},
		{
			"with_memprofile_http_pprof",
			`
package main
import "runtime"
import _ "net/http/pprof"
func main() {
	println(runtime.MemProfileRate)
}
`,
			"524288",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tempDir := t.TempDir()
			src := filepath.Join(tempDir, "x.go")
			if err := os.WriteFile(src, []byte(tt.prog), 0644); err != nil {
				t.Fatal(err)
			}
			cmd := testenv.Command(t, testenv.GoToolPath(t), "run", src)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatal(err)
			}
			got := strings.TrimSpace(string(out))
			if got != tt.wantOut {
				t.Errorf("got %q; want %q", got, tt.wantOut)
			}
		})
	}
}

func TestRISCVTrampolines(t *testing.T) {
	testenv.MustHaveGoBuild(t)
	t.Parallel()

	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "x.s")

	// Calling b from a or c should not use trampolines, however
	// calling from d to a will require one.
	buf := new(bytes.Buffer)
	fmt.Fprintf(buf, "TEXT a(SB),$0-0\n")
	for i := 0; i < 1<<17; i++ {
		fmt.Fprintf(buf, "\tADD $0, X0, X0\n")
	}
	fmt.Fprintf(buf, "\tCALL b(SB)\n")
	fmt.Fprintf(buf, "\tRET\n")
	fmt.Fprintf(buf, "TEXT b(SB),$0-0\n")
	fmt.Fprintf(buf, "\tRET\n")
	fmt.Fprintf(buf, "TEXT c(SB),$0-0\n")
	fmt.Fprintf(buf, "\tCALL b(SB)\n")
	fmt.Fprintf(buf, "\tRET\n")
	fmt.Fprintf(buf, "TEXT ·d(SB),0,$0-0\n")
	for i := 0; i < 1<<17; i++ {
		fmt.Fprintf(buf, "\tADD $0, X0, X0\n")
	}
	fmt.Fprintf(buf, "\tCALL a(SB)\n")
	fmt.Fprintf(buf, "\tCALL c(SB)\n")
	fmt.Fprintf(buf, "\tRET\n")
	if err := os.WriteFile(tmpFile, buf.Bytes(), 0644); err != nil {
		t.Fatalf("Failed to write assembly file: %v", err)
	}

	if err := os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte("module riscvtramp"), 0644); err != nil {
		t.Fatalf("Failed to write file: %v\n", err)
	}
	main := `package main
func main() {
	d()
}

func d()
`
	if err := os.WriteFile(filepath.Join(tmpDir, "x.go"), []byte(main), 0644); err != nil {
		t.Fatalf("failed to write main: %v\n", err)
	}
	cmd := testenv.Command(t, testenv.GoToolPath(t), "build", "-ldflags=-linkmode=internal")
	cmd.Dir = tmpDir
	cmd.Env = append(os.Environ(), "GOARCH=riscv64", "GOOS=linux")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Build failed: %v, output: %s", err, out)
	}

	// Check what trampolines exist.
	cmd = testenv.Command(t, testenv.GoToolPath(t), "tool", "nm", filepath.Join(tmpDir, "riscvtramp"))
	cmd.Env = append(os.Environ(), "GOARCH=riscv64", "GOOS=linux")
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("nm failure: %s\n%s\n", err, string(out))
	}
	if !bytes.Contains(out, []byte(" T a-tramp0")) {
		t.Errorf("Trampoline a-tramp0 is missing")
	}
	if bytes.Contains(out, []byte(" T b-tramp0")) {
		t.Errorf("Trampoline b-tramp0 exists unnecessarily")
	}
}
```