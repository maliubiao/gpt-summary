Response:
Let's break down the thought process for analyzing the Go code snippet.

**1. Initial Understanding: The Context**

The first thing I noticed was the package path: `go/src/cmd/cgo/internal/testshared/shared_test.go`. This immediately signals that this is test code related to `cgo` and specifically the "shared" build mode. The `_test` suffix confirms it's a testing file. The `internal` directory suggests it's not intended for public use but rather for internal testing within the `cgo` command.

**2. Core Functionality Identification: Keyword Spotting and Structure**

I started scanning the code for keywords and structural elements that reveal its purpose.

* **`package shared_test`**: Reinforces that this is a test package.
* **`import (...)`**:  The imports provide valuable clues. `testing` is obviously for testing. `os/exec` indicates running external commands. `go/build` suggests interaction with the Go build system. `debug/elf` points to examining ELF files (shared libraries). `flag` indicates command-line flag processing. This combination strongly suggests the code tests building and manipulating shared libraries.
* **`var globalSkip = func(t testing.TB) {}`**:  A mechanism to skip tests under certain conditions.
* **`var gopathInstallDir, gorootInstallDir string`**:  Variables to store installation directories, likely for built artifacts.
* **`var minpkgs = []string{"runtime", "sync/atomic"}`**:  A minimal set of packages used for creating shared libraries.
* **`var testX = flag.Bool(...)`, `var testWork = flag.Bool(...)`**:  Definition of command-line flags.
* **`func run(t *testing.T, ...)` and `func runWithEnv(t *testing.T, ...)`**: Helper functions to execute commands and check for errors.
* **`func goCmd(t *testing.T, ...)`**: A core function to invoke the `go` tool. The logic around `-x` and the installation suffix hints at how it interacts with the build process.
* **`func testMain(m *testing.M) (int, error)` and `func TestMain(m *testing.M)`**: Standard Go test setup. The logic within `testMain` is crucial for understanding the test environment setup (GOPATH, GOROOT manipulation).
* **Numerous `func Test...` functions**:  Each function prefixed with `Test` is an individual test case. Their names (e.g., `TestSOBuilt`, `TestNoTextrel`, `TestTrivialExecutable`) provide hints about what each test verifies.

**3. Inferring the Purpose and Go Features Tested**

Based on the identified elements, I started forming hypotheses about the code's functionality:

* **Testing `-buildmode=shared`**: The presence of "shared" in the package path, variable names, and command invocations strongly suggests testing the shared library build mode in Go.
* **Testing CGO with shared libraries**: The `cmd/cgo` path and the use of `testenv.HasCGO()` indicate that CGO interaction with shared libraries is also being tested.
* **ELF file manipulation**: The `debug/elf` import points to testing aspects of the generated shared libraries' structure (e.g., checking for `DT_TEXTREL`, symbols, notes).
* **Linking and RPATH**: The `AssertIsLinkedTo`, `AssertHasRPath` functions, and the tests involving executable dependencies, suggest verifying correct linking and runtime path configuration.
* **ABI compatibility**: The `TestABIChecking` function directly tests the behavior when ABI-breaking changes are introduced.
* **Rebuilding logic**: `TestRebuilding`, `resetFileStamps`, and `touch` indicate testing how the Go build system handles rebuilding shared libraries when dependencies change.
* **Command-line flag processing**: The `flag` package usage and the descriptions of `testX` and `testWork` confirm that the test suite has its own command-line options.

**4. Code Example Construction (Mental Simulation and Pattern Matching)**

For each inferred Go feature, I mentally sketched out how it would be used in a typical scenario and then looked for corresponding patterns in the test code.

* **`-buildmode=shared`**:  The `goCmd` calls with `"-buildmode=shared"` were direct examples.
* **CGO**: The `TestCgoExecutable` and `TestCgoPIE` tests directly use packages with C code.
* **ELF checks**: The `TestNoTextrel`, `TestNoDupSymbols`, `TestNotes` functions demonstrate how the `elf` package is used to inspect shared library properties.
* **Linking**: The `AssertIsLinkedTo` function and the tests like `TestTrivialExecutable`, `TestGopathShlib` illustrate how linking is verified.

**5. Command-Line Argument Analysis**

I explicitly looked at how the `flag` package was used to define `testX` and `testWork` and then traced how these flags affected the execution of `goCmd`. This allowed me to explain their purpose and behavior.

**6. Identifying Potential Pitfalls**

I considered common issues developers might encounter when working with shared libraries in Go:

* **Forgetting `-linkshared`**: This is a fundamental requirement.
* **Incorrect RPATH/LD_LIBRARY_PATH**:  The tests verify RPATH, so this is a relevant point.
* **ABI incompatibility**: The `TestABIChecking` test directly addresses this.
* **Module mode incompatibility**: The code explicitly disables module mode, highlighting this as a potential issue.

**7. Structuring the Output**

Finally, I organized the information into the requested categories: functionality, code examples, command-line arguments, and common mistakes. I aimed for clear and concise explanations, backed by evidence from the code.

**Self-Correction/Refinement During the Process:**

* **Initial Focus on Individual Tests**: At first, I might have been tempted to analyze each `Test...` function in isolation. However, I quickly realized that understanding the setup in `testMain` and the helper functions like `goCmd` was crucial for grasping the overall picture.
* **Recognizing the Test Environment**:  The manipulation of GOPATH and GOROOT in `testMain` was a key insight. This indicated that the tests are designed to run in a controlled environment.
* **Connecting the Dots**: I continually looked for connections between different parts of the code. For example, the `minpkgs` variable directly relates to the initial shared library build in `testMain`.

By following this systematic approach, I could effectively analyze the Go code snippet and provide a comprehensive explanation of its functionality and the Go features it tests.
这个 `shared_test.go` 文件是 Go 语言 `cmd/cgo` 工具的内部测试文件，专注于测试 `cgo` 在构建共享库 (`-buildmode=shared`) 时的行为。

以下是它列举的功能：

1. **构建共享库 (`-buildmode=shared`)**:  测试使用 `go install -buildmode=shared` 命令构建 Go 共享库的功能。这包括构建只包含运行时和少量包的最小共享库，以及包含用户代码的共享库。
2. **链接到共享库 (`-linkshared`)**: 测试使用 `-linkshared` 标志将可执行文件链接到共享库的功能。这包括链接到 Go 运行时共享库以及用户自定义的共享库。
3. **检查生成的共享库**:  测试生成的共享库的各种属性，例如：
    * **是否被成功构建**: 检查共享库文件是否存在。
    * **是否不包含 textrel**: 验证共享库是否没有针对文本段的重定位 (对于安全性和性能很重要)。
    * **是否不包含重复符号**: 检查是否存在重复的符号定义。
    * **是否包含 .shlibname 文件**: 验证为共享库中的包生成了 `.shlibname` 文件，用于记录该包所在的共享库名称。
    * **是否包含特定的 ELF notes**: 检查共享库是否包含用于描述包列表、ABI 哈希和依赖项的特定 ELF notes。
    * **是否链接到正确的依赖**: 验证可执行文件和共享库链接到了预期的其他共享库。
    * **是否包含正确的 RPATH**: 验证可执行文件包含了正确的运行时库搜索路径 (RPATH)。
4. **测试不同类型的可执行文件**: 测试构建和运行不同类型的可执行文件，包括：
    * **简单的可执行文件**:  链接到共享运行时库的最小可执行文件。
    * **PIE (Position Independent Executable) 可执行文件**: 链接到共享运行时库的 PIE 可执行文件。
    * **使用 cgo 的可执行文件**: 链接到共享运行时库并包含 C 代码的可执行文件。
    * **链接到 GOPATH 中的共享库的可执行文件**: 测试链接到用户自定义的共享库。
5. **测试共享库的重建**:  测试当依赖的源代码或中间文件发生变化时，共享库是否能正确地被重建。
6. **测试 ABI (Application Binary Interface) 兼容性**:  测试当共享库的 ABI 发生变化时，链接到该库的可执行文件是否会检测到不兼容并报错。
7. **测试隐式包含**: 测试当一个包显式导入另一个包时，将前者构建为共享库是否会隐式包含后者。
8. **测试接口类型**:  确保空接口和非空接口的类型字段在不同的共享库中是唯一的，以保证接口比较的正确性。
9. **测试全局变量**: 测试从共享库中访问全局变量的功能。
10. **测试安装的共享包**: 测试针对已安装的共享包运行测试。
11. **测试生成的指针方法和哈希函数**: 测试在使用了 `-linkshared` 的情况下，生成的指针方法和哈希函数是否能正常工作。
12. **测试包的加载顺序**: 确保以非依赖顺序添加包也能正确构建共享库。
13. **测试 GC 数据**: 验证链接器在需要共享库中定义的类型时，能正确生成 GC (垃圾回收) 数据。
14. **测试符号解码**: 确保不会从共享库中解码类型符号 (避免潜在的 panic)。
15. **测试弱引用**: 验证在使用共享库实现接口时，弱引用能正常工作。
16. **测试构建 `std`**: 测试能否将 Go 标准库构建成共享库。

**推理 Go 语言功能的实现（并用 Go 代码举例说明）:**

这个测试文件主要关注 `go` 工具的 **构建模式 (`-buildmode`)** 和 **链接模式 (`-linkshared`)**。

**示例 1: 构建共享库**

```go
// 假设我们有一个简单的包 depBase，其路径是 ./depBase
// depBase/dep.go 内容如下:
package depBase

func HelloFromDepBase() string {
	return "Hello from depBase"
}

// 使用 go install 构建共享库
// 假设在 TestMain 中已经设置好了 GOPATH 和 GOROOT
goCmd(t, "install", "-buildmode=shared", "-linkshared", "./depBase")

// 运行 go list 命令可以查看生成的共享库路径
shlib := goCmd(t, "list", "-f", "{{.Shlib}}", "-buildmode=shared", "-linkshared", "./depBase")
// 假设输出类似: /path/to/gopath/pkg/linux_amd64_dynlink/testshared/depBase.so
fmt.Println(shlib)
```

**假设的输入与输出:**

* **输入 (命令):** `go install -buildmode=shared -linkshared ./depBase`
* **输出 (生成的共享库路径，取决于环境):** `/path/to/gopath/pkg/linux_amd64_dynlink/testshared/depBase.so`

**示例 2: 链接到共享库并运行**

```go
// 假设我们有一个可执行文件 exe，其路径是 ./exe
// exe/main.go 内容如下:
package main

import (
	"fmt"
	"testshared/depBase"
)

func main() {
	fmt.Println(depBase.HelloFromDepBase())
}

// 使用 go install 链接到共享库并构建可执行文件
goCmd(t, "install", "-linkshared", "./exe")

// 运行生成的可执行文件
run(t, "executable linked to shared library", "../../bin/exe")

// 可以使用 AssertIsLinkedTo 检查可执行文件是否链接到了 depBase 的共享库
// 假设 shlib 是上一个例子中获取的共享库路径
AssertIsLinkedTo(t, "../../bin/exe", filepath.Base(shlib))
```

**假设的输入与输出:**

* **输入 (命令):** `go install -linkshared ./exe`
* **输出 (运行可执行文件):** `Hello from depBase`

**命令行参数的具体处理:**

该测试文件自身处理了两个命令行参数：

* **`-testx`**:  类型为 `bool`，默认值为 `false`。如果设置为 `true`，则传递 `-x` 和 `-ldflags=-v` 给 `go` 子命令。
    * `-x`:  让 `go` 工具打印执行的外部命令，用于调试。
    * `-ldflags=-v`:  让链接器打印详细的链接信息。
* **`-testwork`**: 类型为 `bool`，默认值为 `false`。如果设置为 `true`，则会记录临时工作目录的路径，并且在测试结束后不会删除该目录。这对于调试测试过程中的构建产物很有用。

这两个参数在 `TestMain` 函数中使用 `flag` 包进行解析：

```go
var testX = flag.Bool("testx", false, "if true, pass -x to 'go' subcommands invoked by the test")
var testWork = flag.Bool("testwork", false, "if true, log and do not delete the temporary working directory")

func TestMain(m *testing.M) {
	log.SetFlags(log.Lshortfile)
	flag.Parse()
    // ... 后面根据 testWork 的值决定是否删除临时目录
    // ... 在 goCmd 函数中会根据 testX 的值添加 -x 和 -ldflags
}
```

**使用者易犯错的点 (假设开发者直接使用这些测试函数作为示例):**

1. **依赖测试环境**: 这些测试严重依赖于 `TestMain` 函数中设置的特定测试环境，包括 GOPATH、GOROOT 和临时目录的创建。直接复制这些测试函数到其他环境中可能无法正常运行。
2. **硬编码路径**: 代码中使用了诸如 `"../../bin/exe"` 这样的相对路径，这依赖于特定的目录结构。在不同的项目结构中使用可能会出错。
3. **假设共享库已构建**: 某些测试假设共享库已经被构建。在实际使用中，需要确保构建共享库的步骤在运行依赖它的代码之前完成。
4. **忘记 `-linkshared` 标志**:  在构建需要链接到共享库的可执行文件时，必须显式使用 `-linkshared` 标志。遗漏这个标志会导致链接错误或者可执行文件包含共享库的代码副本。

**示例说明易犯错的点:**

假设一个开发者想参考 `TestTrivialExecutable` 来构建和运行一个链接到共享库的简单程序，他可能会直接复制以下代码：

```go
func TestMyExecutable(t *testing.T) {
	goCmd(t, "install", "-linkshared", "./my_trivial")
	run(t, "my trivial executable", "../../bin/my_trivial")
	AssertIsLinkedTo(t, "../../bin/my_trivial", soname)
	AssertHasRPath(t, "../../bin/my_trivial", gorootInstallDir)
	checkSize(t, "../../bin/my_trivial", 256000)
}
```

**潜在的问题:**

* **`goCmd` 上下文**:  直接调用 `goCmd` 可能无法正常工作，因为它依赖于 `TestMain` 中设置的 `oldGOROOT` 等全局变量。
* **路径错误**: `"../../bin/my_trivial"` 这个路径假设了特定的目录结构，如果开发者将这段代码放在不同的位置，这个路径将不正确。
* **`soname` 和 `gorootInstallDir` 未定义**: 这两个变量也在 `TestMain` 中初始化，直接使用会导致编译错误。

因此，使用者需要理解这些测试代码的上下文，而不能简单地复制粘贴。他们应该参考测试代码的思想和方法，而不是直接使用测试函数本身。这个测试文件更多的是为了验证 `cgo` 和共享库功能的正确性，而不是作为通用的代码示例。

### 提示词
```
这是路径为go/src/cmd/cgo/internal/testshared/shared_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package shared_test

import (
	"bufio"
	"bytes"
	"cmd/cgo/internal/cgotest"
	"debug/elf"
	"encoding/binary"
	"flag"
	"fmt"
	"go/build"
	"internal/platform"
	"internal/testenv"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

var globalSkip = func(t testing.TB) {}

var gopathInstallDir, gorootInstallDir string
var oldGOROOT string

// This is the smallest set of packages we can link into a shared
// library (runtime/cgo is built implicitly).
var minpkgs = []string{"runtime", "sync/atomic"}
var soname = "libruntime,sync-atomic.so"

var testX = flag.Bool("testx", false, "if true, pass -x to 'go' subcommands invoked by the test")
var testWork = flag.Bool("testwork", false, "if true, log and do not delete the temporary working directory")

// run runs a command and calls t.Errorf if it fails.
func run(t *testing.T, msg string, args ...string) {
	runWithEnv(t, msg, nil, args...)
}

// runWithEnv runs a command under the given environment and calls t.Errorf if it fails.
func runWithEnv(t *testing.T, msg string, env []string, args ...string) {
	c := exec.Command(args[0], args[1:]...)
	if len(env) != 0 {
		c.Env = append(os.Environ(), env...)
	}
	if output, err := c.CombinedOutput(); err != nil {
		t.Errorf("executing %s (%s) failed %s:\n%s", strings.Join(args, " "), msg, err, output)
	}
}

// goCmd invokes the go tool with the installsuffix set up by TestMain. It calls
// t.Fatalf if the command fails.
func goCmd(t *testing.T, args ...string) string {
	newargs := []string{args[0]}
	if *testX && args[0] != "env" {
		newargs = append(newargs, "-x", "-ldflags=-v")
	}
	newargs = append(newargs, args[1:]...)
	c := exec.Command(filepath.Join(oldGOROOT, "bin", "go"), newargs...)
	stderr := new(strings.Builder)
	c.Stderr = stderr

	if testing.Verbose() && t == nil {
		fmt.Fprintf(os.Stderr, "+ go %s\n", strings.Join(args, " "))
		c.Stderr = os.Stderr
	}
	output, err := c.Output()

	if err != nil {
		if t != nil {
			t.Helper()
			t.Fatalf("executing %s failed %v:\n%s", strings.Join(c.Args, " "), err, stderr)
		} else {
			// Panic instead of using log.Fatalf so that deferred cleanup may run in testMain.
			log.Panicf("executing %s failed %v:\n%s", strings.Join(c.Args, " "), err, stderr)
		}
	}
	if testing.Verbose() && t != nil {
		t.Logf("go %s", strings.Join(args, " "))
		if stderr.Len() > 0 {
			t.Logf("%s", stderr)
		}
	}
	return string(bytes.TrimSpace(output))
}

// TestMain calls testMain so that the latter can use defer (TestMain exits with os.Exit).
func testMain(m *testing.M) (int, error) {
	if testing.Short() && os.Getenv("GO_BUILDER_NAME") == "" {
		globalSkip = func(t testing.TB) { t.Skip("short mode and $GO_BUILDER_NAME not set") }
		return m.Run(), nil
	}
	if !platform.BuildModeSupported(runtime.Compiler, "shared", runtime.GOOS, runtime.GOARCH) {
		globalSkip = func(t testing.TB) { t.Skip("shared build mode not supported") }
		return m.Run(), nil
	}
	if !testenv.HasCGO() {
		globalSkip = testenv.MustHaveCGO
		return m.Run(), nil
	}

	cwd, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	oldGOROOT = filepath.Join(cwd, "../../../../..")

	workDir, err := os.MkdirTemp("", "shared_test")
	if err != nil {
		return 0, err
	}
	if *testWork || testing.Verbose() {
		fmt.Printf("+ mkdir -p %s\n", workDir)
	}
	if !*testWork {
		defer os.RemoveAll(workDir)
	}

	// -buildmode=shared fundamentally does not work in module mode.
	// (It tries to share package dependencies across builds, but in module mode
	// each module has its own distinct set of dependency versions.)
	// We would like to eliminate it (see https://go.dev/issue/47788),
	// but first need to figure out a replacement that covers the small subset
	// of use-cases where -buildmode=shared still works today.
	// For now, run the tests in GOPATH mode only.
	os.Setenv("GO111MODULE", "off")

	// Some tests need to edit the source in GOPATH, so copy this directory to a
	// temporary directory and chdir to that.
	gopath := filepath.Join(workDir, "gopath")
	modRoot, err := cloneTestdataModule(gopath)
	if err != nil {
		return 0, err
	}
	if testing.Verbose() {
		fmt.Printf("+ export GOPATH=%s\n", gopath)
		fmt.Printf("+ cd %s\n", modRoot)
	}
	os.Setenv("GOPATH", gopath)
	// Explicitly override GOBIN as well, in case it was set through a GOENV file.
	os.Setenv("GOBIN", filepath.Join(gopath, "bin"))
	os.Chdir(modRoot)
	os.Setenv("PWD", modRoot)

	// The test also needs to install libraries into GOROOT/pkg, so copy the
	// subset of GOROOT that we need.
	//
	// TODO(golang.org/issue/28553): Rework -buildmode=shared so that it does not
	// need to write to GOROOT.
	goroot := filepath.Join(workDir, "goroot")
	if err := cloneGOROOTDeps(goroot); err != nil {
		return 0, err
	}
	if testing.Verbose() {
		fmt.Fprintf(os.Stderr, "+ export GOROOT=%s\n", goroot)
	}
	os.Setenv("GOROOT", goroot)

	myContext := build.Default
	myContext.GOROOT = goroot
	myContext.GOPATH = gopath

	// All tests depend on runtime being built into a shared library. Because
	// that takes a few seconds, do it here and have all tests use the version
	// built here.
	goCmd(nil, append([]string{"install", "-buildmode=shared"}, minpkgs...)...)

	shlib := goCmd(nil, "list", "-linkshared", "-f={{.Shlib}}", "runtime")
	if shlib != "" {
		gorootInstallDir = filepath.Dir(shlib)
	}

	myContext.InstallSuffix = "_dynlink"
	depP, err := myContext.Import("./depBase", ".", build.ImportComment)
	if err != nil {
		return 0, fmt.Errorf("import failed: %v", err)
	}
	if depP.PkgTargetRoot == "" {
		gopathInstallDir = filepath.Dir(goCmd(nil, "list", "-buildmode=shared", "-f", "{{.Target}}", "./depBase"))
	} else {
		gopathInstallDir = filepath.Join(depP.PkgTargetRoot, "testshared")
	}
	return m.Run(), nil
}

func TestMain(m *testing.M) {
	log.SetFlags(log.Lshortfile)
	flag.Parse()

	exitCode, err := testMain(m)
	if err != nil {
		log.Fatal(err)
	}
	os.Exit(exitCode)
}

// cloneTestdataModule clones the packages from src/testshared into gopath.
// It returns the directory within gopath at which the module root is located.
func cloneTestdataModule(gopath string) (string, error) {
	modRoot := filepath.Join(gopath, "src", "testshared")
	if err := cgotest.OverlayDir(modRoot, "testdata"); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(modRoot, "go.mod"), []byte("module testshared\n"), 0644); err != nil {
		return "", err
	}
	return modRoot, nil
}

// cloneGOROOTDeps copies (or symlinks) the portions of GOROOT/src and
// GOROOT/pkg relevant to this test into the given directory.
// It must be run from within the testdata module.
func cloneGOROOTDeps(goroot string) error {
	// Before we clone GOROOT, figure out which packages we need to copy over.
	listArgs := []string{
		"list",
		"-deps",
		"-f", "{{if and .Standard (not .ForTest)}}{{.ImportPath}}{{end}}",
	}
	stdDeps := goCmd(nil, append(listArgs, minpkgs...)...)
	testdataDeps := goCmd(nil, append(listArgs, "-test", "./...")...)

	pkgs := append(strings.Split(strings.TrimSpace(stdDeps), "\n"),
		strings.Split(strings.TrimSpace(testdataDeps), "\n")...)
	sort.Strings(pkgs)
	var pkgRoots []string
	for _, pkg := range pkgs {
		parentFound := false
		for _, prev := range pkgRoots {
			if pkg == prev || strings.HasPrefix(pkg, prev+"/") {
				// We will copy in the source for pkg when we copy in prev.
				parentFound = true
				break
			}
		}
		if !parentFound {
			pkgRoots = append(pkgRoots, pkg)
		}
	}

	gorootDirs := []string{
		"pkg/tool",
		"pkg/include",
	}
	for _, pkg := range pkgRoots {
		gorootDirs = append(gorootDirs, filepath.Join("src", pkg))
	}

	for _, dir := range gorootDirs {
		if testing.Verbose() {
			fmt.Fprintf(os.Stderr, "+ cp -r %s %s\n", filepath.Join(oldGOROOT, dir), filepath.Join(goroot, dir))
		}
		if err := cgotest.OverlayDir(filepath.Join(goroot, dir), filepath.Join(oldGOROOT, dir)); err != nil {
			return err
		}
	}

	return nil
}

// The shared library was built at the expected location.
func TestSOBuilt(t *testing.T) {
	globalSkip(t)
	_, err := os.Stat(filepath.Join(gorootInstallDir, soname))
	if err != nil {
		t.Error(err)
	}
}

func hasDynTag(f *elf.File, tag elf.DynTag) bool {
	ds := f.SectionByType(elf.SHT_DYNAMIC)
	if ds == nil {
		return false
	}
	d, err := ds.Data()
	if err != nil {
		return false
	}
	for len(d) > 0 {
		var t elf.DynTag
		switch f.Class {
		case elf.ELFCLASS32:
			t = elf.DynTag(f.ByteOrder.Uint32(d[0:4]))
			d = d[8:]
		case elf.ELFCLASS64:
			t = elf.DynTag(f.ByteOrder.Uint64(d[0:8]))
			d = d[16:]
		}
		if t == tag {
			return true
		}
	}
	return false
}

// The shared library does not have relocations against the text segment.
func TestNoTextrel(t *testing.T) {
	globalSkip(t)
	sopath := filepath.Join(gorootInstallDir, soname)
	f, err := elf.Open(sopath)
	if err != nil {
		t.Fatal("elf.Open failed: ", err)
	}
	defer f.Close()
	if hasDynTag(f, elf.DT_TEXTREL) {
		t.Errorf("%s has DT_TEXTREL set", soname)
	}
}

// The shared library does not contain symbols called ".dup"
// (See golang.org/issue/14841.)
func TestNoDupSymbols(t *testing.T) {
	globalSkip(t)
	sopath := filepath.Join(gorootInstallDir, soname)
	f, err := elf.Open(sopath)
	if err != nil {
		t.Fatal("elf.Open failed: ", err)
	}
	defer f.Close()
	syms, err := f.Symbols()
	if err != nil {
		t.Errorf("error reading symbols %v", err)
		return
	}
	for _, s := range syms {
		if s.Name == ".dup" {
			t.Fatalf("%s contains symbol called .dup", sopath)
		}
	}
}

// The install command should have created a "shlibname" file for the
// listed packages (and runtime/cgo, and math on arm) indicating the
// name of the shared library containing it.
func TestShlibnameFiles(t *testing.T) {
	globalSkip(t)
	pkgs := append([]string{}, minpkgs...)
	pkgs = append(pkgs, "runtime/cgo")
	if runtime.GOARCH == "arm" {
		pkgs = append(pkgs, "math")
	}
	for _, pkg := range pkgs {
		shlibnamefile := filepath.Join(gorootInstallDir, pkg+".shlibname")
		contentsb, err := os.ReadFile(shlibnamefile)
		if err != nil {
			t.Errorf("error reading shlibnamefile for %s: %v", pkg, err)
			continue
		}
		contents := strings.TrimSpace(string(contentsb))
		if contents != soname {
			t.Errorf("shlibnamefile for %s has wrong contents: %q", pkg, contents)
		}
	}
}

// Is a given offset into the file contained in a loaded segment?
func isOffsetLoaded(f *elf.File, offset uint64) bool {
	for _, prog := range f.Progs {
		if prog.Type == elf.PT_LOAD {
			if prog.Off <= offset && offset < prog.Off+prog.Filesz {
				return true
			}
		}
	}
	return false
}

func rnd(v int32, r int32) int32 {
	if r <= 0 {
		return v
	}
	v += r - 1
	c := v % r
	if c < 0 {
		c += r
	}
	v -= c
	return v
}

func readwithpad(r io.Reader, sz int32) ([]byte, error) {
	data := make([]byte, rnd(sz, 4))
	_, err := io.ReadFull(r, data)
	if err != nil {
		return nil, err
	}
	data = data[:sz]
	return data, nil
}

type note struct {
	name    string
	tag     int32
	desc    string
	section *elf.Section
}

// Read all notes from f. As ELF section names are not supposed to be special, one
// looks for a particular note by scanning all SHT_NOTE sections looking for a note
// with a particular "name" and "tag".
func readNotes(f *elf.File) ([]*note, error) {
	var notes []*note
	for _, sect := range f.Sections {
		if sect.Type != elf.SHT_NOTE {
			continue
		}
		r := sect.Open()
		for {
			var namesize, descsize, tag int32
			err := binary.Read(r, f.ByteOrder, &namesize)
			if err != nil {
				if err == io.EOF {
					break
				}
				return nil, fmt.Errorf("read namesize failed: %v", err)
			}
			err = binary.Read(r, f.ByteOrder, &descsize)
			if err != nil {
				return nil, fmt.Errorf("read descsize failed: %v", err)
			}
			err = binary.Read(r, f.ByteOrder, &tag)
			if err != nil {
				return nil, fmt.Errorf("read type failed: %v", err)
			}
			name, err := readwithpad(r, namesize)
			if err != nil {
				return nil, fmt.Errorf("read name failed: %v", err)
			}
			desc, err := readwithpad(r, descsize)
			if err != nil {
				return nil, fmt.Errorf("read desc failed: %v", err)
			}
			notes = append(notes, &note{name: string(name), tag: tag, desc: string(desc), section: sect})
		}
	}
	return notes, nil
}

func dynStrings(t *testing.T, path string, flag elf.DynTag) []string {
	t.Helper()
	f, err := elf.Open(path)
	if err != nil {
		t.Fatalf("elf.Open(%q) failed: %v", path, err)
	}
	defer f.Close()
	dynstrings, err := f.DynString(flag)
	if err != nil {
		t.Fatalf("DynString(%s) failed on %s: %v", flag, path, err)
	}
	return dynstrings
}

func AssertIsLinkedToRegexp(t *testing.T, path string, re *regexp.Regexp) {
	t.Helper()
	for _, dynstring := range dynStrings(t, path, elf.DT_NEEDED) {
		if re.MatchString(dynstring) {
			return
		}
	}
	t.Errorf("%s is not linked to anything matching %v", path, re)
}

func AssertIsLinkedTo(t *testing.T, path, lib string) {
	t.Helper()
	AssertIsLinkedToRegexp(t, path, regexp.MustCompile(regexp.QuoteMeta(lib)))
}

func AssertHasRPath(t *testing.T, path, dir string) {
	t.Helper()
	for _, tag := range []elf.DynTag{elf.DT_RPATH, elf.DT_RUNPATH} {
		for _, dynstring := range dynStrings(t, path, tag) {
			for _, rpath := range strings.Split(dynstring, ":") {
				if filepath.Clean(rpath) == filepath.Clean(dir) {
					return
				}
			}
		}
	}
	t.Errorf("%s does not have rpath %s", path, dir)
}

// Build a trivial program that links against the shared runtime and check it runs.
func TestTrivialExecutable(t *testing.T) {
	globalSkip(t)
	goCmd(t, "install", "-linkshared", "./trivial")
	run(t, "trivial executable", "../../bin/trivial")
	AssertIsLinkedTo(t, "../../bin/trivial", soname)
	AssertHasRPath(t, "../../bin/trivial", gorootInstallDir)
	// It is 19K on linux/amd64, with separate-code in binutils ld and 64k being most common alignment
	// 4*64k should be enough, but this might need revision eventually.
	checkSize(t, "../../bin/trivial", 256000)
}

// Build a trivial program in PIE mode that links against the shared runtime and check it runs.
func TestTrivialExecutablePIE(t *testing.T) {
	globalSkip(t)
	goCmd(t, "build", "-buildmode=pie", "-o", "trivial.pie", "-linkshared", "./trivial")
	run(t, "trivial executable", "./trivial.pie")
	AssertIsLinkedTo(t, "./trivial.pie", soname)
	AssertHasRPath(t, "./trivial.pie", gorootInstallDir)
	// It is 19K on linux/amd64, with separate-code in binutils ld and 64k being most common alignment
	// 4*64k should be enough, but this might need revision eventually.
	checkSize(t, "./trivial.pie", 256000)
}

// Check that the file size does not exceed a limit.
func checkSize(t *testing.T, f string, limit int64) {
	fi, err := os.Stat(f)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	if sz := fi.Size(); sz > limit {
		t.Errorf("file too large: got %d, want <= %d", sz, limit)
	}
}

// Build a division test program and check it runs.
func TestDivisionExecutable(t *testing.T) {
	globalSkip(t)
	goCmd(t, "install", "-linkshared", "./division")
	run(t, "division executable", "../../bin/division")
}

// Build an executable that uses cgo linked against the shared runtime and check it
// runs.
func TestCgoExecutable(t *testing.T) {
	globalSkip(t)
	goCmd(t, "install", "-linkshared", "./execgo")
	run(t, "cgo executable", "../../bin/execgo")
}

func checkPIE(t *testing.T, name string) {
	f, err := elf.Open(name)
	if err != nil {
		t.Fatal("elf.Open failed: ", err)
	}
	defer f.Close()
	if f.Type != elf.ET_DYN {
		t.Errorf("%s has type %v, want ET_DYN", name, f.Type)
	}
	if hasDynTag(f, elf.DT_TEXTREL) {
		t.Errorf("%s has DT_TEXTREL set", name)
	}
}

func TestTrivialPIE(t *testing.T) {
	if strings.HasSuffix(os.Getenv("GO_BUILDER_NAME"), "-alpine") {
		t.Skip("skipping on alpine until issue #54354 resolved")
	}
	globalSkip(t)
	testenv.MustHaveBuildMode(t, "pie")
	name := "trivial_pie"
	goCmd(t, "build", "-buildmode=pie", "-o="+name, "./trivial")
	defer os.Remove(name)
	run(t, name, "./"+name)
	checkPIE(t, name)
}

func TestCgoPIE(t *testing.T) {
	globalSkip(t)
	testenv.MustHaveCGO(t)
	testenv.MustHaveBuildMode(t, "pie")
	name := "cgo_pie"
	goCmd(t, "build", "-buildmode=pie", "-o="+name, "./execgo")
	defer os.Remove(name)
	run(t, name, "./"+name)
	checkPIE(t, name)
}

// Build a GOPATH package into a shared library that links against the goroot runtime
// and an executable that links against both.
func TestGopathShlib(t *testing.T) {
	globalSkip(t)
	goCmd(t, "install", "-buildmode=shared", "-linkshared", "./depBase")
	shlib := goCmd(t, "list", "-f", "{{.Shlib}}", "-buildmode=shared", "-linkshared", "./depBase")
	AssertIsLinkedTo(t, shlib, soname)
	goCmd(t, "install", "-linkshared", "./exe")
	AssertIsLinkedTo(t, "../../bin/exe", soname)
	AssertIsLinkedTo(t, "../../bin/exe", filepath.Base(shlib))
	AssertHasRPath(t, "../../bin/exe", gorootInstallDir)
	AssertHasRPath(t, "../../bin/exe", filepath.Dir(gopathInstallDir))
	// And check it runs.
	run(t, "executable linked to GOPATH library", "../../bin/exe")
}

// The shared library contains a note listing the packages it contains in a section
// that is not mapped into memory.
func testPkgListNote(t *testing.T, f *elf.File, note *note) {
	if note.section.Flags != 0 {
		t.Errorf("package list section has flags %v, want 0", note.section.Flags)
	}
	if isOffsetLoaded(f, note.section.Offset) {
		t.Errorf("package list section contained in PT_LOAD segment")
	}
	if note.desc != "testshared/depBase\n" {
		t.Errorf("incorrect package list %q, want %q", note.desc, "testshared/depBase\n")
	}
}

// The shared library contains a note containing the ABI hash that is mapped into
// memory and there is a local symbol called go.link.abihashbytes that points 16
// bytes into it.
func testABIHashNote(t *testing.T, f *elf.File, note *note) {
	if note.section.Flags != elf.SHF_ALLOC {
		t.Errorf("abi hash section has flags %v, want SHF_ALLOC", note.section.Flags)
	}
	if !isOffsetLoaded(f, note.section.Offset) {
		t.Errorf("abihash section not contained in PT_LOAD segment")
	}
	var hashbytes elf.Symbol
	symbols, err := f.Symbols()
	if err != nil {
		t.Errorf("error reading symbols %v", err)
		return
	}
	for _, sym := range symbols {
		if sym.Name == "go:link.abihashbytes" {
			hashbytes = sym
		}
	}
	if hashbytes.Name == "" {
		t.Errorf("no symbol called go:link.abihashbytes")
		return
	}
	if elf.ST_BIND(hashbytes.Info) != elf.STB_LOCAL {
		t.Errorf("%s has incorrect binding %v, want STB_LOCAL", hashbytes.Name, elf.ST_BIND(hashbytes.Info))
	}
	if f.Sections[hashbytes.Section] != note.section {
		t.Errorf("%s has incorrect section %v, want %s", hashbytes.Name, f.Sections[hashbytes.Section].Name, note.section.Name)
	}
	if hashbytes.Value-note.section.Addr != 16 {
		t.Errorf("%s has incorrect offset into section %d, want 16", hashbytes.Name, hashbytes.Value-note.section.Addr)
	}
}

// A Go shared library contains a note indicating which other Go shared libraries it
// was linked against in an unmapped section.
func testDepsNote(t *testing.T, f *elf.File, note *note) {
	if note.section.Flags != 0 {
		t.Errorf("package list section has flags %v, want 0", note.section.Flags)
	}
	if isOffsetLoaded(f, note.section.Offset) {
		t.Errorf("package list section contained in PT_LOAD segment")
	}
	// libdepBase.so just links against the lib containing the runtime.
	if note.desc != soname {
		t.Errorf("incorrect dependency list %q, want %q", note.desc, soname)
	}
}

// The shared library contains notes with defined contents; see above.
func TestNotes(t *testing.T) {
	globalSkip(t)
	goCmd(t, "install", "-buildmode=shared", "-linkshared", "./depBase")
	shlib := goCmd(t, "list", "-f", "{{.Shlib}}", "-buildmode=shared", "-linkshared", "./depBase")
	f, err := elf.Open(shlib)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	notes, err := readNotes(f)
	if err != nil {
		t.Fatal(err)
	}
	pkgListNoteFound := false
	abiHashNoteFound := false
	depsNoteFound := false
	for _, note := range notes {
		if note.name != "Go\x00\x00" {
			continue
		}
		switch note.tag {
		case 1: // ELF_NOTE_GOPKGLIST_TAG
			if pkgListNoteFound {
				t.Error("multiple package list notes")
			}
			testPkgListNote(t, f, note)
			pkgListNoteFound = true
		case 2: // ELF_NOTE_GOABIHASH_TAG
			if abiHashNoteFound {
				t.Error("multiple abi hash notes")
			}
			testABIHashNote(t, f, note)
			abiHashNoteFound = true
		case 3: // ELF_NOTE_GODEPS_TAG
			if depsNoteFound {
				t.Error("multiple dependency list notes")
			}
			testDepsNote(t, f, note)
			depsNoteFound = true
		}
	}
	if !pkgListNoteFound {
		t.Error("package list note not found")
	}
	if !abiHashNoteFound {
		t.Error("abi hash note not found")
	}
	if !depsNoteFound {
		t.Error("deps note not found")
	}
}

// Build a GOPATH package (depBase) into a shared library that links against the goroot
// runtime, another package (dep2) that links against the first, and an
// executable that links against dep2.
func TestTwoGopathShlibs(t *testing.T) {
	globalSkip(t)
	goCmd(t, "install", "-buildmode=shared", "-linkshared", "./depBase")
	goCmd(t, "install", "-buildmode=shared", "-linkshared", "./dep2")
	goCmd(t, "install", "-linkshared", "./exe2")
	run(t, "executable linked to GOPATH library", "../../bin/exe2")
}

func TestThreeGopathShlibs(t *testing.T) {
	globalSkip(t)
	goCmd(t, "install", "-buildmode=shared", "-linkshared", "./depBase")
	goCmd(t, "install", "-buildmode=shared", "-linkshared", "./dep2")
	goCmd(t, "install", "-buildmode=shared", "-linkshared", "./dep3")
	goCmd(t, "install", "-linkshared", "./exe3")
	run(t, "executable linked to GOPATH library", "../../bin/exe3")
}

// If gccgo is not available or not new enough, call t.Skip.
func requireGccgo(t *testing.T) {
	t.Helper()

	if runtime.GOARCH == "ppc64" || runtime.GOARCH == "ppc64le" {
		t.Skip("gccgo test skipped on PPC64 until issue #60798 is resolved")
	}

	gccgoName := os.Getenv("GCCGO")
	if gccgoName == "" {
		gccgoName = "gccgo"
	}
	gccgoPath, err := exec.LookPath(gccgoName)
	if err != nil {
		t.Skip("gccgo not found")
	}
	cmd := exec.Command(gccgoPath, "-dumpversion")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s -dumpversion failed: %v\n%s", gccgoPath, err, output)
	}
	dot := bytes.Index(output, []byte{'.'})
	if dot > 0 {
		output = output[:dot]
	}
	major, err := strconv.Atoi(strings.TrimSpace(string(output)))
	if err != nil {
		t.Skipf("can't parse gccgo version number %s", output)
	}
	if major < 5 {
		t.Skipf("gccgo too old (%s)", strings.TrimSpace(string(output)))
	}

	gomod, err := exec.Command("go", "env", "GOMOD").Output()
	if err != nil {
		t.Fatalf("go env GOMOD: %v", err)
	}
	if len(bytes.TrimSpace(gomod)) > 0 {
		t.Skipf("gccgo not supported in module mode; see golang.org/issue/30344")
	}
}

// Build a GOPATH package into a shared library with gccgo and an executable that
// links against it.
func TestGoPathShlibGccgo(t *testing.T) {
	globalSkip(t)
	requireGccgo(t)

	libgoRE := regexp.MustCompile("libgo.so.[0-9]+")

	goCmd(t, "install", "-compiler=gccgo", "-buildmode=shared", "-linkshared", "./depBase")

	// Run 'go list' after 'go install': with gccgo, we apparently don't know the
	// shlib location until after we've installed it.
	shlib := goCmd(t, "list", "-compiler=gccgo", "-buildmode=shared", "-linkshared", "-f", "{{.Shlib}}", "./depBase")

	AssertIsLinkedToRegexp(t, shlib, libgoRE)
	goCmd(t, "install", "-compiler=gccgo", "-linkshared", "./exe")
	AssertIsLinkedToRegexp(t, "../../bin/exe", libgoRE)
	AssertIsLinkedTo(t, "../../bin/exe", filepath.Base(shlib))
	AssertHasRPath(t, "../../bin/exe", filepath.Dir(shlib))
	// And check it runs.
	run(t, "gccgo-built", "../../bin/exe")
}

// The gccgo version of TestTwoGopathShlibs: build a GOPATH package into a shared
// library with gccgo, another GOPATH package that depends on the first and an
// executable that links the second library.
func TestTwoGopathShlibsGccgo(t *testing.T) {
	globalSkip(t)
	requireGccgo(t)

	libgoRE := regexp.MustCompile("libgo.so.[0-9]+")

	goCmd(t, "install", "-compiler=gccgo", "-buildmode=shared", "-linkshared", "./depBase")
	goCmd(t, "install", "-compiler=gccgo", "-buildmode=shared", "-linkshared", "./dep2")
	goCmd(t, "install", "-compiler=gccgo", "-linkshared", "./exe2")

	// Run 'go list' after 'go install': with gccgo, we apparently don't know the
	// shlib location until after we've installed it.
	dep2 := goCmd(t, "list", "-compiler=gccgo", "-buildmode=shared", "-linkshared", "-f", "{{.Shlib}}", "./dep2")
	depBase := goCmd(t, "list", "-compiler=gccgo", "-buildmode=shared", "-linkshared", "-f", "{{.Shlib}}", "./depBase")

	AssertIsLinkedToRegexp(t, depBase, libgoRE)
	AssertIsLinkedToRegexp(t, dep2, libgoRE)
	AssertIsLinkedTo(t, dep2, filepath.Base(depBase))
	AssertIsLinkedToRegexp(t, "../../bin/exe2", libgoRE)
	AssertIsLinkedTo(t, "../../bin/exe2", filepath.Base(dep2))
	AssertIsLinkedTo(t, "../../bin/exe2", filepath.Base(depBase))

	// And check it runs.
	run(t, "gccgo-built", "../../bin/exe2")
}

// Testing rebuilding of shared libraries when they are stale is a bit more
// complicated that it seems like it should be. First, we make everything "old": but
// only a few seconds old, or it might be older than gc (or the runtime source) and
// everything will get rebuilt. Then define a timestamp slightly newer than this
// time, which is what we set the mtime to of a file to cause it to be seen as new,
// and finally another slightly even newer one that we can compare files against to
// see if they have been rebuilt.
var oldTime = time.Now().Add(-9 * time.Second)
var nearlyNew = time.Now().Add(-6 * time.Second)
var stampTime = time.Now().Add(-3 * time.Second)

// resetFileStamps makes "everything" (bin, src, pkg from GOPATH and the
// test-specific parts of GOROOT) appear old.
func resetFileStamps() {
	chtime := func(path string, info os.FileInfo, err error) error {
		return os.Chtimes(path, oldTime, oldTime)
	}
	reset := func(path string) {
		if err := filepath.Walk(path, chtime); err != nil {
			log.Panicf("resetFileStamps failed: %v", err)
		}

	}
	reset("../../bin")
	reset("../../pkg")
	reset("../../src")
	reset(gorootInstallDir)
}

// touch changes path and returns a function that changes it back.
// It also sets the time of the file, so that we can see if it is rewritten.
func touch(t *testing.T, path string) (cleanup func()) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	old := make([]byte, len(data))
	copy(old, data)
	if bytes.HasPrefix(data, []byte("!<arch>\n")) {
		// Change last digit of build ID.
		// (Content ID in the new content-based build IDs.)
		const marker = `build id "`
		i := bytes.Index(data, []byte(marker))
		if i < 0 {
			t.Fatal("cannot find build id in archive")
		}
		j := bytes.IndexByte(data[i+len(marker):], '"')
		if j < 0 {
			t.Fatal("cannot find build id in archive")
		}
		i += len(marker) + j - 1
		if data[i] == 'a' {
			data[i] = 'b'
		} else {
			data[i] = 'a'
		}
	} else {
		// assume it's a text file
		data = append(data, '\n')
	}

	// If the file is still a symlink from an overlay, delete it so that we will
	// replace it with a regular file instead of overwriting the symlinked one.
	fi, err := os.Lstat(path)
	if err == nil && !fi.Mode().IsRegular() {
		fi, err = os.Stat(path)
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	if err != nil {
		t.Fatal(err)
	}

	// If we're replacing a symlink to a read-only file, make the new file
	// user-writable.
	perm := fi.Mode().Perm() | 0200

	if err := os.WriteFile(path, data, perm); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, nearlyNew, nearlyNew); err != nil {
		t.Fatal(err)
	}
	return func() {
		if err := os.WriteFile(path, old, perm); err != nil {
			t.Fatal(err)
		}
	}
}

// isNew returns if the path is newer than the time stamp used by touch.
func isNew(t *testing.T, path string) bool {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.ModTime().After(stampTime)
}

// Fail unless path has been rebuilt (i.e. is newer than the time stamp used by
// isNew)
func AssertRebuilt(t *testing.T, msg, path string) {
	t.Helper()
	if !isNew(t, path) {
		t.Errorf("%s was not rebuilt (%s)", msg, path)
	}
}

// Fail if path has been rebuilt (i.e. is newer than the time stamp used by isNew)
func AssertNotRebuilt(t *testing.T, msg, path string) {
	t.Helper()
	if isNew(t, path) {
		t.Errorf("%s was rebuilt (%s)", msg, path)
	}
}

func TestRebuilding(t *testing.T) {
	globalSkip(t)
	goCmd(t, "install", "-buildmode=shared", "-linkshared", "./depBase")
	goCmd(t, "install", "-linkshared", "./exe")
	info := strings.Fields(goCmd(t, "list", "-buildmode=shared", "-linkshared", "-f", "{{.Target}} {{.Shlib}}", "./depBase"))
	if len(info) != 2 {
		t.Fatalf("go list failed to report Target and/or Shlib")
	}
	target := info[0]
	shlib := info[1]

	// If the source is newer than both the .a file and the .so, both are rebuilt.
	t.Run("newsource", func(t *testing.T) {
		resetFileStamps()
		cleanup := touch(t, "./depBase/dep.go")
		defer func() {
			cleanup()
			goCmd(t, "install", "-linkshared", "./exe")
		}()
		goCmd(t, "install", "-linkshared", "./exe")
		AssertRebuilt(t, "new source", target)
		AssertRebuilt(t, "new source", shlib)
	})

	// If the .a file is newer than the .so, the .so is rebuilt (but not the .a)
	t.Run("newarchive", func(t *testing.T) {
		resetFileStamps()
		AssertNotRebuilt(t, "new .a file before build", target)
		goCmd(t, "list", "-linkshared", "-f={{.ImportPath}} {{.Stale}} {{.StaleReason}} {{.Target}}", "./depBase")
		AssertNotRebuilt(t, "new .a file before build", target)
		cleanup := touch(t, target)
		defer func() {
			cleanup()
			goCmd(t, "install", "-v", "-linkshared", "./exe")
		}()
		goCmd(t, "install", "-v", "-linkshared", "./exe")
		AssertNotRebuilt(t, "new .a file", target)
		AssertRebuilt(t, "new .a file", shlib)
	})
}

func appendFile(t *testing.T, path, content string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0660)
	if err != nil {
		t.Fatalf("os.OpenFile failed: %v", err)
	}
	defer func() {
		err := f.Close()
		if err != nil {
			t.Fatalf("f.Close failed: %v", err)
		}
	}()
	_, err = f.WriteString(content)
	if err != nil {
		t.Fatalf("f.WriteString failed: %v", err)
	}
}

func createFile(t *testing.T, path, content string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		t.Fatalf("os.OpenFile failed: %v", err)
	}
	_, err = f.WriteString(content)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatalf("WriteString failed: %v", err)
	}
}

func TestABIChecking(t *testing.T) {
	globalSkip(t)
	goCmd(t, "install", "-buildmode=shared", "-linkshared", "./depBase")
	goCmd(t, "install", "-linkshared", "./exe")

	// If we make an ABI-breaking change to depBase and rebuild libp.so but not exe,
	// exe will abort with a complaint on startup.
	// This assumes adding an exported function breaks ABI, which is not true in
	// some senses but suffices for the narrow definition of ABI compatibility the
	// toolchain uses today.
	resetFileStamps()

	createFile(t, "./depBase/break.go", "package depBase\nfunc ABIBreak() {}\n")
	defer os.Remove("./depBase/break.go")

	goCmd(t, "install", "-buildmode=shared", "-linkshared", "./depBase")
	c := exec.Command("../../bin/exe")
	output, err := c.CombinedOutput()
	if err == nil {
		t.Fatal("executing exe did not fail after ABI break")
	}
	scanner := bufio.NewScanner(bytes.NewReader(output))
	foundMsg := false
	const wantPrefix = "abi mismatch detected between the executable and lib"
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), wantPrefix) {
			foundMsg = true
			break
		}
	}
	if err = scanner.Err(); err != nil {
		t.Errorf("scanner encountered error: %v", err)
	}
	if !foundMsg {
		t.Fatalf("exe failed, but without line %q; got output:\n%s", wantPrefix, output)
	}

	// Rebuilding exe makes it work again.
	goCmd(t, "install", "-linkshared", "./exe")
	run(t, "rebuilt exe", "../../bin/exe")

	// If we make a change which does not break ABI (such as adding an unexported
	// function) and rebuild libdepBase.so, exe still works, even if new function
	// is in a file by itself.
	resetFileStamps()
	createFile(t, "./depBase/dep2.go", "package depBase\nfunc noABIBreak() {}\n")
	goCmd(t, "install", "-buildmode=shared", "-linkshared", "./depBase")
	run(t, "after non-ABI breaking change", "../../bin/exe")
}

// If a package 'explicit' imports a package 'implicit', building
// 'explicit' into a shared library implicitly includes implicit in
// the shared library. Building an executable that imports both
// explicit and implicit builds the code from implicit into the
// executable rather than fetching it from the shared library. The
// link still succeeds and the executable still runs though.
func TestImplicitInclusion(t *testing.T) {
	globalSkip(t)
	goCmd(t, "install", "-buildmode=shared", "-linkshared", "./explicit")
	goCmd(t, "install", "-linkshared", "./implicitcmd")
	run(t, "running executable linked against library that contains same package as it", "../../bin/implicitcmd")
}

// Tests to make sure that the type fields of empty interfaces and itab
// fields of nonempty interfaces are unique even across modules,
// so that interface equality works correctly.
func TestInterface(t *testing.T) {
	globalSkip(t)
	goCmd(t, "install", "-buildmode=shared", "-linkshared", "./iface_a")
	// Note: iface_i gets installed implicitly as a dependency of iface_a.
	goCmd(t, "install", "-buildmode=shared", "-linkshared", "./iface_b")
	goCmd(t, "install", "-linkshared", "./iface")
	run(t, "running type/itab uniqueness tester", "../../bin/iface")
}

// Access a global variable from a library.
func TestGlobal(t *testing.T) {
	globalSkip(t)
	goCmd(t, "install", "-buildmode=shared", "-linkshared", "./globallib")
	goCmd(t, "install", "-linkshared", "./global")
	run(t, "global executable", "../../bin/global")
	AssertIsLinkedTo(t, "../../bin/global", soname)
	AssertHasRPath(t, "../../bin/global", gorootInstallDir)
}

// Run a test using -linkshared of an installed shared package.
// Issue 26400.
func TestTestInstalledShared(t *testing.T) {
	globalSkip(t)
	goCmd(t, "test", "-linkshared", "-test.short", "sync/atomic")
}

// Test generated pointer method with -linkshared.
// Issue 25065.
func TestGeneratedMethod(t *testing.T) {
	globalSkip(t)
	goCmd(t, "install", "-buildmode=shared", "-linkshared", "./issue25065")
}

// Test use of shared library struct with generated hash function.
// Issue 30768.
func TestGeneratedHash(t *testing.T) {
	globalSkip(t)
	goCmd(t, "install", "-buildmode=shared", "-linkshared", "./issue30768/issue30768lib")
	goCmd(t, "test", "-linkshared", "./issue30768")
}

// Test that packages can be added not in dependency order (here a depends on b, and a adds
// before b). This could happen with e.g. go build -buildmode=shared std. See issue 39777.
func TestPackageOrder(t *testing.T) {
	globalSkip(t)
	goCmd(t, "install", "-buildmode=shared", "-linkshared", "./issue39777/a", "./issue39777/b")
}

// Test that GC data are generated correctly by the linker when it needs a type defined in
// a shared library. See issue 39927.
func TestGCData(t *testing.T) {
	globalSkip(t)
	goCmd(t, "install", "-buildmode=shared", "-linkshared", "./gcdata/p")
	goCmd(t, "build", "-linkshared", "./gcdata/main")
	runWithEnv(t, "running gcdata/main", []string{"GODEBUG=clobberfree=1"}, "./main")
}

// Test that we don't decode type symbols from shared libraries (which has no data,
// causing panic). See issue 44031.
func TestIssue44031(t *testing.T) {
	globalSkip(t)
	goCmd(t, "install", "-buildmode=shared", "-linkshared", "./issue44031/a")
	goCmd(t, "install", "-buildmode=shared", "-linkshared", "./issue44031/b")
	goCmd(t, "run", "-linkshared", "./issue44031/main")
}

// Test that we use a variable from shared libraries (which implement an
// interface in shared libraries.). A weak reference is used in the itab
// in main process. It can cause unreachable panic. See issue 47873.
func TestIssue47873(t *testing.T) {
	globalSkip(t)
	goCmd(t, "install", "-buildmode=shared", "-linkshared", "./issue47837/a")
	goCmd(t, "run", "-linkshared", "./issue47837/main")
}

func TestIssue62277(t *testing.T) {
	globalSkip(t)
	goCmd(t, "install", "-buildmode=shared", "-linkshared", "./issue62277/p")
	goCmd(t, "test", "-linkshared", "./issue62277")
}

// Test that we can build std in shared mode.
func TestStd(t *testing.T) {
	if testing.Short() {
		t.Skip("skip in short mode")
	}
	globalSkip(t)
	t.Parallel()
	tmpDir := t.TempDir()
	// Use a temporary pkgdir to not interfere with other tests, and not write to GOROOT.
	// Cannot use goCmd as it runs with cloned GOROOT which is incomplete.
	runWithEnv(t, "building std", []string{"GOROOT=" + oldGOROOT},
		filepath.Join(oldGOROOT, "bin", "go"), "install", "-buildmode=shared", "-pkgdir="+tmpDir, "std")

	// Issue #58966.
	runWithEnv(t, "testing issue #58966", []string{"GOROOT=" + oldGOROOT},
		filepath.Join(oldGOROOT, "bin", "go"), "run", "-linkshared", "-pkgdir="+tmpDir, "./issue58966/main.go")
}
```