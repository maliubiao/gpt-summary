Response:
The user wants to understand the functionality of the Go code provided in `go/src/internal/testenv/testenv.go`. I need to analyze the code and identify the key purposes of this package. Specifically, the user is interested in:

1. **Functionality listing**: A summary of what the code does.
2. **Go feature implementation**: If the code implements a specific Go feature, provide an example.
3. **Code inference**:  If I need to infer functionality, include example input and output.
4. **Command-line argument handling**: Details on how the code handles command-line arguments.
5. **Common mistakes**:  Potential pitfalls for users of this package.

Based on the code, it seems like the `testenv` package is designed to provide information about the Go testing environment, particularly within the Go team's infrastructure. It checks for the availability of various tools and features necessary for running tests under different conditions.

Here's a breakdown of the key areas:

- **Builder Information**: Identifying the builder environment.
- **Go Toolchain Availability**: Checking if `go build` and `go run` are functional.
- **Parallelism Support**: Determining if the system can run tests in parallel.
- **Go Tool Path**: Locating the `go` command.
- **GOROOT Location**: Finding the root of the Go installation.
- **Source Code Availability**: Checking if the full Go source is present.
- **Network Access**:  Detecting if external network access is available.
- **CGO Support**: Determining if C code can be used.
- **Linking Capabilities**: Checking internal and PIE linking support.
- **Build Mode Support**: Identifying available build modes.
- **Operating System Features**: Checking for `symlink` and `link` support.
- **Flaky Test Handling**: Mechanisms for skipping known flaky tests.
- **Resource Constraints**: Identifying slow CPUs.
- **Optimization Status**: Checking if compiler optimizations are enabled.
- **Import Configuration**:  Generating import configuration files.
- **System Call Support**:  Identifying system call errors.

I will structure the answer by grouping these related functionalities and providing explanations, code examples (where applicable), and details about command-line arguments. I'll also address the common mistakes if I can identify any based on the code.
`go/src/internal/testenv/testenv.go` 这个文件是 Go 语言标准库中 `internal/testenv` 包的一部分。这个包主要用于提供关于 Go 团队运行的各种测试环境的信息。因为它是一个 `internal` 包，所以这些细节是 Go 团队测试设置（在 build.golang.org 上）特有的，而不是通用测试的基础。

以下是 `testenv.go` 的主要功能：

1. **报告构建器名称:**  `Builder()` 函数用于获取当前运行测试的构建器名称（例如 "linux-amd64" 或 "windows-386-gce"）。如果测试不在 Go 的构建基础设施上运行，则返回空字符串。这有助于区分不同的测试环境。

2. **检查 `go build` 的可用性:** `HasGoBuild()` 函数检查当前系统是否可以使用 `go build` 命令构建程序，并使用 `os.StartProcess` 或 `exec.Command` 运行它们。它还会考虑 `GO_GCFLAGS` 环境变量的影响，如果设置了该变量，则认为无法使用 `go build`。 `MustHaveGoBuild()` 函数则在此基础上，如果 `go build` 不可用，则调用 `t.Skip` 跳过当前测试。

   **Go 功能实现示例 (假设 `go build` 可用):**

   ```go
   package mytest

   import (
       "internal/testenv"
       "testing"
   )

   func TestNeedsGoBuild(t *testing.T) {
       testenv.MustHaveGoBuild(t)
       // 只有当 go build 可用时，才会执行这里的测试逻辑
       t.Log("go build is available")
   }
   ```

   **假设输入:**  在支持 `go build` 的环境中运行此测试。
   **预期输出:**  测试将执行，并可能在日志中输出 "go build is available"。

3. **检查 `go run` 的可用性:** `HasGoRun()` 函数检查当前系统是否可以使用 `go run` 命令运行程序。目前，它与 `HasGoBuild()` 的实现相同，即认为拥有 `go build` 就拥有 `go run`。 `MustHaveGoRun()` 函数则在 `go run` 不可用时跳过测试。

4. **检查并行性:** `HasParallelism()` 函数报告当前系统是否可以并行执行多个线程。`MustHaveParallelism()` 函数在不支持并行性的系统上跳过测试。

5. **获取 Go 工具路径:** `GoToolPath(t testing.TB)` 函数返回 Go 工具（`go` 命令）的路径。如果工具不可用，则调用 `t.Skip`，如果应该可用但找不到，则调用 `t.Fatal`。

   **Go 功能实现示例:**

   ```go
   package mytest

   import (
       "internal/testenv"
       "testing"
   )

   func TestGoToolPath(t *testing.T) {
       path := testenv.GoToolPath(t)
       if path == "" {
           t.Fatalf("Go tool path is empty")
       }
       t.Logf("Go tool path: %s", path)
   }
   ```

   **假设输入:** 在安装了 Go 的环境中运行此测试。
   **预期输出:** 测试将执行，并输出 Go 工具的路径。

6. **获取 GOROOT 路径:** `GOROOT(t testing.TB)` 函数报告 Go 项目源代码树根目录的路径。它通常等同于 `runtime.GOROOT`，但在使用 `-trimpath` 构建测试二进制且无法执行 `go env GOROOT` 时仍然有效。如果无法找到 GOROOT，则如果 `t` 非空则跳过测试，否则会 panic。

7. **获取 Go 工具路径 (无测试上下文):** `GoTool()` 函数返回 Go 工具的路径，但不依赖于 `testing.TB`。

8. **检查源代码可用性:** `MustHaveSource(t testing.TB)` 检查整个源代码树是否在 GOROOT 下可用。在某些环境中（如 `ios`），源代码可能不可用，此时会跳过测试。

9. **检查外部网络连接:** `HasExternalNetwork()` 函数报告当前系统是否可以使用外部（非 localhost）网络。`MustHaveExternalNetwork()` 函数在无法连接外部网络时跳过测试。它会考虑 `-short` 标志以及 `js` 和 `wasip1` 等平台。

10. **检查 CGO 支持:** `HasCGO()` 函数报告当前系统是否可以使用 cgo。`MustHaveCGO()` 函数在 cgo 不可用时跳过测试。

11. **检查内部链接能力:** `CanInternalLink(withCgo bool)` 函数报告当前系统是否可以使用内部链接来链接程序。`MustInternalLink(t testing.TB, withCgo bool)` 函数在不支持内部链接时跳过测试。`MustInternalLinkPIE(t testing.TB)` 检查是否支持使用内部链接构建 PIE 二进制文件。

12. **检查构建模式支持:** `MustHaveBuildMode(t testing.TB, buildmode string)` 检查当前系统是否可以使用给定的构建模式构建程序。

13. **检查符号链接支持:** `HasSymlink()` 函数报告当前系统是否可以使用 `os.Symlink`。`MustHaveSymlink(t testing.TB)` 函数在不支持符号链接时跳过测试。

14. **检查硬链接支持:** `HasLink()` 函数报告当前系统是否可以使用 `os.Link`。`MustHaveLink(t testing.TB)` 函数在不支持硬链接时跳过测试。

15. **处理已知不稳定的测试:** `SkipFlaky(t testing.TB, issue int)` 函数允许跳过已知不稳定的测试，除非使用了 `-flaky` 标志。`SkipFlakyNet(t testing.TB)` 根据 `GO_BUILDER_FLAKY_NET` 环境变量跳过在已知网络不稳定的构建器上运行的测试。

   **命令行参数处理:**

   `testenv` 包本身注册了一个命令行标志 `-flaky`。当使用 `go test -flaky` 运行测试时，`*flaky` 变量会被设置为 `true`，`SkipFlaky` 函数将不会跳过相应的测试。

16. **判断 CPU 是否缓慢:** `CPUIsSlow()` 函数根据 `runtime.GOARCH` 判断当前运行测试的 CPU 是否被认为是缓慢的。`SkipIfShortAndSlow(t testing.TB)` 函数在设置了 `-short` 标志且 CPU 被认为是缓慢的情况下跳过测试。

17. **检查优化是否关闭:** `SkipIfOptimizationOff(t testing.TB)` 函数在编译器优化被禁用时跳过测试。

18. **写入 importcfg 文件:** `WriteImportcfg(t testing.TB, dstPath string, packageFiles map[string]string, pkgs ...string)` 函数用于写入一个 importcfg 文件，该文件被编译器或链接器使用，其中包含包文件映射以及 `pkgs` 中包的传递依赖。

   **Go 功能实现示例:**

   ```go
   package mytest

   import (
       "internal/testenv"
       "os"
       "path/filepath"
       "testing"
   )

   func TestWriteImportcfg(t *testing.T) {
       testenv.MustHaveGoBuild(t)

       tmpDir := t.TempDir()
       importcfgPath := filepath.Join(tmpDir, "importcfg")
       packageFiles := map[string]string{
           "fmt": filepath.Join(testenv.GOROOT(t), "src", "fmt", "fmt.go"),
       }
       testenv.WriteImportcfg(t, importcfgPath, packageFiles, "os")

       content, err := os.ReadFile(importcfgPath)
       if err != nil {
           t.Fatal(err)
       }
       t.Logf("importcfg content:\n%s", string(content))
       // 验证 importcfg 文件的内容
   }
   ```

   **假设输入:** 在支持 `go build` 的环境中运行此测试。
   **预期输出:** 将创建一个名为 `importcfg` 的文件，其中包含 `fmt` 包的路径以及 `os` 包及其依赖的导出信息。

19. **判断系统调用是否不受支持:** `SyscallIsNotSupported(err error)` 函数判断给定的错误是否可能指示当前平台或执行环境不支持某个系统调用。

20. **根据架构并行执行测试:** `ParallelOn64Bit(t *testing.T)` 函数仅在 64 位架构上调用 `t.Parallel()`，用于避免在 32 位机器上因内存使用过多而导致的问题。

**使用者易犯错的点:**

* **直接在非 Go 团队基础设施上使用:**  `internal/testenv` 的设计目的是为了支持 Go 团队的测试基础设施。直接在其他环境中使用可能导致行为不一致或错误，因为它依赖于特定的环境变量（如 `GO_BUILDER_NAME`）和构建环境。
* **过度依赖 `MustHave...` 函数:**  如果在不理解底层原因的情况下过度使用 `MustHave...` 系列函数（例如 `MustHaveGoBuild`），可能会无意中跳过一些在当前环境下实际上可以运行的测试。应该根据测试的实际需求来决定是否需要这些检查。例如，一个简单的、不依赖于 `go build` 的测试不应该调用 `MustHaveGoBuild`。
* **忽略 `-flaky` 标志:** 在本地开发或调试时，如果测试被 `SkipFlaky` 跳过，开发者可能没有意识到这是一个已知不稳定的测试，除非他们使用了 `-flaky` 标志。这可能会导致在提交代码后，该不稳定的测试在构建系统中暴露出来。

总的来说，`go/src/internal/testenv/testenv.go` 提供了一组工具，用于根据 Go 团队的特定测试环境的特性来控制测试的执行。它允许测试根据构建器、操作系统特性、工具链可用性等条件有条件地运行或跳过。

### 提示词
```
这是路径为go/src/internal/testenv/testenv.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package testenv provides information about what functionality
// is available in different testing environments run by the Go team.
//
// It is an internal package because these details are specific
// to the Go team's test setup (on build.golang.org) and not
// fundamental to tests in general.
package testenv

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"internal/cfg"
	"internal/goarch"
	"internal/platform"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// Save the original environment during init for use in checks. A test
// binary may modify its environment before calling HasExec to change its
// behavior (such as mimicking a command-line tool), and that modified
// environment might cause environment checks to behave erratically.
var origEnv = os.Environ()

// Builder reports the name of the builder running this test
// (for example, "linux-amd64" or "windows-386-gce").
// If the test is not running on the build infrastructure,
// Builder returns the empty string.
func Builder() string {
	return os.Getenv("GO_BUILDER_NAME")
}

// HasGoBuild reports whether the current system can build programs with “go build”
// and then run them with os.StartProcess or exec.Command.
func HasGoBuild() bool {
	if os.Getenv("GO_GCFLAGS") != "" {
		// It's too much work to require every caller of the go command
		// to pass along "-gcflags="+os.Getenv("GO_GCFLAGS").
		// For now, if $GO_GCFLAGS is set, report that we simply can't
		// run go build.
		return false
	}

	return tryGoBuild() == nil
}

var tryGoBuild = sync.OnceValue(func() error {
	// To run 'go build', we need to be able to exec a 'go' command.
	// We somewhat arbitrarily choose to exec 'go tool -n compile' because that
	// also confirms that cmd/go can find the compiler. (Before CL 472096,
	// we sometimes ended up with cmd/go installed in the test environment
	// without a cmd/compile it could use to actually build things.)
	goTool, err := goTool()
	if err != nil {
		return err
	}
	cmd := exec.Command(goTool, "tool", "-n", "compile")
	cmd.Env = origEnv
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("%v: %w", cmd, err)
	}
	out = bytes.TrimSpace(out)
	if len(out) == 0 {
		return fmt.Errorf("%v: no tool reported", cmd)
	}
	if _, err := exec.LookPath(string(out)); err != nil {
		return err
	}

	if platform.MustLinkExternal(runtime.GOOS, runtime.GOARCH, false) {
		// We can assume that we always have a complete Go toolchain available.
		// However, this platform requires a C linker to build even pure Go
		// programs, including tests. Do we have one in the test environment?
		// (On Android, for example, the device running the test might not have a
		// C toolchain installed.)
		//
		// If CC is set explicitly, assume that we do. Otherwise, use 'go env CC'
		// to determine which toolchain it would use by default.
		if os.Getenv("CC") == "" {
			cmd := exec.Command(goTool, "env", "CC")
			cmd.Env = origEnv
			out, err := cmd.Output()
			if err != nil {
				return fmt.Errorf("%v: %w", cmd, err)
			}
			out = bytes.TrimSpace(out)
			if len(out) == 0 {
				return fmt.Errorf("%v: no CC reported", cmd)
			}
			_, err = exec.LookPath(string(out))
			return err
		}
	}
	return nil
})

// MustHaveGoBuild checks that the current system can build programs with “go build”
// and then run them with os.StartProcess or exec.Command.
// If not, MustHaveGoBuild calls t.Skip with an explanation.
func MustHaveGoBuild(t testing.TB) {
	if os.Getenv("GO_GCFLAGS") != "" {
		t.Helper()
		t.Skipf("skipping test: 'go build' not compatible with setting $GO_GCFLAGS")
	}
	if !HasGoBuild() {
		t.Helper()
		t.Skipf("skipping test: 'go build' unavailable: %v", tryGoBuild())
	}
}

// HasGoRun reports whether the current system can run programs with “go run”.
func HasGoRun() bool {
	// For now, having go run and having go build are the same.
	return HasGoBuild()
}

// MustHaveGoRun checks that the current system can run programs with “go run”.
// If not, MustHaveGoRun calls t.Skip with an explanation.
func MustHaveGoRun(t testing.TB) {
	if !HasGoRun() {
		t.Helper()
		t.Skipf("skipping test: 'go run' not available on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
}

// HasParallelism reports whether the current system can execute multiple
// threads in parallel.
// There is a copy of this function in cmd/dist/test.go.
func HasParallelism() bool {
	switch runtime.GOOS {
	case "js", "wasip1":
		return false
	}
	return true
}

// MustHaveParallelism checks that the current system can execute multiple
// threads in parallel. If not, MustHaveParallelism calls t.Skip with an explanation.
func MustHaveParallelism(t testing.TB) {
	if !HasParallelism() {
		t.Helper()
		t.Skipf("skipping test: no parallelism available on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
}

// GoToolPath reports the path to the Go tool.
// It is a convenience wrapper around GoTool.
// If the tool is unavailable GoToolPath calls t.Skip.
// If the tool should be available and isn't, GoToolPath calls t.Fatal.
func GoToolPath(t testing.TB) string {
	MustHaveGoBuild(t)
	path, err := GoTool()
	if err != nil {
		t.Fatal(err)
	}
	// Add all environment variables that affect the Go command to test metadata.
	// Cached test results will be invalidate when these variables change.
	// See golang.org/issue/32285.
	for _, envVar := range strings.Fields(cfg.KnownEnv) {
		os.Getenv(envVar)
	}
	return path
}

var findGOROOT = sync.OnceValues(func() (path string, err error) {
	if path := runtime.GOROOT(); path != "" {
		// If runtime.GOROOT() is non-empty, assume that it is valid.
		//
		// (It might not be: for example, the user may have explicitly set GOROOT
		// to the wrong directory. But this case is
		// rare, and if that happens the user can fix what they broke.)
		return path, nil
	}

	// runtime.GOROOT doesn't know where GOROOT is (perhaps because the test
	// binary was built with -trimpath).
	//
	// Since this is internal/testenv, we can cheat and assume that the caller
	// is a test of some package in a subdirectory of GOROOT/src. ('go test'
	// runs the test in the directory containing the packaged under test.) That
	// means that if we start walking up the tree, we should eventually find
	// GOROOT/src/go.mod, and we can report the parent directory of that.
	//
	// Notably, this works even if we can't run 'go env GOROOT' as a
	// subprocess.

	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("finding GOROOT: %w", err)
	}

	dir := cwd
	for {
		parent := filepath.Dir(dir)
		if parent == dir {
			// dir is either "." or only a volume name.
			return "", fmt.Errorf("failed to locate GOROOT/src in any parent directory")
		}

		if base := filepath.Base(dir); base != "src" {
			dir = parent
			continue // dir cannot be GOROOT/src if it doesn't end in "src".
		}

		b, err := os.ReadFile(filepath.Join(dir, "go.mod"))
		if err != nil {
			if os.IsNotExist(err) {
				dir = parent
				continue
			}
			return "", fmt.Errorf("finding GOROOT: %w", err)
		}
		goMod := string(b)

		for goMod != "" {
			var line string
			line, goMod, _ = strings.Cut(goMod, "\n")
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[0] == "module" && fields[1] == "std" {
				// Found "module std", which is the module declaration in GOROOT/src!
				return parent, nil
			}
		}
	}
})

// GOROOT reports the path to the directory containing the root of the Go
// project source tree. This is normally equivalent to runtime.GOROOT, but
// works even if the test binary was built with -trimpath and cannot exec
// 'go env GOROOT'.
//
// If GOROOT cannot be found, GOROOT skips t if t is non-nil,
// or panics otherwise.
func GOROOT(t testing.TB) string {
	path, err := findGOROOT()
	if err != nil {
		if t == nil {
			panic(err)
		}
		t.Helper()
		t.Skip(err)
	}
	return path
}

// GoTool reports the path to the Go tool.
func GoTool() (string, error) {
	if !HasGoBuild() {
		return "", errors.New("platform cannot run go tool")
	}
	return goTool()
}

var goTool = sync.OnceValues(func() (string, error) {
	return exec.LookPath("go")
})

// MustHaveSource checks that the entire source tree is available under GOROOT.
// If not, it calls t.Skip with an explanation.
func MustHaveSource(t testing.TB) {
	switch runtime.GOOS {
	case "ios":
		t.Helper()
		t.Skip("skipping test: no source tree on " + runtime.GOOS)
	}
}

// HasExternalNetwork reports whether the current system can use
// external (non-localhost) networks.
func HasExternalNetwork() bool {
	return !testing.Short() && runtime.GOOS != "js" && runtime.GOOS != "wasip1"
}

// MustHaveExternalNetwork checks that the current system can use
// external (non-localhost) networks.
// If not, MustHaveExternalNetwork calls t.Skip with an explanation.
func MustHaveExternalNetwork(t testing.TB) {
	if runtime.GOOS == "js" || runtime.GOOS == "wasip1" {
		t.Helper()
		t.Skipf("skipping test: no external network on %s", runtime.GOOS)
	}
	if testing.Short() {
		t.Helper()
		t.Skipf("skipping test: no external network in -short mode")
	}
}

// HasCGO reports whether the current system can use cgo.
func HasCGO() bool {
	return hasCgo()
}

var hasCgo = sync.OnceValue(func() bool {
	goTool, err := goTool()
	if err != nil {
		return false
	}
	cmd := exec.Command(goTool, "env", "CGO_ENABLED")
	cmd.Env = origEnv
	out, err := cmd.Output()
	if err != nil {
		panic(fmt.Sprintf("%v: %v", cmd, out))
	}
	ok, err := strconv.ParseBool(string(bytes.TrimSpace(out)))
	if err != nil {
		panic(fmt.Sprintf("%v: non-boolean output %q", cmd, out))
	}
	return ok
})

// MustHaveCGO calls t.Skip if cgo is not available.
func MustHaveCGO(t testing.TB) {
	if !HasCGO() {
		t.Helper()
		t.Skipf("skipping test: no cgo")
	}
}

// CanInternalLink reports whether the current system can link programs with
// internal linking.
func CanInternalLink(withCgo bool) bool {
	return !platform.MustLinkExternal(runtime.GOOS, runtime.GOARCH, withCgo)
}

// MustInternalLink checks that the current system can link programs with internal
// linking.
// If not, MustInternalLink calls t.Skip with an explanation.
func MustInternalLink(t testing.TB, withCgo bool) {
	if !CanInternalLink(withCgo) {
		t.Helper()
		if withCgo && CanInternalLink(false) {
			t.Skipf("skipping test: internal linking on %s/%s is not supported with cgo", runtime.GOOS, runtime.GOARCH)
		}
		t.Skipf("skipping test: internal linking on %s/%s is not supported", runtime.GOOS, runtime.GOARCH)
	}
}

// MustInternalLinkPIE checks whether the current system can link PIE binary using
// internal linking.
// If not, MustInternalLinkPIE calls t.Skip with an explanation.
func MustInternalLinkPIE(t testing.TB) {
	if !platform.InternalLinkPIESupported(runtime.GOOS, runtime.GOARCH) {
		t.Helper()
		t.Skipf("skipping test: internal linking for buildmode=pie on %s/%s is not supported", runtime.GOOS, runtime.GOARCH)
	}
}

// MustHaveBuildMode reports whether the current system can build programs in
// the given build mode.
// If not, MustHaveBuildMode calls t.Skip with an explanation.
func MustHaveBuildMode(t testing.TB, buildmode string) {
	if !platform.BuildModeSupported(runtime.Compiler, buildmode, runtime.GOOS, runtime.GOARCH) {
		t.Helper()
		t.Skipf("skipping test: build mode %s on %s/%s is not supported by the %s compiler", buildmode, runtime.GOOS, runtime.GOARCH, runtime.Compiler)
	}
}

// HasSymlink reports whether the current system can use os.Symlink.
func HasSymlink() bool {
	ok, _ := hasSymlink()
	return ok
}

// MustHaveSymlink reports whether the current system can use os.Symlink.
// If not, MustHaveSymlink calls t.Skip with an explanation.
func MustHaveSymlink(t testing.TB) {
	ok, reason := hasSymlink()
	if !ok {
		t.Helper()
		t.Skipf("skipping test: cannot make symlinks on %s/%s: %s", runtime.GOOS, runtime.GOARCH, reason)
	}
}

// HasLink reports whether the current system can use os.Link.
func HasLink() bool {
	// From Android release M (Marshmallow), hard linking files is blocked
	// and an attempt to call link() on a file will return EACCES.
	// - https://code.google.com/p/android-developer-preview/issues/detail?id=3150
	return runtime.GOOS != "plan9" && runtime.GOOS != "android"
}

// MustHaveLink reports whether the current system can use os.Link.
// If not, MustHaveLink calls t.Skip with an explanation.
func MustHaveLink(t testing.TB) {
	if !HasLink() {
		t.Helper()
		t.Skipf("skipping test: hardlinks are not supported on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
}

var flaky = flag.Bool("flaky", false, "run known-flaky tests too")

func SkipFlaky(t testing.TB, issue int) {
	if !*flaky {
		t.Helper()
		t.Skipf("skipping known flaky test without the -flaky flag; see golang.org/issue/%d", issue)
	}
}

func SkipFlakyNet(t testing.TB) {
	if v, _ := strconv.ParseBool(os.Getenv("GO_BUILDER_FLAKY_NET")); v {
		t.Helper()
		t.Skip("skipping test on builder known to have frequent network failures")
	}
}

// CPUIsSlow reports whether the CPU running the test is suspected to be slow.
func CPUIsSlow() bool {
	switch runtime.GOARCH {
	case "arm", "mips", "mipsle", "mips64", "mips64le", "wasm":
		return true
	}
	return false
}

// SkipIfShortAndSlow skips t if -short is set and the CPU running the test is
// suspected to be slow.
//
// (This is useful for CPU-intensive tests that otherwise complete quickly.)
func SkipIfShortAndSlow(t testing.TB) {
	if testing.Short() && CPUIsSlow() {
		t.Helper()
		t.Skipf("skipping test in -short mode on %s", runtime.GOARCH)
	}
}

// SkipIfOptimizationOff skips t if optimization is disabled.
func SkipIfOptimizationOff(t testing.TB) {
	if OptimizationOff() {
		t.Helper()
		t.Skip("skipping test with optimization disabled")
	}
}

// WriteImportcfg writes an importcfg file used by the compiler or linker to
// dstPath containing entries for the file mappings in packageFiles, as well
// as for the packages transitively imported by the package(s) in pkgs.
//
// pkgs may include any package pattern that is valid to pass to 'go list',
// so it may also be a list of Go source files all in the same directory.
func WriteImportcfg(t testing.TB, dstPath string, packageFiles map[string]string, pkgs ...string) {
	t.Helper()

	icfg := new(bytes.Buffer)
	icfg.WriteString("# import config\n")
	for k, v := range packageFiles {
		fmt.Fprintf(icfg, "packagefile %s=%s\n", k, v)
	}

	if len(pkgs) > 0 {
		// Use 'go list' to resolve any missing packages and rewrite the import map.
		cmd := Command(t, GoToolPath(t), "list", "-export", "-deps", "-f", `{{if ne .ImportPath "command-line-arguments"}}{{if .Export}}{{.ImportPath}}={{.Export}}{{end}}{{end}}`)
		cmd.Args = append(cmd.Args, pkgs...)
		cmd.Stderr = new(strings.Builder)
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("%v: %v\n%s", cmd, err, cmd.Stderr)
		}

		for _, line := range strings.Split(string(out), "\n") {
			if line == "" {
				continue
			}
			importPath, export, ok := strings.Cut(line, "=")
			if !ok {
				t.Fatalf("invalid line in output from %v:\n%s", cmd, line)
			}
			if packageFiles[importPath] == "" {
				fmt.Fprintf(icfg, "packagefile %s=%s\n", importPath, export)
			}
		}
	}

	if err := os.WriteFile(dstPath, icfg.Bytes(), 0666); err != nil {
		t.Fatal(err)
	}
}

// SyscallIsNotSupported reports whether err may indicate that a system call is
// not supported by the current platform or execution environment.
func SyscallIsNotSupported(err error) bool {
	return syscallIsNotSupported(err)
}

// ParallelOn64Bit calls t.Parallel() unless there is a case that cannot be parallel.
// This function should be used when it is necessary to avoid t.Parallel on
// 32-bit machines, typically because the test uses lots of memory.
func ParallelOn64Bit(t *testing.T) {
	if goarch.PtrSize == 4 {
		return
	}
	t.Parallel()
}
```