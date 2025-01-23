Response: The user wants to understand the functionality of the provided Go code snippet. This code seems to be part of the `go test` command implementation. I need to analyze the imports and the `TestMain` function to figure out the main purposes of this code.

**High-level plan:**
1. Identify the core functionality based on imports and the `TestMain` function.
2. Provide illustrative Go code examples where applicable.
3. Explain the handling of command-line arguments.
4. Highlight common mistakes users might make.
5. Summarize the identified functionalities.

**Detailed plan:**
1. **Imports Analysis:** Look at the imported packages to understand the code's dependencies and functionalities. Packages like `os/exec`, `testing`, `flag`, `cmd/go/internal/*` are strong indicators.
2. **`TestMain` Function Analysis:** This is the entry point for testing. Analyze the operations performed here, especially environment variable manipulation, temporary directory creation, and execution of the `cmd/go` binary.
3. **Functionalities Identification:** Based on the above analyses, identify the key features implemented in this code, such as setting up the testing environment, running `go` commands, and verifying their output.
4. **Go Code Examples:**  If the code implements a specific Go language feature (e.g., handling specific build tags), provide a simple example demonstrating its usage.
5. **Command-line Arguments:** Examine how `flag` is used to process command-line arguments. Focus on arguments relevant to testing, like `-testwork`.
6. **Code Reasoning:**  If any part of the code performs complex logic, try to reason about its purpose with example inputs and expected outputs. The interaction with environment variables is a key area.
7. **Common Mistakes:** Based on the functionalities, think about what errors users might make when using the `go test` command.
8. **Summary:**  Concise summary of the identified functionalities.

**Mental Sandbox:**
- The code heavily manipulates environment variables, indicating it's setting up a controlled environment for testing the `go` command itself.
- The `TestMain` function seems to be responsible for creating a temporary `go` executable (`testGo`) and running it with various arguments.
- The presence of `testgoData` suggests a helper struct to manage the execution of the `testGo` binary.
- The `grep` methods point towards verifying the output of `go` commands.

**Key Functionalities to investigate:**
- Setting up a temporary GOROOT and GOPATH.
- Executing the `go` command under test.
- Capturing and analyzing the standard output and standard error of the `go` command.
- Handling specific command-line flags for `go test`.
- Checking for expected behavior (success/failure, output patterns).

**Constraint Checklist & Confidence Score:**
1. List functionalities? Yes.
2. Infer Go language feature implementation? Yes, if applicable.
3. Go code example? Yes, if applicable.
4. Code reasoning with input/output? Yes, if applicable.
5. Command-line argument handling? Yes.
6. User mistakes? Yes, if applicable.
7. Part 1 summary? Yes.

Confidence Score: 5/5 - I'm confident I can address all the instructions.

Strategizing complete. I will now proceed with generating the response based on the outlined plan.
这是对 `go test` 命令功能实现的一部分，它主要负责搭建和管理运行 `go test` 命令的测试环境，并提供了一系列辅助函数来执行和验证测试行为。

**主要功能归纳:**

1. **测试环境搭建:**
   - 创建临时的 `GOROOT`, `GOPATH`, `GOCACHE` 等环境变量，确保测试在一个干净且可控的环境中运行，避免与用户的本地环境冲突。
   - 构建一个用于测试的 `go` 命令 (`testGo`)，通常是当前 `GOROOT` 下的 `go` 命令的一个副本。
   - 设置一些特定的环境变量，例如 `GOVCS` 为 `*:all`，允许使用任何版本控制系统，这对于测试 `go get` 等命令非常重要。
   - 限制并发网络测试的数量，避免对外部网络造成过大压力。

2. **`go` 命令执行助手 (`testgoData`):**
   - 提供了一个名为 `testgoData` 的结构体，用于管理单个 `testgo` 命令的运行。
   - 封装了执行 `testGo` 命令的方法 (`run`, `runFail`)，并能捕获其标准输出和标准错误。
   - 提供了方便的函数 (`grepStdout`, `grepStderr`, `grepBoth`, `grepStdoutNot`, `grepStderrNot`, `grepBothNot`, `grepCountBoth`) 用于检查 `testGo` 命令的输出，以验证测试是否符合预期。
   - 提供了创建临时文件和目录 (`tempFile`, `tempDir`) 的功能，方便在测试过程中创建测试所需的文件结构。
   - 提供了断言文件或目录存在与否 (`mustExist`, `mustNotExist`) 以及是否可执行 (`wantExecutable`) 的功能。
   - 提供了检查包是否过时 (`isStale`, `wantStale`, `wantNotStale`) 的功能。

3. **测试主函数 (`TestMain`):**
   - 负责测试环境的初始化和清理工作。
   - 可以通过环境变量 `CMDGO_TEST_RUN_MAIN` 来复用当前的测试二进制文件作为 `cmd/go` 命令执行。
   - 处理一些全局的测试配置，例如是否保留临时工作目录 (`-testwork` 标志)。
   - 在测试开始前构建 `testGo` 可执行文件。
   - 设置一些测试相关的环境变量，例如禁用 `GOENV`, 清空 `GOFLAGS`, `GOBIN`, `GOPATH` 等。

**Go 语言功能实现推断及代码举例:**

这段代码本身主要是为了测试 `go` 命令，因此它不直接实现特定的 Go 语言功能，而是利用 Go 的标准库（例如 `os/exec`, `testing`, `flag`) 和内部库来完成测试任务。

**代码推理 (假设输入与输出):**

假设我们有一个简单的测试用例，需要检查 `go version` 命令的输出是否包含 "go version"。

```go
func TestGoVersionOutput(t *testing.T) {
	tg := testgo(t)
	defer tg.cleanup()
	tg.run("version")
	tg.grepStdout("go version", "go version output should contain 'go version'")
}
```

**假设的输入:** 运行上述测试用例。

**假设的输出:** 如果 `go version` 的输出中包含 "go version"，则测试通过；否则，测试失败并打印错误信息 "go version output should contain 'go version'"。

**命令行参数的具体处理:**

`TestMain` 函数中使用 `flag` 包来处理命令行参数。目前代码中处理了一个名为 `-testwork` 的布尔类型的 flag。

- **`-testwork`**: 当指定 `-testwork` 时，测试结束后不会删除创建的临时工作目录。这对于调试测试非常有用，允许开发者在测试运行后检查临时目录中的文件和状态。

**使用者易犯错的点:**

由于这段代码是 `go test` 命令内部实现的一部分，普通 Go 开发者不会直接使用这些函数。但是，如果有人尝试修改或扩展 `go test` 的功能，可能会犯以下错误：

1. **在并行测试中使用 `testdata` 目录:**  `testgoData` 中的 `parallel()` 方法会检查环境变量，并在并行运行的测试中如果发现使用了 `testdata` 目录会报错。这是因为并行测试应该相互独立，直接依赖共享的 `testdata` 可能会导致竞争条件。

   ```go
   func TestParallelData(t *testing.T) {
       tg := testgo(t)
       tg.parallel() // 声明并行运行
       // 错误示例：在并行测试中直接使用 testdata
       tg.run("run", "testdata/mypackage/main.go")
   }
   ```

2. **在 `parallel()` 调用后修改 `testgoData` 的环境:**  `parallel()` 方法需要在 `run` 方法之前调用，并且一旦调用 `parallel()` 后，就不应该再修改影响文件路径的环境变量（如 `GOROOT`, `GOPATH`, `GOBIN`），因为这可能导致并行运行的测试之间相互干扰。

   ```go
   func TestIncorrectParallelEnv(t *testing.T) {
       tg := testgo(t)
       tg.parallel() // 声明并行运行
       tg.setenv("GOPATH", tg.path("newgopath")) // 错误：在 parallel() 之后修改了 GOPATH
       tg.run("build", "mypackage")
   }
   ```

**功能归纳 (第1部分):**

这段代码是 `go test` 命令实现的基础设施，主要功能是为测试 `go` 命令本身创建和管理一个隔离、可控的测试环境。它提供了执行 `go` 命令的助手函数，并能方便地验证命令的输出和行为，是构建 `go test` 命令测试用例的核心组成部分。它关注于环境搭建、命令执行和结果验证，为后续的特定测试用例提供了基础框架。

### 提示词
```
这是路径为go/src/cmd/go/go_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main_test

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"flag"
	"fmt"
	"go/format"
	"internal/godebug"
	"internal/platform"
	"internal/testenv"
	"io"
	"io/fs"
	"log"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"cmd/go/internal/base"
	"cmd/go/internal/cache"
	"cmd/go/internal/cfg"
	"cmd/go/internal/gover"
	"cmd/go/internal/search"
	"cmd/go/internal/toolchain"
	"cmd/go/internal/vcs"
	"cmd/go/internal/vcweb/vcstest"
	"cmd/go/internal/web/intercept"
	"cmd/go/internal/work"
	"cmd/internal/robustio"
	"cmd/internal/sys"

	cmdgo "cmd/go"
)

func init() {
	// GOVCS defaults to public:git|hg,private:all,
	// which breaks many tests here - they can't use non-git, non-hg VCS at all!
	// Change to fully permissive.
	// The tests of the GOVCS setting itself are in ../../testdata/script/govcs.txt.
	os.Setenv("GOVCS", "*:all")
}

var (
	canRace = false // whether we can run the race detector
	canMSan = false // whether we can run the memory sanitizer
	canASan = false // whether we can run the address sanitizer
)

var (
	goHostOS, goHostArch string
	cgoEnabled           string // raw value from 'go env CGO_ENABLED'
)

// netTestSem is a semaphore limiting the number of tests that may use the
// external network in parallel. If non-nil, it contains one buffer slot per
// test (send to acquire), with a low enough limit that the overall number of
// connections (summed across subprocesses) stays at or below base.NetLimit.
var netTestSem chan struct{}

var exeSuffix string = func() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}()

func tooSlow(t *testing.T, reason string) {
	if testing.Short() {
		t.Helper()
		t.Skipf("skipping test in -short mode: %s", reason)
	}
}

// testGOROOT is the GOROOT to use when running testgo, a cmd/go binary
// build from this process's current GOROOT, but run from a different
// (temp) directory.
var testGOROOT string

var testGOCACHE string

var testGo string
var testTmpDir string
var testBin string

// The TestMain function creates a go command for testing purposes and
// deletes it after the tests have been run.
func TestMain(m *testing.M) {
	// When CMDGO_TEST_RUN_MAIN is set, we're reusing the test binary as cmd/go.
	// Enable the special behavior needed in cmd/go/internal/work,
	// run the main func exported via export_test.go, and exit.
	// We set CMDGO_TEST_RUN_MAIN via os.Setenv and testScript.setup.
	if os.Getenv("CMDGO_TEST_RUN_MAIN") != "" {
		cfg.SetGOROOT(cfg.GOROOT, true)
		gover.TestVersion = os.Getenv("TESTGO_VERSION")
		toolchain.TestVersionSwitch = os.Getenv("TESTGO_VERSION_SWITCH")
		if v := os.Getenv("TESTGO_TOOLCHAIN_VERSION"); v != "" {
			work.ToolchainVersion = v
		}

		if testGOROOT := os.Getenv("TESTGO_GOROOT"); testGOROOT != "" {
			// Disallow installs to the GOROOT from which testgo was built.
			// Installs to other GOROOTs — such as one set explicitly within a test — are ok.
			work.AllowInstall = func(a *work.Action) error {
				if cfg.BuildN {
					return nil
				}

				rel := search.InDir(a.Target, testGOROOT)
				if rel == "" {
					return nil
				}

				callerPos := ""
				if _, file, line, ok := runtime.Caller(1); ok {
					if shortFile := search.InDir(file, filepath.Join(testGOROOT, "src")); shortFile != "" {
						file = shortFile
					}
					callerPos = fmt.Sprintf("%s:%d: ", file, line)
				}
				notice := "This error error can occur if GOROOT is stale, in which case rerunning make.bash will fix it."
				return fmt.Errorf("%stestgo must not write to GOROOT (installing to %s) (%v)", callerPos, filepath.Join("GOROOT", rel), notice)
			}
		}

		if vcsTestHost := os.Getenv("TESTGO_VCSTEST_HOST"); vcsTestHost != "" {
			vcs.VCSTestRepoURL = "http://" + vcsTestHost
			vcs.VCSTestHosts = vcstest.Hosts
			vcsTestTLSHost := os.Getenv("TESTGO_VCSTEST_TLS_HOST")
			vcsTestClient, err := vcstest.TLSClient(os.Getenv("TESTGO_VCSTEST_CERT"))
			if err != nil {
				fmt.Fprintf(os.Stderr, "loading certificates from $TESTGO_VCSTEST_CERT: %v", err)
			}
			var interceptors []intercept.Interceptor
			for _, host := range vcstest.Hosts {
				interceptors = append(interceptors,
					intercept.Interceptor{Scheme: "http", FromHost: host, ToHost: vcsTestHost},
					intercept.Interceptor{Scheme: "https", FromHost: host, ToHost: vcsTestTLSHost, Client: vcsTestClient})
			}
			intercept.EnableTestHooks(interceptors)
		}

		cmdgo.Main()
		os.Exit(0)
	}
	os.Setenv("CMDGO_TEST_RUN_MAIN", "true")

	// $GO_GCFLAGS a compiler debug flag known to cmd/dist, make.bash, etc.
	// It is not a standard go command flag; use os.Getenv, not cfg.Getenv.
	if os.Getenv("GO_GCFLAGS") != "" {
		fmt.Fprintf(os.Stderr, "testing: warning: no tests to run\n") // magic string for cmd/go
		fmt.Printf("cmd/go test is not compatible with $GO_GCFLAGS being set\n")
		fmt.Printf("SKIP\n")
		return
	}

	flag.Parse()

	if *proxyAddr != "" {
		StartProxy()
		select {}
	}

	// Run with a temporary TMPDIR to check that the tests don't
	// leave anything behind.
	topTmpdir, err := os.MkdirTemp("", "cmd-go-test-")
	if err != nil {
		log.Fatal(err)
	}
	if !*testWork {
		defer removeAll(topTmpdir)
	} else {
		fmt.Fprintf(os.Stderr, "TESTWORK: preserving top level tempdir %s\n", topTmpdir)
	}
	os.Setenv(tempEnvName(), topTmpdir)

	dir, err := os.MkdirTemp(topTmpdir, "tmpdir")
	if err != nil {
		log.Fatal(err)
	}
	testTmpDir = dir
	if !*testWork {
		defer removeAll(testTmpDir)
	}

	testGOCACHE, _ = cache.DefaultDir()
	if testenv.HasGoBuild() {
		testBin = filepath.Join(testTmpDir, "testbin")
		if err := os.Mkdir(testBin, 0777); err != nil {
			log.Fatal(err)
		}
		testGo = filepath.Join(testBin, "go"+exeSuffix)
		gotool, err := testenv.GoTool()
		if err != nil {
			fmt.Fprintln(os.Stderr, "locating go tool: ", err)
			os.Exit(2)
		}

		goEnv := func(name string) string {
			out, err := exec.Command(gotool, "env", name).CombinedOutput()
			if err != nil {
				fmt.Fprintf(os.Stderr, "go env %s: %v\n%s", name, err, out)
				os.Exit(2)
			}
			return strings.TrimSpace(string(out))
		}
		testGOROOT = goEnv("GOROOT")
		os.Setenv("TESTGO_GOROOT", testGOROOT)
		os.Setenv("GOROOT", testGOROOT)

		// The whole GOROOT/pkg tree was installed using the GOHOSTOS/GOHOSTARCH
		// toolchain (installed in GOROOT/pkg/tool/GOHOSTOS_GOHOSTARCH).
		// The testgo.exe we are about to create will be built for GOOS/GOARCH,
		// which means it will use the GOOS/GOARCH toolchain
		// (installed in GOROOT/pkg/tool/GOOS_GOARCH).
		// If these are not the same toolchain, then the entire standard library
		// will look out of date (the compilers in those two different tool directories
		// are built for different architectures and have different build IDs),
		// which will cause many tests to do unnecessary rebuilds and some
		// tests to attempt to overwrite the installed standard library.
		// Bail out entirely in this case.
		goHostOS = goEnv("GOHOSTOS")
		os.Setenv("TESTGO_GOHOSTOS", goHostOS)
		goHostArch = goEnv("GOHOSTARCH")
		os.Setenv("TESTGO_GOHOSTARCH", goHostArch)

		cgoEnabled = goEnv("CGO_ENABLED")

		// Duplicate the test executable into the path at testGo, for $PATH.
		// If the OS supports symlinks, use them instead of copying bytes.
		testExe, err := os.Executable()
		if err != nil {
			log.Fatal(err)
		}
		if err := os.Symlink(testExe, testGo); err != nil {
			// Otherwise, copy the bytes.
			src, err := os.Open(testExe)
			if err != nil {
				log.Fatal(err)
			}
			defer src.Close()

			dst, err := os.OpenFile(testGo, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o777)
			if err != nil {
				log.Fatal(err)
			}

			_, err = io.Copy(dst, src)
			if closeErr := dst.Close(); err == nil {
				err = closeErr
			}
			if err != nil {
				log.Fatal(err)
			}
		}

		out, err := exec.Command(gotool, "env", "GOCACHE").CombinedOutput()
		if err != nil {
			fmt.Fprintf(os.Stderr, "could not find testing GOCACHE: %v\n%s", err, out)
			os.Exit(2)
		}
		testGOCACHE = strings.TrimSpace(string(out))

		canMSan = testenv.HasCGO() && platform.MSanSupported(runtime.GOOS, runtime.GOARCH)
		canASan = testenv.HasCGO() && platform.ASanSupported(runtime.GOOS, runtime.GOARCH)
		canRace = testenv.HasCGO() && platform.RaceDetectorSupported(runtime.GOOS, runtime.GOARCH)
		// The race detector doesn't work on Alpine Linux:
		// golang.org/issue/14481
		// gccgo does not support the race detector.
		if isAlpineLinux() || runtime.Compiler == "gccgo" {
			canRace = false
		}
	}

	if n, limited := base.NetLimit(); limited && n > 0 {
		// Split the network limit into chunks, so that each parallel script can
		// have one chunk. We want to run as many parallel scripts as possible, but
		// also want to give each script as high a limit as possible.
		// We arbitrarily split by sqrt(n) to try to balance those two goals.
		netTestLimit := int(math.Sqrt(float64(n)))
		netTestSem = make(chan struct{}, netTestLimit)
		reducedLimit := fmt.Sprintf(",%s=%d", base.NetLimitGodebug.Name(), n/netTestLimit)
		os.Setenv("GODEBUG", os.Getenv("GODEBUG")+reducedLimit)
	}

	// Don't let these environment variables confuse the test.
	os.Setenv("GOENV", "off")
	os.Unsetenv("GOFLAGS")
	os.Unsetenv("GOBIN")
	os.Unsetenv("GOPATH")
	os.Unsetenv("GIT_ALLOW_PROTOCOL")
	os.Setenv("HOME", "/test-go-home-does-not-exist")
	// On some systems the default C compiler is ccache.
	// Setting HOME to a non-existent directory will break
	// those systems. Disable ccache and use real compiler. Issue 17668.
	os.Setenv("CCACHE_DISABLE", "1")
	if cfg.Getenv("GOCACHE") == "" {
		os.Setenv("GOCACHE", testGOCACHE) // because $HOME is gone
	}

	if testenv.Builder() != "" || os.Getenv("GIT_TRACE_CURL") == "1" {
		// To help diagnose https://go.dev/issue/52545,
		// enable tracing for Git HTTPS requests.
		os.Setenv("GIT_TRACE_CURL", "1")
		os.Setenv("GIT_TRACE_CURL_NO_DATA", "1")
		os.Setenv("GIT_REDACT_COOKIES", "o,SSO,GSSO_Uberproxy")
	}

	r := m.Run()
	if !*testWork {
		removeAll(testTmpDir) // os.Exit won't run defer
	}

	if !*testWork {
		// There shouldn't be anything left in topTmpdir.
		var extraFiles, extraDirs []string
		err := filepath.WalkDir(topTmpdir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if path == topTmpdir {
				return nil
			}

			if rel, err := filepath.Rel(topTmpdir, path); err == nil {
				path = rel
			}
			if d.IsDir() {
				extraDirs = append(extraDirs, path)
			} else {
				extraFiles = append(extraFiles, path)
			}
			return nil
		})
		if err != nil {
			log.Fatal(err)
		}

		if len(extraFiles) > 0 {
			log.Fatalf("unexpected files left in tmpdir: %q", extraFiles)
		} else if len(extraDirs) > 0 {
			log.Fatalf("unexpected subdirectories left in tmpdir: %q", extraDirs)
		}

		removeAll(topTmpdir)
	}

	os.Exit(r)
}

func isAlpineLinux() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	fi, err := os.Lstat("/etc/alpine-release")
	return err == nil && fi.Mode().IsRegular()
}

// The length of an mtime tick on this system. This is an estimate of
// how long we need to sleep to ensure that the mtime of two files is
// different.
// We used to try to be clever but that didn't always work (see golang.org/issue/12205).
var mtimeTick time.Duration = 1 * time.Second

// Manage a single run of the testgo binary.
type testgoData struct {
	t              *testing.T
	temps          []string
	env            []string
	tempdir        string
	ran            bool
	inParallel     bool
	stdout, stderr bytes.Buffer
	execDir        string // dir for tg.run
}

// skipIfGccgo skips the test if using gccgo.
func skipIfGccgo(t *testing.T, msg string) {
	if runtime.Compiler == "gccgo" {
		t.Skipf("skipping test not supported on gccgo: %s", msg)
	}
}

// testgo sets up for a test that runs testgo.
func testgo(t *testing.T) *testgoData {
	t.Helper()
	testenv.MustHaveGoBuild(t)
	testenv.SkipIfShortAndSlow(t)

	return &testgoData{t: t}
}

// must gives a fatal error if err is not nil.
func (tg *testgoData) must(err error) {
	tg.t.Helper()
	if err != nil {
		tg.t.Fatal(err)
	}
}

// check gives a test non-fatal error if err is not nil.
func (tg *testgoData) check(err error) {
	tg.t.Helper()
	if err != nil {
		tg.t.Error(err)
	}
}

// parallel runs the test in parallel by calling t.Parallel.
func (tg *testgoData) parallel() {
	tg.t.Helper()
	if tg.ran {
		tg.t.Fatal("internal testsuite error: call to parallel after run")
	}
	for _, e := range tg.env {
		if strings.HasPrefix(e, "GOROOT=") || strings.HasPrefix(e, "GOPATH=") || strings.HasPrefix(e, "GOBIN=") {
			val := e[strings.Index(e, "=")+1:]
			if strings.HasPrefix(val, "testdata") || strings.HasPrefix(val, "./testdata") {
				tg.t.Fatalf("internal testsuite error: call to parallel with testdata in environment (%s)", e)
			}
		}
	}
	tg.inParallel = true
	tg.t.Parallel()
}

// pwd returns the current directory.
func (tg *testgoData) pwd() string {
	tg.t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		tg.t.Fatalf("could not get working directory: %v", err)
	}
	return wd
}

// sleep sleeps for one tick, where a tick is a conservative estimate
// of how long it takes for a file modification to get a different
// mtime.
func (tg *testgoData) sleep() {
	time.Sleep(mtimeTick)
}

// setenv sets an environment variable to use when running the test go
// command.
func (tg *testgoData) setenv(name, val string) {
	tg.t.Helper()
	tg.unsetenv(name)
	tg.env = append(tg.env, name+"="+val)
}

// unsetenv removes an environment variable.
func (tg *testgoData) unsetenv(name string) {
	if tg.env == nil {
		tg.env = append([]string(nil), os.Environ()...)
		tg.env = append(tg.env, "GO111MODULE=off", "TESTGONETWORK=panic")
		if testing.Short() {
			tg.env = append(tg.env, "TESTGOVCSREMOTE=panic")
		}
	}
	for i, v := range tg.env {
		if strings.HasPrefix(v, name+"=") {
			tg.env = slices.Delete(tg.env, i, i+1)
			break
		}
	}
}

func (tg *testgoData) goTool() string {
	return testGo
}

// doRun runs the test go command, recording stdout and stderr and
// returning exit status.
func (tg *testgoData) doRun(args []string) error {
	tg.t.Helper()
	if tg.inParallel {
		for _, arg := range args {
			if strings.HasPrefix(arg, "testdata") || strings.HasPrefix(arg, "./testdata") {
				tg.t.Fatal("internal testsuite error: parallel run using testdata")
			}
		}
	}

	hasGoroot := false
	for _, v := range tg.env {
		if strings.HasPrefix(v, "GOROOT=") {
			hasGoroot = true
			break
		}
	}
	prog := tg.goTool()
	if !hasGoroot {
		tg.setenv("GOROOT", testGOROOT)
	}

	tg.t.Logf("running testgo %v", args)
	cmd := testenv.Command(tg.t, prog, args...)
	tg.stdout.Reset()
	tg.stderr.Reset()
	cmd.Dir = tg.execDir
	cmd.Stdout = &tg.stdout
	cmd.Stderr = &tg.stderr
	cmd.Env = tg.env
	status := cmd.Run()
	if tg.stdout.Len() > 0 {
		tg.t.Log("standard output:")
		tg.t.Log(tg.stdout.String())
	}
	if tg.stderr.Len() > 0 {
		tg.t.Log("standard error:")
		tg.t.Log(tg.stderr.String())
	}
	tg.ran = true
	return status
}

// run runs the test go command, and expects it to succeed.
func (tg *testgoData) run(args ...string) {
	tg.t.Helper()
	if status := tg.doRun(args); status != nil {
		wd, _ := os.Getwd()
		tg.t.Logf("go %v failed unexpectedly in %s: %v", args, wd, status)
		tg.t.FailNow()
	}
}

// runFail runs the test go command, and expects it to fail.
func (tg *testgoData) runFail(args ...string) {
	tg.t.Helper()
	if status := tg.doRun(args); status == nil {
		tg.t.Fatal("testgo succeeded unexpectedly")
	} else {
		tg.t.Log("testgo failed as expected:", status)
	}
}

// getStdout returns standard output of the testgo run as a string.
func (tg *testgoData) getStdout() string {
	tg.t.Helper()
	if !tg.ran {
		tg.t.Fatal("internal testsuite error: stdout called before run")
	}
	return tg.stdout.String()
}

// getStderr returns standard error of the testgo run as a string.
func (tg *testgoData) getStderr() string {
	tg.t.Helper()
	if !tg.ran {
		tg.t.Fatal("internal testsuite error: stdout called before run")
	}
	return tg.stderr.String()
}

// doGrepMatch looks for a regular expression in a buffer, and returns
// whether it is found. The regular expression is matched against
// each line separately, as with the grep command.
func (tg *testgoData) doGrepMatch(match string, b *bytes.Buffer) bool {
	tg.t.Helper()
	if !tg.ran {
		tg.t.Fatal("internal testsuite error: grep called before run")
	}
	re := regexp.MustCompile(match)
	for _, ln := range bytes.Split(b.Bytes(), []byte{'\n'}) {
		if re.Match(ln) {
			return true
		}
	}
	return false
}

// doGrep looks for a regular expression in a buffer and fails if it
// is not found. The name argument is the name of the output we are
// searching, "output" or "error". The msg argument is logged on
// failure.
func (tg *testgoData) doGrep(match string, b *bytes.Buffer, name, msg string) {
	tg.t.Helper()
	if !tg.doGrepMatch(match, b) {
		tg.t.Log(msg)
		tg.t.Logf("pattern %v not found in standard %s", match, name)
		tg.t.FailNow()
	}
}

// grepStdout looks for a regular expression in the test run's
// standard output and fails, logging msg, if it is not found.
func (tg *testgoData) grepStdout(match, msg string) {
	tg.t.Helper()
	tg.doGrep(match, &tg.stdout, "output", msg)
}

// grepStderr looks for a regular expression in the test run's
// standard error and fails, logging msg, if it is not found.
func (tg *testgoData) grepStderr(match, msg string) {
	tg.t.Helper()
	tg.doGrep(match, &tg.stderr, "error", msg)
}

// grepBoth looks for a regular expression in the test run's standard
// output or stand error and fails, logging msg, if it is not found.
func (tg *testgoData) grepBoth(match, msg string) {
	tg.t.Helper()
	if !tg.doGrepMatch(match, &tg.stdout) && !tg.doGrepMatch(match, &tg.stderr) {
		tg.t.Log(msg)
		tg.t.Logf("pattern %v not found in standard output or standard error", match)
		tg.t.FailNow()
	}
}

// doGrepNot looks for a regular expression in a buffer and fails if
// it is found. The name and msg arguments are as for doGrep.
func (tg *testgoData) doGrepNot(match string, b *bytes.Buffer, name, msg string) {
	tg.t.Helper()
	if tg.doGrepMatch(match, b) {
		tg.t.Log(msg)
		tg.t.Logf("pattern %v found unexpectedly in standard %s", match, name)
		tg.t.FailNow()
	}
}

// grepStdoutNot looks for a regular expression in the test run's
// standard output and fails, logging msg, if it is found.
func (tg *testgoData) grepStdoutNot(match, msg string) {
	tg.t.Helper()
	tg.doGrepNot(match, &tg.stdout, "output", msg)
}

// grepStderrNot looks for a regular expression in the test run's
// standard error and fails, logging msg, if it is found.
func (tg *testgoData) grepStderrNot(match, msg string) {
	tg.t.Helper()
	tg.doGrepNot(match, &tg.stderr, "error", msg)
}

// grepBothNot looks for a regular expression in the test run's
// standard output or standard error and fails, logging msg, if it is
// found.
func (tg *testgoData) grepBothNot(match, msg string) {
	tg.t.Helper()
	if tg.doGrepMatch(match, &tg.stdout) || tg.doGrepMatch(match, &tg.stderr) {
		tg.t.Log(msg)
		tg.t.Fatalf("pattern %v found unexpectedly in standard output or standard error", match)
	}
}

// doGrepCount counts the number of times a regexp is seen in a buffer.
func (tg *testgoData) doGrepCount(match string, b *bytes.Buffer) int {
	tg.t.Helper()
	if !tg.ran {
		tg.t.Fatal("internal testsuite error: doGrepCount called before run")
	}
	re := regexp.MustCompile(match)
	c := 0
	for _, ln := range bytes.Split(b.Bytes(), []byte{'\n'}) {
		if re.Match(ln) {
			c++
		}
	}
	return c
}

// grepCountBoth returns the number of times a regexp is seen in both
// standard output and standard error.
func (tg *testgoData) grepCountBoth(match string) int {
	tg.t.Helper()
	return tg.doGrepCount(match, &tg.stdout) + tg.doGrepCount(match, &tg.stderr)
}

// creatingTemp records that the test plans to create a temporary file
// or directory. If the file or directory exists already, it will be
// removed. When the test completes, the file or directory will be
// removed if it exists.
func (tg *testgoData) creatingTemp(path string) {
	tg.t.Helper()
	if filepath.IsAbs(path) && !strings.HasPrefix(path, tg.tempdir) {
		tg.t.Fatalf("internal testsuite error: creatingTemp(%q) with absolute path not in temporary directory", path)
	}
	tg.must(robustio.RemoveAll(path))
	tg.temps = append(tg.temps, path)
}

// makeTempdir makes a temporary directory for a run of testgo. If
// the temporary directory was already created, this does nothing.
func (tg *testgoData) makeTempdir() {
	tg.t.Helper()
	if tg.tempdir == "" {
		var err error
		tg.tempdir, err = os.MkdirTemp("", "gotest")
		tg.must(err)
	}
}

// tempFile adds a temporary file for a run of testgo.
func (tg *testgoData) tempFile(path, contents string) {
	tg.t.Helper()
	tg.makeTempdir()
	tg.must(os.MkdirAll(filepath.Join(tg.tempdir, filepath.Dir(path)), 0755))
	bytes := []byte(contents)
	if strings.HasSuffix(path, ".go") {
		formatted, err := format.Source(bytes)
		if err == nil {
			bytes = formatted
		}
	}
	tg.must(os.WriteFile(filepath.Join(tg.tempdir, path), bytes, 0644))
}

// tempDir adds a temporary directory for a run of testgo.
func (tg *testgoData) tempDir(path string) {
	tg.t.Helper()
	tg.makeTempdir()
	if err := os.MkdirAll(filepath.Join(tg.tempdir, path), 0755); err != nil && !os.IsExist(err) {
		tg.t.Fatal(err)
	}
}

// path returns the absolute pathname to file with the temporary
// directory.
func (tg *testgoData) path(name string) string {
	tg.t.Helper()
	if tg.tempdir == "" {
		tg.t.Fatalf("internal testsuite error: path(%q) with no tempdir", name)
	}
	if name == "." {
		return tg.tempdir
	}
	return filepath.Join(tg.tempdir, name)
}

// mustExist fails if path does not exist.
func (tg *testgoData) mustExist(path string) {
	tg.t.Helper()
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			tg.t.Fatalf("%s does not exist but should", path)
		}
		tg.t.Fatalf("%s stat failed: %v", path, err)
	}
}

// mustNotExist fails if path exists.
func (tg *testgoData) mustNotExist(path string) {
	tg.t.Helper()
	if _, err := os.Stat(path); err == nil || !os.IsNotExist(err) {
		tg.t.Fatalf("%s exists but should not (%v)", path, err)
	}
}

// wantExecutable fails with msg if path is not executable.
func (tg *testgoData) wantExecutable(path, msg string) {
	tg.t.Helper()
	if st, err := os.Stat(path); err != nil {
		if !os.IsNotExist(err) {
			tg.t.Log(err)
		}
		tg.t.Fatal(msg)
	} else {
		if runtime.GOOS != "windows" && st.Mode()&0111 == 0 {
			tg.t.Fatalf("binary %s exists but is not executable", path)
		}
	}
}

// isStale reports whether pkg is stale, and why
func (tg *testgoData) isStale(pkg string) (bool, string) {
	tg.t.Helper()
	tg.run("list", "-f", "{{.Stale}}:{{.StaleReason}}", pkg)
	v := strings.TrimSpace(tg.getStdout())
	f := strings.SplitN(v, ":", 2)
	if len(f) == 2 {
		switch f[0] {
		case "true":
			return true, f[1]
		case "false":
			return false, f[1]
		}
	}
	tg.t.Fatalf("unexpected output checking staleness of package %v: %v", pkg, v)
	panic("unreachable")
}

// wantStale fails with msg if pkg is not stale.
func (tg *testgoData) wantStale(pkg, reason, msg string) {
	tg.t.Helper()
	stale, why := tg.isStale(pkg)
	if !stale {
		tg.t.Fatal(msg)
	}
	// We always accept the reason as being "not installed but
	// available in build cache", because when that is the case go
	// list doesn't try to sort out the underlying reason why the
	// package is not installed.
	if reason == "" && why != "" || !strings.Contains(why, reason) && !strings.Contains(why, "not installed but available in build cache") {
		tg.t.Errorf("wrong reason for Stale=true: %q, want %q", why, reason)
	}
}

// wantNotStale fails with msg if pkg is stale.
func (tg *testgoData) wantNotStale(pkg, reason, msg string) {
	tg.t.Helper()
	stale, why := tg.isStale(pkg)
	if stale {
		tg.t.Fatal(msg)
	}
	if reason == "" && why != "" || !strings.Contains(why, reason) {
		tg.t.Errorf("wrong reason for Stale=false: %q, want %q", why, reason)
	}
}

// If -testwork is specified, the test prints the name of the temp directory
// and does not remove it when done, so that a programmer can
// poke at the test file tree afterward.
var testWork = flag.Bool("testwork", false, "")

// cleanup cleans up a test that runs testgo.
func (tg *testgoData) cleanup() {
	tg.t.Helper()
	if *testWork {
		if tg.tempdir != "" {
			tg.t.Logf("TESTWORK=%s\n", tg.path("."))
		}
		return
	}
	for _, path := range tg.temps {
		tg.check(removeAll(path))
	}
	if tg.tempdir != "" {
		tg.check(removeAll(tg.tempdir))
	}
}

func removeAll(dir string) error {
	// module cache has 0444 directories;
	// make them writable in order to remove content.
	filepath.WalkDir(dir, func(path string, info fs.DirEntry, err error) error {
		// chmod not only directories, but also things that we couldn't even stat
		// due to permission errors: they may also be unreadable directories.
		if err != nil || info.IsDir() {
			os.Chmod(path, 0777)
		}
		return nil
	})
	return robustio.RemoveAll(dir)
}

func TestNewReleaseRebuildsStalePackagesInGOPATH(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping lengthy test in short mode")
	}

	tg := testgo(t)
	defer tg.cleanup()
	tg.parallel()

	// Set GOCACHE to an empty directory so that a previous run of
	// this test does not affect the staleness of the packages it builds.
	tg.tempDir("gocache")
	tg.setenv("GOCACHE", tg.path("gocache"))

	// Copy the runtime packages into a temporary GOROOT
	// so that we can change files.
	var dirs []string
	tg.run("list", "-deps", "runtime")
	pkgs := strings.Split(strings.TrimSpace(tg.getStdout()), "\n")
	for _, pkg := range pkgs {
		dirs = append(dirs, filepath.Join("src", pkg))
	}
	dirs = append(dirs,
		filepath.Join("pkg/tool", goHostOS+"_"+goHostArch),
		"pkg/include",
	)
	for _, copydir := range dirs {
		srcdir := filepath.Join(testGOROOT, copydir)
		tg.tempDir(filepath.Join("goroot", copydir))
		err := filepath.WalkDir(srcdir,
			func(path string, info fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if info.IsDir() {
					return nil
				}
				srcrel, err := filepath.Rel(srcdir, path)
				if err != nil {
					return err
				}
				dest := filepath.Join("goroot", copydir, srcrel)
				if _, err := os.Stat(dest); err == nil {
					return nil
				}
				data, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				tg.tempFile(dest, string(data))
				if strings.Contains(copydir, filepath.Join("pkg", "tool")) {
					os.Chmod(tg.path(dest), 0777)
				}
				return nil
			})
		if err != nil {
			t.Fatal(err)
		}
	}
	tg.setenv("GOROOT", tg.path("goroot"))

	addVar := func(name string, idx int) (restore func()) {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		old := data
		data = append(data, fmt.Sprintf("var DummyUnusedVar%d bool\n", idx)...)
		if err := os.WriteFile(name, append(data, '\n'), 0666); err != nil {
			t.Fatal(err)
		}
		tg.sleep()
		return func() {
			if err := os.WriteFile(name, old, 0666); err != nil {
				t.Fatal(err)
			}
		}
	}

	// Every main package depends on the "runtime".
	tg.tempFile("d1/src/p1/p1.go", `package main; func main(){}`)
	tg.setenv("GOPATH", tg.path("d1"))
	// Pass -i flag to rebuild everything outdated.
	tg.run("install", "p1")
	tg.wantNotStale("p1", "", "./testgo list claims p1 is stale, incorrectly, before any changes")

	// Changing mtime of internal/runtime/sys/sys.go
	// should have no effect: only the content matters.
	// In fact this should be true even outside a release branch.
	sys := tg.path("goroot/src/internal/runtime/sys/sys.go")
	tg.sleep()
	restore := addVar(sys, 0)
	restore()
	tg.wantNotStale("p1", "", "./testgo list claims p1 is stale, incorrectly, after updating mtime of internal/runtime/sys/sys.go")

	// But changing content of any file should have an effect.
	// Previously zversion.go was the only one that mattered;
	// now they all matter, so keep using sys.go.
	restore = addVar(sys, 1)
	defer restore()
	tg.wantStale("p1", "stale dependency: internal/runtime/sys", "./testgo list claims p1 is NOT stale, incorrectly, after changing sys.go")
	restore()
	tg.wantNotStale("p1", "", "./testgo list claims p1 is stale, incorrectly, after changing back to old release")
	addVar(sys, 2)
	tg.wantStale("p1", "stale dependency: internal/runtime/sys", "./testgo list claims p1 is NOT stale, incorrectly, after changing sys.go again")
	tg.run("install", "p1")
	tg.wantNotStale("p1", "", "./testgo list claims p1 is stale after building with new release")

	// Restore to "old" release.
	restore()
	tg.wantStale("p1", "not installed but available in build cache", "./testgo list claims p1 is NOT stale, incorrectly, after restoring sys.go")
	tg.run("install", "p1")
	tg.wantNotStale("p1", "", "./testgo list claims p1 is stale after building with old release")
}

func TestPackageMainTestCompilerFlags(t *testing.T) {
	tg := testgo(t)
	defer tg.cleanup()
	tg.parallel()
	tg.makeTempdir()
	tg.setenv("GOPATH", tg.path("."))
	tg.tempFile("src/p1/p1.go", "package main\n")
	tg.tempFile("src/p1/p1_test.go", "package main\nimport \"testing\"\nfunc Test(t *testing.T){}\n")
	tg.run("test", "-c", "-n", "p1")
	tg.grepBothNot(`([\\/]compile|gccgo).* (-p main|-fgo-pkgpath=main).*p1\.go`, "should not have run compile -p main p1.go")
	tg.grepStderr(`([\\/]compile|gccgo).* (-p p1|-fgo-pkgpath=p1).*p1\.go`, "should have run compile -p p1 p1.go")
}

// Issue 4104.
func TestGoTestWithPackageListedMultipleTimes(t *testing.T) {
	tooSlow(t, "links and runs a test")

	tg := testgo(t)
	defer tg.cleanup()
	tg.parallel()
	tg.run("test", "errors", "errors", "errors", "errors", "errors")
	if strings.Contains(strings.TrimSpace(tg.getStdout()), "\n") {
		t.Error("go test errors errors errors errors errors tested the same package multiple times")
	}
}

func TestGoListHasAConsistentOrder(t *testing.T) {
	tooSlow(t, "walks all of GOROOT/src twice")

	tg := testgo(t)
	defer tg.cleanup()
	tg.parallel()
	tg.run("list", "std")
	first := tg.getStdout()
	tg.run("list", "std")
	if first != tg.getStdout() {
		t.Error("go list std ordering is inconsistent")
	}
}

func TestGoListStdDoesNotIncludeCommands(t *testing.T) {
	tooSlow(t, "walks all of GOROOT/src")

	tg := testgo(t)
	defer tg.cleanup()
	tg.parallel()
	tg.run("list", "std")
	tg.grepStdoutNot("cmd/", "go list std shows commands")
}

func TestGoListCmdOnlyShowsCommands(t *testing.T) {
	skipIfGccgo(t, "gccgo does not have GOROOT")
	tooSlow(t, "walks all of GOROOT/src/cmd")

	tg := testgo(t)
	defer tg.cleanup()
	tg.parallel()
	tg.run("list", "cmd")
	out := strings.TrimSpace(tg.getStdout())
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "cmd/") {
			t.Error("go list cmd shows non-commands")
			break
		}
	}
}

func TestGoListDeps(t *testing.T) {
	tg := testgo(t)
	defer tg.cleanup()
	tg.parallel()
	tg.tempDir("src/p1/p2/p3/p4")
	tg.setenv("GOPATH", tg.path("."))
	tg.tempFile("src/p1/p.go", "package p1\nimport _ \"p1/p2\"\n")
	tg.tempFile("src/p1/p2/p.go", "package p2\nimport _ \"p1/p2/p3\"\n")
	tg.tempFile("src/p1/p2/p3/p.go", "package p3\nimport _ \"p1/p2/p3/p4\"\n")
	tg.tempFile("src/p1/p2/p3/p4/p.go", "package p4\n")
	tg.run("list", "-f", "{{.Deps}}", "p1")
	tg.grepStdout("p1/p2/p3/p4", "Deps(p1) does not mention p4")

	tg.run("list", "-deps", "p1")
	tg.grepStdout("p1/p2/p3/p4", "-deps p1 does not mention p4")

	if runtime.Compiler != "gccgo" {
		// Check the list is in dependency order.
		tg.run("list", "-deps", "math")
		want := "unsafe\ninternal/cpu\nmath/bits\nmath\n"
		out := tg.stdout.String()
		if !strings.Contains(out, "internal/cpu") {
			// Some systems don't use internal/cpu.
			want = "unsafe\nmath/bits\nmath\n"
		}
		if tg.stdout.String() != want {
			t.Fatalf("list -deps math: wrong order\nhave %q\nwant %q", tg.stdout.String(), want)
		}
	}
}

func TestGoListTest(t *testing.T) {
	skipIfGccgo(t, "gccgo does not have standard packages")
	tg := testgo(t)
	defer tg.cleanup()
	tg.parallel()
	tg.makeTempdir()
	tg.setenv("GOCACHE", tg.tempdir)

	tg.run("list", "-test", "-deps", "bytes")
	tg.grepStdout(`^bytes.test$`, "missing test main")
	tg.grepStdout(`^bytes$`, "missing real bytes")
	tg.grepStdout(`^bytes \[bytes.test\]$`, "missing test copy of bytes")
	tg.grepStdout(`^testing \[bytes.test\]$`, "missing test copy of testing")
	tg.grepStdoutNot(`^testing$`, "unexpected real copy of testing")

	tg.run("list", "-test", "bytes")
	tg.grepStdout(`^bytes.test$`, "missing test main")
	tg.grepStdout(`^bytes$`, "missing real bytes")
	tg.grepStdout(`^bytes \[bytes.test\]$`, "unexpected test copy of bytes")
	tg.grepStdoutNot(`^testing \[bytes.test\]$`, "unexpected test copy of testing")
	tg.grepStdoutNot(`^testing$`, "unexpected real copy of testing")

	tg.run("list", "-test", "cmd/buildid", "cmd/doc")
	tg.grepStdout(`^cmd/buildid$`, "missing cmd/buildid")
	tg.grepStdout(`^cmd/doc$`, "missing cmd/doc")
	tg.grepStdout(`^cmd/doc\.test$`, "missing cmd/doc test")
	tg.grepStdoutNot(`^cmd/buildid\.test$`, "unexpected cmd/buildid test")
	tg.grepStdoutNot(`^testing`, "unexpected testing")

	tg.run("list", "-test", "runtime/cgo")
	tg.grepStdout(`^runtime/cgo$`, "missing runtime/cgo")

	tg.run("list", "-deps", "-f", "{{if .DepOnly}}{{.ImportPath}}{{end}}", "sort")
	tg.grepStdout(`^internal/reflectlite$`, "missing internal/reflectlite")
	tg.grepStdoutNot(`^sort`, "unexpected sort")
}

func TestGoListCompiledCgo(t *testing.T) {
	tooSlow(t, "compiles cgo files")

	tg := testgo(t)
	defer tg.cleanup()
	tg.parallel()
	tg.makeTempdir()
	tg.setenv("GOCACHE", tg.tempdir)

	tg.run("list", "-f", `{{join .CgoFiles "\n"}}`, "net")
	if tg.stdout.String() == "" {
		t.Skip("net does not use cgo")
	}
	if strings.Contains(tg.stdout.String(), tg.tempdir) {
		t.Fatalf(".CgoFiles unexpectedly mentioned cache %s", tg.tempdir)
	}
	tg.run("list", "-compiled", "-f", `{{.Dir}}{{"\n"}}{{join .CompiledGoFiles "\n"}}`, "net")
	if !strings.Contains(tg.stdout.String(), tg.tempdir) {
		t.Fatalf(".CompiledGoFiles with -compiled did not mention cache %s", tg.tempdir)
	}
	dir := ""
	for _, file := range strings.Split(tg.stdout.String(), "\n") {
		if file == "" {
			continue
		}
		if dir == "" {
			dir = file
			continue
		}
		if !strings.Contains(file, "/") && !strings.Contains(file, `\`) {
			file = filepath.Join(dir, file)
		}
		if _, err := os.Stat(file); err != nil {
			t.Fatalf("cannot find .CompiledGoFiles result %s: %v", file, err)
		}
	}
}

func TestGoListExport(t *testing.T) {
	skipIfGccgo(t, "gccgo does not have standard packages")
	tg := testgo(t)
	defer tg.cleanup()
	tg.parallel()
	tg.makeTempdir()
	tg.setenv("GOCACHE", tg.tempdir)

	tg.run("list", "-f", "{{.Export}}", "strings")
	if tg.stdout.String() != "" {
		t.Fatalf(".Export without -export unexpectedly set")
	}
	tg.run("list", "-export", "-f", "{{.Export}}", "strings")
	file := strings.TrimSpace(tg.stdout.String())
	if file == "" {
		t.Fatalf(".Export with -export was empty")
	}
	if _, err := os.Stat(file); err != nil {
		t.Fatalf("cannot find .Export result %s: %v", file, err)
	}

	tg.run("list", "-export", "-f", "{{.BuildID}}", "strings")
	buildID := strings.TrimSpace(tg.stdout.String())
	if buildID == "" {
		t.Fatalf(".BuildID with -export was empty")
	}

	tg.run("tool", "buildid", file)
	toolBuildID := strings.TrimSpace(tg.stdout.String())
	if buildID != toolBuildID {
		t.Fatalf(".BuildID with -export %q disagrees with 'go tool buildid' %q", buildID, toolBuildID)
	}
}

// Issue 4096. Validate the output of unsuccessful go install foo/quxx.
func TestUnsuccessfulGoInstallShouldMentionMissingPackage(t *testing.T) {
	tg := testgo(t)
	defer tg.cleanup()
	tg.parallel()
	tg.runFail("install", "foo/quxx")
	if tg.grepCountBoth(`cannot find package "foo/quxx" in any of`) != 1 {
		t.Error(`go install foo/quxx expected error: .*cannot find package "foo/quxx" in any of`)
	}
}

func TestGOROOTSearchFailureReporting(t *testing.T) {
	tg := testgo(t)
	defer tg.cleanup()
	tg.parallel()
	tg.runFail("install", "foo/quxx")
	if tg.grepCountBoth(regexp.QuoteMeta(filepath.Join("foo", "quxx"))+` \(from \$GOROOT\)$`) != 1 {
		t.Error(`go install foo/quxx expected error: .*foo/quxx (from $GOROOT)`)
	}
}

func TestMultipleGOPATHEntriesReportedSeparately(t *testing.T) {
	tg := testgo(t)
	defer tg.cleanup()
	tg.parallel()
	sep := string(filepath.ListSeparator)
	tg.setenv("GOPATH", filepath.Join(tg.pwd(), "testdata", "a")+sep+filepath.Join(tg.pwd(), "testdata", "b"))
	tg.runFail("install", "foo/quxx")
	if tg.grepCountBoth(`testdata[/\\].[/\\]src[/\\]foo[/\\]quxx`) != 2 {
		t.Error(`go install foo/quxx expected error: .*testdata/a/src/foo/quxx (from $GOPATH)\n.*testdata/b/src/foo/quxx`)
	}
}

// Test (from $GOPATH) annotation is reported for the first GOPATH entry,
func TestMentionGOPATHInFirstGOPATHEntry(t *testing.T) {
	tg := testgo(t)
	defer tg.cleanup()
	tg.parallel()
	sep := string(filepath.ListSeparator)
	tg.setenv("GOPATH", filepath.Join(tg.pwd(), "testdata", "a")+sep+filepath.Join(tg.pwd(), "testdata", "b"))
	tg.runFail("install", "foo/quxx")
	if tg.grepCountBoth(regexp.QuoteMeta(filepath.Join("testdata", "a", "src", "foo", "quxx"))+` \(from \$GOPATH\)$`) != 1 {
		t.Error(`go install foo/quxx expected error: .*testdata/a/src/foo/quxx (from $GOPATH)`)
	}
}

// but not on the second.
func TestMentionGOPATHNotOnSecondEntry(t *testing.T) {
	tg := testgo(t)
	defer tg.cleanup()
	tg.parallel()
	sep := string(filepath.ListSeparator)
	tg.setenv("GOPATH", filepath.Join(tg.pwd(), "testdata", "a")+sep+filepath.Join(tg.pwd(), "testdata", "b"))
	tg.runFail("install", "foo/quxx")
	if tg.grepCountBoth(regexp.QuoteMeta(filepath.Join("testdata", "b", "src", "foo", "quxx"))+`$`) != 1 {
		t.Error(`go install foo/quxx expected error: .*testdata/b/src/foo/quxx`)
	}
}

func homeEnvName() string {
	switch runtime.GOOS {
	case "windows":
		return "USERPROFILE"
	case "plan9":
		return "home"
	default:
		return "HOME"
	}
}

func tempEnvName() string {
	switch runtime.GOOS {
	case "windows":
		return "TMP"
	case "plan9":
		return "TMPDIR" // actually plan 9 doesn't have one at all but this is fine
	default:
		return "TMPDIR"
	}
}

func pathEnvName() string {
	switch runtime.GOOS {
	case "plan9":
		return "path"
	default:
		return "PATH"
	}
}

func TestDefaultGOPATH(t *testing.T) {
	tg := testgo(t)
	defer tg.cleanup()
	tg.parallel()
	tg.tempDir("home/go")
	tg.setenv(homeEnvName(), tg.path("home"))
	// Set TEST_TELEMETRY_DIR to a path that doesn't exist
	// so that the counter uploading code doesn't write
	// the counter token file to the temp dir after the test finishes.
	tg.setenv("TEST_TELEMETRY_DIR", "/no-telemetry-dir")

	tg.run("env", "GOPATH")
	tg.grepStdout(regexp.QuoteMeta(tg.path("home/go")), "want GOPATH=$HOME/go")

	tg.setenv("GOROOT", tg.path("home/go"))
	tg.run("env", "GOPATH")
	tg.grepStdoutNot(".", "want unset GOPATH because GOROOT=$HOME/go")

	tg.setenv("GOROOT", tg.path("home/go")+"/")
	tg.run("env", "GOPATH")
	tg.grepStdoutNot(".", "want unset GOPATH because GOROOT=$HOME/go/")
}

func TestDefaultGOPATHPrintedSearchList(t *testing.T) {
	tg := testgo(t)
	defer tg.cleanup()
	tg.parallel()
	tg.setenv("GOPATH", "")
	tg.tempDir("home")
	tg.setenv(homeEnvName(), tg.path("home"))
	// Set TEST_TELEMETRY_DIR to a path that doesn't exist
	// so that the counter uploading code doesn't write
	// the counter token file to the temp dir after the test finishes.
	tg.setenv("TEST_TELEMETRY_DIR", "/no-telemetry-dir")

	tg.runFail("install", "github.com/golang/example/hello")
	tg.grepStderr(regexp.QuoteMeta(tg.path("home/go/src/github.com/golang/example/hello"))+`.*from \$GOPATH`, "expected default GOPATH")
}

func TestLdflagsArgumentsWithSpacesIssue3941(t *testing.T) {
	skipIfGccgo(t, "gccgo does not support -ldflags -X")
	tooSlow(t, "compiles and links a binary")

	tg := testgo(t)
	defer tg.cleanup()
	tg.parallel()
	tg.tempFile("main.go", `package main
		var extern string
		func main() {
			println(extern)
		}`)
	tg.run("run", "-ldflags", `-X "main.extern=hello world"`, tg.path("main.go"))
	tg.grepStderr("^hello world", `ldflags -X "main.extern=hello world"' failed`)
}

func TestLdFlagsLongArgumentsIssue42295(t *testing.T) {
	// Test the extremely long command line arguments that contain '\n' characters
	// get encoded and passed correctly.
	skipIfGccgo(t, "gccgo does not support -ldflags -X")
	tooSlow(t, "compiles and links a binary")

	tg := testgo(t)
	defer tg.cleanup()
	tg.parallel()
	tg.tempFile("main.go", `package main
		var extern string
		func main() {
			print(extern)
		}`)
	testStr := "test test test test test \n\\ "
	var buf strings.Builder
	for buf.Len() < sys.ExecArgLengthLimit+1 {
		buf.WriteString(testStr)
	}
	tg.run("run", "-ldflags", fmt.Sprintf(`-X "main.extern=%s"`, buf.String()), tg.path("main.go"))
	if tg.stderr.String() != buf.String() {
		t.Errorf("strings differ")
	}
}

func TestGoTestDashCDashOControlsBinaryLocation(t *testing.T) {
	skipIfGccgo(t, "gccgo has no standard packages")
	tooSlow(t, "compiles and links a test binary")

	tg := testgo(t)
	defer tg.cleanup()
	tg.parallel()
	tg.makeTempdir()
	tg.run("test", "-c", "-o", tg.path("myerrors.test"+exeSuffix), "errors")
	tg.wantExecutable(tg.path("myerrors.test"+exeSuffix), "go test -c -o myerrors.test did not create myerrors.test")
}

func TestGoTestDashOWritesBinary(t *testing.T) {
	skipIfGccgo(t, "gccgo has no standard packages")
	tooSlow(t, "compiles and runs a test binary")

	tg := testgo(t)
	defer tg.cleanup()
	tg.parallel()
	tg.makeTempdir()
	tg.run("test", "-o", tg.path("myerrors.test"+exeSuffix), "errors")
	tg.wantExecutable(tg.path("myerrors.test"+exeSuffix), "go test -o myerrors.test did not create myerrors.test")
}

// Issue 4515.
func TestInstallWithTags(t *testing.T) {
	tooSlow(t, "compiles and links binaries")

	tg := testgo(t)
	defer tg.cleanup()
	tg.parallel()
	tg.tempDir("bin")
	tg.tempFile("src/example/a/main.go", `package main
		func main() {}`)
	tg.tempFile("src/example/b/main.go", `// +build mytag

		package main
		func main() {}`)
	tg.setenv("GOPATH", tg.path("."))
	tg.run("install", "-tags", "mytag", "example/a", "example/b")
	tg.wantExecutable(tg.path("bin/a"+exeSuffix), "go install example/a example/b did not install binaries")
	tg.wantExecutable(tg.path("bin/b"+exeSuffix), "go install example/a example/b did not install binaries")
	tg.must(os.Remove(tg.path("bin/a" + exeSuffix)))
	tg.must(os.Remove(tg.path("bin/b" + exeSuffix)))
	tg.run("install", "-tags", "mytag", "example/...")
	tg.wantExecutable(tg.path("bin/a"+exeSuffix), "go install example/... did not install binaries")
	tg.wantExecutable(tg.path("bin/b"+exeSuffix), "go install example/... did not install binaries")
	tg.run("list", "-tags", "mytag", "example/b...")
	if strings.TrimSpace(tg.getStdout()) != "example/b" {
		t.Error("go list example/b did not find example/b")
	}
}

// Issue 17451, 17662.
func TestSymlinkWarning(t *testing.T) {
	tg := testgo(t)
	defer tg.cleanup()
	tg.parallel()
	tg.makeTempdir()
	tg.setenv("GOPATH", tg.path("."))

	tg.tempDir("src/example/xx")
	tg.tempDir("yy/zz")
	tg.tempFile("yy/zz/zz.go", "package zz\n")
	if err := os.Symlink(tg.path("yy"), tg.path("src/example/xx/yy")); err != nil {
		t.Skipf("symlink failed: %v", err)
	}
	tg.run("list", "example/xx/z...")
	tg.grepStdoutNot(".", "list should not have matched anything")
	tg.grepStderr("matched no packages", "list should have reported that pattern matched no packages")
	tg.grepStderrNot("symlink", "list should not have reported symlink")

	tg.run("list", "example/xx/...")
	tg.grepStdoutNot(".", "list should not have matched anything")
	tg.grepStderr("matched no packages", "list should have reported that pattern matched no packages")
	tg.grepStderr("ignoring symlink", "list should have reported symlink")
}

func TestCgoShowsFullPathNames(t *testing.T) {
	testenv.MustHaveCGO(t)

	tg := testgo(t)
	defer tg.cleanup()
	tg.parallel()
	tg.tempFile("src/x/y/dirname/foo.go", `
		package foo
		import "C"
		func f() {`)
	tg.setenv("GOPATH", tg.path("."))
	tg.runFail("build", "x/y/dirname")
	tg.grepBoth("x/y/dirname", "error did not use full path")
}

func TestCgoHandlesWlORIGIN(t *testing.T) {
	tooSlow(t, "compiles cgo files")
	testenv.MustHaveCGO(t)

	tg := testgo(t)
	defer tg.cleanup()
	tg.parallel()
	tg.tempFile("src/origin/origin.go", `package origin
		// #cgo !darwin,!windows LDFLAGS: -Wl,-rpath,$ORIGIN
		// void f(void) {}
		import "C"
		func f() { C.f() }`)
	tg.setenv("GOPATH", tg.path("."))
	tg.run("build", "origin")
}

func TestCgoPkgConfig(t *testing.T) {
	tooSlow(t, "compiles cgo files")
	testenv.MustHaveCGO(t)

	tg := testgo(t)
	defer tg.cleanup()
	tg.parallel()

	tg.run("env", "PKG_CONFIG")
	pkgConfig := strings.TrimSpace(tg.getStdout())
	testenv.MustHaveExecPath(t, pkgConfig)
	if out, err := testenv.Command(t, pkgConfig, "--atleast-pkgconfig-version", "0.24").CombinedOutput(); err != nil {
		t.Skipf("%s --atleast-pkgconfig-version 0.24: %v\n%s", pkgConfig, err, out)
	}

	// OpenBSD's pkg-config is strict about whitespace and only
	// supports backslash-escaped whitespace. It does not support
	// quotes, which the normal freedesktop.org pkg-config does
	// support. See https://man.openbsd.org/pkg-config.1
	tg.tempFile("foo.pc", `
Name: foo
Description: The foo library
Version: 1.0.0
Cflags: -Dhello=10 -Dworld=+32 -DDEFINED_FROM_PKG_CONFIG=hello\ world
`)
	tg.tempFile("foo.go", `package main

/*
#cgo pkg-config: foo
int value() {
	return DEFINED_FROM_PKG_CONFIG;
}
*/
import "C"
import "os"

func main() {
	if C.value() != 42 {
		println("value() =", C.value(), "wanted 42")
		os.Exit(1)
	}
}
`)
	tg.setenv("PKG_CONFIG_PATH", tg.path("."))
	tg.run("run", tg.path("foo.go"))

	if runtime.GOOS != "darwin" { // darwin doesn't like these ldflags
		// test for ldflags
		tg.tempFile("bar.pc", `
Name: bar
Description: The bar library
Version: 1.0.0
Libs: -Wl,-rpath=/path\ with\ spaces/bin
`)
	}

	tg.tempFile("bar.go", `package main
/*
#cgo pkg-config: bar
*/
import "C"
func main() {}
`)
	tg.run("run", tg.path("bar.go"))
}

func TestListTemplateContextFunction(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		v    string
		want string
	}{
		{"GOARCH", runtime.GOARCH},
		{"GOOS", runtime.GOOS},
		{"GOROOT", testGOROOT},
		{"GOPATH", os.Getenv("GOPATH")},
		{"CgoEnabled", ""},
		{"UseAllFiles", ""},
		{"Compiler", ""},
		{"BuildTags", ""},
		{"ReleaseTags", ""},
		{"InstallSuffix", ""},
	} {
		tt := tt
		t.Run(tt.v, func(t *testing.T) {
			tg := testgo(t)
			tg.parallel()
			defer tg.cleanup()
			tmpl := "{{context." + tt.v + "}}"
			tg.run("list", "-f", tmpl)
			if tt.want == "" {
				return
			}
			if got := strings.TrimSpace(tg.getStdout()); got != tt.want {
				t.Errorf("go list -f %q: got %q; want %q", tmpl, got, tt.want)
			}
		})
	}
}

// Test that you cannot use a local import in a package
// accessed by a non-local import (found in a GOPATH/GOROOT).
// See golang.org/issue/17475.
func TestImportLocal(t *testing.T) {
	tooSlow(t, "builds a lot of sequential packages")

	tg := testgo(t)
	tg.parallel()
	defer tg.cleanup()

	tg.tempFile("src/dir/x/x.go", `package x
		var X int
	`)
	tg.setenv("GOPATH", tg.path("."))
	tg.run("build", "dir/x")

	// Ordinary import should work.
	tg.tempFile("src/dir/p0/p.go", `package p0
		import "dir/x"
		var _ = x.X
	`)
	tg.run("build", "dir/p0")

	// Relative import should not.
	tg.tempFile("src/dir/p1/p.go", `package p1
		import "../x"
		var _ = x.X
	`)
	tg.runFail("build", "dir/p1")
	tg.grepStderr("local import.*in non-local package", "did not diagnose local import")

	// ... even in a test.
	tg.tempFile("src/dir/p2/p.go", `package p2
	`)
	tg.tempFile("src/dir/p2/p_test.go", `package p2
		import "../x"
		import "testing"
		var _ = x.X
		func TestFoo(t *testing.T) {}
	`)
	tg.run("build", "dir/p2")
	tg.runFail("test", "dir/p2")
	tg.grepStderr("local import.*in non-local package", "did not diagnose local import")

	// ... even in an xtest.
	tg.tempFile("src/dir/p2/p_test.go", `package p2_test
		import "../x"
		import "testing"
		var _ = x.X
		func TestFoo(t *testing.T) {}
	`)
	tg.run("build", "dir/p2")
	tg.runFail("test", "dir/p2")
	tg.grepStderr("local import.*in non-local package", "did not diagnose local import")

	// Relative import starting with ./ should not work either.
	tg.tempFile("src/dir/d.go", `package dir
		import "./x"
		var _ = x.X
	`)
	tg.runFail("build", "dir")
	tg.grepStderr("local import.*in non-local package", "did not diagnose local import")

	// ... even in a test.
	tg.tempFile("src/dir/d.go", `package dir
	`)
	tg.tempFile("src/dir/d_test.go", `package dir
		import "./x"
		import "testing"
		var _ = x.X
		func TestFoo(t *testing.T) {}
	`)
	tg.run("build", "dir")
	tg.runFail("test", "dir")
	tg.grepStderr("local import.*in non-local package", "did not diagnose local import")

	// ... even in an xtest.
	tg.tempFile("src/dir/d_test.go", `package dir_test
		import "./x"
		import "testing"
		var _ = x.X
		func TestFoo(t *testing.T) {}
	`)
	tg.run("build", "dir")
	tg.runFail("test", "dir")
	tg.grepStderr("local import.*in non-local package", "did not diagnose local import")

	// Relative import plain ".." should not work.
	tg.tempFile("src/dir/x/y/y.go", `package dir
		import ".."
		var _ = x.X
	`)
	tg.runFail("build", "dir/x/y")
	tg.grepStderr("local import.*in non-local package", "did not diagnose local import")

	// ... even in a test.
	tg.tempFile("src/dir/x/y/y.go", `package y
	`)
	tg.tempFile("src/dir/x/y/y_test.go", `package y
		import ".."
		import "testing"
		var _ = x.X
		func TestFoo(t *testing.T) {}
	`)
	tg.run("build", "dir/x/y")
	tg.runFail("test", "dir/x/y")
	tg.grepStderr("local import.*in non-local package", "did not diagnose local import")

	// ... even in an x test.
	tg.tempFile("src/dir/x/y/y_test.go", `package y_test
		import ".."
		import "testing"
		var _ = x.X
		func TestFoo(t *testing.T) {}
	`)
	tg.run("build", "dir/x/y")
	tg.runFail("test", "dir/x/y")
	tg.grepStderr("local import.*in non-local package", "did not diagnose local import")

	// Relative import "." should not work.
	tg.tempFile("src/dir/x/xx.go", `package x
		import "."
		var _ = x.X
	`)
	tg.runFail("build", "dir/x")
	tg.grepStderr("cannot import current directory", "did not diagnose import current directory")

	// ... even in a test.
	tg.tempFile("src/dir/x/xx.go", `package x
	`)
	tg.tempFile("src/dir/x/xx_test.go", `package x
		import "."
		import "testing"
		var _ = x.X
		func TestFoo(t *testing.T) {}
	`)
	tg.run("build", "dir/x")
	tg.runFail("test", "dir/x")
	tg.grepStderr("cannot import current directory", "did not diagnose import current directory")

	// ... even in an xtest.
	tg.tempFile("src/dir/x/xx.go", `package x
	`)
	tg.tempFile("src/dir/x/xx_test.go", `package x_test
		import "."
		import "testing"
		var _ = x.X
		func TestFoo(t *testing.T) {}
	`)
	tg.run("build", "dir/x")
	tg.runFail("test", "dir/x")
	tg.grepStderr("cannot import current directory", "did not diagnose import current directory")
}

func TestGoInstallPkgdir(t *testing.T) {
	skipIfGccgo(t, "gccgo has no standard packages")
	tooSlow(t, "builds a package with cgo dependencies")
	// Only the stdlib packages that use cgo have install
	// targets, (we're using net below) so cgo is required
	// for the install.
	testenv.MustHaveCGO(t)

	tg := testgo(t)
	tg.parallel()
	tg.setenv("GODEBUG", "installgoroot=all")
	defer tg.cleanup()
	tg.makeTempdir()
	pkg := tg.path(".")
	tg.run("install", "-pkgdir", pkg, "net")
	tg.mustExist(filepath.Join(pkg, "net.a"))
	tg.mustNotExist(filepath.Join(pkg, "runtime/cgo.a"))
}

// For issue 14337.
func TestParallelTest(t *testing.T) {
	tooSlow(t, "links and runs test binaries")

	tg := testgo(t)
	tg.parallel()
	defer tg.cleanup()
	tg.makeTempdir()
	const testSrc = `package package_test
		import (
			"testing"
		)
		func TestTest(t *testing.T) {
		}`
	tg.tempFile("src/p1/p1_test.go", strings.Replace(testSrc, "package_test", "p1_test", 1))
	tg.tempFile("src/p2/p2_test.go", strings.Replace(testSrc, "package_test", "p2_test", 1))
	tg.tempFile("src/p3/p3_test.go", strings.Replace(testSrc, "package_test", "p3_test", 1))
	tg.tempFile("src/p4/p4_test.go", strings.Replace(testSrc, "package_test", "p4_test", 1))
	tg.setenv("GOPATH", tg.path("."))
	tg.run("test", "-p=4", "p1", "p2", "p3", "p4")
}

func TestBinaryOnlyPackages(t *testing.T) {
	tooSlow(t, "compiles several packages sequentially")

	tg := testgo(t)
	defer tg.cleanup()
	tg.parallel()
	tg.makeTempdir()
	tg.setenv("GOPATH", tg.path("."))

	tg.tempFile("src/p1/p1.go", `//go:binary-only-package

		package p1
	`)
	tg.wantStale("p1", "binary-only packages are no longer supported", "p1 is binary-only, and this message should always be printed")
	tg.runFail("install", "p1")
	tg.grepStderr("binary-only packages are no longer supported", "did not report attempt to compile binary-only package")

	tg.tempFile("src/p1/p1.go", `
		package p1
		import "fmt"
		func F(b bool) { fmt.Printf("hello from p1\n"); if b { F(false) } }
	`)
	tg.run("install", "p1")
	os.Remove(tg.path("src/p1/p1.go"))
	tg.mustNotExist(tg.path("src/p1/p1.go"))

	tg.tempFile("src/p2/p2.go", `//go:binary-only-packages-are-not-great

		package p2
		import "p1"
		func F() { p1.F(true) }
	`)
	tg.runFail("install", "p2")
	tg.grepStderr("no Go files", "did not complain about missing sources")

	tg.tempFile("src/p1/missing.go", `//go:binary-only-package

		package p1
		import _ "fmt"
		func G()
	`)
	tg.wantStale("p1", "binary-only package", "should NOT want to rebuild p1 (first)")
	tg.runFail("install", "p2")
	tg.grepStderr("p1: binary-only packages are no longer supported", "did not report error for binary-only p1")

	tg.run("list", "-deps", "-f", "{{.ImportPath}}: {{.BinaryOnly}}", "p2")
	tg.grepStdout("p1: true", "p1 not listed as BinaryOnly")
	tg.grepStdout("p2: false", "p2 listed as BinaryOnly")
}

// Issue 16050 and 21884.
func TestLinkSysoFiles(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("not linux/amd64")
	}

	tg := testgo(t)
	defer tg.cleanup()
	tg.parallel()
	tg.tempDir("src/syso")
	tg.tempFile("src/syso/a.syso", ``)
	tg.tempFile("src/syso/b.go", `package syso`)
	tg.setenv("GOPATH", tg.path("."))

	// We should see the .syso file regardless of the setting of
	// CGO_ENABLED.

	tg.setenv("CGO_ENABLED", "1")
	tg.run("list", "-f", "{{.SysoFiles}}", "syso")
	tg.grepStdout("a.syso", "missing syso file with CGO_ENABLED=1")

	tg.setenv("CGO_ENABLED", "0")
	tg.run("list", "-f", "{{.SysoFiles}}", "syso")
	tg.grepStdout("a.syso", "missing syso file with CGO_ENABLED=0")

	tg.setenv("CGO_ENABLED", "1")
	tg.run("list", "-msan", "-f", "{{.SysoFiles}}", "syso")
	tg.grepStdoutNot("a.syso", "unexpected syso file with -msan")
}

// Issue 16120.
func TestGenerateUsesBuildContext(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("this test won't run under Windows")
	}

	tg := testgo(t)
	defer tg.cleanup()
	tg.parallel()
	tg.tempDir("src/gen")
	tg.tempFile("src/gen/gen.go", "package gen\n//go:generate echo $GOOS $GOARCH\n")
	tg.setenv("GOPATH", tg.path("."))

	tg.setenv("GOOS", "linux")
	tg.setenv("GOARCH", "amd64")
	tg.run("generate", "gen")
	tg.grepStdout("linux amd64", "unexpected GOOS/GOARCH combination")

	tg.setenv("GOOS", "darwin")
	tg.setenv("GOARCH", "arm64")
	tg.run("generate", "gen")
	tg.grepStdout("darwin arm64", "unexpected GOOS/GOARCH combination")
}

func TestGoEnv(t *testing.T) {
	tg := testgo(t)
	tg.parallel()
	defer tg.cleanup()
	tg.setenv("GOOS", "freebsd") // to avoid invalid pair errors
	tg.setenv("GOARCH", "arm")
	tg.run("env", "GOARCH")
	tg.grepStdout("^arm$", "GOARCH not honored")

	tg.run("env", "GCCGO")
	tg.grepStdout(".", "GCCGO unexpectedly empty")

	tg.run("env", "CGO_CFLAGS")
	tg.grepStdout(".", "default CGO_CFLAGS unexpectedly empty")

	tg.setenv("CGO_CFLAGS", "-foobar")
	tg.run("env", "CGO_CFLAGS")
	tg.grepStdout("^-foobar$", "CGO_CFLAGS not honored")

	tg.setenv("CC", "gcc -fmust -fgo -ffaster")
	tg.run("env", "CC")
	tg.grepStdout("gcc", "CC not found")
	tg.run("env", "GOGCCFLAGS")
	tg.grepStdout("-ffaster", "CC arguments not found")

	tg.run("env", "GOVERSION")
	envVersion := strings.TrimSpace(tg.stdout.String())

	tg.run("version")
	cmdVersion := strings.TrimSpace(tg.stdout.String())

	// If 'go version' is "go version <version> <goos>/<goarch>", then
	// 'go env GOVERSION' is just "<version>".
	if cmdVersion == envVersion || !strings.Contains(cmdVersion, envVersion) {
		t.Fatalf("'go env GOVERSION' %q should be a shorter substring of 'go version' %q", envVersion, cmdVersion)
	}
}

const (
	noMatchesPattern = `(?m)^ok.*\[no tests to run\]`
	okPattern        = `(?m)^ok`
)

// Issue 18044.
func TestLdBindNow(t *testing.T) {
	tg := testgo(t)
	defer tg.cleanup()
	tg.parallel()
	tg.setenv("LD_BIND_NOW", "1")
	tg.run("help")
}

// Issue 18225.
// This is really a cmd/asm issue but this is a convenient place to test it.
func TestConcurrentAsm(t *testing.T) {
	skipIfGccgo(t, "gccgo does not use cmd/asm")
	tg := testgo(t)
	defer tg.cleanup()
	tg.parallel()
	asm := `DATA ·constants<>+0x0(SB)/8,$0
GLOBL ·constants<>(SB),8,$8
`
	tg.tempFile("go/src/p/a.s", asm)
	tg.tempFile("go/src/p/b.s", asm)
	tg.tempFile("go/src/p/p.go", `package p`)
	tg.setenv("GOPATH", tg.path("go"))
	tg.run("build", "p")
}

// Issue 18975.
func TestFFLAGS(t *testing.T) {
	testenv.MustHaveCGO(t)

	tg := testgo(t)
	defer tg.cleanup()
	tg.parallel()

	tg.tempFile("p/src/p/main.go", `package main
		// #cgo FFLAGS: -no-such-fortran-flag
		import "C"
		func main() {}
	`)
	tg.tempFile("p/src/p/a.f", `! comment`)
	tg.setenv("GOPATH", tg.path("p"))

	// This should normally fail because we are passing an unknown flag,
	// but issue #19080 points to Fortran compilers that succeed anyhow.
	// To work either way we call doRun directly rather than run or runFail.
	tg.doRun([]string{"build", "-x", "p"})

	tg.grepStderr("no-such-fortran-flag", `missing expected "-no-such-fortran-flag"`)
}

// Issue 19198.
// This is really a cmd/link issue but this is a convenient place to test it.
func TestDuplicateGlobalAsmSymbols(t *testing.T) {
	skipIfGccgo(t, "gccgo does not use cmd/asm")
	tooSlow(t, "links a binary with cgo dependencies")
	if runtime.GOARCH != "386" && runtime.GOARCH != "amd64" {
		t.Skipf("skipping test on %s", runtime.GOARCH)
	}
	testenv.MustHaveCGO(t)

	tg := testgo(t)
	defer tg.cleanup()
	tg.parallel()

	asm := `
#include "textflag.h"

DATA sym<>+0x0(SB)/8,$0
GLOBL sym<>(SB),(NOPTR+RODATA),$8

TEXT ·Data(SB),NOSPLIT,$0
	MOVB sym<>(SB), AX
	MOVB AX, ret+0(FP)
	RET
`
	tg.tempFile("go/src/a/a.s", asm)
	tg.tempFile("go/src/a/a.go", `package a; func Data() uint8`)
	tg.tempFile("go/src/b/b.s", asm)
	tg.tempFile("go/src/b/b.go", `package b; func Data() uint8`)
	tg.tempFile("go/src/p/p.go", `
package main
import "a"
import "b"
import "C"
func main() {
	_ = a.Data() + b.Data()
}
`)
	tg.setenv("GOPATH", tg.path("go"))
	exe := tg.path("p.exe")
	tg.creatingTemp(exe)
	tg.run("build", "-o", exe, "p")
}

func copyFile(src, dst string, perm fs.FileMode) error {
	sf, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sf.Close()

	df, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}

	_, err = io.Copy(df, sf)
	err2 := df.Close()
	if err != nil {
		return err
	}
	return err2
}

func TestNeedVersion(t *testing.T) {
	skipIfGccgo(t, "gccgo does not use cmd/compile")
	tg := testgo(t)
	defer tg.cleanup()
	tg.parallel()
	tg.tempFile("goversion.go", `package main; func main() {}`)
	path := tg.path("goversion.go")
	tg.setenv("TESTGO_TOOLCHAIN_VERSION", "go1.testgo")
	tg.runFail("run", path)
	tg.grepStderr("compile", "does not match go tool version")
}

func TestBuildmodePIE(t *testing.T) {
	tooSlow(t, "links binaries")

	if !platform.BuildModeSupported(runtime.Compiler, "pie", runtime.GOOS, runtime.GOARCH) {
		t.Skipf("skipping test because buildmode=pie is not supported on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	// Skip on alpine until https://go.dev/issues/54354 resolved.
	if strings.HasSuffix(testenv.Builder(), "-alpine") {
		t.Skip("skipping PIE tests on alpine; see https://go.dev/issues/54354")
	}
	t.Run("non-cgo", func(t *testing.T) {
		testBuildmodePIE(t, false, true)
	})
	t.Run("cgo", func(t *testing.T) {
		testenv.MustHaveCGO(t)
		testBuildmodePIE(t, true, true)
	})
}

func TestWindowsDefaultBuildmodIsPIE(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("skipping windows only test")
	}
	tooSlow(t, "links binaries")

	t.Run("non-cgo", func(t *testing.T) {
		testBuildmodePIE(t, false, false)
	})
	t.Run("cgo", func(t *testing.T) {
		testenv.MustHaveCGO(t)
		testBuildmodePIE(t, true, false)
	})
}

func testBuildmodePIE(t *testing.T, useCgo, setBuildmodeToPIE bool) {
	tg := testgo(t)
	defer tg.cleanup()
	tg.parallel()

	var s string
	if useCgo {
		s = `import "C";`
	}
	tg.tempFile("main.go", fmt.Sprintf(`package main;%s func main() { print("hello") }`, s))
	src := tg.path("main.go")
	obj := tg.path("main.exe")
	args := []string{"build"}
	if setBuildmodeToPIE {
		args = append(args, "-buildmode=pie")
	}
	args = append(args, "-o", obj, src)
	tg.run(args...)

	switch runtime.GOOS {
	case "linux", "android", "freebsd":
		f, err := elf.Open(obj)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if f.Type != elf.ET_DYN {
			t.Errorf("PIE type must be ET_DYN, but %s", f.Type)
		}
	case "darwin", "ios":
		f, err := macho.Open(obj)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if f.Flags&macho.FlagDyldLink == 0 {
			t.Error("PIE must have DyldLink flag, but not")
		}
		if f.Flags&macho.FlagPIE == 0 {
			t.Error("PIE must have PIE flag, but not")
		}
	case "windows":
		f, err := pe.Open(obj)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if f.Section(".reloc") == nil {
			t.Error(".reloc section is not present")
		}
		if (f.FileHeader.Characteristics & pe.IMAGE_FILE_RELOCS_STRIPPED) != 0 {
			t.Error("IMAGE_FILE_RELOCS_STRIPPED flag is set")
		}
		var dc uint16
		switch oh := f.OptionalHeader.(type) {
		case *pe.OptionalHeader32:
			dc = oh.DllCharacteristics
		case *pe.OptionalHeader64:
			dc = oh.DllCharacteristics
			if (dc & pe.IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA) == 0 {
				t.Error("IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA flag is not set")
			}
		default:
			t.Fatalf("unexpected optional header type of %T", f.OptionalHeader)
		}
		if (dc & pe.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) == 0 {
			t.Error("IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE flag is not set")
		}
		if useCgo {
			// Test that only one symbol is exported (#40795).
			// PIE binaries don´t require .edata section but unfortunately
			// binutils doesn´t generate a .reloc section unless there is
			// at least one symbol exported.
			// See https://sourceware.org/bugzilla/show_bug.cgi?id=19011
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

			// Only _cgo_dummy_export should be exported
			if e.NumberOfFunctions != 1 {
				t.Fatalf("got %d exported functions; want 1", e.NumberOfFunctions)
			}
			if e.NumberOfNames != 1 {
				t.Fatalf("got %d exported names; want 1", e.NumberOfNames)
			}
		}
	default:
		// testBuildmodePIE opens object files, so it needs to understand the object
		// file format.
		t.Skipf("skipping test: test helper does not support %s", runtime.GOOS)
	}

	out, err := testenv.Command(t, obj).CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}

	if string(out) != "hello" {
		t.Errorf("got %q; want %q", out, "hello")
	}
}

func TestUpxCompression(t *testing.T) {
	if runtime.GOOS != "linux" ||
		(runtime.GOARCH != "amd64" && runtime.GOARCH != "386") {
		t.Skipf("skipping upx test on %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	testenv.MustHaveExecPath(t, "upx")
	out, err := testenv.Command(t, "upx", "--version").CombinedOutput()
	if err != nil {
		t.Fatalf("upx --version failed: %v", err)
	}

	// upx --version prints `upx <version>` in the first line of output:
	//   upx 3.94
	//   [...]
	re := regexp.MustCompile(`([[:digit:]]+)\.([[:digit:]]+)`)
	upxVersion := re.FindStringSubmatch(string(out))
	if len(upxVersion) != 3 {
		t.Fatalf("bad upx version string: %s", upxVersion)
	}

	major, err1 := strconv.Atoi(upxVersion[1])
	minor, err2 := strconv.Atoi(upxVersion[2])
	if err1 != nil || err2 != nil {
		t.Fatalf("bad upx version string: %s", upxVersion[0])
	}

	// Anything below 3.94 is known not to work with go binaries
	if (major < 3) || (major == 3 && minor < 94) {
		t.Skipf("skipping because upx version %v.%v is too old", major, minor)
	}

	tg := testgo(t)
	defer tg.cleanup()
	tg.parallel()

	tg.tempFile("main.go", `package main; import "fmt"; func main() { fmt.Print("hello upx") }`)
	src := tg.path("main.go")
	obj := tg.path("main")
	tg.run("build", "-o", obj, src)

	out, err = testenv.Command(t, "upx", obj).CombinedOutput()
	if err != nil {
		t.Logf("executing upx\n%s\n", out)
		t.Fatalf("upx failed with %v", err)
	}

	out, err = testenv.Command(t, obj).CombinedOutput()
	if err != nil {
		t.Logf("%s", out)
		t.Fatalf("running compressed go binary failed
```