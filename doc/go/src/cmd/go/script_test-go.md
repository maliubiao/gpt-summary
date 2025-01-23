Response: Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Understanding of the Context:**

The first lines are crucial: `// Copyright 2018 The Go Authors. All rights reserved.` and `// Script-driven tests. // See testdata/script/README for an overview.`  This immediately tells us this code is part of the Go standard library's testing infrastructure, specifically for running script-based tests. The reference to `testdata/script/README` suggests that there's a specific format and conventions for these scripts.

**2. Identifying Key Functions:**

Scanning the code for function names gives us a high-level view of the program's structure:

* `TestScript(t *testing.T)`: This is the main entry point for the test, as indicated by the `testing.T` argument.
* `scriptEnv(srv *vcstest.Server, srvCertFile string)`: This function seems to set up the environment for the scripts. The arguments suggest interaction with a version control server (`vcstest`).
* `updateSum(t testing.TB, e *script.Engine, s *script.State, archive *txtar.Archive)`: This function's name strongly suggests it's involved in updating `go.sum` files.
* `readCounters(t *testing.T, telemetryDir string)` and `checkCounters(t *testing.T, telemetryDir string)`:  These functions are clearly related to reading and checking telemetry data.
* Helper functions like `tbContext`, `tbFromContext`, and `initScriptDirs` are also present.

**3. Analyzing `TestScript` in Detail:**

This function is the core of the test execution. Let's break down its key actions:

* **Setup:**
    * `testenv.MustHaveGoBuild(t)` and `testenv.SkipIfShortAndSlow(t)`: Standard Go testing setup.
    * Version Control Server (`vcstest`):  A temporary VCS server is started. This implies some tests involve VCS interactions.
    * Proxy (`StartProxy()`):  A proxy is started, indicating tests might involve network requests.
    * Context with Timeout: A context is created with a timeout, crucial for preventing tests from running indefinitely.
    * `scriptEnv`: The environment for the scripts is created.
    * `script.Engine`: An engine is initialized to run the scripts.
* **Running Tests:**
    * `t.Run("README", ...)`: A specific test for the README file.
    * `filepath.Glob("testdata/script/*.txt")`:  It finds all the script files in the `testdata/script` directory.
    * Loop through files: Each `.txt` file is treated as a test case.
    * `os.MkdirTemp`: A temporary working directory is created for each test.
    * `script.NewState`: A new state is created for the script execution.
    * `txtar.ParseFile`: The script file is parsed. The `.txt` format suggests a specific structure (likely input files and commands).
    * `s.ExtractFiles`: Files from the parsed archive are extracted to the temporary directory.
    * `-testsum` handling: If the `-testsum` flag is set, `updateSum` is called.
    * `scripttest.Run`: This is where the actual script execution happens.
    * `checkCounters`: Telemetry counters are checked.
* **Cleanup:** Temporary directories are removed.

**4. Deciphering the Purpose of Key Components:**

* **`script.Engine` and `scripttest.Run`:** These strongly suggest the framework for running the scripts. The `script` package likely defines the scripting language and execution environment.
* **`txtar.Archive`:** The use of `txtar` points to a specific file format for the test scripts. Looking up the `txtar` package documentation would confirm its purpose (archives of text files).
* **`-testsum` flag:**  The logic within `updateSum` clearly indicates this flag controls actions related to `go.mod` and `go.sum` files. The different values (`tidy`, `listm`, `listall`) correspond to specific `go` commands.
* **Telemetry:** The `telemetryDir`, `readCounters`, and `checkCounters` functions show this test suite verifies that telemetry data is being collected correctly when `go` commands are executed within the scripts.

**5. Inferring Go Language Feature Testing:**

Given the context of `cmd/go`, this test suite is likely used to test various functionalities of the `go` command itself. The interaction with `go.mod`, `go.sum`, VCS, and network proxies points to testing features like:

* **Module management:**  The `-testsum` flag and `updateSum` function are direct evidence of testing `go mod tidy`, `go list -m all`, etc.
* **Version control:** The `vcstest.Server` and the environment variables related to it indicate testing how the `go` command interacts with different VCS systems.
* **Network operations:** The proxy setup suggests testing scenarios involving downloading modules or other network-related tasks.
* **Telemetry:**  Verifying that the `go` command collects and reports telemetry data.

**6. Constructing Examples (Mental Walkthrough and then Coding):**

Based on the analysis, we can formulate examples:

* **`-testsum tidy`:**  Imagine a script with a `go.mod` that has extra or missing requirements. `go mod tidy` should fix it. The `updateSum` function would be responsible for running this and updating the script file.
* **VCS interaction:** A script might use `go get` to fetch a package from the mock VCS server. The environment variables set up by `scriptEnv` would point the `go` command to this server.
* **Network proxy:** A script might attempt to download a module, and the started proxy could simulate different network conditions or require authentication.

**7. Identifying Potential Mistakes:**

Thinking about how someone might use these tests incorrectly leads to:

* **Incorrect script format:** Not following the `txtar` format would cause parsing errors.
* **Assuming internet access without the `[net]` condition:**  The `TESTGONETWORK=panic` setting highlights that network access is restricted by default.
* **Misunderstanding the purpose of `-testsum`:**  Using it without a `go.mod` file wouldn't have any effect.

**Self-Correction/Refinement during the thought process:**

* Initially, I might have just seen `TestScript` and thought it was a generic testing function. However, noticing the specific imports (`cmd/go/internal/cfg`, `cmd/go/internal/gover`, `cmd/go/internal/vcweb/vcstest`) quickly narrows down the scope to testing the `go` command.
* Seeing `txtar` might be unfamiliar. A quick search or recognizing it from previous Go experience is needed to understand its role.
* The purpose of the telemetry checks might not be immediately obvious. Connecting it to the broader effort of Go command telemetry requires some background knowledge.

By following this detailed analysis, we can arrive at a comprehensive understanding of the code's functionality, the Go features it tests, and potential pitfalls for users.
这段代码是 Go 语言 `cmd/go` 工具的一部分，它的主要功能是 **执行基于脚本的集成测试**。  这些脚本存储在 `testdata/script/*.txt` 文件中，用于测试 `go` 命令的各种行为。

下面我将详细列举它的功能，并尝试推理它所测试的 Go 语言功能，并提供代码示例和对命令行参数的处理说明。

**功能列举:**

1. **加载和解析测试脚本:**  它会遍历 `testdata/script` 目录下的所有 `.txt` 文件，并将每个文件视为一个独立的测试用例。
2. **创建隔离的测试环境:**  对于每个测试脚本，它会创建一个临时的、隔离的工作目录，以避免测试之间的相互影响。
3. **初始化测试环境:**  在临时工作目录中，它会设置必要的环境变量，例如 `GOPATH`, `GOROOT`, `GOOS`, `GOARCH` 等，以及一些用于模拟 VCS 环境的变量。
4. **解压测试数据:**  `.txt` 文件实际上是 `txtar` 格式的归档文件，可以包含初始的文件和目录结构。这段代码会解析 `txtar` 文件，并在临时工作目录中创建这些文件和目录。
5. **执行脚本命令:**  `.txt` 文件的注释部分包含了一系列的命令，这些命令会被逐行解析并执行。这些命令通常是 `go` 命令的各种子命令，例如 `go build`, `go run`, `go mod`, `go get` 等。
6. **断言执行结果:**  脚本中的命令可以包含断言，用于检查命令的输出、错误代码、文件内容等是否符合预期。
7. **更新 `go.sum` 文件 (可选):**  如果设置了 `-testsum` 标志，并且测试目录下存在 `go.mod` 文件，它会在测试开始时运行 `go mod tidy` 或类似的命令来生成或更新 `go.sum` 文件。如果测试通过，它还会将更新后的 `go.sum` 写回测试文件。
8. **收集和检查遥测数据:** 代码中包含收集和检查遥测数据的逻辑，这表明它也在测试 `go` 命令的遥测功能。
9. **模拟 VCS 环境:**  代码使用了 `vcstest` 包来创建一个模拟的 VCS 服务器，用于测试 `go` 命令与版本控制系统的交互。
10. **处理超时:**  代码为每个测试设置了超时时间，防止测试无限期运行。

**推理测试的 Go 语言功能:**

根据代码的结构和使用的包，可以推断出它主要用于测试以下 Go 语言功能：

* **模块管理 (Go Modules):**  通过 `-testsum` 标志和对 `go.mod`, `go.sum` 文件的处理，可以判断它在测试 `go mod init`, `go mod tidy`, `go mod graph`, `go list -m all` 等模块相关的命令。
* **构建和编译:**  脚本中很可能会包含 `go build`, `go install` 等命令，用于测试 Go 代码的编译和安装过程。
* **运行:**  `go run` 命令会被用于测试直接运行 Go 代码。
* **获取依赖 (go get):**  通过模拟 VCS 环境，可以测试 `go get` 命令从不同版本控制系统获取依赖的功能。
* **版本控制集成:**  `vcstest` 包的使用表明正在测试 `go` 命令与 Git, Mercurial 等版本控制系统的集成。
* **环境变量处理:**  代码中设置了大量的环境变量，这表明它也在测试 `go` 命令对环境变量的依赖和处理。
* **遥测 (Telemetry):**  `countertest` 包的使用和 `checkCounters` 函数表明正在测试 `go` 命令的遥测数据收集功能。
* **内部工具链:**  由于这是 `cmd/go` 的测试，它自然也会覆盖到 Go 语言的内部工具链，例如编译器、链接器等。

**Go 代码示例 (基于推理):**

假设一个测试脚本 `testdata/script/mod_tidy.txt` 包含以下内容：

```text
# Initial go.mod with an unused require.
-- go.mod --
module example.com/hello

go 1.16

require golang.org/x/text v0.3.7
-- hello.go --
package main

import "fmt"

func main() {
	fmt.Println("Hello, world!")
}
# Verify that 'go mod tidy' removes the unused require.
go mod tidy
! stdout '^$'
! stderr 'go.mod: '
grep 'require golang.org/x/text' go.mod
! stdout .
```

**假设的输入与输出:**

* **输入:** 执行 `go test cmd/go`，并且这个测试脚本被执行。
* **预期输出:**
    * `go mod tidy` 命令会修改 `go.mod` 文件，移除 `require golang.org/x/text v0.3.7` 这一行。
    * 标准输出为空。
    * 标准错误会包含 "go.mod: "，指示 `go mod tidy` 修改了 `go.mod` 文件。
    * 再次检查 `go.mod` 文件，不包含 `require golang.org/x/text` 这一行。

**命令行参数的具体处理:**

代码中使用了 `flag` 包来处理命令行参数，其中定义了 `-testsum` 参数：

```go
var testSum = flag.String("testsum", "", `may be tidy, listm, or listall. If set, TestScript generates a go.sum file at the beginning of each test and updates test files if they pass.`)
```

* **`-testsum`:**  这个参数接受三个可选值：`tidy`, `listm`, 或 `listall`。
    * **`tidy`:** 如果设置了 `-testsum=tidy`，并且测试目录下存在 `go.mod` 文件，那么在执行测试脚本之前，会运行 `go mod tidy` 命令。  如果测试通过，更新后的 `go.mod` 和 `go.sum` 文件内容会写回到原始的 `.txt` 测试文件中。
    * **`listm`:** 如果设置了 `-testsum=listm`，则运行 `go list -mod=mod -m all` 命令。
    * **`listall`:** 如果设置了 `-testsum=listall`，则运行 `go list -mod=mod all` 命令。

**使用者易犯错的点:**

1. **测试脚本格式错误:**  `.txt` 文件必须遵循 `txtar` 的格式，否则解析会失败。例如，文件分隔符 `\n-- <filename> --\n` 必须正确使用。
2. **对测试环境的假设过于绝对:** 测试脚本运行在一个临时的、隔离的环境中，不能依赖用户本地的配置或已安装的软件包。应该通过脚本自身来设置必要的环境。
3. **网络依赖问题:** 默认情况下，测试网络访问是禁止的 (`TESTGONETWORK=panic`)。如果测试需要网络访问，需要在脚本中使用 `[net]` 条件来启用。忘记添加这个条件会导致测试失败。
4. **不理解 `-testsum` 的作用:**  `-testsum` 主要用于测试模块相关的命令，并且会修改测试文件。如果不理解其作用，可能会导致测试结果的困惑，或者意外修改了测试文件。例如，如果在不应该生成 `go.sum` 的情况下使用了 `-testsum=tidy`，可能会导致测试行为不符合预期。

**代码推理示例 (带假设的输入与输出):**

以下是 `updateSum` 函数处理 `-testsum=tidy` 的一个简化推理过程：

```go
// 假设的输入：
// - 一个包含 go.mod 但缺少 go.sum 的 txtar.Archive
// - testSum 的值为 "tidy"

func updateSum(t testing.TB, e *script.Engine, s *script.State, archive *txtar.Archive) (rewrite bool) {
	gomodIdx, gosumIdx := -1, -1
	for i := range archive.Files {
		switch archive.Files[i].Name {
		case "go.mod":
			gomodIdx = i
		case "go.sum":
			gosumIdx = i
		}
	}
	if gomodIdx < 0 { // 假设存在 go.mod
		return false
	}

	var cmd string
	switch *testSum {
	case "tidy":
		cmd = "go mod tidy" // 选择了 "tidy"
	// ...
	}

	log := new(strings.Builder)
	err := e.Execute(s, "updateSum", bufio.NewReader(strings.NewReader(cmd)), log) // 执行 go mod tidy
	if err != nil {
		t.Fatal(err)
	}

	newGomodData, err := os.ReadFile(s.Path("go.mod"))
	// ... 比较 go.mod 的内容

	newGosumData, err := os.ReadFile(s.Path("go.sum")) // 假设 go mod tidy 生成了 go.sum
	// ...
	switch {
	case os.IsNotExist(err) && gosumIdx >= 0: // 不满足
		// ...
	case err == nil && gosumIdx < 0: // 满足，之前没有 go.sum，现在生成了
		rewrite = true
		gosumIdx = gomodIdx + 1
		archive.Files = append(archive.Files, txtar.File{})
		copy(archive.Files[gosumIdx+1:], archive.Files[gosumIdx:])
		archive.Files[gosumIdx] = txtar.File{Name: "go.sum", Data: newGosumData} // 将新的 go.sum 加入 archive
	// ...
	}
	return rewrite // 返回 true，表示 archive 被修改
}
```

**假设的输出:**

* 如果在执行 `go mod tidy` 之前，`archive` 中只包含 `go.mod` 文件，那么执行 `updateSum` 后，`archive` 中会新增一个 `go.sum` 文件，其内容是 `go mod tidy` 生成的 `go.sum` 文件的内容。
* `rewrite` 的值会是 `true`，表示 `archive` 被修改了。

总而言之，`script_test.go` 是 `cmd/go` 工具自身进行集成测试的关键部分，它通过执行预定义的脚本来验证 `go` 命令的各种功能是否按预期工作，涵盖了模块管理、构建、运行、版本控制集成等多个方面。

### 提示词
```
这是路径为go/src/cmd/go/script_test.go的go语言实现的一部分， 请列举一下它的功能, 　
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

// Script-driven tests.
// See testdata/script/README for an overview.

//go:generate go test cmd/go -v -run=TestScript/README --fixreadme

package main_test

import (
	"bufio"
	"bytes"
	"context"
	_ "embed"
	"flag"
	"internal/testenv"
	"internal/txtar"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"cmd/go/internal/cfg"
	"cmd/go/internal/gover"
	"cmd/go/internal/vcweb/vcstest"
	"cmd/internal/script"
	"cmd/internal/script/scripttest"

	"golang.org/x/telemetry/counter/countertest"
)

var testSum = flag.String("testsum", "", `may be tidy, listm, or listall. If set, TestScript generates a go.sum file at the beginning of each test and updates test files if they pass.`)

// TestScript runs the tests in testdata/script/*.txt.
func TestScript(t *testing.T) {
	testenv.MustHaveGoBuild(t)
	testenv.SkipIfShortAndSlow(t)

	if testing.Short() && runtime.GOOS == "plan9" {
		t.Skipf("skipping test in -short mode on %s", runtime.GOOS)
	}

	srv, err := vcstest.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := srv.Close(); err != nil {
			t.Fatal(err)
		}
	})
	certFile, err := srv.WriteCertificateFile()
	if err != nil {
		t.Fatal(err)
	}

	StartProxy()

	var (
		ctx         = context.Background()
		gracePeriod = 100 * time.Millisecond
	)
	if deadline, ok := t.Deadline(); ok {
		timeout := time.Until(deadline)

		// If time allows, increase the termination grace period to 5% of the
		// remaining time.
		if gp := timeout / 20; gp > gracePeriod {
			gracePeriod = gp
		}

		// When we run commands that execute subprocesses, we want to reserve two
		// grace periods to clean up. We will send the first termination signal when
		// the context expires, then wait one grace period for the process to
		// produce whatever useful output it can (such as a stack trace). After the
		// first grace period expires, we'll escalate to os.Kill, leaving the second
		// grace period for the test function to record its output before the test
		// process itself terminates.
		timeout -= 2 * gracePeriod

		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		t.Cleanup(cancel)
	}

	env, err := scriptEnv(srv, certFile)
	if err != nil {
		t.Fatal(err)
	}
	engine := &script.Engine{
		Conds: scriptConditions(t),
		Cmds:  scriptCommands(quitSignal(), gracePeriod),
		Quiet: !testing.Verbose(),
	}

	t.Run("README", func(t *testing.T) {
		checkScriptReadme(t, engine, env)
	})

	files, err := filepath.Glob("testdata/script/*.txt")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		file := file
		name := strings.TrimSuffix(filepath.Base(file), ".txt")
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			StartProxy()

			workdir, err := os.MkdirTemp(testTmpDir, name)
			if err != nil {
				t.Fatal(err)
			}
			if !*testWork {
				defer removeAll(workdir)
			}

			s, err := script.NewState(tbContext(ctx, t), workdir, env)
			if err != nil {
				t.Fatal(err)
			}

			// Unpack archive.
			a, err := txtar.ParseFile(file)
			if err != nil {
				t.Fatal(err)
			}
			telemetryDir := initScriptDirs(t, s)
			if err := s.ExtractFiles(a); err != nil {
				t.Fatal(err)
			}

			t.Log(time.Now().UTC().Format(time.RFC3339))
			work, _ := s.LookupEnv("WORK")
			t.Logf("$WORK=%s", work)

			// With -testsum, if a go.mod file is present in the test's initial
			// working directory, run 'go mod tidy'.
			if *testSum != "" {
				if updateSum(t, engine, s, a) {
					defer func() {
						if t.Failed() {
							return
						}
						data := txtar.Format(a)
						if err := os.WriteFile(file, data, 0666); err != nil {
							t.Errorf("rewriting test file: %v", err)
						}
					}()
				}
			}

			// Note: Do not use filepath.Base(file) here:
			// editors that can jump to file:line references in the output
			// will work better seeing the full path relative to cmd/go
			// (where the "go test" command is usually run).
			scripttest.Run(t, engine, s, file, bytes.NewReader(a.Comment))
			checkCounters(t, telemetryDir)
		})
	}
}

// testingTBKey is the Context key for a testing.TB.
type testingTBKey struct{}

// tbContext returns a Context derived from ctx and associated with t.
func tbContext(ctx context.Context, t testing.TB) context.Context {
	return context.WithValue(ctx, testingTBKey{}, t)
}

// tbFromContext returns the testing.TB associated with ctx, if any.
func tbFromContext(ctx context.Context) (testing.TB, bool) {
	t := ctx.Value(testingTBKey{})
	if t == nil {
		return nil, false
	}
	return t.(testing.TB), true
}

// initScriptDirs creates the initial directory structure in s for unpacking a
// cmd/go script.
func initScriptDirs(t testing.TB, s *script.State) (telemetryDir string) {
	must := func(err error) {
		if err != nil {
			t.Helper()
			t.Fatal(err)
		}
	}

	work := s.Getwd()
	must(s.Setenv("WORK", work))

	telemetryDir = filepath.Join(work, "telemetry")
	must(os.MkdirAll(telemetryDir, 0777))
	must(s.Setenv("TEST_TELEMETRY_DIR", filepath.Join(work, "telemetry")))

	must(os.MkdirAll(filepath.Join(work, "tmp"), 0777))
	must(s.Setenv(tempEnvName(), filepath.Join(work, "tmp")))

	gopath := filepath.Join(work, "gopath")
	must(s.Setenv("GOPATH", gopath))
	gopathSrc := filepath.Join(gopath, "src")
	must(os.MkdirAll(gopathSrc, 0777))
	must(s.Chdir(gopathSrc))
	return telemetryDir
}

func scriptEnv(srv *vcstest.Server, srvCertFile string) ([]string, error) {
	httpURL, err := url.Parse(srv.HTTP.URL)
	if err != nil {
		return nil, err
	}
	httpsURL, err := url.Parse(srv.HTTPS.URL)
	if err != nil {
		return nil, err
	}
	env := []string{
		pathEnvName() + "=" + testBin + string(filepath.ListSeparator) + os.Getenv(pathEnvName()),
		homeEnvName() + "=/no-home",
		"CCACHE_DISABLE=1", // ccache breaks with non-existent HOME
		"GOARCH=" + runtime.GOARCH,
		"TESTGO_GOHOSTARCH=" + goHostArch,
		"GOCACHE=" + testGOCACHE,
		"GOCOVERDIR=" + os.Getenv("GOCOVERDIR"),
		"GODEBUG=" + os.Getenv("GODEBUG"),
		"GOEXE=" + cfg.ExeSuffix,
		"GOEXPERIMENT=" + os.Getenv("GOEXPERIMENT"),
		"GOOS=" + runtime.GOOS,
		"TESTGO_GOHOSTOS=" + goHostOS,
		"GOPROXY=" + proxyURL,
		"GOPRIVATE=",
		"GOROOT=" + testGOROOT,
		"GOTRACEBACK=system",
		"TESTGONETWORK=panic", // allow only local connections by default; the [net] condition resets this
		"TESTGO_GOROOT=" + testGOROOT,
		"TESTGO_EXE=" + testGo,
		"TESTGO_VCSTEST_HOST=" + httpURL.Host,
		"TESTGO_VCSTEST_TLS_HOST=" + httpsURL.Host,
		"TESTGO_VCSTEST_CERT=" + srvCertFile,
		"TESTGONETWORK=panic", // cleared by the [net] condition
		"GOSUMDB=" + testSumDBVerifierKey,
		"GONOPROXY=",
		"GONOSUMDB=",
		"GOVCS=*:all",
		"devnull=" + os.DevNull,
		"goversion=" + gover.Local(),
		"CMDGO_TEST_RUN_MAIN=true",
		"HGRCPATH=",
		"GOTOOLCHAIN=auto",
		"newline=\n",
	}

	if testenv.Builder() != "" || os.Getenv("GIT_TRACE_CURL") == "1" {
		// To help diagnose https://go.dev/issue/52545,
		// enable tracing for Git HTTPS requests.
		env = append(env,
			"GIT_TRACE_CURL=1",
			"GIT_TRACE_CURL_NO_DATA=1",
			"GIT_REDACT_COOKIES=o,SSO,GSSO_Uberproxy")
	}
	if testing.Short() {
		// VCS commands are always somewhat slow: they either require access to external hosts,
		// or they require our intercepted vcs-test.golang.org to regenerate the repository.
		// Require all tests that use VCS commands which require remote lookups to be skipped in
		// short mode.
		env = append(env, "TESTGOVCSREMOTE=panic")
	}
	if os.Getenv("CGO_ENABLED") != "" || runtime.GOOS != goHostOS || runtime.GOARCH != goHostArch {
		// If the actual CGO_ENABLED might not match the cmd/go default, set it
		// explicitly in the environment. Otherwise, leave it unset so that we also
		// cover the default behaviors.
		env = append(env, "CGO_ENABLED="+cgoEnabled)
	}

	for _, key := range extraEnvKeys {
		if val, ok := os.LookupEnv(key); ok {
			env = append(env, key+"="+val)
		}
	}

	return env, nil
}

var extraEnvKeys = []string{
	"SYSTEMROOT",         // must be preserved on Windows to find DLLs; golang.org/issue/25210
	"WINDIR",             // must be preserved on Windows to be able to run PowerShell command; golang.org/issue/30711
	"LD_LIBRARY_PATH",    // must be preserved on Unix systems to find shared libraries
	"LIBRARY_PATH",       // allow override of non-standard static library paths
	"C_INCLUDE_PATH",     // allow override non-standard include paths
	"CC",                 // don't lose user settings when invoking cgo
	"GO_TESTING_GOTOOLS", // for gccgo testing
	"GCCGO",              // for gccgo testing
	"GCCGOTOOLDIR",       // for gccgo testing
}

// updateSum runs 'go mod tidy', 'go list -mod=mod -m all', or
// 'go list -mod=mod all' in the test's current directory if a file named
// "go.mod" is present after the archive has been extracted. updateSum modifies
// archive and returns true if go.mod or go.sum were changed.
func updateSum(t testing.TB, e *script.Engine, s *script.State, archive *txtar.Archive) (rewrite bool) {
	gomodIdx, gosumIdx := -1, -1
	for i := range archive.Files {
		switch archive.Files[i].Name {
		case "go.mod":
			gomodIdx = i
		case "go.sum":
			gosumIdx = i
		}
	}
	if gomodIdx < 0 {
		return false
	}

	var cmd string
	switch *testSum {
	case "tidy":
		cmd = "go mod tidy"
	case "listm":
		cmd = "go list -m -mod=mod all"
	case "listall":
		cmd = "go list -mod=mod all"
	default:
		t.Fatalf(`unknown value for -testsum %q; may be "tidy", "listm", or "listall"`, *testSum)
	}

	log := new(strings.Builder)
	err := e.Execute(s, "updateSum", bufio.NewReader(strings.NewReader(cmd)), log)
	if log.Len() > 0 {
		t.Logf("%s", log)
	}
	if err != nil {
		t.Fatal(err)
	}

	newGomodData, err := os.ReadFile(s.Path("go.mod"))
	if err != nil {
		t.Fatalf("reading go.mod after -testsum: %v", err)
	}
	if !bytes.Equal(newGomodData, archive.Files[gomodIdx].Data) {
		archive.Files[gomodIdx].Data = newGomodData
		rewrite = true
	}

	newGosumData, err := os.ReadFile(s.Path("go.sum"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("reading go.sum after -testsum: %v", err)
	}
	switch {
	case os.IsNotExist(err) && gosumIdx >= 0:
		// go.sum was deleted.
		rewrite = true
		archive.Files = append(archive.Files[:gosumIdx], archive.Files[gosumIdx+1:]...)
	case err == nil && gosumIdx < 0:
		// go.sum was created.
		rewrite = true
		gosumIdx = gomodIdx + 1
		archive.Files = append(archive.Files, txtar.File{})
		copy(archive.Files[gosumIdx+1:], archive.Files[gosumIdx:])
		archive.Files[gosumIdx] = txtar.File{Name: "go.sum", Data: newGosumData}
	case err == nil && gosumIdx >= 0 && !bytes.Equal(newGosumData, archive.Files[gosumIdx].Data):
		// go.sum was changed.
		rewrite = true
		archive.Files[gosumIdx].Data = newGosumData
	}
	return rewrite
}

func readCounters(t *testing.T, telemetryDir string) map[string]uint64 {
	localDir := filepath.Join(telemetryDir, "local")
	dirents, err := os.ReadDir(localDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // The Go command didn't ever run so the local dir wasn't created
		}
		t.Fatalf("reading telemetry local dir: %v", err)
	}
	totals := map[string]uint64{}
	for _, dirent := range dirents {
		if dirent.IsDir() || !strings.HasSuffix(dirent.Name(), ".count") {
			// not a counter file
			continue
		}
		counters, _, err := countertest.ReadFile(filepath.Join(localDir, dirent.Name()))
		if err != nil {
			t.Fatalf("reading counter file: %v", err)
		}
		for k, v := range counters {
			totals[k] += v
		}
	}

	return totals
}

func checkCounters(t *testing.T, telemetryDir string) {
	counters := readCounters(t, telemetryDir)
	if _, ok := scriptGoInvoked.Load(testing.TB(t)); ok {
		if !disabledOnPlatform && len(counters) == 0 {
			t.Fatal("go was invoked but no counters were incremented")
		}
	}
}

// Copied from https://go.googlesource.com/telemetry/+/5f08a0cbff3f/internal/telemetry/mode.go#122
// TODO(go.dev/issues/66205): replace this with the public API once it becomes available.
//
// disabledOnPlatform indicates whether telemetry is disabled
// due to bugs in the current platform.
const disabledOnPlatform = false ||
	// The following platforms could potentially be supported in the future:
	runtime.GOOS == "openbsd" || // #60614
	runtime.GOOS == "solaris" || // #60968 #60970
	runtime.GOOS == "android" || // #60967
	runtime.GOOS == "illumos" || // #65544
	// These platforms fundamentally can't be supported:
	runtime.GOOS == "js" || // #60971
	runtime.GOOS == "wasip1" || // #60971
	runtime.GOOS == "plan9" // https://github.com/golang/go/issues/57540#issuecomment-1470766639
```