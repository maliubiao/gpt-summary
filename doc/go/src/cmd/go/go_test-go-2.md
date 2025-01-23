Response:
My goal is to analyze the provided Go code snippet from `go/src/cmd/go/go_test.go` and explain its functionalities, potential Go feature implementations, and common pitfalls.

Here's a breakdown of the thinking process:

1. **Understand the Context:** The file `go_test.go` suggests these are integration tests for the `go` command. Each function starting with `Test` likely tests a specific aspect of the `go` command's behavior.

2. **Analyze Individual Test Functions:** I'll go through each `Test...` function, understanding its purpose based on its name and the actions within.

3. **Identify Potential Go Features:** Based on the test names and code, I can infer which Go features are being tested. Keywords like "cache," "coverage," "install," "build," "test," "vet," "cgo," and "linker" are strong indicators.

4. **Code Examples (if applicable):** When a test seems to be verifying a specific feature, I'll try to construct a simple Go code example to illustrate that feature.

5. **Command-Line Argument Analysis:** I'll look for how the tests use the `tg.run` function, which executes `go` commands. The arguments passed to `tg.run` will reveal which command-line flags are being tested.

6. **Input/Output Reasoning:** For tests involving code compilation or execution, I'll analyze the `tg.tempFile` content as input and the `tg.grepStdout`, `tg.grepStderr` assertions as expected output. I'll also consider scenarios where the output should *not* contain certain patterns (`tg.grepStdoutNot`, `tg.grepStderrNot`).

7. **Common Pitfalls:** I'll consider what developers might do incorrectly when using the features being tested, drawing on my knowledge of Go development.

8. **Synthesize and Categorize:** After analyzing each function, I'll group them based on the core functionality they are testing. This helps in summarizing the overall purpose of the code snippet.

**Detailed Analysis of Each Function (leading to the summary):**

* **`TestUpx`**:  Clearly tests the `upx` compression tool's interaction with Go binaries. It executes `upx` and checks the output of the compressed binary.
* **`TestCacheListStale`**: Focuses on the build cache and how `go list` reports staleness. It creates dependencies and checks the `Stale` field in the `go list` output.
* **`TestCacheCoverage`**: Checks the interaction of the build cache with code coverage (`-cover`).
* **`TestIssue22588`**: Addresses a specific bug related to staleness reporting when using `-toolexec`.
* **`TestIssue22531`**: Another bug fix test, this time concerning incorrect staleness reporting after installing a package when the main package's build ID changes.
* **`TestIssue22596`**: Tests the scenario where copying a built binary between different `$GOPATH` environments should result in the target being marked as stale due to a build ID mismatch.
* **`TestTestCache`**:  Extensively tests the build caching mechanism for test packages. It covers scenarios like no changes, comment changes, and actual code changes to verify correct caching behavior.
* **`TestTestSkipVetAfterFailedBuild`**: Checks that `go test` skips `go vet` if the build fails.
* **`TestTestVetRebuild`**: Tests a scenario with `go vet` involving cross-package dependencies and method augmentation.
* **`TestInstallDeps`**: Verifies that `go install` only installs the target package and not its dependencies by default.
* **`TestImportPath`**: Tests the handling of import paths with version suffixes.
* **`TestBadCommandLines`**: Focuses on validating command-line arguments and file/directory names to prevent issues.
* **`TestTwoPkgConfigs`**: Specifically tests how `go build` handles multiple `#cgo pkg-config` directives.
* **`TestCgoCache`**: Tests the build cache in the context of Cgo, ensuring that changes in Cgo flags trigger rebuilds.
* **`TestFilepathUnderCwdFormat`**: A bug fix test for how file paths are formatted in the `-x` output during testing.
* **`TestDontReportRemoveOfEmptyDir`**: Checks that `go install` doesn't produce unnecessary output when removing empty directories.
* **`TestLinkerTmpDirIsDeleted`**: Tests that the temporary directory created by the linker is properly cleaned up after the linking process.
* **`TestCoverpkgTestOnly`**: Tests the `-coverpkg` flag to ensure coverage is correctly calculated for specified packages during testing.
* **`TestExecInDeletedDir`**: A platform-specific test to ensure `go version` doesn't crash when executed in a deleted directory.

**Summarization:** After reviewing each test, I can categorize them:

* **Build Cache Verification:** Several tests (`TestCacheListStale`, `TestCacheCoverage`, `TestTestCache`, `TestCgoCache`) directly focus on the behavior of the Go build cache.
* **`go install` Functionality:** `TestInstallDeps` and parts of other tests examine how `go install` works, including dependency handling.
* **`go test` Functionality:**  Tests like `TestTestCache`, `TestTestSkipVetAfterFailedBuild`, `TestTestVetRebuild`, and `TestCoverpkgTestOnly` validate various aspects of the `go test` command.
* **Error Handling and Input Validation:** `TestBadCommandLines` checks for proper handling of invalid inputs.
* **Specific Bug Fixes:**  Tests named `TestIssue...` are regression tests for previously identified bugs.
* **Cgo Integration:** `TestTwoPkgConfigs`, `TestCgoCache`, and `TestLinkerTmpDirIsDeleted` specifically test interactions with Cgo.
* **Output Formatting:** `TestFilepathUnderCwdFormat` focuses on the format of command output.
* **Edge Cases/System Interaction:** `TestUpx` and `TestExecInDeletedDir` cover less common scenarios.

By grouping the functionalities, I arrive at a concise summary of the code's purpose.
这是 `go/src/cmd/go/go_test.go` 文件的一部分，它主要包含了对 `go` 命令的各种功能的集成测试。 这部分代码延续了前两部分的主题，继续测试 `go` 命令的各种场景，特别是与构建缓存、测试、安装以及错误处理相关的方面。

**主要功能归纳:**

这部分代码主要测试了 `go` 命令的以下功能：

1. **与 UPX 压缩工具的集成:** 测试使用 UPX 压缩 Go 二进制文件后的行为，验证压缩后的程序仍然能正常运行并输出正确的结果。
2. **构建缓存 (Build Cache) 的状态 (`go list -f '{{.ImportPath}} {{.Stale}}'`):**  测试 `go list` 命令在查询包的状态时，能否正确报告包是否需要重新构建（stale）。 这涉及到依赖关系变化后，缓存的更新和状态判断。
3. **代码覆盖率 (Code Coverage) 与构建缓存的交互 (`go test -cover`):** 测试启用代码覆盖率时，构建缓存是否能正确工作，避免不必要的重新编译和链接。
4. **`-toolexec` 参数对构建缓存状态的影响 (`go list -toolexec=/usr/bin/time`)**:  测试使用 `-toolexec` 参数执行构建工具时，是否会错误地报告包的状态。
5. **安装 (Install) 命令的行为和构建缓存的关联 (`go install`):** 测试 `go install` 命令是否正确地安装了目标包，以及构建缓存是否在安装后正确地标记了包的状态。
6. **构建 ID (Build ID) 的管理和缓存失效:** 测试当不同 `$GOPATH` 下存在相同包名但内容不同的包时，复制已构建的二进制文件到另一个 `$GOPATH` 后，构建系统是否能识别出构建 ID 的不匹配，并正确地标记为需要重新构建。
7. **测试缓存 (Test Cache) 的细致行为 (`go test`):** 这是测试的重点部分，涵盖了多种场景，包括：
    * 初次运行测试和后续重复运行测试，验证测试结果的缓存机制。
    * 修改代码注释但不影响编译结果时，缓存的行为。
    * 修改包的代码，观察依赖该包的测试的缓存和重新运行情况。
    * 验证依赖没有修改的包的测试是否被正确地缓存。
8. **在构建失败后跳过 `go vet` (`go test`):** 测试当构建过程失败时，`go test` 命令是否会跳过 `go vet` 步骤。
9. **`go vet` 的重新构建 (`go vet`):** 测试 `go vet` 在特定依赖关系下的正确行为，避免因不正确的依赖传递导致 `go vet` 看到未预期的代码状态。
10. **`go install` 命令的依赖处理:** 测试 `go install` 命令是否默认只安装目标包，而不安装其依赖包。
11. **包含版本号的导入路径 (`go build a`):** 测试 `go build` 命令是否能正确处理包含版本号的导入路径。
12. **对非法命令行参数和文件名的处理 (`go build x/@y.go`):** 测试 `go` 命令能否正确识别并拒绝非法的命令行参数和文件名。
13. **处理多个 `pkg-config` 指令 (`go build x`):** 测试 `go build` 命令在 CGO 环境下，能否正确处理多个 `#cgo pkg-config` 指令。
14. **CGO 缓存 (`go build x`):** 测试在 CGO 环境下，构建缓存是否能正确工作，即使 `CGO_LDFLAGS` 等环境变量发生变化。
15. **`-x` 输出中文件路径的格式 (`go test -x -cover log`):** 测试 `-x` 参数输出的详细构建信息中，文件路径的格式是否正确。
16. **避免报告删除空目录 (`go install -x a`):** 测试 `go install -x` 命令在重复安装已安装的包时，是否会避免输出删除空目录的冗余信息。
17. **链接器临时目录的删除 (`go build -ldflags -v -o /dev/null a.go`):** 测试链接器创建的临时目录在链接过程结束后是否被正确删除。
18. **`-coverpkg` 参数的测试 (`go test -coverpkg=a atest`):** 测试 `-coverpkg` 参数是否能正确指定需要进行覆盖率分析的包。
19. **在已删除的目录下执行 `go version` (`go version`):** 测试在 Linux 等系统上，当工作目录被删除后，执行 `go version` 命令是否会崩溃。

**如果你能推理出它是什么go语言功能的实现，请用go代码举例说明:**

这部分代码主要测试的是 Go 命令本身的功能，而不是具体的 Go 语言特性。然而，通过测试可以推断出一些 Go 语言底层机制的实现，例如：

* **构建缓存:**  通过测试可以推断出 Go 构建系统会记录编译和链接的中间产物，并根据文件内容、时间戳、以及构建配置等信息来判断是否需要重新构建。

   ```go
   // 假设 p.go 被编译成 p.o 并缓存
   // 当 p.go 没有修改时，再次构建不会重新编译
   // go build main.go  // 如果 main.go 依赖 p，且 p 没有变化，会直接使用缓存的 p.o
   ```

* **代码覆盖率:**  测试表明 Go 的测试工具可以生成代码覆盖率报告，这通常是通过在编译后的代码中插入额外的指令来实现的，用于记录哪些代码被执行。

   ```go
   // 运行测试并生成覆盖率报告
   // go test -coverprofile=coverage.out ./...
   // go tool cover -html=coverage.out
   ```

* **`go vet`:** 测试表明 Go 提供了一个静态代码分析工具 `go vet`，用于检查代码中潜在的错误。

   ```go
   // 运行 go vet 分析代码
   // go vet ./...
   ```

**如果涉及代码推理，需要带上假设的输入与输出:**

例如 `TestCacheListStale`：

**假设输入:**

* `gopath/src/p/p.go`:
  ```go
  package p; import _ "q"; func F(){}
  ```
* `gopath/src/q/q.go`:
  ```go
  package q; func F(){}
  ```
* `gopath/src/m/m.go`:
  ```go
  package main; import _ "q"; func main(){}
  ```

**执行命令:**

1. `go install p m`
2. `go list -f='{{.ImportPath}} {{.Stale}}' m q p`

**预期输出:**

```
m false
q true
p false
```

**推理:**

* 安装 `p` 和 `m` 后，`p` 和 `m` 自身以及它们的直接依赖（在这个例子中是空的或者标准库）会被编译并缓存。
* `q` 是 `p` 的依赖，但不是 `m` 的直接依赖，在安装 `m` 时也会被编译并缓存。
* 当执行 `go list` 时，由于 `q` 的构建时间早于 `m` 的构建时间（假设），并且 `m` 依赖于 `q`，所以 `q` 会被标记为 `true` (stale)，表示如果只重新构建 `m`，可能需要重新考虑 `q` 的状态。 `p` 和 `m` 本身在安装后是最新的，所以是 `false`。

**如果涉及命令行参数的具体处理，请详细介绍一下:**

这部分代码大量测试了各种 `go` 命令的命令行参数，例如：

* **`-x`:**  用于打印执行的外部命令，帮助调试构建过程。例如 `tg.run("install", "-x", "m")` 会显示安装 `m` 时执行的编译、链接等命令。
* **`-v`:**  通常用于更详细的输出，例如在 `go test` 中显示测试用例的名称和结果。
* **`-cover`:**  启用代码覆盖率分析。
* **`-coverpkg`:**  指定需要进行覆盖率分析的包。
* **`-f`:**  用于自定义 `go list` 命令的输出格式。例如 `"-f='{{.ImportPath}} {{.Stale}}'"` 指定输出导入路径和是否过时。
* **`-toolexec`:**  指定一个程序来执行构建工具。
* **`-ldflags`:**  传递链接器标志。
* **`-gcflags` / `-gccgoflags`:**  传递编译器标志。
* **`-o`:**  指定输出文件的名称。
* **`-short`:**  在 `go test` 中跳过标记为 long 的测试。

测试代码会构造不同的命令行参数组合，并验证 `go` 命令的预期行为。

**如果有哪些使用者易犯错的点，请举例说明:**

* **对构建缓存的误解:** 用户可能会错误地认为修改了注释或不影响二进制输出的代码后，所有依赖的包都会被重新编译和测试。实际上，Go 的构建缓存会避免不必要的重复工作。
    * **例子:** 修改了 `p1.go` 的注释，但期望 `t1_test.go` (只 import testing) 会被重新编译和运行，但实际上由于 `t1_test.go` 不依赖 `p1` 的具体实现，所以会被缓存。
* **`-coverpkg` 的使用:** 用户可能会错误地指定了 `-coverpkg`，导致覆盖率报告不包含预期的包，或者出现 "no packages being tested depend on matches" 的错误。
    * **例子:**  只想测试 `atest` 包并查看 `a` 包的覆盖率，应该使用 `go test -coverpkg=a atest`。如果错误地使用了其他包名，可能会得不到预期的结果。
* **对 `go install` 的依赖行为的理解:** 用户可能期望 `go install` 会安装目标包的所有依赖，但实际上默认只会安装目标包本身。
    * **例子:** 安装 `main1`，但期望 `p1` 和 `p2` 也被安装到 `$GOPATH/pkg` 目录下，但实际上只有 `main1` 会被安装。

总的来说，这部分代码通过大量的集成测试，确保了 `go` 命令在各种场景下的行为符合预期，并覆盖了一些用户在使用时可能遇到的常见问题。

### 提示词
```
这是路径为go/src/cmd/go/go_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```go
with error %s", err)
	}
	if string(out) != "hello upx" {
		t.Fatalf("bad output from compressed go binary:\ngot %q; want %q", out, "hello upx")
	}
}

var gocacheverify = godebug.New("#gocacheverify")

func TestCacheListStale(t *testing.T) {
	tooSlow(t, "links a binary")
	if gocacheverify.Value() == "1" {
		t.Skip("GODEBUG gocacheverify")
	}

	tg := testgo(t)
	defer tg.cleanup()
	tg.parallel()
	tg.makeTempdir()
	tg.setenv("GOCACHE", tg.path("cache"))
	tg.tempFile("gopath/src/p/p.go", "package p; import _ \"q\"; func F(){}\n")
	tg.tempFile("gopath/src/q/q.go", "package q; func F(){}\n")
	tg.tempFile("gopath/src/m/m.go", "package main; import _ \"q\"; func main(){}\n")

	tg.setenv("GOPATH", tg.path("gopath"))
	tg.run("install", "p", "m")
	tg.run("list", "-f={{.ImportPath}} {{.Stale}}", "m", "q", "p")
	tg.grepStdout("^m false", "m should not be stale")
	tg.grepStdout("^q true", "q should be stale")
	tg.grepStdout("^p false", "p should not be stale")
}

func TestCacheCoverage(t *testing.T) {
	tooSlow(t, "links and runs a test binary with coverage enabled")
	if gocacheverify.Value() == "1" {
		t.Skip("GODEBUG gocacheverify")
	}

	tg := testgo(t)
	defer tg.cleanup()
	tg.parallel()
	tg.setenv("GOPATH", filepath.Join(tg.pwd(), "testdata"))
	tg.makeTempdir()

	tg.setenv("GOCACHE", tg.path("c1"))
	tg.run("test", "-cover", "-short", "strings")
	tg.run("test", "-cover", "-short", "math", "strings")
}

func TestIssue22588(t *testing.T) {
	// Don't get confused by stderr coming from tools.
	tg := testgo(t)
	defer tg.cleanup()
	tg.parallel()

	tg.wantNotStale("runtime", "", "must be non-stale to compare staleness under -toolexec")

	if _, err := os.Stat("/usr/bin/time"); err != nil {
		t.Skip(err)
	}

	tg.run("list", "-f={{.Stale}}", "runtime")
	tg.run("list", "-toolexec=/usr/bin/time", "-f={{.Stale}}", "runtime")
	tg.grepStdout("false", "incorrectly reported runtime as stale")
}

func TestIssue22531(t *testing.T) {
	tooSlow(t, "links binaries")
	if gocacheverify.Value() == "1" {
		t.Skip("GODEBUG gocacheverify")
	}

	tg := testgo(t)
	defer tg.cleanup()
	tg.parallel()
	tg.makeTempdir()
	tg.setenv("GOPATH", tg.tempdir)
	tg.setenv("GOCACHE", tg.path("cache"))
	tg.tempFile("src/m/main.go", "package main /* c1 */; func main() {}\n")
	tg.run("install", "-x", "m")
	tg.run("list", "-f", "{{.Stale}}", "m")
	tg.grepStdout("false", "reported m as stale after install")
	tg.run("tool", "buildid", tg.path("bin/m"+exeSuffix))

	// The link action ID did not include the full main build ID,
	// even though the full main build ID is written into the
	// eventual binary. That caused the following install to
	// be a no-op, thinking the gofmt binary was up-to-date,
	// even though .Stale could see it was not.
	tg.tempFile("src/m/main.go", "package main /* c2 */; func main() {}\n")
	tg.run("install", "-x", "m")
	tg.run("list", "-f", "{{.Stale}}", "m")
	tg.grepStdout("false", "reported m as stale after reinstall")
	tg.run("tool", "buildid", tg.path("bin/m"+exeSuffix))
}

func TestIssue22596(t *testing.T) {
	tooSlow(t, "links binaries")
	if gocacheverify.Value() == "1" {
		t.Skip("GODEBUG gocacheverify")
	}

	tg := testgo(t)
	defer tg.cleanup()
	tg.parallel()
	tg.makeTempdir()
	tg.setenv("GOCACHE", tg.path("cache"))
	tg.tempFile("gopath1/src/p/p.go", "package p; func F(){}\n")
	tg.tempFile("gopath2/src/p/p.go", "package p; func F(){}\n")

	tg.setenv("GOPATH", tg.path("gopath1"))
	tg.run("list", "-f={{.Target}}", "p")
	target1 := strings.TrimSpace(tg.getStdout())
	tg.run("install", "p")
	tg.wantNotStale("p", "", "p stale after install")

	tg.setenv("GOPATH", tg.path("gopath2"))
	tg.run("list", "-f={{.Target}}", "p")
	target2 := strings.TrimSpace(tg.getStdout())
	tg.must(os.MkdirAll(filepath.Dir(target2), 0777))
	tg.must(copyFile(target1, target2, 0666))
	tg.wantStale("p", "build ID mismatch", "p not stale after copy from gopath1")
	tg.run("install", "p")
	tg.wantNotStale("p", "", "p stale after install2")
}

func TestTestCache(t *testing.T) {
	tooSlow(t, "links and runs test binaries")
	if gocacheverify.Value() == "1" {
		t.Skip("GODEBUG gocacheverify")
	}

	tg := testgo(t)
	defer tg.cleanup()
	tg.parallel()
	tg.makeTempdir()
	tg.setenv("GOPATH", tg.tempdir)
	tg.setenv("GOCACHE", tg.path("cache"))

	// The -p=1 in the commands below just makes the -x output easier to read.

	t.Log("\n\nINITIAL\n\n")

	tg.tempFile("src/p1/p1.go", "package p1\nvar X =  1\n")
	tg.tempFile("src/p2/p2.go", "package p2\nimport _ \"p1\"\nvar X = 1\n")
	tg.tempFile("src/t/t1/t1_test.go", "package t\nimport \"testing\"\nfunc Test1(*testing.T) {}\n")
	tg.tempFile("src/t/t2/t2_test.go", "package t\nimport _ \"p1\"\nimport \"testing\"\nfunc Test2(*testing.T) {}\n")
	tg.tempFile("src/t/t3/t3_test.go", "package t\nimport \"p1\"\nimport \"testing\"\nfunc Test3(t *testing.T) {t.Log(p1.X)}\n")
	tg.tempFile("src/t/t4/t4_test.go", "package t\nimport \"p2\"\nimport \"testing\"\nfunc Test4(t *testing.T) {t.Log(p2.X)}")
	tg.run("test", "-x", "-v", "-short", "t/...")

	t.Log("\n\nREPEAT\n\n")

	tg.run("test", "-x", "-v", "-short", "t/...")
	tg.grepStdout(`ok  \tt/t1\t\(cached\)`, "did not cache t1")
	tg.grepStdout(`ok  \tt/t2\t\(cached\)`, "did not cache t2")
	tg.grepStdout(`ok  \tt/t3\t\(cached\)`, "did not cache t3")
	tg.grepStdout(`ok  \tt/t4\t\(cached\)`, "did not cache t4")
	tg.grepStderrNot(`[\\/](compile|gccgo) `, "incorrectly ran compiler")
	tg.grepStderrNot(`[\\/](link|gccgo) `, "incorrectly ran linker")
	tg.grepStderrNot(`p[0-9]\.test`, "incorrectly ran test")

	t.Log("\n\nCOMMENT\n\n")

	// Changing the program text without affecting the compiled package
	// should result in the package being rebuilt but nothing more.
	tg.tempFile("src/p1/p1.go", "package p1\nvar X = 01\n")
	tg.run("test", "-p=1", "-x", "-v", "-short", "t/...")
	tg.grepStdout(`ok  \tt/t1\t\(cached\)`, "did not cache t1")
	tg.grepStdout(`ok  \tt/t2\t\(cached\)`, "did not cache t2")
	tg.grepStdout(`ok  \tt/t3\t\(cached\)`, "did not cache t3")
	tg.grepStdout(`ok  \tt/t4\t\(cached\)`, "did not cache t4")
	tg.grepStderrNot(`([\\/](compile|gccgo) ).*t[0-9]_test\.go`, "incorrectly ran compiler")
	tg.grepStderrNot(`[\\/](link|gccgo) `, "incorrectly ran linker")
	tg.grepStderrNot(`t[0-9]\.test.*test\.short`, "incorrectly ran test")

	t.Log("\n\nCHANGE\n\n")

	// Changing the actual package should have limited effects.
	tg.tempFile("src/p1/p1.go", "package p1\nvar X = 02\n")
	tg.run("test", "-p=1", "-x", "-v", "-short", "t/...")

	// p2 should have been rebuilt.
	tg.grepStderr(`([\\/]compile|gccgo).*p2.go`, "did not recompile p2")

	// t1 does not import anything, should not have been rebuilt.
	tg.grepStderrNot(`([\\/]compile|gccgo).*t1_test.go`, "incorrectly recompiled t1")
	tg.grepStderrNot(`([\\/]link|gccgo).*t1_test`, "incorrectly relinked t1_test")
	tg.grepStdout(`ok  \tt/t1\t\(cached\)`, "did not cache t/t1")

	// t2 imports p1 and must be rebuilt and relinked,
	// but the change should not have any effect on the test binary,
	// so the test should not have been rerun.
	tg.grepStderr(`([\\/]compile|gccgo).*t2_test.go`, "did not recompile t2")
	tg.grepStderr(`([\\/]link|gccgo).*t2\.test`, "did not relink t2_test")
	// This check does not currently work with gccgo, as garbage
	// collection of unused variables is not turned on by default.
	if runtime.Compiler != "gccgo" {
		tg.grepStdout(`ok  \tt/t2\t\(cached\)`, "did not cache t/t2")
	}

	// t3 imports p1, and changing X changes t3's test binary.
	tg.grepStderr(`([\\/]compile|gccgo).*t3_test.go`, "did not recompile t3")
	tg.grepStderr(`([\\/]link|gccgo).*t3\.test`, "did not relink t3_test")
	tg.grepStderr(`t3\.test.*-test.short`, "did not rerun t3_test")
	tg.grepStdoutNot(`ok  \tt/t3\t\(cached\)`, "reported cached t3_test result")

	// t4 imports p2, but p2 did not change, so t4 should be relinked, not recompiled,
	// and not rerun.
	tg.grepStderrNot(`([\\/]compile|gccgo).*t4_test.go`, "incorrectly recompiled t4")
	tg.grepStderr(`([\\/]link|gccgo).*t4\.test`, "did not relink t4_test")
	// This check does not currently work with gccgo, as garbage
	// collection of unused variables is not turned on by default.
	if runtime.Compiler != "gccgo" {
		tg.grepStdout(`ok  \tt/t4\t\(cached\)`, "did not cache t/t4")
	}
}

func TestTestSkipVetAfterFailedBuild(t *testing.T) {
	tg := testgo(t)
	defer tg.cleanup()
	tg.parallel()

	tg.tempFile("x_test.go", `package x
		func f() {
			return 1
		}
	`)

	tg.runFail("test", tg.path("x_test.go"))
	tg.grepStderrNot(`vet`, "vet should be skipped after the failed build")
}

func TestTestVetRebuild(t *testing.T) {
	tooSlow(t, "links and runs test binaries")

	tg := testgo(t)
	defer tg.cleanup()
	tg.parallel()

	// golang.org/issue/23701.
	// b_test imports b with augmented method from export_test.go.
	// b_test also imports a, which imports b.
	// Must not accidentally see un-augmented b propagate through a to b_test.
	tg.tempFile("src/a/a.go", `package a
		import "b"
		type Type struct{}
		func (*Type) M() b.T {return 0}
	`)
	tg.tempFile("src/b/b.go", `package b
		type T int
		type I interface {M() T}
	`)
	tg.tempFile("src/b/export_test.go", `package b
		func (*T) Method() *T { return nil }
	`)
	tg.tempFile("src/b/b_test.go", `package b_test
		import (
			"testing"
			"a"
			. "b"
		)
		func TestBroken(t *testing.T) {
			x := new(T)
			x.Method()
			_ = new(a.Type)
		}
	`)

	tg.setenv("GOPATH", tg.path("."))
	tg.run("test", "b")
	tg.run("vet", "b")
}

func TestInstallDeps(t *testing.T) {
	tooSlow(t, "links a binary")

	tg := testgo(t)
	defer tg.cleanup()
	tg.parallel()
	tg.makeTempdir()
	tg.setenv("GOPATH", tg.tempdir)

	tg.tempFile("src/p1/p1.go", "package p1\nvar X =  1\n")
	tg.tempFile("src/p2/p2.go", "package p2\nimport _ \"p1\"\n")
	tg.tempFile("src/main1/main.go", "package main\nimport _ \"p2\"\nfunc main() {}\n")

	tg.run("list", "-f={{.Target}}", "p1")
	p1 := strings.TrimSpace(tg.getStdout())
	tg.run("list", "-f={{.Target}}", "p2")
	p2 := strings.TrimSpace(tg.getStdout())
	tg.run("list", "-f={{.Target}}", "main1")
	main1 := strings.TrimSpace(tg.getStdout())

	tg.run("install", "main1")

	tg.mustExist(main1)
	tg.mustNotExist(p2)
	tg.mustNotExist(p1)

	tg.run("install", "p2")
	tg.mustExist(p2)
	tg.mustNotExist(p1)
}

// Issue 22986.
func TestImportPath(t *testing.T) {
	tooSlow(t, "links and runs a test binary")

	tg := testgo(t)
	defer tg.cleanup()
	tg.parallel()

	tg.tempFile("src/a/a.go", `
package main

import (
	"log"
	p "a/p-1.0"
)

func main() {
	if !p.V {
		log.Fatal("false")
	}
}`)

	tg.tempFile("src/a/a_test.go", `
package main_test

import (
	p "a/p-1.0"
	"testing"
)

func TestV(t *testing.T) {
	if !p.V {
		t.Fatal("false")
	}
}`)

	tg.tempFile("src/a/p-1.0/p.go", `
package p

var V = true

func init() {}
`)

	tg.setenv("GOPATH", tg.path("."))
	tg.run("build", "-o", tg.path("a.exe"), "a")
	tg.run("test", "a")
}

func TestBadCommandLines(t *testing.T) {
	tg := testgo(t)
	defer tg.cleanup()
	tg.parallel()

	tg.tempFile("src/x/x.go", "package x\n")
	tg.setenv("GOPATH", tg.path("."))

	tg.run("build", "x")

	tg.tempFile("src/x/@y.go", "package x\n")
	tg.runFail("build", "x")
	tg.grepStderr("invalid input file name \"@y.go\"", "did not reject @y.go")
	tg.must(os.Remove(tg.path("src/x/@y.go")))

	tg.tempFile("src/x/-y.go", "package x\n")
	tg.runFail("build", "x")
	tg.grepStderr("invalid input file name \"-y.go\"", "did not reject -y.go")
	tg.must(os.Remove(tg.path("src/x/-y.go")))

	if runtime.Compiler == "gccgo" {
		tg.runFail("build", "-gccgoflags=all=@x", "x")
	} else {
		tg.runFail("build", "-gcflags=all=@x", "x")
	}
	tg.grepStderr("invalid command-line argument @x in command", "did not reject @x during exec")

	tg.tempFile("src/@x/x.go", "package x\n")
	tg.setenv("GOPATH", tg.path("."))
	tg.runFail("build", "@x")
	tg.grepStderr("invalid input directory name \"@x\"|can only use path@version syntax with 'go get' and 'go install' in module-aware mode", "did not reject @x directory")

	tg.tempFile("src/@x/y/y.go", "package y\n")
	tg.setenv("GOPATH", tg.path("."))
	tg.runFail("build", "@x/y")
	tg.grepStderr("invalid import path \"@x/y\"|can only use path@version syntax with 'go get' and 'go install' in module-aware mode", "did not reject @x/y import path")

	tg.tempFile("src/-x/x.go", "package x\n")
	tg.setenv("GOPATH", tg.path("."))
	tg.runFail("build", "--", "-x")
	tg.grepStderr("invalid import path \"-x\"", "did not reject -x import path")

	tg.tempFile("src/-x/y/y.go", "package y\n")
	tg.setenv("GOPATH", tg.path("."))
	tg.runFail("build", "--", "-x/y")
	tg.grepStderr("invalid import path \"-x/y\"", "did not reject -x/y import path")
}

func TestTwoPkgConfigs(t *testing.T) {
	testenv.MustHaveCGO(t)
	if runtime.GOOS == "windows" || runtime.GOOS == "plan9" {
		t.Skipf("no shell scripts on %s", runtime.GOOS)
	}
	tooSlow(t, "builds a package with cgo dependencies")

	tg := testgo(t)
	defer tg.cleanup()
	tg.parallel()
	tg.tempFile("src/x/a.go", `package x
		// #cgo pkg-config: --static a
		import "C"
	`)
	tg.tempFile("src/x/b.go", `package x
		// #cgo pkg-config: --static a
		import "C"
	`)
	tg.tempFile("pkg-config.sh", `#!/bin/sh
echo $* >>`+tg.path("pkg-config.out"))
	tg.must(os.Chmod(tg.path("pkg-config.sh"), 0755))
	tg.setenv("GOPATH", tg.path("."))
	tg.setenv("PKG_CONFIG", tg.path("pkg-config.sh"))
	tg.run("build", "x")
	out, err := os.ReadFile(tg.path("pkg-config.out"))
	tg.must(err)
	out = bytes.TrimSpace(out)
	want := "--cflags --static --static -- a a\n--libs --static --static -- a a"
	if !bytes.Equal(out, []byte(want)) {
		t.Errorf("got %q want %q", out, want)
	}
}

func TestCgoCache(t *testing.T) {
	testenv.MustHaveCGO(t)
	tooSlow(t, "builds a package with cgo dependencies")

	tg := testgo(t)
	defer tg.cleanup()
	tg.parallel()
	tg.tempFile("src/x/a.go", `package main
		// #ifndef VAL
		// #define VAL 0
		// #endif
		// int val = VAL;
		import "C"
		import "fmt"
		func main() { fmt.Println(C.val) }
	`)
	tg.setenv("GOPATH", tg.path("."))
	exe := tg.path("x.exe")
	tg.run("build", "-o", exe, "x")
	tg.setenv("CGO_LDFLAGS", "-lnosuchlibraryexists")
	tg.runFail("build", "-o", exe, "x")
	tg.grepStderr(`nosuchlibraryexists`, "did not run linker with changed CGO_LDFLAGS")
}

// Issue 23982
func TestFilepathUnderCwdFormat(t *testing.T) {
	tg := testgo(t)
	defer tg.cleanup()
	tg.parallel()
	tg.run("test", "-x", "-cover", "log")
	tg.grepStderrNot(`\.log\.cover\.go`, "-x output should contain correctly formatted filepath under cwd")
}

// Issue 24396.
func TestDontReportRemoveOfEmptyDir(t *testing.T) {
	tg := testgo(t)
	defer tg.cleanup()
	tg.parallel()
	tg.tempFile("src/a/a.go", `package a`)
	tg.setenv("GOPATH", tg.path("."))
	tg.run("install", "-x", "a")
	tg.run("install", "-x", "a")
	// The second install should have printed only a WORK= line,
	// nothing else.
	if bytes.Count(tg.stdout.Bytes(), []byte{'\n'})+bytes.Count(tg.stderr.Bytes(), []byte{'\n'}) > 1 {
		t.Error("unnecessary output when installing installed package")
	}
}

// Issue 24704.
func TestLinkerTmpDirIsDeleted(t *testing.T) {
	skipIfGccgo(t, "gccgo does not use cmd/link")
	testenv.MustHaveCGO(t)
	tooSlow(t, "builds a package with cgo dependencies")

	tg := testgo(t)
	defer tg.cleanup()
	tg.parallel()
	tg.tempFile("a.go", `package main; import "C"; func main() {}`)
	tg.run("build", "-ldflags", "-v", "-o", os.DevNull, tg.path("a.go"))
	// Find line that has "host link:" in linker output.
	stderr := tg.getStderr()
	var hostLinkLine string
	for _, line := range strings.Split(stderr, "\n") {
		if !strings.Contains(line, "host link:") {
			continue
		}
		hostLinkLine = line
		break
	}
	if hostLinkLine == "" {
		t.Fatal(`fail to find with "host link:" string in linker output`)
	}
	// Find parameter, like "/tmp/go-link-408556474/go.o" inside of
	// "host link:" line, and extract temp directory /tmp/go-link-408556474
	// out of it.
	tmpdir := hostLinkLine
	i := strings.Index(tmpdir, `go.o"`)
	if i == -1 {
		t.Fatalf(`fail to find "go.o" in "host link:" line %q`, hostLinkLine)
	}
	tmpdir = tmpdir[:i-1]
	i = strings.LastIndex(tmpdir, `"`)
	if i == -1 {
		t.Fatalf(`fail to find " in "host link:" line %q`, hostLinkLine)
	}
	tmpdir = tmpdir[i+1:]
	// Verify that temp directory has been removed.
	_, err := os.Stat(tmpdir)
	if err == nil {
		t.Fatalf("temp directory %q has not been removed", tmpdir)
	}
	if !os.IsNotExist(err) {
		t.Fatalf("Stat(%q) returns unexpected error: %v", tmpdir, err)
	}
}

// Issue 25093.
func TestCoverpkgTestOnly(t *testing.T) {
	skipIfGccgo(t, "gccgo has no cover tool")
	tooSlow(t, "links and runs a test binary with coverage enabled")

	tg := testgo(t)
	defer tg.cleanup()
	tg.parallel()
	tg.tempFile("src/a/a.go", `package a
		func F(i int) int {
			return i*i
		}`)
	tg.tempFile("src/atest/a_test.go", `
		package a_test
		import ( "a"; "testing" )
		func TestF(t *testing.T) { a.F(2) }
	`)
	tg.setenv("GOPATH", tg.path("."))
	tg.run("test", "-coverpkg=a", "atest")
	tg.grepStderrNot("no packages being tested depend on matches", "bad match message")
	tg.grepStdout("coverage: 100", "no coverage")
}

// Regression test for golang.org/issue/34499: version command should not crash
// when executed in a deleted directory on Linux.
func TestExecInDeletedDir(t *testing.T) {
	switch runtime.GOOS {
	case "windows", "plan9",
		"aix",                // Fails with "device busy".
		"solaris", "illumos": // Fails with "invalid argument".
		t.Skipf("%v does not support removing the current working directory", runtime.GOOS)
	}
	tg := testgo(t)
	defer tg.cleanup()

	tg.makeTempdir()
	t.Chdir(tg.tempdir)

	tg.check(os.Remove(tg.tempdir))

	// `go version` should not fail
	tg.run("version")
}
```