Response: The user wants to understand the functionality of the provided Go code snippet, which is a part of the `go_test.go` file within the `cmd/go` package. This file likely contains integration tests for the `go` command.

I need to analyze each test function in the snippet and:
1. **Identify the functionality being tested.**  This will involve understanding the purpose of the test case.
2. **If possible, deduce the related Go language feature.** This may require knowledge of how the `go` command works and what features it supports.
3. **Provide a Go code example to illustrate the feature.**  This example should be simple and directly demonstrate the functionality.
4. **Explain any command-line arguments involved.**  Focus on how the `go` command is being invoked in the test.
5. **Highlight potential pitfalls for users.** This requires thinking about common mistakes developers might make when using the feature.
6. **Summarize the overall functionality covered in this snippet.**

Let's break down each test function:

*   **`TestUPXCompressed`**: Tests the behavior of Go binaries compressed with UPX.
*   **`TestCacheListStale`**:  Checks the `go list` command's ability to identify stale packages based on the build cache.
*   **`TestCacheCoverage`**: Verifies that code coverage works correctly with the build cache.
*   **`TestIssue22588`**: Addresses a specific bug related to staleness reporting when using `toolexec`.
*   **`TestIssue22531`**: Tests a bug fix related to build IDs and the build cache during `go install`.
*   **`TestIssue22596`**: Examines how the build cache handles packages with the same import path in different GOPATH locations.
*   **`TestTestCache`**: Thoroughly tests the build caching mechanism for test commands, focusing on recompilation and relinking behavior.
*   **`TestTestSkipVetAfterFailedBuild`**: Checks that `go test` skips `go vet` if the build fails.
*   **`TestTestVetRebuild`**:  Tests a scenario involving `go vet` and rebuilding packages with specific import relationships.
*   **`TestInstallDeps`**: Verifies that `go install` correctly handles dependencies.
*   **`TestImportPath`**: Tests the handling of import paths with version suffixes.
*   **`TestBadCommandLines`**: Checks that the `go` command correctly rejects invalid command-line inputs and file/directory names.
*   **`TestTwoPkgConfigs`**: Tests the behavior of `cgo` with multiple `pkg-config` directives.
*   **`TestCgoCache`**: Checks the caching behavior of `cgo` builds.
*   **`TestFilepathUnderCwdFormat`**: Tests the formatting of file paths in the output of `go test -x`.
*   **`TestDontReportRemoveOfEmptyDir`**: Verifies that `go install -x` doesn't report the removal of empty directories unnecessarily.
*   **`TestLinkerTmpDirIsDeleted`**: Checks that the temporary directory used by the linker is deleted after the build.
*   **`TestCoverpkgTestOnly`**: Tests the `coverpkg` flag in `go test` for targeting specific packages for coverage.
*   **`TestExecInDeletedDir`**: Checks that `go version` doesn't crash when executed in a deleted directory.
这是 `go/src/cmd/go/go_test.go` 文件的一部分，主要包含了对 `go` 命令各种功能的集成测试。

以下是对这段代码片段中每个测试函数的功能进行详细解释：

**1. `TestUPXCompressed(t *testing.T)`**

*   **功能:** 测试使用 UPX (Ultimate Packer for eXecutables) 压缩后的 Go 二进制文件的执行情况。
*   **涉及的 Go 语言功能:**  Go 二进制文件的构建和执行。以及对外部工具（UPX）的集成。
*   **代码推理及示例:**
    *   **假设输入:** 已经安装了 UPX，并且有一个简单的 Go 程序 `hello.go`。
    *   **hello.go 内容:**
        ```go
        package main

        import "fmt"

        func main() {
            fmt.Println("hello upx")
        }
        ```
    *   **执行命令:**
        ```bash
        go build -o hello
        upx hello
        ./hello
        ```
    *   **预期输出:** `hello upx`
    *   测试代码会构建一个 Go 二进制文件，然后尝试使用 UPX 进行压缩，最后执行压缩后的二进制文件并验证输出是否正确。
*   **命令行参数:** 没有直接处理命令行参数，但隐含地使用了 `go build` 命令。

**2. `TestCacheListStale(t *testing.T)`**

*   **功能:** 测试 `go list` 命令的 `-f` 选项以及 `{{.Stale}}` 模板，用于检查构建缓存中哪些包是过期的 (stale)。
*   **涉及的 Go 语言功能:** 构建缓存 (`GOCACHE`) 和 `go list` 命令。
*   **代码推理及示例:**
    *   **假设输入:**  创建了三个包 `p`, `q`, `m`，其中 `m` 和 `p` 依赖 `q`。
    *   **执行步骤:**
        1. 安装 `p` 和 `m`。
        2. 使用 `go list -f={{.ImportPath}} {{.Stale}} m q p` 命令查看它们的 staleness 状态。
    *   **预期输出:**
        ```
        m false
        q true
        p false
        ```
    *   `q` 会被标记为 `true` (stale)，因为 `p` 和 `m` 在安装时依赖了旧版本的 `q`。
*   **命令行参数:**
    *   `list`: `go list` 命令。
    *   `-f={{.ImportPath}} {{.Stale}}`:  指定 `go list` 的输出格式，显示导入路径和 staleness 状态。

**3. `TestCacheCoverage(t *testing.T)`**

*   **功能:** 测试在使用代码覆盖率 (`-cover`) 功能时，构建缓存是否能够正确工作。
*   **涉及的 Go 语言功能:** 代码覆盖率 (`go test -cover`) 和构建缓存。
*   **代码推理及示例:**
    *   **假设输入:** `testdata` 目录下包含 `strings` 和 `math` 包的测试文件。
    *   **执行命令:**
        ```bash
        go test -cover -short strings
        go test -cover -short math strings
        ```
    *   测试代码会运行两次 `go test -cover` 命令，第一次只针对 `strings` 包，第二次同时针对 `math` 和 `strings` 包，以验证缓存机制是否能正确处理覆盖率数据的生成。
*   **命令行参数:**
    *   `test`: `go test` 命令。
    *   `-cover`: 启用代码覆盖率。
    *   `-short`:  运行标记为 short 的测试。

**4. `TestIssue22588(t *testing.T)`**

*   **功能:** 解决并测试 Issue 22588，该问题与使用 `-toolexec` 选项时，`go list` 错误地报告 `runtime` 包为 stale 有关。
*   **涉及的 Go 语言功能:** `go list` 命令和 `-toolexec` 选项。
*   **代码推理及示例:**
    *   **假设输入:** 系统安装了 `/usr/bin/time` 工具。
    *   **执行命令:**
        ```bash
        go list -f={{.Stale}} runtime
        go list -toolexec=/usr/bin/time -f={{.Stale}} runtime
        ```
    *   测试代码会分别在不使用和使用 `-toolexec` 的情况下运行 `go list`，并断言 `runtime` 包的 staleness 状态始终为 `false`。
*   **命令行参数:**
    *   `list`: `go list` 命令。
    *   `-f={{.Stale}}`:  指定输出格式。
    *   `-toolexec=/usr/bin/time`: 指定用于执行工具链中其他程序的程序。

**5. `TestIssue22531(t *testing.T)`**

*   **功能:** 解决并测试 Issue 22531，该问题与 `go install` 命令在某些情况下未能正确更新二进制文件，导致后续 `go list` 错误地报告包为 stale 有关。
*   **涉及的 Go 语言功能:** `go install`, `go list`, `go tool buildid` 和构建缓存。
*   **代码推理及示例:**
    *   **假设输入:** 创建一个简单的 `main` 包 `m`。
    *   **执行步骤:**
        1. 首次安装 `m`。
        2. 修改 `m` 的源代码。
        3. 再次安装 `m`。
        4. 使用 `go list` 检查 `m` 的 staleness。
    *   测试代码会验证在重新安装后，`go list` 应该报告 `m` 为 `false` (not stale)。
*   **命令行参数:**
    *   `install`: `go install` 命令。
    *   `list`: `go list` 命令。
    *   `-f`: 指定 `go list` 的输出格式。
    *   `tool buildid`: `go tool buildid` 命令用于查看二进制文件的 build ID。
    *   `-x`: 打印执行的命令。

**6. `TestIssue22596(t *testing.T)`**

*   **功能:** 解决并测试 Issue 22596，该问题涉及到在不同 `GOPATH` 下具有相同导入路径的包，以及构建缓存如何处理这种情况。
*   **涉及的 Go 语言功能:** `GOPATH`, `go list`, `go install` 和构建缓存。
*   **代码推理及示例:**
    *   **假设输入:**  在 `gopath1` 和 `gopath2` 中创建了具有相同导入路径 `p` 的包，但内容相同。
    *   **执行步骤:**
        1. 在 `gopath1` 下安装 `p`。
        2. 将 `gopath1` 下构建的 `p` 的目标文件复制到 `gopath2` 下对应的位置。
        3. 在 `gopath2` 下使用 `go list` 检查 `p` 的 staleness，此时应为 `true`，因为 build ID 不匹配。
        4. 在 `gopath2` 下重新安装 `p`。
        5. 再次检查 staleness，应为 `false`。
*   **命令行参数:**
    *   `list`: `go list` 命令。
    *   `-f={{.Target}}`:  获取构建目标的路径。
    *   `install`: `go install` 命令。

**7. `TestTestCache(t *testing.T)`**

*   **功能:** 详细测试 `go test` 命令的缓存机制，包括初始构建、重复执行、注释修改和代码修改对测试结果的影响。
*   **涉及的 Go 语言功能:** `go test` 命令和构建缓存。
*   **代码推理及示例:**  这个测试用例非常复杂，创建了多个相互依赖的包和测试文件，并模拟了不同的修改场景来验证缓存的行为，例如：
    *   **INITIAL:** 首次运行测试，所有包和测试都需要编译和链接。
    *   **REPEAT:** 再次运行相同的测试，应该从缓存中加载结果，无需重新编译和链接。
    *   **COMMENT:** 修改注释，不影响编译结果，测试应该从缓存加载。
    *   **CHANGE:** 修改代码，会触发依赖的包和测试的重新编译和链接。
*   **命令行参数:**
    *   `test`: `go test` 命令。
    *   `-x`: 打印执行的命令。
    *   `-v`: 显示所有测试的详细输出。
    *   `-short`: 运行标记为 short 的测试。
    *   `-p=1`:  限制并行编译的数量，使输出更易读。

**8. `TestTestSkipVetAfterFailedBuild(t *testing.T)`**

*   **功能:** 测试当 `go test` 因为构建失败而退出时，是否会跳过 `go vet` 的执行。
*   **涉及的 Go 语言功能:** `go test` 命令和 `go vet` 工具。
*   **代码推理及示例:**
    *   **假设输入:** 创建一个包含语法错误的测试文件 `x_test.go`。
    *   **执行命令:** `go test x_test.go`
    *   测试代码会运行 `go test` 并断言标准错误输出中不包含 "vet"，因为构建失败应该阻止 vet 运行。
*   **命令行参数:**
    *   `test`: `go test` 命令。

**9. `TestTestVetRebuild(t *testing.T)`**

*   **功能:** 测试 `go test` 和 `go vet` 在处理包含通过 `export_test.go` 扩展方法的包时的行为，确保 vet 不会使用未扩展的版本。
*   **涉及的 Go 语言功能:** `go test`, `go vet`, `export_test.go`。
*   **代码推理及示例:**  这个测试用例创建了相互依赖的包 `a` 和 `b`，其中 `b` 通过 `export_test.go` 添加了额外的方法，并验证 `go test` 和 `go vet` 在这种情况下能够正确工作。
*   **命令行参数:**
    *   `test`: `go test` 命令。
    *   `vet`: `go vet` 命令。

**10. `TestInstallDeps(t *testing.T)`**

*   **功能:** 测试 `go install` 命令是否只安装目标包，而不安装其依赖包。
*   **涉及的 Go 语言功能:** `go install` 命令。
*   **代码推理及示例:**
    *   **假设输入:** 创建三个包 `p1`, `p2`, `main1`，其中 `main1` 依赖 `p2`，`p2` 依赖 `p1`。
    *   **执行步骤:**
        1. 安装 `main1`。
        2. 验证 `main1` 的目标文件存在，而 `p1` 和 `p2` 的目标文件不存在。
        3. 安装 `p2`。
        4. 验证 `p2` 的目标文件存在，而 `p1` 的目标文件仍然不存在。
*   **命令行参数:**
    *   `install`: `go install` 命令。
    *   `list -f={{.Target}}`: 获取构建目标的路径。

**11. `TestImportPath(t *testing.T)`**

*   **功能:** 测试包含版本后缀的导入路径 (例如 `a/p-1.0`) 的处理。
*   **涉及的 Go 语言功能:** 导入路径，`go build`, `go test`。
*   **代码推理及示例:**  创建了一个包 `a/p-1.0` 和一个主程序 `a`，主程序导入了带版本后缀的包。测试验证构建和测试是否能够成功完成。
*   **命令行参数:**
    *   `build`: `go build` 命令。
    *   `-o`: 指定输出文件名。
    *   `test`: `go test` 命令。

**12. `TestBadCommandLines(t *testing.T)`**

*   **功能:** 测试 `go build` 命令是否能够正确处理各种无效的命令行输入，例如无效的文件名、目录名和参数。
*   **涉及的 Go 语言功能:** `go build` 命令的参数解析和错误处理。
*   **代码推理及示例:**  这个测试用例尝试使用各种非法的文件名 (如 `@y.go`, `-y.go`)、目录名 (如 `@x`) 和命令行参数 (如 `@x` 在 `-gcflags` 中)，并验证 `go build` 是否会报错。
*   **命令行参数:**
    *   `build`: `go build` 命令。
    *   `-gcflags`:  传递给 Go 编译器的参数。
    *   `-gccgoflags`: 传递给 gccgo 编译器的参数。
    *   `--`: 用于分隔 go 命令和后续的参数。

**13. `TestTwoPkgConfigs(t *testing.T)`**

*   **功能:** 测试 `cgo` 在遇到多个 `// #cgo pkg-config:` 指令时的行为，验证 `pkg-config` 命令是否被正确调用。
*   **涉及的 Go 语言功能:** `cgo` 和 `pkg-config`。
*   **代码推理及示例:** 创建了一个包含两个 `// #cgo pkg-config: --static a` 指令的 Go 文件，并设置 `PKG_CONFIG` 环境变量指向一个自定义的 shell 脚本，用于记录 `pkg-config` 的调用参数。测试验证 `pkg-config` 是否被调用了两次，并且参数正确。
*   **命令行参数:**
    *   `build`: `go build` 命令。

**14. `TestCgoCache(t *testing.T)`**

*   **功能:** 测试 `cgo` 构建的缓存机制，验证在 `CGO_LDFLAGS` 改变后，链接器是否会被重新运行。
*   **涉及的 Go 语言功能:** `cgo` 和构建缓存。
*   **代码推理及示例:**  首先构建一个包含 `cgo` 代码的程序，然后修改 `CGO_LDFLAGS` 环境变量并尝试重新构建，验证链接器是否因为 `CGO_LDFLAGS` 的改变而被重新调用。
*   **命令行参数:**
    *   `build`: `go build` 命令。
    *   `-o`: 指定输出文件名。

**15. `TestFilepathUnderCwdFormat(t *testing.T)`**

*   **功能:** 解决并测试 Issue 23982，确保 `go test -x` 的输出中包含相对于当前工作目录的正确格式化的文件路径。
*   **涉及的 Go 语言功能:** `go test -x` 命令。
*   **代码推理及示例:**  运行 `go test -x -cover log` 并验证标准错误输出中不包含类似于 `\.log\.cover\.go` 的错误格式的文件路径。
*   **命令行参数:**
    *   `test`: `go test` 命令。
    *   `-x`: 打印执行的命令。
    *   `-cover`: 启用代码覆盖率。

**16. `TestDontReportRemoveOfEmptyDir(t *testing.T)`**

*   **功能:** 解决并测试 Issue 24396，确保 `go install -x` 在安装已安装的包时，不会报告不必要的删除空目录的信息。
*   **涉及的 Go 语言功能:** `go install -x` 命令。
*   **代码推理及示例:**  连续两次安装同一个包，并验证第二次安装时，标准输出和标准错误输出的行数是否不超过一行 (仅包含 `WORK=` 行)。
*   **命令行参数:**
    *   `install`: `go install` 命令。
    *   `-x`: 打印执行的命令。

**17. `TestLinkerTmpDirIsDeleted(t *testing.T)`**

*   **功能:** 解决并测试 Issue 24704，确保链接器使用的临时目录在链接完成后被删除。
*   **涉及的 Go 语言功能:** `go build` 命令和链接器。
*   **代码推理及示例:**  构建一个包含 `cgo` 代码的程序，并使用 `-ldflags -v` 选项来查看链接器的输出，然后解析链接器输出中的临时目录路径，并验证该目录在构建完成后不存在。
*   **命令行参数:**
    *   `build`: `go build` 命令。
    *   `-ldflags`:  传递给链接器的参数。
    *   `-v`:  打印详细的编译和链接信息。
    *   `-o`: 指定输出文件名。

**18. `TestCoverpkgTestOnly(t *testing.T)`**

*   **功能:** 解决并测试 Issue 25093，验证 `go test -coverpkg` 是否能够正确地只针对指定的包进行覆盖率分析，即使测试包没有直接依赖这些包。
*   **涉及的 Go 语言功能:** `go test -coverpkg` 命令。
*   **代码推理及示例:** 创建了一个包 `a` 和一个测试包 `atest`，`atest` 测试 `a` 的功能，但自身不属于 `a` 包。使用 `go test -coverpkg=a atest` 运行测试，并验证输出了 `a` 包的覆盖率信息。
*   **命令行参数:**
    *   `test`: `go test` 命令。
    *   `-coverpkg`: 指定要进行覆盖率分析的包列表。

**19. `TestExecInDeletedDir(t *testing.T)`**

*   **功能:** 解决并测试 Issue 34499，确保在 Linux 系统上，即使当前工作目录被删除，执行 `go version` 命令也不会崩溃。
*   **涉及的 Go 语言功能:** `go version` 命令。
*   **代码推理及示例:**  创建一个临时目录，将当前工作目录切换到该目录，然后删除该目录，最后执行 `go version` 命令，验证命令是否能正常执行。
*   **命令行参数:**
    *   `version`: `go version` 命令。

**总结归纳:**

这段代码片段主要测试了 `go` 命令的以下核心功能及其在不同场景下的行为：

*   **构建过程:** `go build`, `go install` 的基本功能，包括依赖处理、构建缓存、跨 `GOPATH` 的构建、处理包含版本后缀的导入路径等。
*   **测试框架:** `go test` 的各种选项，包括缓存机制、代码覆盖率、跳过 vet、处理 `export_test.go` 文件等。
*   **列表功能:** `go list` 命令及其用于检查包状态 (如 staleness) 的能力。
*   **Cgo 支持:** `cgo` 与构建缓存的交互，以及与 `pkg-config` 的集成。
*   **错误处理:** 对无效命令行输入和文件名的处理。
*   **工具链集成:**  与外部工具 (如 UPX) 和内部工具 (`go vet`, `go tool buildid`) 的集成。

总而言之，这段代码是 `go` 命令功能的重要集成测试，旨在确保 `go` 命令的各个方面都能够按预期工作，并且修复的 Bug 不会再次出现。

Prompt: 
```
这是路径为go/src/cmd/go/go_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第2部分，共2部分，请归纳一下它的功能

"""
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

"""




```