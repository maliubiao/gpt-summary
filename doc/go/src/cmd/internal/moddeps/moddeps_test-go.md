Response: Let's break down the thought process for analyzing the provided Go code.

**1. Initial Understanding: The Purpose of the File**

The file path `go/src/cmd/internal/moddeps/moddeps_test.go` immediately suggests this is a test file within the Go compiler's source code, specifically for a package related to module dependencies (`moddeps`). The `_test.go` suffix confirms this. The "internal" part implies this isn't meant for external use.

**2. High-Level Overview of the Tests**

A quick scan reveals two main test functions: `TestAllDependencies` and `TestDependencyVersionsConsistent`. This hints at two core areas being tested:

* **`TestAllDependencies`**:  Seems to be about ensuring the integrity of dependencies within the Go standard library (GOROOT). Keywords like "vendored," "tidy," and mentions of `go mod vendor`, `go mod tidy`, and `go generate bundle` point towards testing the module dependency management within the Go core. The distinction between "short mode" and "long mode" suggests different levels of thoroughness in the testing.

* **`TestDependencyVersionsConsistent`**:  The name is quite clear. It focuses on ensuring that when multiple modules within GOROOT depend on the same external module, they all use the *same* version.

**3. Deeper Dive into `TestAllDependencies`**

* **Short Mode:**  The code explicitly states the short mode performs a "limited quick check." It focuses on verifying that dependencies are vendored by running `go list -mod=vendor -deps ./...`. If no `vendor` directory exists, it checks that there are no extraneous dependencies using `go list -mod=readonly -m all`.

* **Long Mode:** This is where things get more interesting. The comments emphasize the need for network access and the `diff` command. The core idea is to create a *copy* of the GOROOT, perform module management operations on the copy, and then compare the copy with the original GOROOT using `diff`. This confirms that the operations (`go mod tidy`, `go mod vendor`, `go generate bundle`) produce the expected outcome without introducing unintended changes.

* **Key Operations:** The long mode explicitly runs `go mod tidy`, `go mod verify`, `go mod vendor`, and `go generate bundle`. This provides strong clues about the functionalities being tested.

* **`makeGOROOTCopy`:**  This function is crucial for the long mode. It explains how a temporary copy of GOROOT is created, with special handling for `.git`, `bin`, and `pkg` directories to optimize the process.

* **Error Handling and Advice:** The test provides helpful error messages and advice on how to fix discrepancies (e.g., running `go mod tidy`, `go mod vendor`).

**4. Deeper Dive into `TestDependencyVersionsConsistent`**

* **Focus on `vendor/modules.txt`:**  The test explicitly reads the `vendor/modules.txt` file to determine dependencies. This is a key insight into how Go manages vendored dependencies.

* **Data Structure `seen`:**  The use of a nested map (`map[string]map[requirement][]gorootModule`) is clever. It groups modules based on their dependencies and tracks which modules require which version of a particular dependency.

* **Consistency Check:** The core logic iterates through the `seen` map and flags errors if multiple different versions of the same dependency are found across different GOROOT modules.

**5. Identifying Supporting Functions**

* **`findGorootModules`:** This function is critical for both tests. It programmatically discovers all the Go modules within the GOROOT directory using `filepath.WalkDir` and `go list -json -m`. It also includes a safeguard by checking for the presence of known core modules.

* **`packagePattern`:** This helper function constructs package patterns used with Go tools. The special handling for the "std" module is noteworthy.

* **`runner`:** This struct simplifies running Go commands within a specific directory and environment, making the test code cleaner.

**6. Reasoning About Go Language Features**

Based on the analysis, the test file is clearly exercising:

* **Go Modules:** The core functionality being tested is Go's module system. This includes vendoring, dependency management, and the `go.mod` and `go.sum` files (though not explicitly manipulated, their correctness is implicitly checked).

* **`go mod tidy`:**  Ensures the `go.mod` file is consistent with the imported packages.

* **`go mod vendor`:** Copies dependencies into the `vendor` directory.

* **`go list`:** Used extensively to inspect module information and dependencies.

* **`go generate`:** Used with the `bundle` command, suggesting a code generation step related to bundling dependencies.

* **File System Operations:**  Creating temporary directories, copying files, walking directories (`filepath.WalkDir`), reading files (`os.ReadFile`), and creating symlinks (`os.Symlink`).

* **Command Execution:** Running external Go commands using `internal/testenv`.

**7. Identifying Potential User Errors (for hypothetical users)**

While this test file is for internal Go development, thinking about potential user errors for *similar* functionality is helpful:

* **Forgetting to run `go mod vendor`:**  If a user manually modifies dependencies but doesn't run `go mod vendor`, their builds might fail in environments without network access.

* **Incorrect `go generate` configuration:**  If the `//go:generate` directives are not set up correctly, the bundling process might fail.

* **Manually editing `vendor` directory:** This is generally discouraged and can lead to inconsistencies.

**8. Structuring the Answer**

Finally, the information needs to be organized logically, starting with a summary of the file's purpose, then detailing the functionalities of each test, providing code examples, explaining command-line arguments (where applicable), and finally listing potential user errors. The use of headings and bullet points enhances readability.
这个`go/src/cmd/internal/moddeps/moddeps_test.go` 文件是 Go 语言源代码的一部分，它包含了对 `cmd/internal/moddeps` 包的测试。从代码内容来看，这个测试文件主要关注 **Go 模块依赖管理** 的相关功能，特别是针对 Go 语言标准库 (GOROOT) 内部模块的依赖一致性和完整性进行验证。

以下是它主要功能的详细列举：

**主要功能：**

1. **`TestAllDependencies` 函数:**
   - **验证 GOROOT 中所有模块的依赖状态是否一致。**  这意味着所有被导入的包都应该在对应的 GOROOT 模块中被 vendor (拷贝到 vendor 目录)。
   - **快速检查模式 (Short mode):**  进行初步的快速检查，不涉及网络访问和 GOROOT 目录的复制。主要检查模块是否包含 `vendor` 目录，以及 `go list -deps` 和 `go list -m all` 命令是否正常工作，以确保依赖被 vendor 或者没有额外的依赖。
   - **完整检查模式 (Long mode):**  需要网络访问和 `diff` 命令。它会创建一个 GOROOT 目录的完整拷贝，并在拷贝的目录中执行模块相关的命令 (如 `go mod tidy`, `go mod vendor`, `go generate bundle`)，然后将修改后的拷贝与原始的 GOROOT 进行比较，以确保模块的整洁性和 vendor 内容的正确性。
   - **测试 `go mod tidy`, `go mod verify`, `go mod vendor`, `go generate bundle` 等命令在 GOROOT 内部模块上的行为和结果。**

2. **`TestDependencyVersionsConsistent` 函数:**
   - **验证 GOROOT 中所有依赖特定外部模块的模块，是否都依赖于该外部模块的相同版本。**  这有助于维护依赖版本的一致性，减少维护负担。它通过解析每个模块 `vendor/modules.txt` 文件来获取依赖信息并进行比较。

**推理其实现的 Go 语言功能：**

这个测试文件主要测试的是 Go 模块系统的相关功能，特别是与 GOROOT 内部模块管理相关的部分。它涵盖了以下 Go 语言功能：

* **Go Modules (`go mod`)**: 这是测试的核心，涉及到模块的声明 (`go.mod`)、依赖管理、vendor 机制等。
* **`go list` 命令**: 用于获取模块的信息，例如模块路径、依赖关系等。测试中使用了 `go list -deps`, `go list -m all`, `go list -json -m` 等不同参数。
* **`go mod tidy` 命令**:  用于清理 `go.mod` 文件，移除未使用的依赖，添加缺失的依赖。
* **`go mod vendor` 命令**: 用于将项目的依赖项复制到项目的 `vendor` 目录中。
* **`go generate` 命令**:  用于执行代码生成。测试中使用了 `go generate -run=bundle`，推测是生成与依赖捆绑相关的代码。
* **`go build` 命令**:  用于构建 Go 程序。测试中用于构建 `golang.org/x/tools/cmd/bundle` 工具。

**Go 代码举例说明:**

假设我们有一个简单的 GOROOT 模块 `mymodule`，它依赖于 `example.com/lib@v1.0.0`。

```go
// go.mod (在 GOROOT/src/mymodule 目录下)
module mymodule

go 1.20

require example.com/lib v1.0.0
```

**`TestAllDependencies` 的测试场景：**

**假设输入 (Long mode):**

1. 存在一个 GOROOT 目录的拷贝，例如 `/tmp/goroot_copy`。
2. `/tmp/goroot_copy/src/mymodule` 目录下有上述 `go.mod` 文件，但 `vendor` 目录为空或者缺失。

**执行的命令：**

```bash
cd /tmp/goroot_copy/src/mymodule
GOROOT=/tmp/goroot_copy PATH=/tmp/goroot_copy/bin:... go mod tidy
GOROOT=/tmp/goroot_copy PATH=/tmp/goroot_copy/bin:... go mod vendor
```

**预期输出:**

1. `go mod tidy` 会更新 `go.mod` 和 `go.sum` 文件（如果需要）。
2. `go mod vendor` 会在 `/tmp/goroot_copy/src/mymodule/vendor` 目录下创建 `example.com/lib` 的源代码。
3. `diff --recursive --unified /tmp/goroot_copy/src/mymodule /actual/goroot/src/mymodule` 命令的输出应该为空，表示拷贝的目录与原始目录一致（在 vendor 之后）。

**`TestDependencyVersionsConsistent` 的测试场景：**

**假设输入:**

1. GOROOT 中存在两个模块 `moduleA` 和 `moduleB`。
2. `moduleA` 的 `vendor/modules.txt` 中包含 `# example.com/common v1.0.0`。
3. `moduleB` 的 `vendor/modules.txt` 中包含 `# example.com/common v1.0.0`。

**测试过程:**

测试会读取 `moduleA` 和 `moduleB` 的 `vendor/modules.txt` 文件，并提取 `example.com/common` 的版本信息。

**预期结果:**

由于两个模块都依赖于 `example.com/common` 的 `v1.0.0` 版本，测试会通过，不会报告错误。

**命令行参数的具体处理：**

测试代码本身并不直接处理命令行参数。它依赖于 `testing` 包提供的机制，例如 `testing.Short()` 来区分短模式和长模式测试。

* **`-short` 标志:**  传递 `-short` 标志给 `go test` 命令会使 `testing.Short()` 返回 `true`，从而执行 `TestAllDependencies` 的快速检查部分。如果不传递 `-short`，则会执行完整的检查部分。

**使用者易犯错的点 (针对类似功能的实现者，而非此测试的使用者):**

1. **没有正确处理 GOROOT 环境变量:**  测试代码中多次使用 `testenv.GOROOT(t)` 获取 GOROOT 路径，并将其设置到子进程的环境变量中。如果一个类似的依赖管理工具没有正确处理 GOROOT，可能会导致在不同的 Go 环境下行为不一致。

2. **忽略 vendor 目录的重要性:** `TestAllDependencies` 强调了 vendor 目录的存在和内容一致性。开发者在构建类似工具时，需要理解 vendor 目录的作用，并确保其内容的正确性。

3. **依赖外部命令 (如 `diff`) 而没有进行可用性检查:**  长模式测试依赖于 `diff` 命令。如果一个类似的工具依赖于外部命令，应该在运行前检查这些命令是否可用，并给出友好的提示。

4. **在测试中修改全局状态:**  `TestAllDependencies` 的长模式通过创建 GOROOT 的拷贝来避免修改原始 GOROOT。在编写类似的测试时，需要注意避免修改全局状态，以确保测试的可重复性和独立性。

总而言之，这个测试文件是 Go 语言模块系统内部工作原理的一个很好的示例，它展示了如何通过自动化测试来保证依赖管理功能的正确性和一致性，特别是在 Go 语言标准库这种关键的场景下。

Prompt: 
```
这是路径为go/src/cmd/internal/moddeps/moddeps_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2020 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package moddeps_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"internal/testenv"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"

	"golang.org/x/mod/module"
)

// TestAllDependencies ensures dependencies of all
// modules in GOROOT are in a consistent state.
//
// In short mode, it does a limited quick check and stops there.
// In long mode, it also makes a copy of the entire GOROOT tree
// and requires network access to perform more thorough checks.
// Keep this distinction in mind when adding new checks.
//
// See issues 36852, 41409, and 43687.
// (Also see golang.org/issue/27348.)
func TestAllDependencies(t *testing.T) {
	goBin := testenv.GoToolPath(t)

	// Ensure that all packages imported within GOROOT
	// are vendored in the corresponding GOROOT module.
	//
	// This property allows offline development within the Go project, and ensures
	// that all dependency changes are presented in the usual code review process.
	//
	// As a quick first-order check, avoid network access and the need to copy the
	// entire GOROOT tree or explicitly invoke version control to check for changes.
	// Just check that packages are vendored. (In non-short mode, we go on to also
	// copy the GOROOT tree and perform more rigorous consistency checks. Jump below
	// for more details.)
	for _, m := range findGorootModules(t) {
		// This short test does NOT ensure that the vendored contents match
		// the unmodified contents of the corresponding dependency versions.
		t.Run(m.Path+"(quick)", func(t *testing.T) {
			t.Logf("module %s in directory %s", m.Path, m.Dir)

			if m.hasVendor {
				// Load all of the packages in the module to ensure that their
				// dependencies are vendored. If any imported package is missing,
				// 'go list -deps' will fail when attempting to load it.
				cmd := testenv.Command(t, goBin, "list", "-mod=vendor", "-deps", "./...")
				cmd.Dir = m.Dir
				cmd.Env = append(cmd.Environ(), "GO111MODULE=on", "GOWORK=off")
				cmd.Stderr = new(strings.Builder)
				_, err := cmd.Output()
				if err != nil {
					t.Errorf("%s: %v\n%s", strings.Join(cmd.Args, " "), err, cmd.Stderr)
					t.Logf("(Run 'go mod vendor' in %s to ensure that dependencies have been vendored.)", m.Dir)
				}
				return
			}

			// There is no vendor directory, so the module must have no dependencies.
			// Check that the list of active modules contains only the main module.
			cmd := testenv.Command(t, goBin, "list", "-mod=readonly", "-m", "all")
			cmd.Dir = m.Dir
			cmd.Env = append(cmd.Environ(), "GO111MODULE=on", "GOWORK=off")
			cmd.Stderr = new(strings.Builder)
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("%s: %v\n%s", strings.Join(cmd.Args, " "), err, cmd.Stderr)
			}
			if strings.TrimSpace(string(out)) != m.Path {
				t.Errorf("'%s' reported active modules other than %s:\n%s", strings.Join(cmd.Args, " "), m.Path, out)
				t.Logf("(Run 'go mod tidy' in %s to ensure that no extraneous dependencies were added, or 'go mod vendor' to copy in imported packages.)", m.Dir)
			}
		})
	}

	// We now get to the slow, but more thorough part of the test.
	// Only run it in long test mode.
	if testing.Short() {
		return
	}

	// Ensure that all modules within GOROOT are tidy, vendored, and bundled.
	// Ensure that the vendored contents match the unmodified contents of the
	// corresponding dependency versions.
	//
	// The non-short section of this test requires network access and the diff
	// command.
	//
	// It makes a temporary copy of the entire GOROOT tree (where it can safely
	// perform operations that may mutate the tree), executes the same module
	// maintenance commands that we expect Go developers to run, and then
	// diffs the potentially modified module copy with the real one in GOROOT.
	// (We could try to rely on Git to do things differently, but that's not the
	// path we've chosen at this time. This allows the test to run when the tree
	// is not checked into Git.)

	testenv.MustHaveExternalNetwork(t)
	if haveDiff := func() bool {
		diff, err := testenv.Command(t, "diff", "--recursive", "--unified", ".", ".").CombinedOutput()
		if err != nil || len(diff) != 0 {
			return false
		}
		diff, err = testenv.Command(t, "diff", "--recursive", "--unified", ".", "..").CombinedOutput()
		if err == nil || len(diff) == 0 {
			return false
		}
		return true
	}(); !haveDiff {
		// For now, the diff command is a mandatory dependency of this test.
		// This test will primarily run on longtest builders, since few people
		// would test the cmd/internal/moddeps package directly, and all.bash
		// runs tests in short mode. It's fine to skip if diff is unavailable.
		t.Skip("skipping because a diff command with support for --recursive and --unified flags is unavailable")
	}

	// We're going to check the standard modules for tidiness, so we need a usable
	// GOMODCACHE. If the default directory doesn't exist, use a temporary
	// directory instead. (That can occur, for example, when running under
	// run.bash with GO_TEST_SHORT=0: run.bash sets GOPATH=/nonexist-gopath, and
	// GO_TEST_SHORT=0 causes it to run this portion of the test.)
	var modcacheEnv []string
	{
		out, err := testenv.Command(t, goBin, "env", "GOMODCACHE").Output()
		if err != nil {
			t.Fatalf("%s env GOMODCACHE: %v", goBin, err)
		}
		modcacheOk := false
		if gomodcache := string(bytes.TrimSpace(out)); gomodcache != "" {
			if _, err := os.Stat(gomodcache); err == nil {
				modcacheOk = true
			}
		}
		if !modcacheOk {
			modcacheEnv = []string{
				"GOMODCACHE=" + t.TempDir(),
				"GOFLAGS=" + os.Getenv("GOFLAGS") + " -modcacherw", // Allow t.TempDir() to clean up subdirectories.
			}
		}
	}

	// Build the bundle binary at the golang.org/x/tools
	// module version specified in GOROOT/src/cmd/go.mod.
	bundleDir := t.TempDir()
	r := runner{
		Dir: filepath.Join(testenv.GOROOT(t), "src/cmd"),
		Env: append(os.Environ(), modcacheEnv...),
	}
	r.run(t, goBin, "build", "-mod=readonly", "-o", bundleDir, "golang.org/x/tools/cmd/bundle")

	var gorootCopyDir string
	for _, m := range findGorootModules(t) {
		// Create a test-wide GOROOT copy. It can be created once
		// and reused between subtests whenever they don't fail.
		//
		// This is a relatively expensive operation, but it's a pre-requisite to
		// be able to safely run commands like "go mod tidy", "go mod vendor", and
		// "go generate" on the GOROOT tree content. Those commands may modify the
		// tree, and we don't want to happen to the real tree as part of executing
		// a test.
		if gorootCopyDir == "" {
			gorootCopyDir = makeGOROOTCopy(t)
		}

		t.Run(m.Path+"(thorough)", func(t *testing.T) {
			t.Logf("module %s in directory %s", m.Path, m.Dir)

			defer func() {
				if t.Failed() {
					// The test failed, which means it's possible the GOROOT copy
					// may have been modified. No choice but to reset it for next
					// module test case. (This is slow, but it happens only during
					// test failures.)
					gorootCopyDir = ""
				}
			}()

			rel, err := filepath.Rel(testenv.GOROOT(t), m.Dir)
			if err != nil {
				t.Fatalf("filepath.Rel(%q, %q): %v", testenv.GOROOT(t), m.Dir, err)
			}
			r := runner{
				Dir: filepath.Join(gorootCopyDir, rel),
				Env: append(append(os.Environ(), modcacheEnv...),
					// Set GOROOT.
					"GOROOT="+gorootCopyDir,
					// Add GOROOTcopy/bin and bundleDir to front of PATH.
					"PATH="+filepath.Join(gorootCopyDir, "bin")+string(filepath.ListSeparator)+
						bundleDir+string(filepath.ListSeparator)+os.Getenv("PATH"),
					"GOWORK=off",
				),
			}
			goBinCopy := filepath.Join(gorootCopyDir, "bin", "go")
			r.run(t, goBinCopy, "mod", "tidy")   // See issue 43687.
			r.run(t, goBinCopy, "mod", "verify") // Verify should be a no-op, but test it just in case.
			r.run(t, goBinCopy, "mod", "vendor") // See issue 36852.
			pkgs := packagePattern(m.Path)
			r.run(t, goBinCopy, "generate", `-run=^//go:generate bundle `, pkgs) // See issue 41409.
			advice := "$ cd " + m.Dir + "\n" +
				"$ go mod tidy                               # to remove extraneous dependencies\n" +
				"$ go mod vendor                             # to vendor dependencies\n" +
				"$ go generate -run=bundle " + pkgs + "               # to regenerate bundled packages\n"
			if m.Path == "std" {
				r.run(t, goBinCopy, "generate", "syscall", "internal/syscall/...") // See issue 43440.
				advice += "$ go generate syscall internal/syscall/...  # to regenerate syscall packages\n"
			}
			// TODO(golang.org/issue/43440): Check anything else influenced by dependency versions.

			diff, err := testenv.Command(t, "diff", "--recursive", "--unified", r.Dir, m.Dir).CombinedOutput()
			if err != nil || len(diff) != 0 {
				t.Errorf(`Module %s in %s is not tidy (-want +got):

%s
To fix it, run:

%s
(If module %[1]s is definitely tidy, this could mean
there's a problem in the go or bundle command.)`, m.Path, m.Dir, diff, advice)
			}
		})
	}
}

// packagePattern returns a package pattern that matches all packages
// in the module modulePath, and ideally as few others as possible.
func packagePattern(modulePath string) string {
	if modulePath == "std" {
		return "std"
	}
	return modulePath + "/..."
}

// makeGOROOTCopy makes a temporary copy of the current GOROOT tree.
// The goal is to allow the calling test t to safely mutate a GOROOT
// copy without also modifying the original GOROOT.
//
// It copies the entire tree as is, with the exception of the GOROOT/.git
// directory, which is skipped, and the GOROOT/{bin,pkg} directories,
// which are symlinked. This is done for speed, since a GOROOT tree is
// functional without being in a Git repository, and bin and pkg are
// deemed safe to share for the purpose of the TestAllDependencies test.
func makeGOROOTCopy(t *testing.T) string {
	t.Helper()

	gorootCopyDir := t.TempDir()
	err := filepath.Walk(testenv.GOROOT(t), func(src string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() && src == filepath.Join(testenv.GOROOT(t), ".git") {
			return filepath.SkipDir
		}

		rel, err := filepath.Rel(testenv.GOROOT(t), src)
		if err != nil {
			return fmt.Errorf("filepath.Rel(%q, %q): %v", testenv.GOROOT(t), src, err)
		}
		dst := filepath.Join(gorootCopyDir, rel)

		if info.IsDir() && (src == filepath.Join(testenv.GOROOT(t), "bin") ||
			src == filepath.Join(testenv.GOROOT(t), "pkg")) {
			// If the OS supports symlinks, use them instead
			// of copying the bin and pkg directories.
			if err := os.Symlink(src, dst); err == nil {
				return filepath.SkipDir
			}
		}

		perm := info.Mode() & os.ModePerm
		if info.Mode()&os.ModeSymlink != 0 {
			info, err = os.Stat(src)
			if err != nil {
				return err
			}
			perm = info.Mode() & os.ModePerm
		}

		// If it's a directory, make a corresponding directory.
		if info.IsDir() {
			return os.MkdirAll(dst, perm|0200)
		}

		// Copy the file bytes.
		// We can't create a symlink because the file may get modified;
		// we need to ensure that only the temporary copy is affected.
		s, err := os.Open(src)
		if err != nil {
			return err
		}
		defer s.Close()
		d, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
		if err != nil {
			return err
		}
		_, err = io.Copy(d, s)
		if err != nil {
			d.Close()
			return err
		}
		return d.Close()
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("copied GOROOT from %s to %s", testenv.GOROOT(t), gorootCopyDir)
	return gorootCopyDir
}

type runner struct {
	Dir string
	Env []string
}

// run runs the command and requires that it succeeds.
func (r runner) run(t *testing.T, args ...string) {
	t.Helper()
	cmd := testenv.Command(t, args[0], args[1:]...)
	cmd.Dir = r.Dir
	cmd.Env = slices.Clip(r.Env)
	if r.Dir != "" {
		cmd.Env = append(cmd.Env, "PWD="+r.Dir)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("> %s\n", strings.Join(args, " "))
		t.Fatalf("command failed: %s\n%s", err, out)
	}
}

// TestDependencyVersionsConsistent verifies that each module in GOROOT that
// requires a given external dependency requires the same version of that
// dependency.
//
// This property allows us to maintain a single release branch of each such
// dependency, minimizing the number of backports needed to pull in critical
// fixes. It also ensures that any bug detected and fixed in one GOROOT module
// (such as "std") is fixed in all other modules (such as "cmd") as well.
func TestDependencyVersionsConsistent(t *testing.T) {
	// Collect the dependencies of all modules in GOROOT, indexed by module path.
	type requirement struct {
		Required    module.Version
		Replacement module.Version
	}
	seen := map[string]map[requirement][]gorootModule{} // module path → requirement → set of modules with that requirement
	for _, m := range findGorootModules(t) {
		if !m.hasVendor {
			// TestAllDependencies will ensure that the module has no dependencies.
			continue
		}

		// We want this test to be able to run offline and with an empty module
		// cache, so we verify consistency only for the module versions listed in
		// vendor/modules.txt. That includes all direct dependencies and all modules
		// that provide any imported packages.
		//
		// It's ok if there are undetected differences in modules that do not
		// provide imported packages: we will not have to pull in any backports of
		// fixes to those modules anyway.
		vendor, err := os.ReadFile(filepath.Join(m.Dir, "vendor", "modules.txt"))
		if err != nil {
			t.Error(err)
			continue
		}

		for _, line := range strings.Split(strings.TrimSpace(string(vendor)), "\n") {
			parts := strings.Fields(line)
			if len(parts) < 3 || parts[0] != "#" {
				continue
			}

			// This line is of the form "# module version [=> replacement [version]]".
			var r requirement
			r.Required.Path = parts[1]
			r.Required.Version = parts[2]
			if len(parts) >= 5 && parts[3] == "=>" {
				r.Replacement.Path = parts[4]
				if module.CheckPath(r.Replacement.Path) != nil {
					// If the replacement is a filesystem path (rather than a module path),
					// we don't know whether the filesystem contents have changed since
					// the module was last vendored.
					//
					// Fortunately, we do not currently use filesystem-local replacements
					// in GOROOT modules.
					t.Errorf("cannot check consistency for filesystem-local replacement in module %s (%s):\n%s", m.Path, m.Dir, line)
				}

				if len(parts) >= 6 {
					r.Replacement.Version = parts[5]
				}
			}

			if seen[r.Required.Path] == nil {
				seen[r.Required.Path] = make(map[requirement][]gorootModule)
			}
			seen[r.Required.Path][r] = append(seen[r.Required.Path][r], m)
		}
	}

	// Now verify that we saw only one distinct version for each module.
	for path, versions := range seen {
		if len(versions) > 1 {
			t.Errorf("Modules within GOROOT require different versions of %s.", path)
			for r, mods := range versions {
				desc := new(strings.Builder)
				desc.WriteString(r.Required.Version)
				if r.Replacement.Path != "" {
					fmt.Fprintf(desc, " => %s", r.Replacement.Path)
					if r.Replacement.Version != "" {
						fmt.Fprintf(desc, " %s", r.Replacement.Version)
					}
				}

				for _, m := range mods {
					t.Logf("%s\trequires %v", m.Path, desc)
				}
			}
		}
	}
}

type gorootModule struct {
	Path      string
	Dir       string
	hasVendor bool
}

// findGorootModules returns the list of modules found in the GOROOT source tree.
func findGorootModules(t *testing.T) []gorootModule {
	t.Helper()
	goBin := testenv.GoToolPath(t)

	goroot.once.Do(func() {
		// If the root itself is a symlink to a directory,
		// we want to follow it (see https://go.dev/issue/64375).
		// Add a trailing separator to force that to happen.
		root := testenv.GOROOT(t)
		if !os.IsPathSeparator(root[len(root)-1]) {
			root += string(filepath.Separator)
		}
		goroot.err = filepath.WalkDir(root, func(path string, info fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() && path != root && (info.Name() == "vendor" || info.Name() == "testdata") {
				return filepath.SkipDir
			}
			if info.IsDir() && path == filepath.Join(testenv.GOROOT(t), "pkg") {
				// GOROOT/pkg contains generated artifacts, not source code.
				//
				// In https://golang.org/issue/37929 it was observed to somehow contain
				// a module cache, so it is important to skip. (That helps with the
				// running time of this test anyway.)
				return filepath.SkipDir
			}
			if info.IsDir() && path != root && (strings.HasPrefix(info.Name(), "_") || strings.HasPrefix(info.Name(), ".")) {
				// _ and . prefixed directories can be used for internal modules
				// without a vendor directory that don't contribute to the build
				// but might be used for example as code generators.
				return filepath.SkipDir
			}
			if info.IsDir() || info.Name() != "go.mod" {
				return nil
			}
			dir := filepath.Dir(path)

			// Use 'go list' to describe the module contained in this directory (but
			// not its dependencies).
			cmd := testenv.Command(t, goBin, "list", "-json", "-m")
			cmd.Dir = dir
			cmd.Env = append(cmd.Environ(), "GO111MODULE=on", "GOWORK=off")
			cmd.Stderr = new(strings.Builder)
			out, err := cmd.Output()
			if err != nil {
				return fmt.Errorf("'go list -json -m' in %s: %w\n%s", dir, err, cmd.Stderr)
			}

			var m gorootModule
			if err := json.Unmarshal(out, &m); err != nil {
				return fmt.Errorf("decoding 'go list -json -m' in %s: %w", dir, err)
			}
			if m.Path == "" || m.Dir == "" {
				return fmt.Errorf("'go list -json -m' in %s failed to populate Path and/or Dir", dir)
			}
			if _, err := os.Stat(filepath.Join(dir, "vendor")); err == nil {
				m.hasVendor = true
			}
			goroot.modules = append(goroot.modules, m)
			return nil
		})
		if goroot.err != nil {
			return
		}

		// knownGOROOTModules is a hard-coded list of modules that are known to exist in GOROOT.
		// If findGorootModules doesn't find a module, it won't be covered by tests at all,
		// so make sure at least these modules are found. See issue 46254. If this list
		// becomes a nuisance to update, can be replaced with len(goroot.modules) check.
		knownGOROOTModules := [...]string{
			"std",
			"cmd",
			// The "misc" module sometimes exists, but cmd/distpack intentionally removes it.
		}
		var seen = make(map[string]bool) // Key is module path.
		for _, m := range goroot.modules {
			seen[m.Path] = true
		}
		for _, m := range knownGOROOTModules {
			if !seen[m] {
				goroot.err = fmt.Errorf("findGorootModules didn't find the well-known module %q", m)
				break
			}
		}
		sort.Slice(goroot.modules, func(i, j int) bool {
			return goroot.modules[i].Dir < goroot.modules[j].Dir
		})
	})
	if goroot.err != nil {
		t.Fatal(goroot.err)
	}
	return goroot.modules
}

// goroot caches the list of modules found in the GOROOT source tree.
var goroot struct {
	once    sync.Once
	modules []gorootModule
	err     error
}

"""



```