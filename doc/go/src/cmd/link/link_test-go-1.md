Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Understanding the Goal:**

The request asks for a functional summary of the given Go code, which is a part of the `go/src/cmd/link/link_test.go` file. The key is to identify *what* each test function is testing.

**2. Initial Scan and Structure Identification:**

The code is clearly structured as a series of Go test functions. Each function name starts with `Test` and takes a `*testing.T` argument. This is standard Go testing convention. Immediately, we can infer that this code is designed to test the Go linker (`cmd/link`).

**3. Analyzing Individual Test Functions (Iterative Process):**

For each `Test` function, the process is similar:

* **Read the function name:** The name usually provides a strong clue about what's being tested (e.g., `TestIssue38554`, `TestLargeReloc`). Issue numbers often indicate a specific bug or feature being addressed.
* **Examine the setup:** Look for common setup steps like creating temporary directories (`t.TempDir()`), creating source files (`os.WriteFile`), and building executables using `testenv.Command` and `testenv.GoToolPath`. This indicates the tests involve compiling and linking Go code.
* **Identify the core action:** What is the test *doing* with the built executable?  Is it running it, checking its size, or expecting a build error?
* **Look for assertions/checks:**  `t.Errorf`, `t.Fatalf`, and `strings.Contains` are common assertion methods. These tell us what the test expects to happen.
* **Infer the tested feature/bug:** Based on the setup, action, and assertions, try to deduce the Go linker feature or bug being tested. For example, if a test checks the size of the executable after building a program with a large unused variable, it's likely testing optimizations related to dead code elimination or symbol handling.
* **Consider special conditions:** Look for checks for specific operating systems (`runtime.GOOS`), architectures (`runtime.GOARCH`), or build tags (like `testenv.HasCGO`). These indicate platform-specific testing.

**Example Walkthrough (TestIssue38554):**

1. **Name:** `TestIssue38554` -  Likely testing a specific reported issue.
2. **Setup:** Creates a temporary directory, writes a Go source file (`testIssue38554Src`) containing a large, unused variable of type `T`, and builds an executable.
3. **Core Action:**  Checks the size of the built executable.
4. **Assertions:** Expects the size to be *less than* 5MB.
5. **Inference:** This test is likely checking that the linker correctly handles large, unused variables and doesn't include them in the final executable, preventing unnecessarily large binaries. The `//go:noinline` comment suggests it might be related to inlining behavior.

**4. Grouping and Categorization:**

After analyzing each test, group them by the type of linker functionality they are testing. Common categories emerge:

* **Error Handling:** Tests that expect the linker to fail under certain conditions (e.g., `TestUnlinkableObj`, `TestIssue42396`).
* **Code Optimization/Size Reduction:** Tests related to dead code elimination or symbol stripping (`TestIssue38554`, `TestFlagS`).
* **Relocations:** Tests dealing with how the linker resolves addresses (`TestLargeReloc`).
* **External Linking (CGO):** Tests that involve interaction with external linkers, often related to C code (`TestExtLinkCmdlineDeterminism`, `TestResponseFile`, `TestDynimportVar`).
* **Code Layout and Determinism:** Tests that explore how the linker arranges code and whether the output is deterministic (`TestRandLayout`, `TestExtLinkCmdlineDeterminism`).
* **Linkname Directive:** Tests for the `//go:linkname` directive and its restrictions (`TestCheckLinkname`).

**5. Summarization and Refinement:**

Finally, write a concise summary of each category of tests. Use clear and understandable language, avoiding overly technical jargon where possible. Provide illustrative code examples when the functionality isn't immediately obvious from the test name. Pay attention to the specific questions in the prompt (command-line arguments, potential errors, etc.).

**Self-Correction/Refinement during the process:**

* **Initial misinterpretations:**  Sometimes, the initial guess about a test's purpose might be slightly off. Reviewing the code and assertions helps refine the understanding. For example, initially, one might think `TestIssue38554` is solely about large variables, but the `//go:noinline` hint points towards interaction with the compiler's inlining decisions.
* **Identifying common patterns:**  Recognizing recurring patterns like temporary directory creation and `testenv.Command` usage makes the analysis more efficient.
* **Focusing on the "why":**  Don't just describe *what* the test does, explain *why* it's doing it and what linker behavior it's verifying.

By following this structured approach, we can systematically analyze the provided Go test code and provide a comprehensive functional summary.
## 功能归纳：go/src/cmd/link/link_test.go 第2部分

这部分 `link_test.go` 文件主要包含了一系列针对 Go 链接器 (`cmd/link`) 的集成测试。这些测试旨在验证链接器在不同场景下的正确性和健壮性。具体功能可以归纳为以下几个方面：

**1. 测试链接器对特定代码结构的优化和处理能力：**

* **`TestIssue38554`：**  测试链接器是否能正确处理包含未使用的巨大临时变量（large stack temporary, stmp）的情况，确保最终生成的可执行文件大小不会因此变得过大。这涉及到链接器的 **死代码消除** 和 **符号管理** 能力。
* **`TestLargeReloc`：** 测试链接器处理大偏移量重定位的能力，尤其是在外部链接模式下，验证是否能正确处理超出某些平台重定位字段限制的情况。这关系到链接器的 **重定位** 功能的正确性。

**2. 测试链接器的错误处理机制：**

* **`TestIssue42396`：**  测试在使用了 `-race` 标志启用竞态检测器的情况下，如果代码中存在编译错误（例如引用了未定义的内建函数），链接器是否能给出合理的错误提示，而不是崩溃（panic）。这测试了链接器的 **错误报告** 机制。
* **`TestUnlinkableObj`：** 测试链接器在遇到无法链接的目标文件（例如，使用 `go tool compile` 编译时缺少 `-p` 标志的包）时，是否会正确地报错，并提供明确的错误信息。这验证了链接器的 **依赖检查** 和 **错误处理** 能力。

**3. 测试链接器的确定性和稳定性：**

* **`TestExtLinkCmdlineDeterminism`：** 测试在使用外部链接器 (`-linkmode=external`) 时，传递给外部链接器的命令行参数顺序是否是确定的。这对于保证构建的可重复性非常重要。

**4. 测试链接器与外部链接器的集成：**

* **`TestResponseFile`：** 测试当传递给外部链接器的参数过多时，链接器是否能正确创建并使用 response file (响应文件) 来传递这些参数，避免超出操作系统命令行长度的限制。
* **`TestDynimportVar`：** 测试链接器在动态导入变量的场景下的功能，主要针对 Darwin 平台。这涉及到链接器如何处理动态链接和符号查找。

**5. 测试链接器的代码优化和精简能力：**

* **`TestFlagS`：** 测试 `-s` 标志是否能正确地从生成的可执行文件中剥离符号表信息，从而减小文件大小。这关系到链接器的 **符号剥离** 功能。

**6. 测试链接器的代码布局随机化功能：**

* **`TestRandLayout`：** 测试 `-randlayout` 标志是否能随机化函数布局，并且生成的二进制文件仍然可以正常运行。这是一种安全特性，可以增加某些攻击的难度。

**7. 测试链接器对 `//go:linkname` 指令的限制：**

* **`TestCheckLinkname`：** 测试链接器是否能正确阻止使用某些被禁止的 `//go:linkname` 指令的情况，以维护语言的封装性和稳定性。

总的来说，这部分测试覆盖了 Go 链接器的多个关键功能，包括代码优化、错误处理、与外部链接器的集成、代码布局控制以及对语言特性的支持和限制。

接下来，我们针对其中一些功能，结合代码进行更详细的分析。

---

**功能详解与代码示例：**

**1. 测试链接器对特定代码结构的优化和处理能力：`TestIssue38554`**

* **功能：** 验证链接器不会因为代码中存在未使用的巨大局部变量而生成过大的可执行文件。
* **假设输入：** 包含 `testIssue38554Src` 内容的 `x.go` 文件。
* **预期输出：** 编译成功，且生成的可执行文件大小小于 5MB。
* **代码解释：**
    * `testIssue38554Src` 定义了一个类型 `T`，它是一个大小为 10MB 的字节数组。
    * 函数 `f()` 返回一个 `T` 类型的零值，但由于被标记为 `//go:noinline`，编译器不会将其内联，这会导致在编译期间生成一个较大的临时变量。
    * `main()` 函数调用了 `f()`，但实际上并没有使用返回值 `x` 的内容。
    * `TestIssue38554` 测试编译后的可执行文件大小是否合理，期望链接器能识别出 `x` 未被使用，从而在最终的可执行文件中避免包含这 10MB 的数据。
* **易犯错的点：**  如果开发者在不理解链接器优化的情况下，可能会认为定义了这么大的变量就会导致最终文件很大。这个测试展示了链接器的优化能力。

**2. 测试链接器的错误处理机制：`TestUnlinkableObj`**

* **功能：** 验证链接器在遇到未正确编译的目标文件时，能够给出明确的错误信息。
* **假设输入：** 两个 Go 源文件 `x.go` 和 `p.go`，其中 `p.go` 使用 `go tool compile` 编译时缺少 `-p` 标志。
* **预期输出：** 链接过程失败，并且输出信息包含 "unlinkable object"。
* **代码解释：**
    * `p.go` 被编译成目标文件 `p.o` 时，故意省略了 `-p` 标志，导致其缺少包路径信息，成为一个无法被链接的“孤立”目标文件。
    * `x.go` 导入了包 `p`。
    * `TestUnlinkableObj` 测试当链接器尝试将 `x.o` 和 `p.o` 链接在一起时，是否会因为 `p.o` 缺少必要的包信息而报错。
* **命令行参数处理：** 测试中使用了 `go tool compile` 命令，并故意省略了 `-p` 参数来模拟生成不可链接的目标文件。链接阶段则使用 `go tool link` 命令。
* **易犯错的点：**  初学者可能不理解 `-p` 标志在编译非 `main` 包时的重要性，可能会遇到链接错误但不知道原因。这个测试强调了正确编译包的重要性。

**3. 测试链接器的确定性和稳定性：`TestExtLinkCmdlineDeterminism`**

* **功能：** 验证在使用外部链接器时，传递给它的命令行参数顺序是固定的。
* **假设输入：** 包含 cgo export 的 Go 源文件 `testSrc`。
* **预期输出：** 多次编译后，传递给外部链接器的命令行参数（host link 部分）保持一致。
* **代码解释：**
    * `testSrc` 包含了 cgo 的 `//export` 指令，这意味着链接过程会涉及到外部链接器。
    * `TestExtLinkCmdlineDeterminism` 多次执行 `go build` 命令，并捕获每次执行时传递给外部链接器的命令行参数。
    * 通过比较多次执行的输出，验证参数顺序是否一致。
* **命令行参数处理：**  测试使用了 `-ldflags=-v -linkmode=external` 来强制使用外部链接器，并且使用 `-v` 标志来查看链接过程中的详细信息，包括传递给外部链接器的命令。
* **易犯错的点：**  在某些构建系统中，依赖于命令行参数顺序可能会导致问题。这个测试保证了 Go 工具链在这方面的稳定性。

**代码示例（模拟 `TestIssue38554` 的场景）：**

```go
package main

type T [10 << 20]byte // 10MB 字节数组

//go:noinline
func createLargeArray() T {
	return T{}
}

func main() {
	largeArray := createLargeArray() // 创建一个大的局部变量，但未使用
	_ = largeArray[0] // 象征性地使用一下，防止编译器完全优化掉函数调用
	println("Program finished")
}
```

**预期编译结果：** 生成的可执行文件大小应该接近一个“hello world”程序的大小，而不会接近 10MB。链接器应该能够识别出 `largeArray` 虽然被创建，但其内容在后续并没有被实质性使用，从而避免将其包含在最终的可执行文件中。

总结来说，这部分 `link_test.go` 通过各种测试用例，细致地检验了 Go 链接器的各项功能和特性，确保其在不同场景下都能正确、稳定地工作，并能提供良好的错误处理和优化能力。

### 提示词
```
这是路径为go/src/cmd/link/link_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Errorf("running test program did not fail. output:\n%s", out)
	}
}

const testIssue38554Src = `
package main

type T [10<<20]byte

//go:noinline
func f() T {
	return T{} // compiler will make a large stmp symbol, but not used.
}

func main() {
	x := f()
	println(x[1])
}
`

func TestIssue38554(t *testing.T) {
	testenv.MustHaveGoBuild(t)

	t.Parallel()

	tmpdir := t.TempDir()

	src := filepath.Join(tmpdir, "x.go")
	err := os.WriteFile(src, []byte(testIssue38554Src), 0666)
	if err != nil {
		t.Fatalf("failed to write source file: %v", err)
	}
	exe := filepath.Join(tmpdir, "x.exe")
	cmd := testenv.Command(t, testenv.GoToolPath(t), "build", "-o", exe, src)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}

	fi, err := os.Stat(exe)
	if err != nil {
		t.Fatalf("failed to stat output file: %v", err)
	}

	// The test program is not much different from a helloworld, which is
	// typically a little over 1 MB. We allow 5 MB. If the bad stmp is live,
	// it will be over 10 MB.
	const want = 5 << 20
	if got := fi.Size(); got > want {
		t.Errorf("binary too big: got %d, want < %d", got, want)
	}
}

const testIssue42396src = `
package main

//go:noinline
//go:nosplit
func callee(x int) {
}

func main() {
	callee(9)
}
`

func TestIssue42396(t *testing.T) {
	testenv.MustHaveGoBuild(t)

	if !platform.RaceDetectorSupported(runtime.GOOS, runtime.GOARCH) {
		t.Skip("no race detector support")
	}

	t.Parallel()

	tmpdir := t.TempDir()

	src := filepath.Join(tmpdir, "main.go")
	err := os.WriteFile(src, []byte(testIssue42396src), 0666)
	if err != nil {
		t.Fatalf("failed to write source file: %v", err)
	}
	exe := filepath.Join(tmpdir, "main.exe")
	cmd := testenv.Command(t, testenv.GoToolPath(t), "build", "-gcflags=-race", "-o", exe, src)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("build unexpectedly succeeded")
	}

	// Check to make sure that we see a reasonable error message
	// and not a panic.
	if strings.Contains(string(out), "panic:") {
		t.Fatalf("build should not fail with panic:\n%s", out)
	}
	const want = "reference to undefined builtin"
	if !strings.Contains(string(out), want) {
		t.Fatalf("error message incorrect: expected it to contain %q but instead got:\n%s\n", want, out)
	}
}

const testLargeRelocSrc = `
package main

var x = [1<<25]byte{1<<23: 23, 1<<24: 24}

var addr = [...]*byte{
	&x[1<<23-1],
	&x[1<<23],
	&x[1<<23+1],
	&x[1<<24-1],
	&x[1<<24],
	&x[1<<24+1],
}

func main() {
	// check relocations in instructions
	check(x[1<<23-1], 0)
	check(x[1<<23], 23)
	check(x[1<<23+1], 0)
	check(x[1<<24-1], 0)
	check(x[1<<24], 24)
	check(x[1<<24+1], 0)

	// check absolute address relocations in data
	check(*addr[0], 0)
	check(*addr[1], 23)
	check(*addr[2], 0)
	check(*addr[3], 0)
	check(*addr[4], 24)
	check(*addr[5], 0)
}

func check(x, y byte) {
	if x != y {
		panic("FAIL")
	}
}
`

func TestLargeReloc(t *testing.T) {
	// Test that large relocation addend is handled correctly.
	// In particular, on darwin/arm64 when external linking,
	// Mach-O relocation has only 24-bit addend. See issue #42738.
	testenv.MustHaveGoBuild(t)
	t.Parallel()

	tmpdir := t.TempDir()

	src := filepath.Join(tmpdir, "x.go")
	err := os.WriteFile(src, []byte(testLargeRelocSrc), 0666)
	if err != nil {
		t.Fatalf("failed to write source file: %v", err)
	}
	cmd := testenv.Command(t, testenv.GoToolPath(t), "run", src)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Errorf("build failed: %v. output:\n%s", err, out)
	}

	if testenv.HasCGO() { // currently all targets that support cgo can external link
		cmd = testenv.Command(t, testenv.GoToolPath(t), "run", "-ldflags=-linkmode=external", src)
		out, err = cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("build failed: %v. output:\n%s", err, out)
		}
	}
}

func TestUnlinkableObj(t *testing.T) {
	// Test that the linker emits an error with unlinkable object.
	testenv.MustHaveGoBuild(t)
	t.Parallel()

	if true /* was buildcfg.Experiment.Unified */ {
		t.Skip("TODO(mdempsky): Fix ICE when importing unlinkable objects for GOEXPERIMENT=unified")
	}

	tmpdir := t.TempDir()

	xSrc := filepath.Join(tmpdir, "x.go")
	pSrc := filepath.Join(tmpdir, "p.go")
	xObj := filepath.Join(tmpdir, "x.o")
	pObj := filepath.Join(tmpdir, "p.o")
	exe := filepath.Join(tmpdir, "x.exe")
	importcfgfile := filepath.Join(tmpdir, "importcfg")
	testenv.WriteImportcfg(t, importcfgfile, map[string]string{"p": pObj})
	err := os.WriteFile(xSrc, []byte("package main\nimport _ \"p\"\nfunc main() {}\n"), 0666)
	if err != nil {
		t.Fatalf("failed to write source file: %v", err)
	}
	err = os.WriteFile(pSrc, []byte("package p\n"), 0666)
	if err != nil {
		t.Fatalf("failed to write source file: %v", err)
	}
	cmd := testenv.Command(t, testenv.GoToolPath(t), "tool", "compile", "-importcfg="+importcfgfile, "-o", pObj, pSrc) // without -p
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("compile p.go failed: %v. output:\n%s", err, out)
	}
	cmd = testenv.Command(t, testenv.GoToolPath(t), "tool", "compile", "-importcfg="+importcfgfile, "-p=main", "-o", xObj, xSrc)
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("compile x.go failed: %v. output:\n%s", err, out)
	}
	cmd = testenv.Command(t, testenv.GoToolPath(t), "tool", "link", "-importcfg="+importcfgfile, "-o", exe, xObj)
	out, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("link did not fail")
	}
	if !bytes.Contains(out, []byte("unlinkable object")) {
		t.Errorf("did not see expected error message. out:\n%s", out)
	}

	// It is okay to omit -p for (only) main package.
	cmd = testenv.Command(t, testenv.GoToolPath(t), "tool", "compile", "-importcfg="+importcfgfile, "-p=p", "-o", pObj, pSrc)
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("compile p.go failed: %v. output:\n%s", err, out)
	}
	cmd = testenv.Command(t, testenv.GoToolPath(t), "tool", "compile", "-importcfg="+importcfgfile, "-o", xObj, xSrc) // without -p
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("compile failed: %v. output:\n%s", err, out)
	}

	cmd = testenv.Command(t, testenv.GoToolPath(t), "tool", "link", "-importcfg="+importcfgfile, "-o", exe, xObj)
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Errorf("link failed: %v. output:\n%s", err, out)
	}
}

func TestExtLinkCmdlineDeterminism(t *testing.T) {
	// Test that we pass flags in deterministic order to the external linker
	testenv.MustHaveGoBuild(t)
	testenv.MustHaveCGO(t) // this test requires -linkmode=external
	t.Parallel()

	// test source code, with some cgo exports
	testSrc := `
package main
import "C"
//export F1
func F1() {}
//export F2
func F2() {}
//export F3
func F3() {}
func main() {}
`

	tmpdir := t.TempDir()
	src := filepath.Join(tmpdir, "x.go")
	if err := os.WriteFile(src, []byte(testSrc), 0666); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(tmpdir, "x.exe")

	// Use a deterministic tmp directory so the temporary file paths are
	// deterministic.
	linktmp := filepath.Join(tmpdir, "linktmp")
	if err := os.Mkdir(linktmp, 0777); err != nil {
		t.Fatal(err)
	}

	// Link with -v -linkmode=external to see the flags we pass to the
	// external linker.
	ldflags := "-ldflags=-v -linkmode=external -tmpdir=" + linktmp
	var out0 []byte
	for i := 0; i < 5; i++ {
		cmd := testenv.Command(t, testenv.GoToolPath(t), "build", ldflags, "-o", exe, src)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("build failed: %v, output:\n%s", err, out)
		}
		if err := os.Remove(exe); err != nil {
			t.Fatal(err)
		}

		// extract the "host link" invocation
		j := bytes.Index(out, []byte("\nhost link:"))
		if j == -1 {
			t.Fatalf("host link step not found, output:\n%s", out)
		}
		out = out[j+1:]
		k := bytes.Index(out, []byte("\n"))
		if k == -1 {
			t.Fatalf("no newline after host link, output:\n%s", out)
		}
		out = out[:k]

		// filter out output file name, which is passed by the go
		// command and is nondeterministic.
		fs := bytes.Fields(out)
		for i, f := range fs {
			if bytes.Equal(f, []byte(`"-o"`)) && i+1 < len(fs) {
				fs[i+1] = []byte("a.out")
				break
			}
		}
		out = bytes.Join(fs, []byte{' '})

		if i == 0 {
			out0 = out
			continue
		}
		if !bytes.Equal(out0, out) {
			t.Fatalf("output differ:\n%s\n==========\n%s", out0, out)
		}
	}
}

// TestResponseFile tests that creating a response file to pass to the
// external linker works correctly.
func TestResponseFile(t *testing.T) {
	t.Parallel()

	testenv.MustHaveGoBuild(t)

	// This test requires -linkmode=external. Currently all
	// systems that support cgo support -linkmode=external.
	testenv.MustHaveCGO(t)

	tmpdir := t.TempDir()

	src := filepath.Join(tmpdir, "x.go")
	if err := os.WriteFile(src, []byte(`package main; import "C"; func main() {}`), 0666); err != nil {
		t.Fatal(err)
	}

	cmd := testenv.Command(t, testenv.GoToolPath(t), "build", "-o", "output", "x.go")
	cmd.Dir = tmpdir

	// Add enough arguments to push cmd/link into creating a response file.
	var sb strings.Builder
	sb.WriteString(`'-ldflags=all="-extldflags=`)
	for i := 0; i < sys.ExecArgLengthLimit/len("-g"); i++ {
		if i > 0 {
			sb.WriteString(" ")
		}
		sb.WriteString("-g")
	}
	sb.WriteString(`"'`)
	cmd = testenv.CleanCmdEnv(cmd)
	cmd.Env = append(cmd.Env, "GOFLAGS="+sb.String())

	out, err := cmd.CombinedOutput()
	if len(out) > 0 {
		t.Logf("%s", out)
	}
	if err != nil {
		t.Error(err)
	}
}

func TestDynimportVar(t *testing.T) {
	// Test that we can access dynamically imported variables.
	// Currently darwin only.
	if runtime.GOOS != "darwin" {
		t.Skip("skip on non-darwin platform")
	}

	testenv.MustHaveGoBuild(t)
	testenv.MustHaveCGO(t)

	t.Parallel()

	tmpdir := t.TempDir()
	exe := filepath.Join(tmpdir, "a.exe")
	src := filepath.Join("testdata", "dynimportvar", "main.go")

	for _, mode := range []string{"internal", "external"} {
		cmd := testenv.Command(t, testenv.GoToolPath(t), "build", "-ldflags=-linkmode="+mode, "-o", exe, src)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("build (linkmode=%s) failed: %v\n%s", mode, err, out)
		}
		cmd = testenv.Command(t, exe)
		out, err = cmd.CombinedOutput()
		if err != nil {
			t.Errorf("executable failed to run (%s): %v\n%s", mode, err, out)
		}
	}
}

const helloSrc = `
package main
var X = 42
var Y int
func main() { println("hello", X, Y) }
`

func TestFlagS(t *testing.T) {
	// Test that the -s flag strips the symbol table.
	testenv.MustHaveGoBuild(t)

	t.Parallel()

	tmpdir := t.TempDir()
	exe := filepath.Join(tmpdir, "a.exe")
	src := filepath.Join(tmpdir, "a.go")
	err := os.WriteFile(src, []byte(helloSrc), 0666)
	if err != nil {
		t.Fatal(err)
	}

	modes := []string{"auto"}
	if testenv.HasCGO() {
		modes = append(modes, "external")
	}

	// check a text symbol, a data symbol, and a BSS symbol
	syms := []string{"main.main", "main.X", "main.Y"}

	for _, mode := range modes {
		cmd := testenv.Command(t, testenv.GoToolPath(t), "build", "-ldflags=-s -linkmode="+mode, "-o", exe, src)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("build (linkmode=%s) failed: %v\n%s", mode, err, out)
		}
		cmd = testenv.Command(t, testenv.GoToolPath(t), "tool", "nm", exe)
		out, err = cmd.CombinedOutput()
		if err != nil && !errors.As(err, new(*exec.ExitError)) {
			// Error exit is fine as it may have no symbols.
			// On darwin we need to emit dynamic symbol references so it
			// actually has some symbols, and nm succeeds.
			t.Errorf("(mode=%s) go tool nm failed: %v\n%s", mode, err, out)
		}
		for _, s := range syms {
			if bytes.Contains(out, []byte(s)) {
				t.Errorf("(mode=%s): unexpected symbol %s", mode, s)
			}
		}
	}
}

func TestRandLayout(t *testing.T) {
	// Test that the -randlayout flag randomizes function order and
	// generates a working binary.
	testenv.MustHaveGoBuild(t)

	t.Parallel()

	tmpdir := t.TempDir()

	src := filepath.Join(tmpdir, "hello.go")
	err := os.WriteFile(src, []byte(trivialSrc), 0666)
	if err != nil {
		t.Fatal(err)
	}

	var syms [2]string
	for i, seed := range []string{"123", "456"} {
		exe := filepath.Join(tmpdir, "hello"+seed+".exe")
		cmd := testenv.Command(t, testenv.GoToolPath(t), "build", "-ldflags=-randlayout="+seed, "-o", exe, src)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("seed=%v: build failed: %v\n%s", seed, err, out)
		}
		cmd = testenv.Command(t, exe)
		err = cmd.Run()
		if err != nil {
			t.Fatalf("seed=%v: executable failed to run: %v\n%s", seed, err, out)
		}
		cmd = testenv.Command(t, testenv.GoToolPath(t), "tool", "nm", exe)
		out, err = cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("seed=%v: fail to run \"go tool nm\": %v\n%s", seed, err, out)
		}
		syms[i] = string(out)
	}
	if syms[0] == syms[1] {
		t.Errorf("randlayout with different seeds produced same layout:\n%s\n===\n\n%s", syms[0], syms[1])
	}
}

func TestCheckLinkname(t *testing.T) {
	// Test that code containing blocked linknames does not build.
	testenv.MustHaveGoBuild(t)
	t.Parallel()

	tmpdir := t.TempDir()

	tests := []struct {
		src string
		ok  bool
	}{
		// use (instantiation) of public API is ok
		{"ok.go", true},
		// push linkname is ok
		{"push.go", true},
		// pull linkname of blocked symbol is not ok
		{"coro.go", false},
		{"coro_var.go", false},
		// assembly reference is not ok
		{"coro_asm", false},
		// pull-only linkname is not ok
		{"coro2.go", false},
		// pull linkname of a builtin symbol is not ok
		{"builtin.go", false},
		// legacy bad linkname is ok, for now
		{"fastrand.go", true},
		{"badlinkname.go", true},
	}
	for _, test := range tests {
		test := test
		t.Run(test.src, func(t *testing.T) {
			t.Parallel()
			src := filepath.Join("testdata", "linkname", test.src)
			exe := filepath.Join(tmpdir, test.src+".exe")
			cmd := testenv.Command(t, testenv.GoToolPath(t), "build", "-o", exe, src)
			out, err := cmd.CombinedOutput()
			if test.ok && err != nil {
				t.Errorf("build failed unexpectedly: %v:\n%s", err, out)
			}
			if !test.ok && err == nil {
				t.Errorf("build succeeded unexpectedly: %v:\n%s", err, out)
			}
		})
	}
}
```