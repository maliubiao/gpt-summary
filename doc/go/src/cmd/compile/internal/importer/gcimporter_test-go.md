Response: The user wants to understand the functionality of the Go code provided in `go/src/cmd/compile/internal/importer/gcimporter_test.go`. I need to analyze the code and explain its purpose. Specifically, I should identify:

1. **Core Functionality:** What does this test file do?  It seems to involve importing Go packages.
2. **Demonstration:**  If possible, provide a simple Go code example illustrating the functionality being tested.
3. **Code Inference:** If the code reveals details about how package importing works, explain that with assumptions and inputs/outputs.
4. **Command-line Handling:** Are there any command-line arguments involved? Explain their use.
5. **Common Mistakes:**  Are there any common pitfalls for users of this functionality? Provide examples.

Let's break down the code section by section to understand its behavior:

* **`TestMain`:** Initializes the `GOROOT` environment variable for testing. This suggests the tests involve compiling and importing packages, likely from the standard library or testdata.
* **`compile`:**  This function compiles a Go source file using `go tool compile`. It manages creating an import configuration file (`importcfg`) if necessary. This is a crucial part of simulating the compilation process.
* **`testPath`:** This function uses the `Import` function (the focus of this test file) to import a package. It times the import and reports any errors.
* **`mktmpdir`:** Creates a temporary directory structure for the tests.
* **`TestImportTestdata`:** Tests importing packages within the `testdata` directory. It compiles these packages first and then imports them. It also checks the imported packages for expected dependencies.
* **`TestVersionHandling`:** Tests the importer's ability to handle different versions of compiled packages. It checks for successful imports of valid versions and errors when importing corrupted or unsupported versions.
* **`TestImportStdLib`:** Tests importing packages from the Go standard library. This is a significant test of the importer's robustness.
* **`importedObjectTests` and `TestImportedTypes`:**  Tests importing specific types and objects from various packages and verifies their string representations.
* **`verifyInterfaceMethodRecvs`:**  A helper function to check the receiver types of interface methods.
* **`TestIssueXXXX` functions:** These are specific test cases for reported issues, likely bug fixes related to the importer. They often involve compiling specific code snippets and verifying the import behavior.
* **`importPkg`:** A helper function to import a package and report errors.
* **`compileAndImportPkg`:** A helper function to compile and then import a package.
* **`lookupObj`:** A helper function to find an object in a package's scope.
* **`importMap` and `TestIssue69912`:**  `importMap` implements a simple importer. `TestIssue69912` appears to test concurrent access to imported packages, potentially exposing race conditions.

Based on this analysis, the primary function of this test file is to verify the correctness and robustness of the `gcimporter`, which is responsible for importing Go packages compiled with the `gc` compiler. The tests cover various scenarios, including importing from testdata, handling different versions, importing standard library packages, and addressing specific bug reports.
`go/src/cmd/compile/internal/importer/gcimporter_test.go` 是 Go 语言编译器 `cmd/compile` 中 `internal/importer` 包的一个测试文件。它的主要功能是测试 `gcimporter` 包的实现。`gcimporter` 的作用是从编译器生成的对象文件（通常以 `.o` 或 `.a` 结尾）中读取导出的类型信息，以便在编译其他依赖这些包的代码时使用。

更具体地说，这个测试文件涵盖了以下几个方面：

1. **基本导入功能测试:**  验证 `gcimporter` 是否能够正确地导入由 `gc` 编译器编译生成的包的导出信息。这包括常量、变量、类型、函数等。
2. **版本兼容性测试:** 测试 `gcimporter` 是否能够处理不同 Go 版本编译生成的对象文件，以及在遇到不兼容版本时是否能正确报错。
3. **标准库导入测试:** 验证 `gcimporter` 是否能够成功导入 Go 标准库的包。
4. **导入对象细节测试:**  测试导入的类型和对象的各种属性是否正确，例如类型定义、函数签名、接口定义等。
5. **特定问题修复测试:**  包含针对特定 issue 的测试用例，例如 `TestIssue5815`，`TestIssue13566` 等，这些测试用例旨在验证 `gcimporter` 是否修复了已知的问题。
6. **并发安全性测试:**  测试在并发场景下使用 `gcimporter` 是否安全，例如 `TestIssue69912`。

**`gcimporter` 的功能实现推断及 Go 代码示例**

`gcimporter` 实现了 `go/types` 包中定义的 `Importer` 接口。该接口定义了一个 `Import(path string) (*Package, error)` 方法，用于根据包的导入路径加载包的信息。`gcimporter` 的实现会读取指定路径的对象文件，解析其中的导出数据，并构建出 `go/types.Package` 对象。

假设我们有一个简单的 Go 包 `mypkg`，包含一个类型定义和一个函数：

```go
// go/src/mypkg/mypkg.go
package mypkg

type MyInt int

func Add(a, b MyInt) MyInt {
	return a + b
}
```

要测试 `gcimporter` 如何导入这个包，我们首先需要使用 `gc` 编译器编译它：

```bash
mkdir -p $GOPATH/src/mypkg
cd $GOPATH/src/mypkg
echo 'package mypkg

type MyInt int

func Add(a, b MyInt) MyInt {
	return a + b
}' > mypkg.go
go tool compile -p mypkg -o mypkg.o mypkg.go
```

编译成功后，会生成 `mypkg.o` 文件。现在，我们可以使用 `gcimporter` 的测试代码来模拟导入这个包的过程。虽然我们不能直接调用 `gcimporter` 的内部函数，但我们可以理解测试代码是如何工作的。

在 `gcimporter_test.go` 中，`compile` 函数就模拟了编译的过程。而 `testPath` 函数则模拟了导入的过程。 我们可以大致理解 `Import` 函数会读取 `mypkg.o` 文件，解析其中的导出信息，然后创建一个 `types2.Package` 对象，其中包含了 `MyInt` 类型和 `Add` 函数的信息。

**代码推理示例 (基于 `TestImportTestdata`)**

假设 `testdata/exports.go` 文件内容如下：

```go
// testdata/exports.go
package exports

import "go/ast"

type Node = ast.Node

func IsNilFilter(f ast.ObjKind) bool {
	return f == ast.Bad
}
```

在 `TestImportTestdata` 函数中，会先编译 `testdata/exports.go`。  `compile` 函数会执行类似于以下的命令：

```bash
go tool compile -p testdata/exports -D testdata -importcfg /tmp/some_temp_dir/testdata/exports.importcfg -o /tmp/some_temp_dir/testdata/exports.o testdata/exports.go
```

其中 `-p testdata/exports` 指定了包的路径，`-D testdata` 设置了编译时可以访问的目录，`-importcfg` 指定了导入配置文件的路径（如果需要导入其他包），`-o` 指定了输出对象文件的路径。

编译成功后，`testPath` 函数会被调用，尝试导入 `./testdata/exports` 包。`Import` 函数（在 `internal/importer/gcimporter.go` 中）会读取 `/tmp/some_temp_dir/testdata/exports.o` 文件，解析其中的导出数据，构建 `types2.Package` 对象。

**假设的输入与输出：**

* **输入（对于 `Import` 函数）：** 包的导入路径 `"./testdata/exports"`，源代码目录 `/tmp/some_temp_dir`。
* **从对象文件 `exports.o` 中读取的导出信息（简化）：**
  ```
  package testdata/exports
  type Node = go/ast.Node
  func IsNilFilter(f go/ast.ObjKind) bool
  ```
* **输出（`Import` 函数返回的 `types2.Package` 对象）：** 该对象会包含：
    * 包的名称：`exports`
    * 包的路径：`testdata/exports`
    * 导入的包：`go/ast`
    * 定义的类型：`Node` (其底层类型是 `ast.Node`)
    * 定义的函数：`IsNilFilter` (参数类型是 `ast.ObjKind`，返回值类型是 `bool`)

**命令行参数的具体处理**

`gcimporter_test.go` 中涉及到命令行参数的地方主要在 `compile` 函数中调用 `go tool compile`。

* **`-p <path>`:**  指定要编译的包的导入路径。例如，`testdata/exports`。
* **`-D <directory>`:**  设置编译时可以访问的目录，这通常用于指定测试数据所在的目录。
* **`-importcfg <file>`:** 指定导入配置文件的路径。该文件包含了包导入路径到对应对象文件路径的映射。这在编译依赖其他本地包的代码时非常有用。例如，如果 `b.go` 依赖于 `a.go` 编译的包，则需要在编译 `b.go` 时通过 `-importcfg` 指定 `a.o` 的位置。
* **`-o <file>`:** 指定编译输出的对象文件的路径。

在 `compile` 函数中，如果 `packagefiles` 参数不为空，则会创建一个 importcfg 文件，并将依赖包的导入路径和对应的对象文件路径写入该文件。然后，将该文件的路径传递给 `go tool compile` 的 `-importcfg` 参数。

**使用者易犯错的点**

虽然用户通常不会直接使用 `gcimporter` 包，但理解其背后的机制可以帮助避免在使用 Go 构建工具时的一些常见错误：

1. **依赖包未编译或对象文件丢失:** 如果在编译一个包时，其依赖的包尚未编译生成对象文件，或者对象文件被意外删除，`gcimporter` 在尝试导入时会失败，导致编译错误。
   * **示例:**  假设 `package b` 依赖于 `package a`，但你只编译了 `b`，而没有先编译 `a`，或者 `a.o` 文件不存在，那么编译 `b` 将会失败。

2. **循环依赖:** `gcimporter` 在处理循环依赖时可能会遇到问题。Go 编译器会尝试检测并阻止循环依赖，但在某些复杂的情况下可能会出现错误。
   * **示例:** 如果 `package a` 导入 `package b`，而 `package b` 也导入 `package a`，就会形成循环依赖。

3. **版本不兼容的对象文件:**  如果在不同的 Go 版本下编译包，然后尝试混合使用这些对象文件，`gcimporter` 可能会因为格式不兼容而报错。
   * **示例:**  使用 Go 1.19 编译的包的对象文件可能无法被 Go 1.18 的 `gcimporter` 正确导入。`TestVersionHandling` 就测试了这种情况。

总而言之，`gcimporter_test.go` 通过各种测试用例，全面地验证了 `gcimporter` 作为 Go 编译器重要组成部分的功能和健壮性，确保了 Go 语言的编译过程能够正确地处理包的导入。

### 提示词
```
这是路径为go/src/cmd/compile/internal/importer/gcimporter_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package importer

import (
	"bytes"
	"cmd/compile/internal/syntax"
	"cmd/compile/internal/types2"
	"fmt"
	"go/build"
	"internal/exportdata"
	"internal/testenv"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	build.Default.GOROOT = testenv.GOROOT(nil)
	os.Exit(m.Run())
}

// compile runs the compiler on filename, with dirname as the working directory,
// and writes the output file to outdirname.
// compile gives the resulting package a packagepath of testdata/<filebasename>.
func compile(t *testing.T, dirname, filename, outdirname string, packagefiles map[string]string) string {
	// filename must end with ".go"
	basename, ok := strings.CutSuffix(filepath.Base(filename), ".go")
	if !ok {
		t.Helper()
		t.Fatalf("filename doesn't end in .go: %s", filename)
	}
	objname := basename + ".o"
	outname := filepath.Join(outdirname, objname)
	pkgpath := path.Join("testdata", basename)

	importcfgfile := os.DevNull
	if len(packagefiles) > 0 {
		importcfgfile = filepath.Join(outdirname, basename) + ".importcfg"
		importcfg := new(bytes.Buffer)
		for k, v := range packagefiles {
			fmt.Fprintf(importcfg, "packagefile %s=%s\n", k, v)
		}
		if err := os.WriteFile(importcfgfile, importcfg.Bytes(), 0655); err != nil {
			t.Fatal(err)
		}
	}

	cmd := testenv.Command(t, testenv.GoToolPath(t), "tool", "compile", "-p", pkgpath, "-D", "testdata", "-importcfg", importcfgfile, "-o", outname, filename)
	cmd.Dir = dirname
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Helper()
		t.Logf("%s", out)
		t.Fatalf("go tool compile %s failed: %s", filename, err)
	}
	return outname
}

func testPath(t *testing.T, path, srcDir string) *types2.Package {
	t0 := time.Now()
	pkg, err := Import(make(map[string]*types2.Package), path, srcDir, nil)
	if err != nil {
		t.Errorf("testPath(%s): %s", path, err)
		return nil
	}
	t.Logf("testPath(%s): %v", path, time.Since(t0))
	return pkg
}

func mktmpdir(t *testing.T) string {
	tmpdir := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmpdir, "testdata"), 0700); err != nil {
		t.Fatal("mktmpdir:", err)
	}
	return tmpdir
}

func TestImportTestdata(t *testing.T) {
	// This package only handles gc export data.
	if runtime.Compiler != "gc" {
		t.Skipf("gc-built packages not available (compiler = %s)", runtime.Compiler)
	}

	testenv.MustHaveGoBuild(t)

	testfiles := map[string][]string{
		"exports.go":  {"go/ast"},
		"generics.go": nil,
	}

	for testfile, wantImports := range testfiles {
		tmpdir := mktmpdir(t)

		importMap := map[string]string{}
		for _, pkg := range wantImports {
			export, _, err := exportdata.FindPkg(pkg, "testdata")
			if export == "" {
				t.Fatalf("no export data found for %s: %v", pkg, err)
			}
			importMap[pkg] = export
		}

		compile(t, "testdata", testfile, filepath.Join(tmpdir, "testdata"), importMap)
		path := "./testdata/" + strings.TrimSuffix(testfile, ".go")

		if pkg := testPath(t, path, tmpdir); pkg != nil {
			// The package's Imports list must include all packages
			// explicitly imported by testfile, plus all packages
			// referenced indirectly via exported objects in testfile.
			got := fmt.Sprint(pkg.Imports())
			for _, want := range wantImports {
				if !strings.Contains(got, want) {
					t.Errorf(`Package("exports").Imports() = %s, does not contain %s`, got, want)
				}
			}
		}
	}
}

func TestVersionHandling(t *testing.T) {
	testenv.MustHaveGoBuild(t)

	// This package only handles gc export data.
	if runtime.Compiler != "gc" {
		t.Skipf("gc-built packages not available (compiler = %s)", runtime.Compiler)
	}

	const dir = "./testdata/versions"
	list, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	tmpdir := mktmpdir(t)
	corruptdir := filepath.Join(tmpdir, "testdata", "versions")
	if err := os.Mkdir(corruptdir, 0700); err != nil {
		t.Fatal(err)
	}

	for _, f := range list {
		name := f.Name()
		if !strings.HasSuffix(name, ".a") {
			continue // not a package file
		}
		if strings.Contains(name, "corrupted") {
			continue // don't process a leftover corrupted file
		}
		pkgpath := "./" + name[:len(name)-2]

		if testing.Verbose() {
			t.Logf("importing %s", name)
		}

		// test that export data can be imported
		_, err := Import(make(map[string]*types2.Package), pkgpath, dir, nil)
		if err != nil {
			// ok to fail if it fails with a 'not the start of an archive file' error for select files
			if strings.Contains(err.Error(), "no longer supported") {
				switch name {
				case "test_go1.8_4.a",
					"test_go1.8_5.a":
					continue
				}
				// fall through
			}
			// ok to fail if it fails with a 'no longer supported' error for select files
			if strings.Contains(err.Error(), "no longer supported") {
				switch name {
				case "test_go1.7_0.a",
					"test_go1.7_1.a",
					"test_go1.8_4.a",
					"test_go1.8_5.a",
					"test_go1.11_6b.a",
					"test_go1.11_999b.a":
					continue
				}
				// fall through
			}
			// ok to fail if it fails with a 'newer version' error for select files
			if strings.Contains(err.Error(), "newer version") {
				switch name {
				case "test_go1.11_999i.a":
					continue
				}
				// fall through
			}
			t.Errorf("import %q failed: %v", pkgpath, err)
			continue
		}

		// create file with corrupted export data
		// 1) read file
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		// 2) find export data
		i := bytes.Index(data, []byte("\n$$B\n")) + 5
		// Export data can contain "\n$$\n" in string constants, however,
		// searching for the next end of section marker "\n$$\n" is good enough for testzs.
		j := bytes.Index(data[i:], []byte("\n$$\n")) + i
		if i < 0 || j < 0 || i > j {
			t.Fatalf("export data section not found (i = %d, j = %d)", i, j)
		}
		// 3) corrupt the data (increment every 7th byte)
		for k := j - 13; k >= i; k -= 7 {
			data[k]++
		}
		// 4) write the file
		pkgpath += "_corrupted"
		filename := filepath.Join(corruptdir, pkgpath) + ".a"
		os.WriteFile(filename, data, 0666)

		// test that importing the corrupted file results in an error
		_, err = Import(make(map[string]*types2.Package), pkgpath, corruptdir, nil)
		if err == nil {
			t.Errorf("import corrupted %q succeeded", pkgpath)
		} else if msg := err.Error(); !strings.Contains(msg, "version skew") {
			t.Errorf("import %q error incorrect (%s)", pkgpath, msg)
		}
	}
}

func TestImportStdLib(t *testing.T) {
	if testing.Short() {
		t.Skip("the imports can be expensive, and this test is especially slow when the build cache is empty")
	}
	testenv.MustHaveGoBuild(t)

	// This package only handles gc export data.
	if runtime.Compiler != "gc" {
		t.Skipf("gc-built packages not available (compiler = %s)", runtime.Compiler)
	}

	// Get list of packages in stdlib. Filter out test-only packages with {{if .GoFiles}} check.
	var stderr bytes.Buffer
	cmd := exec.Command("go", "list", "-f", "{{if .GoFiles}}{{.ImportPath}}{{end}}", "std")
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("failed to run go list to determine stdlib packages: %v\nstderr:\n%v", err, stderr.String())
	}
	pkgs := strings.Fields(string(out))

	var nimports int
	for _, pkg := range pkgs {
		t.Run(pkg, func(t *testing.T) {
			if testPath(t, pkg, filepath.Join(testenv.GOROOT(t), "src", path.Dir(pkg))) != nil {
				nimports++
			}
		})
	}
	const minPkgs = 225 // 'GOOS=plan9 go1.18 list std | wc -l' reports 228; most other platforms have more.
	if len(pkgs) < minPkgs {
		t.Fatalf("too few packages (%d) were imported", nimports)
	}

	t.Logf("tested %d imports", nimports)
}

var importedObjectTests = []struct {
	name string
	want string
}{
	// non-interfaces
	{"crypto.Hash", "type Hash uint"},
	{"go/ast.ObjKind", "type ObjKind int"},
	{"go/types.Qualifier", "type Qualifier func(*Package) string"},
	{"go/types.Comparable", "func Comparable(T Type) bool"},
	{"math.Pi", "const Pi untyped float"},
	{"math.Sin", "func Sin(x float64) float64"},
	{"go/ast.NotNilFilter", "func NotNilFilter(_ string, v reflect.Value) bool"},
	{"internal/exportdata.FindPkg", "func FindPkg(path string, srcDir string) (filename string, id string, err error)"},

	// interfaces
	{"context.Context", "type Context interface{Deadline() (deadline time.Time, ok bool); Done() <-chan struct{}; Err() error; Value(key any) any}"},
	{"crypto.Decrypter", "type Decrypter interface{Decrypt(rand io.Reader, msg []byte, opts DecrypterOpts) (plaintext []byte, err error); Public() PublicKey}"},
	{"encoding.BinaryMarshaler", "type BinaryMarshaler interface{MarshalBinary() (data []byte, err error)}"},
	{"io.Reader", "type Reader interface{Read(p []byte) (n int, err error)}"},
	{"io.ReadWriter", "type ReadWriter interface{Reader; Writer}"},
	{"go/ast.Node", "type Node interface{End() go/token.Pos; Pos() go/token.Pos}"},
	{"go/types.Type", "type Type interface{String() string; Underlying() Type}"},
}

func TestImportedTypes(t *testing.T) {
	testenv.MustHaveGoBuild(t)

	// This package only handles gc export data.
	if runtime.Compiler != "gc" {
		t.Skipf("gc-built packages not available (compiler = %s)", runtime.Compiler)
	}

	for _, test := range importedObjectTests {
		s := strings.Split(test.name, ".")
		if len(s) != 2 {
			t.Fatal("inconsistent test data")
		}
		importPath := s[0]
		objName := s[1]

		pkg, err := Import(make(map[string]*types2.Package), importPath, ".", nil)
		if err != nil {
			t.Error(err)
			continue
		}

		obj := pkg.Scope().Lookup(objName)
		if obj == nil {
			t.Errorf("%s: object not found", test.name)
			continue
		}

		got := types2.ObjectString(obj, types2.RelativeTo(pkg))
		if got != test.want {
			t.Errorf("%s: got %q; want %q", test.name, got, test.want)
		}

		if named, _ := obj.Type().(*types2.Named); named != nil {
			verifyInterfaceMethodRecvs(t, named, 0)
		}
	}
}

// verifyInterfaceMethodRecvs verifies that method receiver types
// are named if the methods belong to a named interface type.
func verifyInterfaceMethodRecvs(t *testing.T, named *types2.Named, level int) {
	// avoid endless recursion in case of an embedding bug that lead to a cycle
	if level > 10 {
		t.Errorf("%s: embeds itself", named)
		return
	}

	iface, _ := named.Underlying().(*types2.Interface)
	if iface == nil {
		return // not an interface
	}

	// The unified IR importer always sets interface method receiver
	// parameters to point to the Interface type, rather than the Named.
	// See #49906.
	var want types2.Type = iface

	// check explicitly declared methods
	for i := 0; i < iface.NumExplicitMethods(); i++ {
		m := iface.ExplicitMethod(i)
		recv := m.Type().(*types2.Signature).Recv()
		if recv == nil {
			t.Errorf("%s: missing receiver type", m)
			continue
		}
		if recv.Type() != want {
			t.Errorf("%s: got recv type %s; want %s", m, recv.Type(), named)
		}
	}

	// check embedded interfaces (if they are named, too)
	for i := 0; i < iface.NumEmbeddeds(); i++ {
		// embedding of interfaces cannot have cycles; recursion will terminate
		if etype, _ := iface.EmbeddedType(i).(*types2.Named); etype != nil {
			verifyInterfaceMethodRecvs(t, etype, level+1)
		}
	}
}

func TestIssue5815(t *testing.T) {
	testenv.MustHaveGoBuild(t)

	// This package only handles gc export data.
	if runtime.Compiler != "gc" {
		t.Skipf("gc-built packages not available (compiler = %s)", runtime.Compiler)
	}

	pkg := importPkg(t, "strings", ".")

	scope := pkg.Scope()
	for _, name := range scope.Names() {
		obj := scope.Lookup(name)
		if obj.Pkg() == nil {
			t.Errorf("no pkg for %s", obj)
		}
		if tname, _ := obj.(*types2.TypeName); tname != nil {
			named := tname.Type().(*types2.Named)
			for i := 0; i < named.NumMethods(); i++ {
				m := named.Method(i)
				if m.Pkg() == nil {
					t.Errorf("no pkg for %s", m)
				}
			}
		}
	}
}

// Smoke test to ensure that imported methods get the correct package.
func TestCorrectMethodPackage(t *testing.T) {
	testenv.MustHaveGoBuild(t)

	// This package only handles gc export data.
	if runtime.Compiler != "gc" {
		t.Skipf("gc-built packages not available (compiler = %s)", runtime.Compiler)
	}

	imports := make(map[string]*types2.Package)
	_, err := Import(imports, "net/http", ".", nil)
	if err != nil {
		t.Fatal(err)
	}

	mutex := imports["sync"].Scope().Lookup("Mutex").(*types2.TypeName).Type()
	obj, _, _ := types2.LookupFieldOrMethod(types2.NewPointer(mutex), false, nil, "Lock")
	lock := obj.(*types2.Func)
	if got, want := lock.Pkg().Path(), "sync"; got != want {
		t.Errorf("got package path %q; want %q", got, want)
	}
}

func TestIssue13566(t *testing.T) {
	testenv.MustHaveGoBuild(t)

	// This package only handles gc export data.
	if runtime.Compiler != "gc" {
		t.Skipf("gc-built packages not available (compiler = %s)", runtime.Compiler)
	}

	tmpdir := mktmpdir(t)
	testoutdir := filepath.Join(tmpdir, "testdata")

	// b.go needs to be compiled from the output directory so that the compiler can
	// find the compiled package a. We pass the full path to compile() so that we
	// don't have to copy the file to that directory.
	bpath, err := filepath.Abs(filepath.Join("testdata", "b.go"))
	if err != nil {
		t.Fatal(err)
	}

	jsonExport, _, err := exportdata.FindPkg("encoding/json", "testdata")
	if jsonExport == "" {
		t.Fatalf("no export data found for encoding/json: %v", err)
	}

	compile(t, "testdata", "a.go", testoutdir, map[string]string{"encoding/json": jsonExport})
	compile(t, testoutdir, bpath, testoutdir, map[string]string{"testdata/a": filepath.Join(testoutdir, "a.o")})

	// import must succeed (test for issue at hand)
	pkg := importPkg(t, "./testdata/b", tmpdir)

	// make sure all indirectly imported packages have names
	for _, imp := range pkg.Imports() {
		if imp.Name() == "" {
			t.Errorf("no name for %s package", imp.Path())
		}
	}
}

func TestIssue13898(t *testing.T) {
	testenv.MustHaveGoBuild(t)

	// This package only handles gc export data.
	if runtime.Compiler != "gc" {
		t.Skipf("gc-built packages not available (compiler = %s)", runtime.Compiler)
	}

	// import go/internal/gcimporter which imports go/types partially
	imports := make(map[string]*types2.Package)
	_, err := Import(imports, "go/internal/gcimporter", ".", nil)
	if err != nil {
		t.Fatal(err)
	}

	// look for go/types package
	var goTypesPkg *types2.Package
	for path, pkg := range imports {
		if path == "go/types" {
			goTypesPkg = pkg
			break
		}
	}
	if goTypesPkg == nil {
		t.Fatal("go/types not found")
	}

	// look for go/types.Object type
	obj := lookupObj(t, goTypesPkg.Scope(), "Object")
	typ, ok := obj.Type().(*types2.Named)
	if !ok {
		t.Fatalf("go/types.Object type is %v; wanted named type", typ)
	}

	// lookup go/types.Object.Pkg method
	m, index, indirect := types2.LookupFieldOrMethod(typ, false, nil, "Pkg")
	if m == nil {
		t.Fatalf("go/types.Object.Pkg not found (index = %v, indirect = %v)", index, indirect)
	}

	// the method must belong to go/types
	if m.Pkg().Path() != "go/types" {
		t.Fatalf("found %v; want go/types", m.Pkg())
	}
}

func TestIssue15517(t *testing.T) {
	testenv.MustHaveGoBuild(t)

	// This package only handles gc export data.
	if runtime.Compiler != "gc" {
		t.Skipf("gc-built packages not available (compiler = %s)", runtime.Compiler)
	}

	tmpdir := mktmpdir(t)

	compile(t, "testdata", "p.go", filepath.Join(tmpdir, "testdata"), nil)

	// Multiple imports of p must succeed without redeclaration errors.
	// We use an import path that's not cleaned up so that the eventual
	// file path for the package is different from the package path; this
	// will expose the error if it is present.
	//
	// (Issue: Both the textual and the binary importer used the file path
	// of the package to be imported as key into the shared packages map.
	// However, the binary importer then used the package path to identify
	// the imported package to mark it as complete; effectively marking the
	// wrong package as complete. By using an "unclean" package path, the
	// file and package path are different, exposing the problem if present.
	// The same issue occurs with vendoring.)
	imports := make(map[string]*types2.Package)
	for i := 0; i < 3; i++ {
		if _, err := Import(imports, "./././testdata/p", tmpdir, nil); err != nil {
			t.Fatal(err)
		}
	}
}

func TestIssue15920(t *testing.T) {
	testenv.MustHaveGoBuild(t)

	// This package only handles gc export data.
	if runtime.Compiler != "gc" {
		t.Skipf("gc-built packages not available (compiler = %s)", runtime.Compiler)
	}

	compileAndImportPkg(t, "issue15920")
}

func TestIssue20046(t *testing.T) {
	testenv.MustHaveGoBuild(t)

	// This package only handles gc export data.
	if runtime.Compiler != "gc" {
		t.Skipf("gc-built packages not available (compiler = %s)", runtime.Compiler)
	}

	// "./issue20046".V.M must exist
	pkg := compileAndImportPkg(t, "issue20046")
	obj := lookupObj(t, pkg.Scope(), "V")
	if m, index, indirect := types2.LookupFieldOrMethod(obj.Type(), false, nil, "M"); m == nil {
		t.Fatalf("V.M not found (index = %v, indirect = %v)", index, indirect)
	}
}
func TestIssue25301(t *testing.T) {
	testenv.MustHaveGoBuild(t)

	// This package only handles gc export data.
	if runtime.Compiler != "gc" {
		t.Skipf("gc-built packages not available (compiler = %s)", runtime.Compiler)
	}

	compileAndImportPkg(t, "issue25301")
}

func TestIssue25596(t *testing.T) {
	testenv.MustHaveGoBuild(t)

	// This package only handles gc export data.
	if runtime.Compiler != "gc" {
		t.Skipf("gc-built packages not available (compiler = %s)", runtime.Compiler)
	}

	compileAndImportPkg(t, "issue25596")
}

func importPkg(t *testing.T, path, srcDir string) *types2.Package {
	pkg, err := Import(make(map[string]*types2.Package), path, srcDir, nil)
	if err != nil {
		t.Helper()
		t.Fatal(err)
	}
	return pkg
}

func compileAndImportPkg(t *testing.T, name string) *types2.Package {
	t.Helper()
	tmpdir := mktmpdir(t)
	compile(t, "testdata", name+".go", filepath.Join(tmpdir, "testdata"), nil)
	return importPkg(t, "./testdata/"+name, tmpdir)
}

func lookupObj(t *testing.T, scope *types2.Scope, name string) types2.Object {
	if obj := scope.Lookup(name); obj != nil {
		return obj
	}
	t.Helper()
	t.Fatalf("%s not found", name)
	return nil
}

// importMap implements the types2.Importer interface.
type importMap map[string]*types2.Package

func (m importMap) Import(path string) (*types2.Package, error) { return m[path], nil }

func TestIssue69912(t *testing.T) {
	testenv.MustHaveGoBuild(t)

	// This package only handles gc export data.
	if runtime.Compiler != "gc" {
		t.Skipf("gc-built packages not available (compiler = %s)", runtime.Compiler)
	}

	tmpdir := t.TempDir()
	testoutdir := filepath.Join(tmpdir, "testdata")
	if err := os.Mkdir(testoutdir, 0700); err != nil {
		t.Fatalf("making output dir: %v", err)
	}

	compile(t, "testdata", "issue69912.go", testoutdir, nil)

	issue69912, err := Import(make(map[string]*types2.Package), "./testdata/issue69912", tmpdir, nil)
	if err != nil {
		t.Fatal(err)
	}

	check := func(pkgname, src string, imports importMap) (*types2.Package, error) {
		f, err := syntax.Parse(syntax.NewFileBase(pkgname), strings.NewReader(src), nil, nil, 0)
		if err != nil {
			return nil, err
		}
		config := &types2.Config{
			Importer: imports,
		}
		return config.Check(pkgname, []*syntax.File{f}, nil)
	}

	// Use the resulting package concurrently, via dot-imports, to exercise the
	// race of issue #69912.
	const pSrc = `package p

import . "issue69912"

type S struct {
	f T
}
`
	importer := importMap{
		"issue69912": issue69912,
	}
	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := check("p", pSrc, importer); err != nil {
				t.Errorf("Check failed: %v", err)
			}
		}()
	}
	wg.Wait()
}
```