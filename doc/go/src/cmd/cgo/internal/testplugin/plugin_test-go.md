Response:
The user wants to understand the functionality of the Go code provided, which is a test file for the `plugin` package in Go.

Here's a breakdown of the thought process to address the request:

1. **Identify the core purpose:** The file `plugin_test.go` located in `go/src/cmd/cgo/internal/testplugin/` strongly suggests it's a testing suite for the Go plugin functionality. The `package plugin_test` further confirms this.

2. **Analyze `TestMain` function:** This is the entry point for the tests. It performs crucial setup steps:
    * Parses command-line flags.
    * Sets up logging.
    * Implements skip conditions based on `testing.Short()`, platform support for plugins, and CGO availability.
    * Creates a temporary `GOPATH` and copies testdata into it. This is typical for isolated testing.
    * Builds several plugin `.so` files and a host executable. This indicates the tests will likely involve loading and interacting with these plugins.

3. **Examine helper functions:**
    * `prettyPrintf`:  A utility for formatted printing, sanitizing temporary directories from the output for cleaner logs.
    * `goCmd`: A crucial function that executes the `go` command with appropriate flags. This is the primary way the tests interact with the Go toolchain.
    * `escape`:  Escapes strings for shell command construction.
    * `asCommandLine`: Constructs a readable command-line representation of an `exec.Cmd`. This helps in debugging and understanding the executed commands.
    * `run`: Executes a command, captures output and errors, and handles test failures.

4. **Analyze individual `Test...` functions:** Each function prefixed with `Test` represents a specific test case. By examining their names and the `goCmd` calls within them, we can infer their purpose:
    * `TestDWARFSections`: Tests the generation of DWARF debugging information for plugins.
    * `TestBuildID`: Checks if plugins have a build ID.
    * `TestRunHost`: Runs the host executable.
    * `TestUniqueTypesAndItabs`:  Verifies that types and itabs are handled correctly across plugin boundaries.
    * `TestIssue...`:  These tests are specifically designed to address and prevent regressions for reported issues. Their names directly correspond to issue numbers in the Go issue tracker. They cover a range of scenarios, including:
        * Avoiding duplicate itabs (Issue 18676)
        * Handling non-alphanumeric characters in plugin paths (Issue 19534)
        * Linking variables into plugins (Issue 19418)
        * Loading multiple plugins (Issue 22175)
        * Building plugins in packages (Issue 22295)
        * Interaction with garbage collection (Issue 25756)
        * Using plugins with PIE executables (TestIssue25756pie)
        * Exporting and calling methods from plugins (TestMethod, TestMethod2, TestMethod3)
        * Resolving symbols across plugins (Issue 44956)
        * Building plugins without a main package (Issue 52937)
        * Handling function calls across plugin boundaries (Issue 53989)
        * Issues with `fork/exec` and plugins on macOS (TestForkExec)
        * Handling special characters in symbol names (TestSymbolNameMangle)
        * Interaction of plugins with code splitting (TestTextSectionSplit)
        * Handling dynimport variables (Issue 67976)

5. **Identify the Go feature under test:** Based on the file name, package name, and the build mode used (`-buildmode=plugin`), it's clear the code tests the **Go plugin functionality**.

6. **Construct example code:** Create a simple example demonstrating how to build and load a Go plugin. This should include:
    * A plugin source file.
    * A host executable source file.
    * The commands to build both.
    * The code to load and use the plugin.

7. **Infer command-line arguments:** The `TestMain` function and the `goCmd` helper function use various command-line arguments for the `go` tool. List the important ones and explain their purpose in the context of plugin testing.

8. **Identify potential pitfalls:** Think about common errors developers might encounter when working with Go plugins, such as:
    * Incorrect `buildmode`.
    * Not handling errors during plugin loading.
    * Symbol conflicts between the host and plugin.
    * Platform compatibility issues.

9. **Structure the response:** Organize the findings into clear sections covering the functionality, the Go feature being tested, example code, command-line arguments, and potential pitfalls. Use code blocks for examples and clear explanations for each point.
The code snippet you provided is a part of the Go standard library's testing suite for the `plugin` package, specifically for the `cgo` tool's interaction with plugins. Let's break down its functionalities:

**Core Functionality:**

This test file aims to verify the correct behavior of Go plugins, especially in scenarios involving C code (due to its location within `cmd/cgo/internal`). It achieves this by:

1. **Building and Loading Plugins:** It dynamically compiles Go code into plugin files (`.so` on Linux/macOS, `.dll` on Windows) using the `-buildmode=plugin` flag.
2. **Executing Host Programs:** It compiles and runs Go executables that are designed to load and interact with the previously built plugins.
3. **Testing Various Plugin Features and Edge Cases:**  The individual `Test...` functions cover a wide range of plugin-related scenarios, including:
    * **Basic plugin loading and symbol access.**
    * **Handling of DWARF debugging information in plugins.**
    * **Verification of build IDs for plugins.**
    * **Ensuring unique types and itabs across plugin boundaries.**
    * **Testing fixes for specific reported issues (identified by issue numbers).** These tests often target subtle bugs or corner cases in the plugin implementation. Examples include issues related to:
        * Duplicate itabs.
        * Non-alphanumeric characters in plugin paths.
        * Linking variables into plugins.
        * Loading multiple plugins.
        * Building plugins within packages.
        * Interactions with garbage collection.
        * Using plugins with Position Independent Executables (PIE).
        * Exporting and calling methods from plugins.
        * Resolving symbols across multiple plugins.
        * Potential hangs during `fork/exec` on macOS.
        * Handling special characters in symbol names.
        * Code splitting and its impact on plugins.
        * Handling dynimport variables.
4. **Setting up Isolated Test Environments:** It creates temporary `GOPATH` directories to avoid interference with the user's actual Go environment.
5. **Sanitizing Output:** The `prettyPrintf` function helps to make the test output more readable by replacing temporary directory paths with `$TMPDIR`.
6. **Conditional Skipping:**  The `globalSkip` function and checks within `testMain` allow skipping tests based on factors like short testing mode, platform support for plugins, and the availability of CGO.

**Go Language Feature Implementation:**

This code directly tests the **Go plugin functionality**, introduced in Go 1.8. Plugins allow you to compile Go packages into shared libraries that can be loaded and used by other Go programs at runtime.

**Go Code Example:**

Here's a simplified example demonstrating the core functionality being tested:

**Plugin Code (plugin.go):**

```go
package main

var V int
var S = "hello from plugin"

func F() string {
	return S
}
```

**Host Code (host.go):**

```go
package main

import (
	"fmt"
	"plugin"
)

func main() {
	p, err := plugin.Open("plugin.so") // Assuming plugin.so is built
	if err != nil {
		panic(err)
	}

	vSym, err := p.Lookup("V")
	if err != nil {
		panic(err)
	}
	var v *int
	v, ok := vSym.(*int)
	if !ok {
		panic("unexpected type from plugin")
	}
	*v = 42
	fmt.Println("Plugin V:", *v)

	fSym, err := p.Lookup("F")
	if err != nil {
		panic(err)
	}
	f, ok := fSym.(func() string)
	if !ok {
		panic("unexpected type from plugin")
	}
	fmt.Println("Plugin F():", f())
}
```

**Building and Running:**

```bash
# Build the plugin
go build -buildmode=plugin -o plugin.so plugin.go

# Build the host program
go build -o host host.go

# Run the host program
./host
```

**Assumptions for the Example:**

* You have a Go development environment set up.
* The `plugin.go` and `host.go` files are in the same directory.

**Expected Output:**

```
Plugin V: 42
Plugin F(): hello from plugin
```

**Code Reasoning with Hypothetical Input and Output:**

Let's consider the `TestBuildID` function:

**Hypothetical Input:**

*  The `plugin1.so` file has been successfully built using `go build -buildmode=plugin ./plugin1`.

**Code Execution:**

```go
func TestBuildID(t *testing.T) {
	// check that plugin has build ID.
	globalSkip(t)
	b := goCmd(t, "tool", "buildid", "plugin1.so")
	if len(b) == 0 {
		t.Errorf("build id not found")
	}
}
```

* `goCmd(t, "tool", "buildid", "plugin1.so")` executes the command `go tool buildid plugin1.so`. This command extracts the build ID from the `plugin1.so` file.

**Hypothetical Output:**

* If `plugin1.so` was built correctly, the `buildid` tool will return a non-empty string representing the build ID (e.g., "some_long_hexadecimal_string"). This value will be assigned to the variable `b`.
* The `if len(b) == 0` condition will be false, and the test will pass.

**Command-Line Parameter Handling (within the test file):**

The test file itself doesn't directly process command-line arguments in the way a typical application does. However, it uses the `flag` package within the `TestMain` function:

```go
func TestMain(m *testing.M) {
	flag.Parse()
	// ... rest of the code
}
```

* `flag.Parse()`: This parses the standard Go testing flags, such as `-test.short`, which is used to conditionally skip tests in `testMain`.

The test file heavily relies on the `go` command-line tool for building plugins and executables. The `goCmd` helper function encapsulates the execution of the `go` command and allows specifying various subcommands and flags. For example:

* `goCmd(nil, "build", "-buildmode=plugin", "./plugin1")`:  Executes `go build -buildmode=plugin ./plugin1`.
    * `build`: The `go` command's build subcommand.
    * `-buildmode=plugin`: A crucial flag that tells the Go compiler to build a plugin.
    * `./plugin1`: The path to the Go package to be built as a plugin.
* `goCmd(nil, "build", "-o", "host.exe", "./host")`: Executes `go build -o host.exe ./host`.
    * `-o host.exe`: Specifies the output file name for the executable.

**Common Mistakes for Users of the `plugin` Package:**

While this code tests the implementation, here are some common mistakes users might make when working with Go plugins:

1. **Incorrect `buildmode`:** Forgetting to use `-buildmode=plugin` when building the plugin will result in a regular package or executable, which cannot be loaded as a plugin.

   ```bash
   # Incorrect: Builds a regular package
   go build ./myplugin

   # Correct: Builds a plugin
   go build -buildmode=plugin -o myplugin.so ./myplugin
   ```

2. **Symbol Versioning and Compatibility:** If the host program and the plugin are compiled with significantly different versions of dependencies or the Go runtime itself, symbol mismatches can occur, leading to errors during plugin loading or execution. This is why the test suite often builds both the host and plugins in the same test run with the same Go version.

3. **Exporting Symbols:** Only exported Go symbols (starting with a capital letter) in the plugin can be accessed by the host program using `plugin.Lookup`. Trying to access unexported symbols will result in an error.

   ```go
   // In the plugin:
   var PublicVar int // Accessible from host
   var privateVar int // Not accessible from host
   ```

4. **Type Compatibility:**  When using `plugin.Lookup`, it's crucial to correctly assert the type of the retrieved symbol. Incorrect type assertions will lead to panics.

   ```go
   // In the host:
   symbol, err := p.Lookup("MyFunction")
   if err != nil {
       // ... handle error
   }
   // Incorrect type assertion (if MyFunction doesn't match)
   myFunc, ok := symbol.(func(int) string)
   if !ok {
       // ... handle type error
   }
   ```

5. **Platform Dependency:** Plugins are generally platform-specific. A plugin built on Linux might not work on Windows, and vice versa. The test suite includes checks for platform compatibility.

This comprehensive breakdown should give you a good understanding of the functionality of the provided Go test code and its relationship to the Go plugin feature.

### 提示词
```
这是路径为go/src/cmd/cgo/internal/testplugin/plugin_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package plugin_test

import (
	"bytes"
	"cmd/cgo/internal/cgotest"
	"context"
	"flag"
	"fmt"
	"internal/platform"
	"internal/testenv"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

var globalSkip = func(t *testing.T) {}

var gcflags string = os.Getenv("GO_GCFLAGS")
var goroot string

func TestMain(m *testing.M) {
	flag.Parse()
	log.SetFlags(log.Lshortfile)
	os.Exit(testMain(m))
}

// tmpDir is used to cleanup logged commands -- s/tmpDir/$TMPDIR/
var tmpDir string

// prettyPrintf prints lines with tmpDir sanitized.
func prettyPrintf(format string, args ...interface{}) {
	s := fmt.Sprintf(format, args...)
	if tmpDir != "" {
		s = strings.ReplaceAll(s, tmpDir, "$TMPDIR")
	}
	fmt.Print(s)
}

func testMain(m *testing.M) int {
	if testing.Short() && os.Getenv("GO_BUILDER_NAME") == "" {
		globalSkip = func(t *testing.T) { t.Skip("short mode and $GO_BUILDER_NAME not set") }
		return m.Run()
	}
	if !platform.BuildModeSupported(runtime.Compiler, "plugin", runtime.GOOS, runtime.GOARCH) {
		globalSkip = func(t *testing.T) { t.Skip("plugin build mode not supported") }
		return m.Run()
	}
	if !testenv.HasCGO() {
		globalSkip = func(t *testing.T) { t.Skip("cgo not supported") }
		return m.Run()
	}

	cwd, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	goroot = filepath.Join(cwd, "../../../../..")

	// Copy testdata into GOPATH/src/testplugin, along with a go.mod file
	// declaring the same path.

	GOPATH, err := os.MkdirTemp("", "plugin_test")
	if err != nil {
		log.Panic(err)
	}
	defer os.RemoveAll(GOPATH)
	tmpDir = GOPATH
	fmt.Printf("TMPDIR=%s\n", tmpDir)

	modRoot := filepath.Join(GOPATH, "src", "testplugin")
	altRoot := filepath.Join(GOPATH, "alt", "src", "testplugin")
	for srcRoot, dstRoot := range map[string]string{
		"testdata":                           modRoot,
		filepath.Join("altpath", "testdata"): altRoot,
	} {
		if err := cgotest.OverlayDir(dstRoot, srcRoot); err != nil {
			log.Panic(err)
		}
		prettyPrintf("mkdir -p %s\n", dstRoot)
		prettyPrintf("rsync -a %s/ %s\n", srcRoot, dstRoot)

		if err := os.WriteFile(filepath.Join(dstRoot, "go.mod"), []byte("module testplugin\n"), 0666); err != nil {
			log.Panic(err)
		}
		prettyPrintf("echo 'module testplugin' > %s/go.mod\n", dstRoot)
	}

	os.Setenv("GOPATH", filepath.Join(GOPATH, "alt"))
	if err := os.Chdir(altRoot); err != nil {
		log.Panic(err)
	} else {
		prettyPrintf("cd %s\n", altRoot)
	}
	os.Setenv("PWD", altRoot)
	goCmd(nil, "build", "-buildmode=plugin", "-o", filepath.Join(modRoot, "plugin-mismatch.so"), "./plugin-mismatch")

	os.Setenv("GOPATH", GOPATH)
	if err := os.Chdir(modRoot); err != nil {
		log.Panic(err)
	} else {
		prettyPrintf("cd %s\n", modRoot)
	}
	os.Setenv("PWD", modRoot)

	os.Setenv("LD_LIBRARY_PATH", modRoot)

	goCmd(nil, "build", "-buildmode=plugin", "./plugin1")
	goCmd(nil, "build", "-buildmode=plugin", "./plugin2")
	so, err := os.ReadFile("plugin2.so")
	if err != nil {
		log.Panic(err)
	}
	if err := os.WriteFile("plugin2-dup.so", so, 0444); err != nil {
		log.Panic(err)
	}
	prettyPrintf("cp plugin2.so plugin2-dup.so\n")

	goCmd(nil, "build", "-buildmode=plugin", "-o=sub/plugin1.so", "./sub/plugin1")
	goCmd(nil, "build", "-buildmode=plugin", "-o=unnamed1.so", "./unnamed1/main.go")
	goCmd(nil, "build", "-buildmode=plugin", "-o=unnamed2.so", "./unnamed2/main.go")
	goCmd(nil, "build", "-o", "host.exe", "./host")

	return m.Run()
}

func goCmd(t *testing.T, op string, args ...string) string {
	if t != nil {
		t.Helper()
	}
	var flags []string
	if op != "tool" {
		flags = []string{"-gcflags", gcflags}
	}
	return run(t, filepath.Join(goroot, "bin", "go"), append(append([]string{op}, flags...), args...)...)
}

// escape converts a string to something suitable for a shell command line.
func escape(s string) string {
	s = strings.Replace(s, "\\", "\\\\", -1)
	s = strings.Replace(s, "'", "\\'", -1)
	// Conservative guess at characters that will force quoting
	if s == "" || strings.ContainsAny(s, "\\ ;#*&$~?!|[]()<>{}`") {
		s = "'" + s + "'"
	}
	return s
}

// asCommandLine renders cmd as something that could be copy-and-pasted into a command line
func asCommandLine(cwd string, cmd *exec.Cmd) string {
	s := "("
	if cmd.Dir != "" && cmd.Dir != cwd {
		s += "cd" + escape(cmd.Dir) + ";"
	}
	for _, e := range cmd.Env {
		if !strings.HasPrefix(e, "PATH=") &&
			!strings.HasPrefix(e, "HOME=") &&
			!strings.HasPrefix(e, "USER=") &&
			!strings.HasPrefix(e, "SHELL=") {
			s += " "
			s += escape(e)
		}
	}
	// These EVs are relevant to this test.
	for _, e := range os.Environ() {
		if strings.HasPrefix(e, "PWD=") ||
			strings.HasPrefix(e, "GOPATH=") ||
			strings.HasPrefix(e, "LD_LIBRARY_PATH=") {
			s += " "
			s += escape(e)
		}
	}
	for _, a := range cmd.Args {
		s += " "
		s += escape(a)
	}
	s += " )"
	return s
}

func run(t *testing.T, bin string, args ...string) string {
	cmd := exec.Command(bin, args...)
	cmdLine := asCommandLine(".", cmd)
	prettyPrintf("%s\n", cmdLine)
	cmd.Stderr = new(strings.Builder)
	out, err := cmd.Output()
	if err != nil {
		if t == nil {
			log.Panicf("%s: %v\n%s", strings.Join(cmd.Args, " "), err, cmd.Stderr)
		} else {
			t.Helper()
			t.Fatalf("%s: %v\n%s", strings.Join(cmd.Args, " "), err, cmd.Stderr)
		}
	}

	return string(bytes.TrimSpace(out))
}

func TestDWARFSections(t *testing.T) {
	// test that DWARF sections are emitted for plugins and programs importing "plugin"
	globalSkip(t)
	goCmd(t, "run", "./checkdwarf/main.go", "plugin2.so", "plugin2.UnexportedNameReuse")
	goCmd(t, "run", "./checkdwarf/main.go", "./host.exe", "main.main")
}

func TestBuildID(t *testing.T) {
	// check that plugin has build ID.
	globalSkip(t)
	b := goCmd(t, "tool", "buildid", "plugin1.so")
	if len(b) == 0 {
		t.Errorf("build id not found")
	}
}

func TestRunHost(t *testing.T) {
	globalSkip(t)
	run(t, "./host.exe")
}

func TestUniqueTypesAndItabs(t *testing.T) {
	globalSkip(t)
	goCmd(t, "build", "-buildmode=plugin", "./iface_a")
	goCmd(t, "build", "-buildmode=plugin", "./iface_b")
	goCmd(t, "build", "-o", "iface.exe", "./iface")
	run(t, "./iface.exe")
}

func TestIssue18676(t *testing.T) {
	// make sure we don't add the same itab twice.
	// The buggy code hangs forever, so use a timeout to check for that.
	globalSkip(t)
	goCmd(t, "build", "-buildmode=plugin", "-o", "plugin.so", "./issue18676/plugin.go")
	goCmd(t, "build", "-o", "issue18676.exe", "./issue18676/main.go")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "./issue18676.exe")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v\n%s", strings.Join(cmd.Args, " "), err, out)
	}
}

func TestIssue19534(t *testing.T) {
	// Test that we can load a plugin built in a path with non-alpha characters.
	globalSkip(t)
	goCmd(t, "build", "-buildmode=plugin", "-gcflags=-p=issue.19534", "-ldflags=-pluginpath=issue.19534", "-o", "plugin.so", "./issue19534/plugin.go")
	goCmd(t, "build", "-o", "issue19534.exe", "./issue19534/main.go")
	run(t, "./issue19534.exe")
}

func TestIssue18584(t *testing.T) {
	globalSkip(t)
	goCmd(t, "build", "-buildmode=plugin", "-o", "plugin.so", "./issue18584/plugin.go")
	goCmd(t, "build", "-o", "issue18584.exe", "./issue18584/main.go")
	run(t, "./issue18584.exe")
}

func TestIssue19418(t *testing.T) {
	globalSkip(t)
	goCmd(t, "build", "-buildmode=plugin", "-ldflags=-X main.Val=linkstr", "-o", "plugin.so", "./issue19418/plugin.go")
	goCmd(t, "build", "-o", "issue19418.exe", "./issue19418/main.go")
	run(t, "./issue19418.exe")
}

func TestIssue19529(t *testing.T) {
	globalSkip(t)
	goCmd(t, "build", "-buildmode=plugin", "-o", "plugin.so", "./issue19529/plugin.go")
}

func TestIssue22175(t *testing.T) {
	globalSkip(t)
	goCmd(t, "build", "-buildmode=plugin", "-o", "issue22175_plugin1.so", "./issue22175/plugin1.go")
	goCmd(t, "build", "-buildmode=plugin", "-o", "issue22175_plugin2.so", "./issue22175/plugin2.go")
	goCmd(t, "build", "-o", "issue22175.exe", "./issue22175/main.go")
	run(t, "./issue22175.exe")
}

func TestIssue22295(t *testing.T) {
	globalSkip(t)
	goCmd(t, "build", "-buildmode=plugin", "-o", "issue.22295.so", "./issue22295.pkg")
	goCmd(t, "build", "-o", "issue22295.exe", "./issue22295.pkg/main.go")
	run(t, "./issue22295.exe")
}

func TestIssue24351(t *testing.T) {
	globalSkip(t)
	goCmd(t, "build", "-buildmode=plugin", "-o", "issue24351.so", "./issue24351/plugin.go")
	goCmd(t, "build", "-o", "issue24351.exe", "./issue24351/main.go")
	run(t, "./issue24351.exe")
}

func TestIssue25756(t *testing.T) {
	globalSkip(t)
	goCmd(t, "build", "-buildmode=plugin", "-o", "life.so", "./issue25756/plugin")
	goCmd(t, "build", "-o", "issue25756.exe", "./issue25756/main.go")
	// Fails intermittently, but 20 runs should cause the failure
	for n := 20; n > 0; n-- {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			t.Parallel()
			run(t, "./issue25756.exe")
		})
	}
}

// Test with main using -buildmode=pie with plugin for issue #43228
func TestIssue25756pie(t *testing.T) {
	globalSkip(t)
	goCmd(t, "build", "-buildmode=plugin", "-o", "life.so", "./issue25756/plugin")
	goCmd(t, "build", "-buildmode=pie", "-o", "issue25756pie.exe", "./issue25756/main.go")
	run(t, "./issue25756pie.exe")
}

func TestMethod(t *testing.T) {
	// Exported symbol's method must be live.
	globalSkip(t)
	goCmd(t, "build", "-buildmode=plugin", "-o", "plugin.so", "./method/plugin.go")
	goCmd(t, "build", "-o", "method.exe", "./method/main.go")
	run(t, "./method.exe")
}

func TestMethod2(t *testing.T) {
	globalSkip(t)
	goCmd(t, "build", "-buildmode=plugin", "-o", "method2.so", "./method2/plugin.go")
	goCmd(t, "build", "-o", "method2.exe", "./method2/main.go")
	run(t, "./method2.exe")
}

func TestMethod3(t *testing.T) {
	globalSkip(t)
	goCmd(t, "build", "-buildmode=plugin", "-o", "method3.so", "./method3/plugin.go")
	goCmd(t, "build", "-o", "method3.exe", "./method3/main.go")
	run(t, "./method3.exe")
}

func TestIssue44956(t *testing.T) {
	globalSkip(t)
	goCmd(t, "build", "-buildmode=plugin", "-o", "issue44956p1.so", "./issue44956/plugin1.go")
	goCmd(t, "build", "-buildmode=plugin", "-o", "issue44956p2.so", "./issue44956/plugin2.go")
	goCmd(t, "build", "-o", "issue44956.exe", "./issue44956/main.go")
	run(t, "./issue44956.exe")
}

func TestIssue52937(t *testing.T) {
	globalSkip(t)
	goCmd(t, "build", "-buildmode=plugin", "-o", "issue52937.so", "./issue52937/main.go")
}

func TestIssue53989(t *testing.T) {
	globalSkip(t)
	goCmd(t, "build", "-buildmode=plugin", "-o", "issue53989.so", "./issue53989/plugin.go")
	goCmd(t, "build", "-o", "issue53989.exe", "./issue53989/main.go")
	run(t, "./issue53989.exe")
}

func TestForkExec(t *testing.T) {
	// Issue 38824: importing the plugin package causes it hang in forkExec on darwin.
	globalSkip(t)

	t.Parallel()
	goCmd(t, "build", "-o", "forkexec.exe", "./forkexec/main.go")

	for i := 0; i < 100; i++ {
		cmd := testenv.Command(t, "./forkexec.exe", "1")
		err := cmd.Run()
		if err != nil {
			if ee, ok := err.(*exec.ExitError); ok && len(ee.Stderr) > 0 {
				t.Logf("stderr:\n%s", ee.Stderr)
			}
			t.Errorf("running command failed: %v", err)
			break
		}
	}
}

func TestSymbolNameMangle(t *testing.T) {
	// Issue 58800: generic function name may contain weird characters
	// that confuse the external linker.
	// Issue 62098: the name mangling code doesn't handle some string
	// symbols correctly.
	globalSkip(t)
	goCmd(t, "build", "-buildmode=plugin", "-o", "mangle.so", "./mangle/plugin.go")
}

func TestIssue62430(t *testing.T) {
	globalSkip(t)
	goCmd(t, "build", "-buildmode=plugin", "-o", "issue62430.so", "./issue62430/plugin.go")
	goCmd(t, "build", "-o", "issue62430.exe", "./issue62430/main.go")
	run(t, "./issue62430.exe")
}

func TestTextSectionSplit(t *testing.T) {
	globalSkip(t)
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skipf("text section splitting is not done in %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	// Use -ldflags=-debugtextsize=262144 to let the linker split text section
	// at a smaller size threshold, so it actually splits for the test binary.
	goCmd(nil, "build", "-ldflags=-debugtextsize=262144", "-o", "host-split.exe", "./host")
	run(t, "./host-split.exe")

	// Check that we did split text sections.
	syms := goCmd(nil, "tool", "nm", "host-split.exe")
	if !strings.Contains(syms, "runtime.text.1") {
		t.Errorf("runtime.text.1 not found, text section not split?")
	}
}

func TestIssue67976(t *testing.T) {
	// Issue 67976: build failure with loading a dynimport variable (the runtime/pprof
	// package does this on darwin) in a plugin on darwin/amd64.
	// The test program uses runtime/pprof in a plugin.
	globalSkip(t)
	goCmd(t, "build", "-buildmode=plugin", "-o", "issue67976.so", "./issue67976/plugin.go")
}
```