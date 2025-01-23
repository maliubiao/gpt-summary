Response:
Let's break down the thought process for analyzing the given Go code snippet.

**1. Initial Understanding and Context:**

* **File Path:** `go/src/cmd/cgo/internal/testsanitizers/cc_test.go` immediately tells us this is a test file (`_test.go`) within the `cgo` tool's internal testing framework, specifically related to "sanitizers".
* **Copyright and Build Constraints:**  The copyright notice is standard. The `//go:build` line is crucial. It restricts the test execution to Linux and FreeBSD (amd64). This hints that the tests involve system-level features or interactions specific to these platforms. The comment about `Pdeathsig` further confirms this.
* **Package Name:** `sanitizers_test` indicates this test suite focuses on how Go code interacts with memory safety and concurrency sanitizers (like ASan, MSan, TSan).
* **Import Statements:**  The imported packages provide strong clues about the functionality:
    * `bytes`, `encoding/json`, `fmt`, `strconv`, `strings`, `unicode`:  Basic string/data manipulation, likely for parsing output or constructing commands.
    * `errors`:  Error handling.
    * `internal/testenv`: Access to the Go testing environment's configuration.
    * `os`, `os/exec`, `os/user`:  Interacting with the operating system, executing commands, and getting user information. This is central to the purpose of the file.
    * `path/filepath`:  Working with file paths.
    * `regexp`:  Regular expression matching, probably for parsing compiler output.
    * `sync`:  Synchronization primitives (like `sync.Once`, `sync.Mutex`), suggesting potential for concurrent operations or controlled initialization.
    * `syscall`:  Low-level system calls, aligning with the build constraints and the `Pdeathsig` comment.
    * `testing`:  The core Go testing framework.
    * `time`:  Time-related functions, likely for timeouts in tests.

**2. Identifying Key Data Structures and Functions:**

* **`overcommit`:** A `sync.Once` with a value and error. This pattern suggests lazy initialization of some overcommit-related setting, likely read from a file. The `requireOvercommit` function confirms this.
* **`env`:** Similar to `overcommit`, but used to cache the output of `go env -json`. The `goEnv` function utilizes this.
* **`replaceEnv`, `appendExperimentEnv`:** Helper functions for modifying the environment of `exec.Cmd` objects. This is typical when running subprocesses with specific configurations.
* **`mustRun`:**  A function to execute a command and fail the test if it encounters an error. The timeout logic is interesting and important for preventing test hangs.
* **`cc`:**  A crucial function. It constructs a command to invoke the C compiler (`$(go env CC)`) with appropriate flags (`$(go env GOGCCFLAGS)`). The complex flag parsing logic within `cc` is worth noting.
* **`version` and `compiler`:**  Used to cache and retrieve the C compiler's version. The `compilerVersion` function performs the actual version detection using `cc --version` and parsing its output.
* **`compilerSupportsLocation`, `inLUCIBuild`, `compilerRequiredTsanVersion`, `compilerRequiredAsanVersion`:** Functions that check specific properties or requirements related to the compiler version and the execution environment.
* **`compilerCheck`:**  A struct for managing checks related to the compiler's ability to work with sanitizers.
* **`config`:**  A central struct that holds the configuration for a specific sanitizer (like ASan, MSan, TSan). It stores C flags, linker flags, and Go flags. The `configure` function creates and manages these configurations.
* **`configs`:** A `sync.Mutex`-protected map to store the `config` objects.
* **`goCmd`, `goCmdWithExperiments`:**  Functions to create `exec.Cmd` objects for running `go` commands with the correct flags and environment variables based on the `config`.
* **`skipIfCSanitizerBroken`, `skipIfRuntimeIncompatible`:**  Functions that use the `compilerCheck` mechanism to conditionally skip tests if the C compiler or Go runtime is incompatible with the configured sanitizer.
* **`checkCSanitizer`, `checkRuntime`:** The actual logic for verifying the C compiler and Go runtime compatibility. `checkCSanitizer` compiles and runs a simple C program. `checkRuntime` checks for the `CGO_TSAN` preprocessor definition.
* **`srcPath`, `tempDir`, `newTempDir`:**  Utilities for managing test files and directories.
* **`hangProneCmd`:**  A function to create commands that are likely to hang, with specific `SysProcAttr` settings to ensure they are reliably killed.

**3. Inferring Functionality and Purpose:**

By examining the data structures and functions, the primary purpose becomes clear: **This file provides a framework for testing Go code that interacts with C code (via cgo) when various sanitizers are enabled.**

* **Sanitizer Configuration:** The `config` struct and `configure` function are central to setting up the build environment for different sanitizers.
* **Compiler Interaction:** The `cc` and `compilerVersion` functions handle interaction with the C compiler.
* **Test Execution:** The `goCmd` and `mustRun` functions manage the execution of Go commands.
* **Compatibility Checks:** The `skipIfCSanitizerBroken` and `skipIfRuntimeIncompatible` functions ensure that tests are skipped if the environment is not correctly configured for the target sanitizer. This prevents spurious test failures.
* **Handling Potential Issues:** The `hangProneCmd` function addresses the problem of tests hanging when sanitizers are involved.

**4. Generating Examples and Identifying Potential Pitfalls:**

Based on the understanding of the code, we can now generate examples and identify potential issues:

* **Example (ASan):**  Focus on how `configure("address")` sets up the flags and how `goCmd` uses this configuration. Show how to use `skipIfCSanitizerBroken`.
* **Example (`go env`):**  Demonstrate how `goEnv` retrieves environment variables.
* **Command-Line Arguments:** Explain that this file *doesn't directly handle command-line arguments*. Its purpose is to *configure* the environment for *other* Go commands.
* **Potential Pitfalls:** Highlight issues like:
    * **Incorrectly set environment variables:**  Explain how this framework *sets* these variables, so users typically don't need to do it manually when using these test functions.
    * **Unsupported platforms:** Emphasize the `//go:build` constraint.
    * **Missing compiler:**  Point out the dependency on a working C compiler.

**5. Structuring the Response:**

Finally, organize the findings into a clear and structured response, covering:

* **Overall Functionality:** A concise summary of the file's purpose.
* **Key Features:**  Listing the main functionalities with brief explanations.
* **Go Language Features:**  Providing illustrative examples of the Go features used (like `sync.Once`, `exec.Command`, `testing` package).
* **Code Reasoning:**  Explaining the logic behind important functions (like `cc` and the compatibility checks).
* **Command-Line Arguments:** Clarifying the role of this file in relation to command-line arguments.
* **Common Mistakes:**  Listing potential pitfalls for users of this testing framework.

This systematic approach, starting with high-level understanding and gradually drilling down into the details, allows for a comprehensive and accurate analysis of the Go code snippet.
The Go code snippet you provided is part of the testing framework for `cgo`, the mechanism that allows Go programs to call C code. Specifically, this file `cc_test.go` focuses on testing how Go programs interact with code compiled using C compilers when various *sanitizers* are enabled. Sanitizers are compiler flags and runtime libraries used to detect memory errors (like buffer overflows, use-after-free), data race conditions, and other undefined behavior in C and C++ code.

Here's a breakdown of its functionality:

**1. Configuration Management for Sanitizer Tests:**

* **`config` struct and `configure` function:** The core of this file revolves around the `config` struct, which stores compiler flags (`cFlags`), linker flags (`ldFlags`), and Go build flags (`goFlags`) necessary to enable specific sanitizers like AddressSanitizer (ASan), MemorySanitizer (MSan), ThreadSanitizer (TSan), and LibFuzzer. The `configure` function creates and caches these `config` objects based on the requested sanitizer name.

* **`configs` map:**  A map to store and retrieve the `config` objects, ensuring that the configuration for a specific sanitizer is only generated once.

**2. C Compiler Interaction:**

* **`cc` function:** This function constructs a command to invoke the C compiler (`$(go env CC)`) with the appropriate flags. It also incorporates the `GOGCCFLAGS` (flags passed to the C compiler when building Go code with cgo). It includes logic to correctly parse potentially quoted flags in `GOGCCFLAGS`.

* **`compilerVersion` function:**  This function attempts to determine the version of the C compiler being used (either GCC or Clang) by running `cc --version` and parsing the output using regular expressions. This is important because certain sanitizer features might have version requirements.

* **`compilerSupportsLocation`, `compilerRequiredTsanVersion`, `compilerRequiredAsanVersion` functions:** These functions use the information from `compilerVersion` to check if the current compiler version meets the requirements for supporting specific sanitizer features or the sanitizer itself on certain architectures.

**3. Go Command Execution with Sanitizers:**

* **`goCmd` and `goCmdWithExperiments` functions:** These functions create `exec.Cmd` objects to execute Go commands (like `go build`, `go test`). They automatically append the necessary Go flags (e.g., `-msan`, `-asan`, `--installsuffix=tsan`) and set the `CGO_CFLAGS` and `CGO_LDFLAGS` environment variables based on the `config` for the chosen sanitizer. `goCmdWithExperiments` also handles setting the `GOEXPERIMENT` environment variable.

* **`mustRun` function:**  A helper function to execute a command and fail the test if the command returns an error. It also includes a timeout mechanism using `t.Deadline()` to prevent tests from hanging indefinitely.

**4. Sanity Checks and Skipping Tests:**

* **`skipIfCSanitizerBroken` function:** This function checks if the C compiler is correctly configured to work with the specified sanitizer. It attempts to compile and run a simple C program with the sanitizer flags. If compilation or execution fails in a way that suggests the sanitizer is not working correctly (e.g., unrecognized flags), the test is skipped.

* **`skipIfRuntimeIncompatible` function:** This function performs checks to ensure the Go runtime is compatible with the configured sanitizer. For example, for ThreadSanitizer (TSan), it checks if the C compiler defines `CGO_TSAN` during preprocessing of `libcgo.h`, indicating TSan support is detected.

**5. Utility Functions:**

* **`requireOvercommit` function:** This function checks if the Linux kernel allows memory overcommit. Some sanitizer tests might rely on this setting.
* **`goEnv` function:** This function retrieves environment variables using `go env -json` and caches the results.
* **`replaceEnv` and `appendExperimentEnv` functions:**  Helpers to modify the environment variables of a command.
* **`inLUCIBuild` function:**  Detects if the tests are running in a LUCI (Google's continuous integration) environment.
* **`srcPath` function:**  Constructs the path to a file within the `testdata` directory.
* **`tempDir` and `newTempDir`:**  Utilities for creating and managing temporary directories for tests.
* **`hangProneCmd` function:** Creates commands that are potentially prone to hanging. It sets the `Pdeathsig` attribute on Linux to ensure the subprocess receives a `SIGKILL` if the parent process dies unexpectedly (important for preventing orphaned processes during test failures with sanitizers).

**Inference of Go Language Features and Examples:**

This code extensively utilizes several core Go language features:

* **`testing` package:**  The foundation for writing unit tests in Go. Functions like `t.Helper()`, `t.Fatal()`, `t.Skipf()`, and `t.Deadline()` are used.

* **`os/exec` package:**  Used to execute external commands like `go` and the C compiler. The `exec.Command` struct and its methods are fundamental.

* **Environment Variables:** The code manipulates environment variables extensively using functions like `os.Environ()`, and sets specific variables for the C compiler (`CGO_CFLAGS`, `CGO_LDFLAGS`) and Go build process (`GOEXPERIMENT`).

* **String Manipulation:** The `strings` package is used for parsing compiler output and constructing command-line arguments.

* **Regular Expressions:** The `regexp` package is used to parse the output of the C compiler's version information.

* **Synchronization Primitives:** `sync.Once` and `sync.Mutex` are used for thread-safe initialization of variables like `overcommit`, `env`, and `configs`.

* **Error Handling:**  Go's standard error handling pattern (`if err != nil`) is prevalent throughout the code.

**Example of Go Code Functionality:**

Let's imagine a test case that needs to build a Go program with AddressSanitizer (ASan) enabled.

```go
func TestASanExample(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	cfg := configure("address") // Get the ASan configuration
	cfg.skipIfCSanitizerBroken(t) // Check if the C compiler works with ASan

	tmpDir := newTempDir(t)
	defer tmpDir.RemoveAll(t)

	// Create a simple Go file that uses cgo
	err := os.WriteFile(tmpDir.Join("main.go"), []byte(`
package main

// #include <stdlib.h>
import "C"

func main() {
	ptr := C.malloc(10)
	C.free(ptr)
	_ = *(*byte)(ptr) // Use-after-free, should be caught by ASan
}
`), 0644)
	if err != nil {
		t.Fatal(err)
	}

	cmd := cfg.goCmd("build", "-o", tmpDir.Join("asan_example"), tmpDir.Join("main.go"))
	mustRun(t, cmd) // Build the program with ASan flags

	// Run the built executable. ASan should detect the error and exit with a non-zero status.
	runCmd := hangProneCmd(tmpDir.Join("asan_example"))
	err = runCmd.Run()
	if err == nil {
		t.Fatalf("ASan did not detect the error")
	}

	// You might want to further inspect the error output to confirm ASan reported the issue.
}
```

**Assumptions and Input/Output for Code Reasoning:**

* **Assumption:** The `go` command and a compatible C compiler (specified by `$(go env CC)`) are available in the system's PATH.
* **Input (for `cc` function):**  A list of arguments to be passed to the C compiler.
* **Output (for `cc` function):** An `*exec.Cmd` object configured to run the C compiler with the provided arguments and relevant flags from `GOGCCFLAGS`.
* **Input (for `compilerVersion`):**  The output of `$(go env CC) --version`.
* **Output (for `compilerVersion`):** A `version` struct containing the major and minor version numbers of the compiler, or an error if parsing fails.

**Command-Line Argument Processing:**

This specific file doesn't directly process command-line arguments for the test execution itself. The `testing` package handles the standard Go test flags (like `-v`, `-short`). However, this file *constructs* commands that will be executed, and those commands might have their own arguments. For example, when the `cc` function builds a C file, it takes arguments like the source file and output path. The `goCmd` function similarly takes arguments for the `go` command (like `build`, `test`, and the package paths).

**Common Mistakes for Users:**

* **Assuming the environment is automatically set up:** Users might try to run sanitizer tests without ensuring they have a compatible C compiler and the necessary sanitizer libraries installed. This framework helps manage the configuration, but the underlying tools need to be present.

* **Manually setting `CGO_CFLAGS` and `CGO_LDFLAGS` when using this framework:** This framework is designed to manage these variables. Manually setting them might conflict with the configurations defined here.

* **Running tests on unsupported platforms:** The `//go:build` constraints limit the execution of these tests to specific operating systems and architectures. Trying to run them elsewhere will result in them being skipped or failing.

* **Not understanding the dependencies on `go env`:** The framework relies heavily on the output of `go env` to determine the C compiler and default flags. Issues with the Go installation or environment setup can lead to problems.

This detailed explanation should give you a good understanding of the functionality of `go/src/cmd/cgo/internal/testsanitizers/cc_test.go`. It's a crucial part of ensuring the reliability and correctness of Go's cgo integration when dealing with memory safety and concurrency concerns.

### 提示词
```
这是路径为go/src/cmd/cgo/internal/testsanitizers/cc_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This test uses the Pdeathsig field of syscall.SysProcAttr, so it only works
// on platforms that support that.

//go:build linux || (freebsd && amd64)

// sanitizers_test checks the use of Go with sanitizers like msan, asan, etc.
// See https://github.com/google/sanitizers.
package sanitizers_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"internal/testenv"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unicode"
)

var overcommit struct {
	sync.Once
	value int
	err   error
}

// requireOvercommit skips t if the kernel does not allow overcommit.
func requireOvercommit(t *testing.T) {
	t.Helper()

	overcommit.Once.Do(func() {
		var out []byte
		out, overcommit.err = os.ReadFile("/proc/sys/vm/overcommit_memory")
		if overcommit.err != nil {
			return
		}
		overcommit.value, overcommit.err = strconv.Atoi(string(bytes.TrimSpace(out)))
	})

	if overcommit.err != nil {
		t.Skipf("couldn't determine vm.overcommit_memory (%v); assuming no overcommit", overcommit.err)
	}
	if overcommit.value == 2 {
		t.Skip("vm.overcommit_memory=2")
	}
}

var env struct {
	sync.Once
	m   map[string]string
	err error
}

// goEnv returns the output of $(go env) as a map.
func goEnv(key string) (string, error) {
	env.Once.Do(func() {
		var out []byte
		out, env.err = exec.Command("go", "env", "-json").Output()
		if env.err != nil {
			return
		}

		env.m = make(map[string]string)
		env.err = json.Unmarshal(out, &env.m)
	})
	if env.err != nil {
		return "", env.err
	}

	v, ok := env.m[key]
	if !ok {
		return "", fmt.Errorf("`go env`: no entry for %v", key)
	}
	return v, nil
}

// replaceEnv sets the key environment variable to value in cmd.
func replaceEnv(cmd *exec.Cmd, key, value string) {
	if cmd.Env == nil {
		cmd.Env = cmd.Environ()
	}
	cmd.Env = append(cmd.Env, key+"="+value)
}

// appendExperimentEnv appends comma-separated experiments to GOEXPERIMENT.
func appendExperimentEnv(cmd *exec.Cmd, experiments []string) {
	if cmd.Env == nil {
		cmd.Env = cmd.Environ()
	}
	exps := strings.Join(experiments, ",")
	for _, evar := range cmd.Env {
		c := strings.SplitN(evar, "=", 2)
		if c[0] == "GOEXPERIMENT" {
			exps = c[1] + "," + exps
		}
	}
	cmd.Env = append(cmd.Env, "GOEXPERIMENT="+exps)
}

// mustRun executes t and fails cmd with a well-formatted message if it fails.
func mustRun(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	out := new(strings.Builder)
	cmd.Stdout = out
	cmd.Stderr = out

	err := cmd.Start()
	if err != nil {
		t.Fatalf("%v: %v", cmd, err)
	}

	if deadline, ok := t.Deadline(); ok {
		timeout := time.Until(deadline)
		timeout -= timeout / 10 // Leave 10% headroom for logging and cleanup.
		timer := time.AfterFunc(timeout, func() {
			cmd.Process.Signal(syscall.SIGQUIT)
		})
		defer timer.Stop()
	}

	if err := cmd.Wait(); err != nil {
		t.Fatalf("%v exited with %v\n%s", cmd, err, out)
	}
}

// cc returns a cmd that executes `$(go env CC) $(go env GOGCCFLAGS) $args`.
func cc(args ...string) (*exec.Cmd, error) {
	CC, err := goEnv("CC")
	if err != nil {
		return nil, err
	}

	GOGCCFLAGS, err := goEnv("GOGCCFLAGS")
	if err != nil {
		return nil, err
	}

	// Split GOGCCFLAGS, respecting quoting.
	//
	// TODO(bcmills): This code also appears in
	// cmd/cgo/internal/testcarchive/carchive_test.go, and perhaps ought to go in
	// src/cmd/dist/test.go as well. Figure out where to put it so that it can be
	// shared.
	var flags []string
	quote := '\000'
	start := 0
	lastSpace := true
	backslash := false
	for i, c := range GOGCCFLAGS {
		if quote == '\000' && unicode.IsSpace(c) {
			if !lastSpace {
				flags = append(flags, GOGCCFLAGS[start:i])
				lastSpace = true
			}
		} else {
			if lastSpace {
				start = i
				lastSpace = false
			}
			if quote == '\000' && !backslash && (c == '"' || c == '\'') {
				quote = c
				backslash = false
			} else if !backslash && quote == c {
				quote = '\000'
			} else if (quote == '\000' || quote == '"') && !backslash && c == '\\' {
				backslash = true
			} else {
				backslash = false
			}
		}
	}
	if !lastSpace {
		flags = append(flags, GOGCCFLAGS[start:])
	}

	cmd := exec.Command(CC, flags...)
	cmd.Args = append(cmd.Args, args...)
	return cmd, nil
}

type version struct {
	name         string
	major, minor int
}

var compiler struct {
	sync.Once
	version
	err error
}

// compilerVersion detects the version of $(go env CC).
//
// It returns a non-nil error if the compiler matches a known version schema but
// the version could not be parsed, or if $(go env CC) could not be determined.
func compilerVersion() (version, error) {
	compiler.Once.Do(func() {
		compiler.err = func() error {
			compiler.name = "unknown"

			cmd, err := cc("--version")
			if err != nil {
				return err
			}
			out, err := cmd.Output()
			if err != nil {
				// Compiler does not support "--version" flag: not Clang or GCC.
				return nil
			}

			var match [][]byte
			if bytes.HasPrefix(out, []byte("gcc")) {
				compiler.name = "gcc"
				cmd, err := cc("-dumpfullversion", "-dumpversion")
				if err != nil {
					return err
				}
				out, err := cmd.Output()
				if err != nil {
					// gcc, but does not support gcc's "-v" flag?!
					return err
				}
				gccRE := regexp.MustCompile(`(\d+)\.(\d+)`)
				match = gccRE.FindSubmatch(out)
			} else {
				clangRE := regexp.MustCompile(`clang version (\d+)\.(\d+)`)
				if match = clangRE.FindSubmatch(out); len(match) > 0 {
					compiler.name = "clang"
				}
			}

			if len(match) < 3 {
				return nil // "unknown"
			}
			if compiler.major, err = strconv.Atoi(string(match[1])); err != nil {
				return err
			}
			if compiler.minor, err = strconv.Atoi(string(match[2])); err != nil {
				return err
			}
			return nil
		}()
	})
	return compiler.version, compiler.err
}

// compilerSupportsLocation reports whether the compiler should be
// able to provide file/line information in backtraces.
func compilerSupportsLocation() bool {
	compiler, err := compilerVersion()
	if err != nil {
		return false
	}
	switch compiler.name {
	case "gcc":
		return compiler.major >= 10
	case "clang":
		// TODO(65606): The clang toolchain on the LUCI builders is not built against
		// zlib, the ASAN runtime can't actually symbolize its own stack trace. Once
		// this is resolved, one way or another, switch this back to 'true'. We still
		// have coverage from the 'gcc' case above.
		if inLUCIBuild() {
			return false
		}
		return true
	default:
		return false
	}
}

// inLUCIBuild returns true if we're currently executing in a LUCI build.
func inLUCIBuild() bool {
	u, err := user.Current()
	if err != nil {
		return false
	}
	return testenv.Builder() != "" && u.Username == "swarming"
}

// compilerRequiredTsanVersion reports whether the compiler is the version required by Tsan.
// Only restrictions for ppc64le are known; otherwise return true.
func compilerRequiredTsanVersion(goos, goarch string) bool {
	compiler, err := compilerVersion()
	if err != nil {
		return false
	}
	if compiler.name == "gcc" && goarch == "ppc64le" {
		return compiler.major >= 9
	}
	return true
}

// compilerRequiredAsanVersion reports whether the compiler is the version required by Asan.
func compilerRequiredAsanVersion(goos, goarch string) bool {
	compiler, err := compilerVersion()
	if err != nil {
		return false
	}
	switch compiler.name {
	case "gcc":
		if goarch == "loong64" {
			return compiler.major >= 14
		}
		if goarch == "ppc64le" {
			return compiler.major >= 9
		}
		return compiler.major >= 7
	case "clang":
		if goarch == "loong64" {
			return compiler.major >= 16
		}
		return compiler.major >= 9
	default:
		return false
	}
}

type compilerCheck struct {
	once sync.Once
	err  error
	skip bool // If true, skip with err instead of failing with it.
}

type config struct {
	sanitizer string

	cFlags, ldFlags, goFlags []string

	sanitizerCheck, runtimeCheck compilerCheck
}

var configs struct {
	sync.Mutex
	m map[string]*config
}

// configure returns the configuration for the given sanitizer.
func configure(sanitizer string) *config {
	configs.Lock()
	defer configs.Unlock()
	if c, ok := configs.m[sanitizer]; ok {
		return c
	}

	c := &config{
		sanitizer: sanitizer,
		cFlags:    []string{"-fsanitize=" + sanitizer},
		ldFlags:   []string{"-fsanitize=" + sanitizer},
	}

	if testing.Verbose() {
		c.goFlags = append(c.goFlags, "-x")
	}

	switch sanitizer {
	case "memory":
		c.goFlags = append(c.goFlags, "-msan")

	case "thread":
		c.goFlags = append(c.goFlags, "--installsuffix=tsan")
		compiler, _ := compilerVersion()
		if compiler.name == "gcc" {
			c.cFlags = append(c.cFlags, "-fPIC")
			c.ldFlags = append(c.ldFlags, "-fPIC", "-static-libtsan")
		}

	case "address":
		c.goFlags = append(c.goFlags, "-asan")
		// Set the debug mode to print the C stack trace.
		c.cFlags = append(c.cFlags, "-g")

	case "fuzzer":
		c.goFlags = append(c.goFlags, "-tags=libfuzzer", "-gcflags=-d=libfuzzer")

	default:
		panic(fmt.Sprintf("unrecognized sanitizer: %q", sanitizer))
	}

	if configs.m == nil {
		configs.m = make(map[string]*config)
	}
	configs.m[sanitizer] = c
	return c
}

// goCmd returns a Cmd that executes "go $subcommand $args" with appropriate
// additional flags and environment.
func (c *config) goCmd(subcommand string, args ...string) *exec.Cmd {
	return c.goCmdWithExperiments(subcommand, args, nil)
}

// goCmdWithExperiments returns a Cmd that executes
// "GOEXPERIMENT=$experiments go $subcommand $args" with appropriate
// additional flags and CGO-related environment variables.
func (c *config) goCmdWithExperiments(subcommand string, args []string, experiments []string) *exec.Cmd {
	cmd := exec.Command("go", subcommand)
	cmd.Args = append(cmd.Args, c.goFlags...)
	cmd.Args = append(cmd.Args, args...)
	replaceEnv(cmd, "CGO_CFLAGS", strings.Join(c.cFlags, " "))
	replaceEnv(cmd, "CGO_LDFLAGS", strings.Join(c.ldFlags, " "))
	appendExperimentEnv(cmd, experiments)
	return cmd
}

// skipIfCSanitizerBroken skips t if the C compiler does not produce working
// binaries as configured.
func (c *config) skipIfCSanitizerBroken(t *testing.T) {
	check := &c.sanitizerCheck
	check.once.Do(func() {
		check.skip, check.err = c.checkCSanitizer()
	})
	if check.err != nil {
		t.Helper()
		if check.skip {
			t.Skip(check.err)
		}
		t.Fatal(check.err)
	}
}

var cMain = []byte(`
int main() {
	return 0;
}
`)

var cLibFuzzerInput = []byte(`
#include <stddef.h>
int LLVMFuzzerTestOneInput(char *data, size_t size) {
	return 0;
}
`)

func (c *config) checkCSanitizer() (skip bool, err error) {
	dir, err := os.MkdirTemp("", c.sanitizer)
	if err != nil {
		return false, fmt.Errorf("failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(dir)

	src := filepath.Join(dir, "return0.c")
	cInput := cMain
	if c.sanitizer == "fuzzer" {
		// libFuzzer generates the main function itself, and uses a different input.
		cInput = cLibFuzzerInput
	}
	if err := os.WriteFile(src, cInput, 0600); err != nil {
		return false, fmt.Errorf("failed to write C source file: %v", err)
	}

	dst := filepath.Join(dir, "return0")
	cmd, err := cc(c.cFlags...)
	if err != nil {
		return false, err
	}
	cmd.Args = append(cmd.Args, c.ldFlags...)
	cmd.Args = append(cmd.Args, "-o", dst, src)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if bytes.Contains(out, []byte("-fsanitize")) &&
			(bytes.Contains(out, []byte("unrecognized")) ||
				bytes.Contains(out, []byte("unsupported"))) {
			return true, errors.New(string(out))
		}
		return true, fmt.Errorf("%#q failed: %v\n%s", strings.Join(cmd.Args, " "), err, out)
	}

	if c.sanitizer == "fuzzer" {
		// For fuzzer, don't try running the test binary. It never finishes.
		return false, nil
	}

	if out, err := exec.Command(dst).CombinedOutput(); err != nil {
		if os.IsNotExist(err) {
			return true, fmt.Errorf("%#q failed to produce executable: %v", strings.Join(cmd.Args, " "), err)
		}
		snippet, _, _ := bytes.Cut(out, []byte("\n"))
		return true, fmt.Errorf("%#q generated broken executable: %v\n%s", strings.Join(cmd.Args, " "), err, snippet)
	}

	return false, nil
}

// skipIfRuntimeIncompatible skips t if the Go runtime is suspected not to work
// with cgo as configured.
func (c *config) skipIfRuntimeIncompatible(t *testing.T) {
	check := &c.runtimeCheck
	check.once.Do(func() {
		check.skip, check.err = c.checkRuntime()
	})
	if check.err != nil {
		t.Helper()
		if check.skip {
			t.Skip(check.err)
		}
		t.Fatal(check.err)
	}
}

func (c *config) checkRuntime() (skip bool, err error) {
	if c.sanitizer != "thread" {
		return false, nil
	}

	// libcgo.h sets CGO_TSAN if it detects TSAN support in the C compiler.
	// Dump the preprocessor defines to check that works.
	// (Sometimes it doesn't: see https://golang.org/issue/15983.)
	cmd, err := cc(c.cFlags...)
	if err != nil {
		return false, err
	}
	cmd.Args = append(cmd.Args, "-dM", "-E", "../../../../runtime/cgo/libcgo.h")
	cmdStr := strings.Join(cmd.Args, " ")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("%#q exited with %v\n%s", cmdStr, err, out)
	}
	if !bytes.Contains(out, []byte("#define CGO_TSAN")) {
		return true, fmt.Errorf("%#q did not define CGO_TSAN", cmdStr)
	}
	return false, nil
}

// srcPath returns the path to the given file relative to this test's source tree.
func srcPath(path string) string {
	return filepath.Join("testdata", path)
}

// A tempDir manages a temporary directory within a test.
type tempDir struct {
	base string
}

func (d *tempDir) RemoveAll(t *testing.T) {
	t.Helper()
	if d.base == "" {
		return
	}
	if err := os.RemoveAll(d.base); err != nil {
		t.Fatalf("Failed to remove temp dir: %v", err)
	}
}

func (d *tempDir) Base() string {
	return d.base
}

func (d *tempDir) Join(name string) string {
	return filepath.Join(d.base, name)
}

func newTempDir(t *testing.T) *tempDir {
	return &tempDir{base: t.TempDir()}
}

// hangProneCmd returns an exec.Cmd for a command that is likely to hang.
//
// If one of these tests hangs, the caller is likely to kill the test process
// using SIGINT, which will be sent to all of the processes in the test's group.
// Unfortunately, TSAN in particular is prone to dropping signals, so the SIGINT
// may terminate the test binary but leave the subprocess running. hangProneCmd
// configures subprocess to receive SIGKILL instead to ensure that it won't
// leak.
func hangProneCmd(name string, arg ...string) *exec.Cmd {
	cmd := exec.Command(name, arg...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Pdeathsig: syscall.SIGKILL,
	}
	return cmd
}
```