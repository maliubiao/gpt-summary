Response: Let's break down the thought process for analyzing this Go code and generating the summary.

1. **Initial Skim and Overall Goal:** The first thing I do is quickly read through the code, paying attention to the comments and package name. The package name `main` and the comment about `go_android_GOARCH_exec` immediately suggest this is a tool designed to execute Go binaries on Android devices. The comment about `syscall.Flock` hints at concurrency control.

2. **Identify Key Functions:** Next, I look for the main functions that seem to perform core actions. `adbRun`, `adb`, `adbCmd`, `adbCopyGoroot`, `adbCopyTree`, and `runMain` stand out.

3. **Analyze Individual Function Purpose:** I then go through each of these key functions to understand their specific roles:
    * `adbRun`:  Executes a command on the Android device using `adb exec-out`. The crucial part is the exit code handling using `newExitCodeFilter`. The comments explicitly mention the unreliability of `adb`'s exit codes, which is important.
    * `adb`:  Executes a simple `adb` command and returns an error if it fails.
    * `adbCmd`:  Builds an `exec.Cmd` for running `adb`, taking into account the `GOANDROID_ADB_FLAGS` environment variable.
    * `adbCopyGoroot`: This function has "copy" in the name and seems to deal with `GOROOT`. The comments about `deviceRoot` and copying "relevant parts of GOROOT" are key. The locking mechanism using `syscall.Flock` is also notable.
    * `adbCopyTree`:  This one is about copying files and directories, specifically `testdata`, `go.mod`, and `go.sum`. The logic of going up the directory tree is important.
    * `runMain`: This appears to be the core logic. It handles locking, waiting for the device, copying `GOROOT`, setting up the environment on the device, and finally running the target binary.

4. **Connect the Functions:**  I start to see how these functions work together. `runMain` orchestrates the process, using `adbCopyGoroot` and `adbCopyTree` to prepare the device environment, and `adbRun` to execute the final binary. The `adb` and `adbCmd` functions are helper functions for executing `adb` commands.

5. **Infer the "Go Language Feature":** Based on the function names and the overall flow, it's clear this isn't a direct implementation *of* a Go language feature. Instead, it *supports* the Go toolchain by providing a way to execute Go code on Android. It acts as a custom `*_exec` tool.

6. **Command Line Arguments:** I scan the `runMain` function for how command-line arguments are handled. `os.Args[1]` is used for the binary path, and `os.Args[2:]` are passed on to the executed binary. This is standard Go command-line parsing.

7. **Error Handling and Assumptions:**  I notice the extensive use of `adb` commands and the error checking after each one. The comments about `adb`'s exit codes being unreliable are a significant assumption and a reason for the custom exit code filtering. The locking mechanism is another crucial assumption to avoid race conditions.

8. **Potential Pitfalls:**  Based on the code and comments, several potential issues arise:
    * **Incorrect `GOROOT` or `GOPATH`:**  The tool relies on these being set correctly on the host machine.
    * **`adb` issues:** If `adb` is not installed or configured correctly, the tool won't work.
    * **Concurrency issues (before locking):** The initial comments mention the reason for the locking mechanism.
    * **File permissions on the device:**  Though not explicitly handled, file permissions on the Android device could be a problem.
    * **Network issues with `adb`:**  Communication problems with the Android device could lead to failures.

9. **Constructing the Summary:** I organize my findings into the requested categories:
    * **Functionality:** Summarize the overall purpose – executing Go binaries on Android.
    * **Go Feature Implementation:** Clarify that it's not *implementing* a Go feature but *supporting* the Go toolchain.
    * **Code Example:** Create a simple `go test` scenario to demonstrate its usage.
    * **Code Logic:** Explain the main steps in `runMain` with assumptions about input and output (e.g., copying files to temporary directories).
    * **Command-Line Arguments:** Describe how `os.Args` is used.
    * **Potential Pitfalls:** List the common mistakes based on the code and comments.

10. **Refinement and Clarity:** Finally, I review the summary for clarity, conciseness, and accuracy, ensuring it addresses all the points in the prompt. For example, initially I might just say "it copies GOROOT," but then I refine it to specify *which* parts are copied and *why*. I also ensure the example code is simple and illustrative. The detailed explanation of the exit code filtering is important because it's a non-trivial part of the code.
Let's break down the functionality of `go/misc/go_android_exec/main.go`.

**Overall Functionality:**

This Go program acts as a wrapper around the `adb` (Android Debug Bridge) tool to enable the Go toolchain (specifically `go test`) to execute Go binaries on an Android device. It's designed to be used as the `GOOS_GOARCH_exec` tool when cross-compiling Go code for Android.

**Inferred Go Language Feature Implementation:**

This program doesn't implement a core Go language feature itself. Instead, it leverages existing Go features like `os/exec` for running external commands (`adb`), `io` for input/output operations, `syscall` for system calls (like file locking), and `path/filepath` for path manipulation.

It's a crucial piece of infrastructure that allows the Go toolchain to target Android. You could say it *implements* the execution part of the Go cross-compilation process for Android.

**Go Code Example Illustrating Usage:**

Imagine you have a simple Go package in `your_project/mypackage` with a test file `mypackage_test.go`. To run the tests on an Android device, you would typically do something like this from the root of your project:

```bash
GOOS=android GOARCH=arm64 go test -v ./mypackage
```

In this scenario, the Go toolchain will detect that you're targeting Android (GOOS=android, GOARCH=arm64). It will then look for a program named `go_android_arm64_exec` (or `go_android_arm_exec` for 32-bit ARM). This `main.go` program, once built and renamed accordingly, is what gets executed.

**Code Logic with Assumptions:**

Let's assume the user runs the command:

```bash
GOOS=android GOARCH=arm64 go test -v ./mypackage
```

**Input:**

*   `os.Args[0]`: Path to the `go_android_arm64_exec` binary itself.
*   `os.Args[1]`: Path to the compiled test binary for the Android target (e.g., `/tmp/go-build384729384/mypackage.test`).
*   `os.Args[2:]`:  The remaining arguments passed to `go test`, such as `-v`.

**Steps:**

1. **Locking:** The program acquires an exclusive lock on a temporary file (`/tmp/go_android_exec-adb-lock`) using `syscall.Flock`. This prevents concurrent `adb` commands, which can be unreliable.

2. **Device Readiness Check:** It uses `adb wait-for-device` and then checks if the Android system has finished booting (`getprop sys.boot_completed`).

3. **Copying GOROOT:** The `adbCopyGoroot` function is called. This (usually happens only once per `make.bash` invocation) copies the necessary parts of the host's Go installation (GOROOT) to a directory on the Android device (`/data/local/tmp/go_android_exec/goroot`). This includes the `go` tool compiled for Android.
    *   **Assumption:** The host machine has a valid Go installation.
    *   **Output:**  The `/data/local/tmp/go_android_exec/goroot` directory on the Android device will contain a Go toolchain.

4. **Preparing Temporary Directory:** A temporary directory is created on the device (`/data/local/tmp/go_android_exec/mypackage.test-<pid>`). This is where the test binary and potentially source files will be copied. A corresponding `gopath` structure is created within this directory.

5. **Determining Package Path:** The `pkgPath` function determines the import path of the package being tested (e.g., `mypackage`). It also checks if it's a standard library package or a user package.

6. **Copying Source Files (if needed):**
    *   If it's a standard library package, the relevant source files are assumed to be present in the copied `GOROOT` on the device.
    *   If it's a user package:
        *   If using Go modules, the entire module directory is pushed to the device.
        *   Otherwise, the directory structure and `.go` files of the package are copied to the device. `adbCopyTree` is used to also copy `testdata`, `go.mod`, and `go.sum` files from the package's directory and its ancestors.

7. **Copying the Test Binary:** The compiled test binary (`os.Args[1]`) is pushed to the temporary directory on the device.

8. **Signal Handling:** A goroutine is started to forward `SIGQUIT` signals to the running process on the Android device. This helps in getting backtraces if the test hangs.

9. **Executing the Test Binary:** An `adb exec-out` command is constructed to run the test binary on the device. This command includes setting up the environment variables (`TMPDIR`, `GOROOT`, `GOPATH`, `CGO_ENABLED`, `GOPROXY`, `GOCACHE`, `PATH`, `HOME`) on the Android device. The current working directory is also set to the appropriate location on the device.
    *   **Command Example:**
        ```
        adb exec-out export TMPDIR="/data/local/tmp/go_android_exec/mypackage.test-12345"; export GOROOT="/data/local/tmp/go_android_exec/goroot"; export GOPATH="/data/local/tmp/go_android_exec/mypackage.test-12345/gopath"; export CGO_ENABLED=0; export GOPROXY=...; export GOCACHE="/data/local/tmp/go_android_exec/gocache"; export PATH="/data/local/tmp/go_android_exec/goroot/bin":$PATH; export HOME="/data/local/tmp/go_android_exec/home"; cd "/data/local/tmp/go_android_exec/mypackage.test-12345/gopath/src/mypackage"; '/data/local/tmp/go_android_exec/mypackage.test-12345/mypackage.test' -test.v
        ```

10. **Capturing Exit Code:** The `adbRun` function uses a custom `exitCodeFilter` to reliably extract the exit code of the executed binary from its output. This is because `adb`'s exit codes can be unreliable.

11. **Cleanup:** The temporary directory on the device is removed using `adb exec-out rm -rf`.

**Output:**

*   The standard output and standard error of the executed test binary are streamed back to the host's terminal.
*   The program returns the exit code of the executed test binary.

**Detailed Introduction to Command-Line Argument Handling:**

The program directly uses `os.Args`.

*   `os.Args[1]` is expected to be the path to the **compiled Go binary for the Android target**. The Go toolchain handles the compilation step before invoking this `go_android_*_exec` program.
*   `os.Args[2:]` are the **arguments that were originally passed to the `go test` command (or any other command that invokes this executor)**. These arguments are directly forwarded to the executed binary on the Android device.

For example, if the command is:

```bash
GOOS=android GOARCH=arm64 go test -v -run=SpecificTest ./mypackage
```

Then inside `main.go`:

*   `os.Args[1]` will be something like `/tmp/go-build.../mypackage.test`
*   `os.Args[2]` will be `-v`
*   `os.Args[3]` will be `-run=SpecificTest`

The code then reconstructs the command to run on the device, correctly passing these arguments.

**Common Mistakes Users Might Make:**

1. **Not having `adb` configured correctly:** The program heavily relies on `adb`. If `adb` is not installed, not in the system's PATH, or the Android device is not properly connected and authorized, the program will fail.

    **Example:** If the user runs the `go test` command without an Android device connected and authorized, they might see errors like:
    ```
    go_android_exec: adb wait-for-device exec-out while [[ -z $(getprop sys.boot_completed) ]]; do sleep 1; done;: error running command: exit status 1
    ```

2. **Incorrectly set `GOROOT` or environment variables:** While the program tries to find `GOROOT`, inconsistencies or incorrect settings can lead to problems during the GOROOT copying phase or when executing the binary on the device.

    **Example:** If `GOROOT` is not set or points to an invalid location, `adbCopyGoroot` will fail, resulting in errors like:
    ```
    go_android_exec: findGoroot: GOROOT not found
    ```

3. **Assuming `adb` exit codes are reliable:**  Users might try to debug issues based on `adb`'s exit codes directly, which this program explicitly handles as unreliable.

4. **Interfering with the locking mechanism:** Manually trying to run `adb` commands concurrently while `go test` is running might lead to unexpected behavior or failures due to the file locking.

In summary, `go/misc/go_android_exec/main.go` is a crucial bridge that enables Go development for Android by handling the execution of Go binaries on the target device using `adb`, managing dependencies, and ensuring a consistent execution environment. It cleverly works around the limitations of `adb` and provides a seamless experience for Go developers targeting Android.

### 提示词
```
这是路径为go/misc/go_android_exec/main.go的go语言实现的一部分， 请归纳一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果介绍代码逻辑，则建议带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This wrapper uses syscall.Flock to prevent concurrent adb commands,
// so for now it only builds on platforms that support that system call.
// TODO(#33974): use a more portable library for file locking.

//go:build darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd

// This program can be used as go_android_GOARCH_exec by the Go tool.
// It executes binaries on an android device using adb.
package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

func adbRun(args string) (int, error) {
	// The exit code of adb is often wrong. In theory it was fixed in 2016
	// (https://code.google.com/p/android/issues/detail?id=3254), but it's
	// still broken on our builders in 2023. Instead, append the exitcode to
	// the output and parse it from there.
	filter, exitStr := newExitCodeFilter(os.Stdout)
	args += "; echo -n " + exitStr + "$?"

	cmd := adbCmd("exec-out", args)
	cmd.Stdout = filter
	// If the adb subprocess somehow hangs, go test will kill this wrapper
	// and wait for our os.Stderr (and os.Stdout) to close as a result.
	// However, if the os.Stderr (or os.Stdout) file descriptors are
	// passed on, the hanging adb subprocess will hold them open and
	// go test will hang forever.
	//
	// Avoid that by wrapping stderr, breaking the short circuit and
	// forcing cmd.Run to use another pipe and goroutine to pass
	// along stderr from adb.
	cmd.Stderr = struct{ io.Writer }{os.Stderr}
	err := cmd.Run()

	// Before we process err, flush any further output and get the exit code.
	exitCode, err2 := filter.Finish()

	if err != nil {
		return 0, fmt.Errorf("adb exec-out %s: %v", args, err)
	}
	return exitCode, err2
}

func adb(args ...string) error {
	if out, err := adbCmd(args...).CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "adb %s\n%s", strings.Join(args, " "), out)
		return err
	}
	return nil
}

func adbCmd(args ...string) *exec.Cmd {
	if flags := os.Getenv("GOANDROID_ADB_FLAGS"); flags != "" {
		args = append(strings.Split(flags, " "), args...)
	}
	return exec.Command("adb", args...)
}

const (
	deviceRoot   = "/data/local/tmp/go_android_exec"
	deviceGoroot = deviceRoot + "/goroot"
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("go_android_exec: ")
	exitCode, err := runMain()
	if err != nil {
		log.Fatal(err)
	}
	os.Exit(exitCode)
}

func runMain() (int, error) {
	// Concurrent use of adb is flaky, so serialize adb commands.
	// See https://github.com/golang/go/issues/23795 or
	// https://issuetracker.google.com/issues/73230216.
	lockPath := filepath.Join(os.TempDir(), "go_android_exec-adb-lock")
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0666)
	if err != nil {
		return 0, err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return 0, err
	}

	// In case we're booting a device or emulator alongside all.bash, wait for
	// it to be ready. adb wait-for-device is not enough, we have to
	// wait for sys.boot_completed.
	if err := adb("wait-for-device", "exec-out", "while [[ -z $(getprop sys.boot_completed) ]]; do sleep 1; done;"); err != nil {
		return 0, err
	}

	// Done once per make.bash.
	if err := adbCopyGoroot(); err != nil {
		return 0, err
	}

	// Prepare a temporary directory that will be cleaned up at the end.
	// Binary names can conflict.
	// E.g. template.test from the {html,text}/template packages.
	binName := filepath.Base(os.Args[1])
	deviceGotmp := fmt.Sprintf(deviceRoot+"/%s-%d", binName, os.Getpid())
	deviceGopath := deviceGotmp + "/gopath"
	defer adb("exec-out", "rm", "-rf", deviceGotmp) // Clean up.

	// Determine the package by examining the current working
	// directory, which will look something like
	// "$GOROOT/src/mime/multipart" or "$GOPATH/src/golang.org/x/mobile".
	// We extract everything after the $GOROOT or $GOPATH to run on the
	// same relative directory on the target device.
	importPath, isStd, modPath, modDir, err := pkgPath()
	if err != nil {
		return 0, err
	}
	var deviceCwd string
	if isStd {
		// Note that we use path.Join here instead of filepath.Join:
		// The device paths should be slash-separated even if the go_android_exec
		// wrapper itself is compiled for Windows.
		deviceCwd = path.Join(deviceGoroot, "src", importPath)
	} else {
		deviceCwd = path.Join(deviceGopath, "src", importPath)
		if modDir != "" {
			// In module mode, the user may reasonably expect the entire module
			// to be present. Copy it over.
			deviceModDir := path.Join(deviceGopath, "src", modPath)
			if err := adb("exec-out", "mkdir", "-p", path.Dir(deviceModDir)); err != nil {
				return 0, err
			}
			// We use a single recursive 'adb push' of the module root instead of
			// walking the tree and copying it piecewise. If the directory tree
			// contains nested modules this could push a lot of unnecessary contents,
			// but for the golang.org/x repos it seems to be significantly (~2x)
			// faster than copying one file at a time (via filepath.WalkDir),
			// apparently due to high latency in 'adb' commands.
			if err := adb("push", modDir, deviceModDir); err != nil {
				return 0, err
			}
		} else {
			if err := adb("exec-out", "mkdir", "-p", deviceCwd); err != nil {
				return 0, err
			}
			if err := adbCopyTree(deviceCwd, importPath); err != nil {
				return 0, err
			}

			// Copy .go files from the package.
			goFiles, err := filepath.Glob("*.go")
			if err != nil {
				return 0, err
			}
			if len(goFiles) > 0 {
				args := append(append([]string{"push"}, goFiles...), deviceCwd)
				if err := adb(args...); err != nil {
					return 0, err
				}
			}
		}
	}

	deviceBin := fmt.Sprintf("%s/%s", deviceGotmp, binName)
	if err := adb("push", os.Args[1], deviceBin); err != nil {
		return 0, err
	}

	// Forward SIGQUIT from the go command to show backtraces from
	// the binary instead of from this wrapper.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGQUIT)
	go func() {
		for range quit {
			// We don't have the PID of the running process; use the
			// binary name instead.
			adb("exec-out", "killall -QUIT "+binName)
		}
	}()
	cmd := `export TMPDIR="` + deviceGotmp + `"` +
		`; export GOROOT="` + deviceGoroot + `"` +
		`; export GOPATH="` + deviceGopath + `"` +
		`; export CGO_ENABLED=0` +
		`; export GOPROXY=` + os.Getenv("GOPROXY") +
		`; export GOCACHE="` + deviceRoot + `/gocache"` +
		`; export PATH="` + deviceGoroot + `/bin":$PATH` +
		`; export HOME="` + deviceRoot + `/home"` +
		`; cd "` + deviceCwd + `"` +
		"; '" + deviceBin + "' " + strings.Join(os.Args[2:], " ")
	code, err := adbRun(cmd)
	signal.Reset(syscall.SIGQUIT)
	close(quit)
	return code, err
}

type exitCodeFilter struct {
	w      io.Writer // Pass through to w
	exitRe *regexp.Regexp
	buf    bytes.Buffer
}

func newExitCodeFilter(w io.Writer) (*exitCodeFilter, string) {
	const exitStr = "exitcode="

	// Build a regexp that matches any prefix of the exit string at the end of
	// the input. We do it this way to avoid assuming anything about the
	// subcommand output (e.g., it might not be \n-terminated).
	var exitReStr strings.Builder
	for i := 1; i <= len(exitStr); i++ {
		fmt.Fprintf(&exitReStr, "%s$|", exitStr[:i])
	}
	// Finally, match the exit string along with an exit code.
	// This is the only case we use a group, and we'll use this
	// group to extract the numeric code.
	fmt.Fprintf(&exitReStr, "%s([0-9]+)$", exitStr)
	exitRe := regexp.MustCompile(exitReStr.String())

	return &exitCodeFilter{w: w, exitRe: exitRe}, exitStr
}

func (f *exitCodeFilter) Write(data []byte) (int, error) {
	n := len(data)
	f.buf.Write(data)
	// Flush to w until a potential match of exitRe
	b := f.buf.Bytes()
	match := f.exitRe.FindIndex(b)
	if match == nil {
		// Flush all of the buffer.
		_, err := f.w.Write(b)
		f.buf.Reset()
		if err != nil {
			return n, err
		}
	} else {
		// Flush up to the beginning of the (potential) match.
		_, err := f.w.Write(b[:match[0]])
		f.buf.Next(match[0])
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

func (f *exitCodeFilter) Finish() (int, error) {
	// f.buf could be empty, contain a partial match of exitRe, or
	// contain a full match.
	b := f.buf.Bytes()
	defer f.buf.Reset()
	match := f.exitRe.FindSubmatch(b)
	if len(match) < 2 || match[1] == nil {
		// Not a full match. Flush.
		if _, err := f.w.Write(b); err != nil {
			return 0, err
		}
		return 0, fmt.Errorf("no exit code (in %q)", string(b))
	}

	// Parse the exit code.
	code, err := strconv.Atoi(string(match[1]))
	if err != nil {
		// Something is malformed. Flush.
		if _, err := f.w.Write(b); err != nil {
			return 0, err
		}
		return 0, fmt.Errorf("bad exit code: %v (in %q)", err, string(b))
	}
	return code, nil
}

// pkgPath determines the package import path of the current working directory,
// and indicates whether it is
// and returns the path to the package source relative to $GOROOT (or $GOPATH).
func pkgPath() (importPath string, isStd bool, modPath, modDir string, err error) {
	errorf := func(format string, args ...any) (string, bool, string, string, error) {
		return "", false, "", "", fmt.Errorf(format, args...)
	}
	goTool, err := goTool()
	if err != nil {
		return errorf("%w", err)
	}
	cmd := exec.Command(goTool, "list", "-e", "-f", "{{.ImportPath}}:{{.Standard}}{{with .Module}}:{{.Path}}:{{.Dir}}{{end}}", ".")
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok && len(ee.Stderr) > 0 {
			return errorf("%v: %s", cmd, ee.Stderr)
		}
		return errorf("%v: %w", cmd, err)
	}

	parts := strings.SplitN(string(bytes.TrimSpace(out)), ":", 4)
	if len(parts) < 2 {
		return errorf("%v: missing ':' in output: %q", cmd, out)
	}
	importPath = parts[0]
	if importPath == "" || importPath == "." {
		return errorf("current directory does not have a Go import path")
	}
	isStd, err = strconv.ParseBool(parts[1])
	if err != nil {
		return errorf("%v: non-boolean .Standard in output: %q", cmd, out)
	}
	if len(parts) >= 4 {
		modPath = parts[2]
		modDir = parts[3]
	}

	return importPath, isStd, modPath, modDir, nil
}

// adbCopyTree copies testdata, go.mod, go.sum files from subdir
// and from parent directories all the way up to the root of subdir.
// go.mod and go.sum files are needed for the go tool modules queries,
// and the testdata directories for tests.  It is common for tests to
// reach out into testdata from parent packages.
func adbCopyTree(deviceCwd, subdir string) error {
	dir := ""
	for {
		for _, name := range []string{"testdata", "go.mod", "go.sum"} {
			hostPath := filepath.Join(dir, name)
			if _, err := os.Stat(hostPath); err != nil {
				continue
			}
			devicePath := path.Join(deviceCwd, dir)
			if err := adb("exec-out", "mkdir", "-p", devicePath); err != nil {
				return err
			}
			if err := adb("push", hostPath, devicePath); err != nil {
				return err
			}
		}
		if subdir == "." {
			break
		}
		subdir = filepath.Dir(subdir)
		dir = path.Join(dir, "..")
	}
	return nil
}

// adbCopyGoroot clears deviceRoot for previous versions of GOROOT, GOPATH
// and temporary data. Then, it copies relevant parts of GOROOT to the device,
// including the go tool built for android.
// A lock file ensures this only happens once, even with concurrent exec
// wrappers.
func adbCopyGoroot() error {
	goTool, err := goTool()
	if err != nil {
		return err
	}
	cmd := exec.Command(goTool, "version")
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("%v: %w", cmd, err)
	}
	goVersion := string(out)

	// Also known by cmd/dist. The bootstrap command deletes the file.
	statPath := filepath.Join(os.TempDir(), "go_android_exec-adb-sync-status")
	stat, err := os.OpenFile(statPath, os.O_CREATE|os.O_RDWR, 0666)
	if err != nil {
		return err
	}
	defer stat.Close()
	// Serialize check and copying.
	if err := syscall.Flock(int(stat.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	s, err := io.ReadAll(stat)
	if err != nil {
		return err
	}
	if string(s) == goVersion {
		return nil
	}

	goroot, err := findGoroot()
	if err != nil {
		return err
	}

	// Delete the device's GOROOT, GOPATH and any leftover test data,
	// and recreate GOROOT.
	if err := adb("exec-out", "rm", "-rf", deviceRoot); err != nil {
		return err
	}

	// Build Go for Android.
	cmd = exec.Command(goTool, "install", "cmd")
	out, err = cmd.CombinedOutput()
	if err != nil {
		if len(bytes.TrimSpace(out)) > 0 {
			log.Printf("\n%s", out)
		}
		return fmt.Errorf("%v: %w", cmd, err)
	}
	if err := adb("exec-out", "mkdir", "-p", deviceGoroot); err != nil {
		return err
	}

	// Copy the Android tools from the relevant bin subdirectory to GOROOT/bin.
	cmd = exec.Command(goTool, "list", "-f", "{{.Target}}", "cmd/go")
	cmd.Stderr = os.Stderr
	out, err = cmd.Output()
	if err != nil {
		return fmt.Errorf("%v: %w", cmd, err)
	}
	platformBin := filepath.Dir(string(bytes.TrimSpace(out)))
	if platformBin == "." {
		return errors.New("failed to locate cmd/go for target platform")
	}
	if err := adb("push", platformBin, path.Join(deviceGoroot, "bin")); err != nil {
		return err
	}

	// Copy only the relevant subdirectories from pkg: pkg/include and the
	// platform-native binaries in pkg/tool.
	if err := adb("exec-out", "mkdir", "-p", path.Join(deviceGoroot, "pkg", "tool")); err != nil {
		return err
	}
	if err := adb("push", filepath.Join(goroot, "pkg", "include"), path.Join(deviceGoroot, "pkg", "include")); err != nil {
		return err
	}

	cmd = exec.Command(goTool, "list", "-f", "{{.Target}}", "cmd/compile")
	cmd.Stderr = os.Stderr
	out, err = cmd.Output()
	if err != nil {
		return fmt.Errorf("%v: %w", cmd, err)
	}
	platformToolDir := filepath.Dir(string(bytes.TrimSpace(out)))
	if platformToolDir == "." {
		return errors.New("failed to locate cmd/compile for target platform")
	}
	relToolDir, err := filepath.Rel(filepath.Join(goroot), platformToolDir)
	if err != nil {
		return err
	}
	if err := adb("push", platformToolDir, path.Join(deviceGoroot, relToolDir)); err != nil {
		return err
	}

	// Copy all other files from GOROOT.
	dirents, err := os.ReadDir(goroot)
	if err != nil {
		return err
	}
	for _, de := range dirents {
		switch de.Name() {
		case "bin", "pkg":
			// We already created GOROOT/bin and GOROOT/pkg above; skip those.
			continue
		}
		if err := adb("push", filepath.Join(goroot, de.Name()), path.Join(deviceGoroot, de.Name())); err != nil {
			return err
		}
	}

	if _, err := stat.WriteString(goVersion); err != nil {
		return err
	}
	return nil
}

func findGoroot() (string, error) {
	gorootOnce.Do(func() {
		// If runtime.GOROOT reports a non-empty path, assume that it is valid.
		// (It may be empty if this binary was built with -trimpath.)
		gorootPath = runtime.GOROOT()
		if gorootPath != "" {
			return
		}

		// runtime.GOROOT is empty — perhaps go_android_exec was built with
		// -trimpath and GOROOT is unset. Try 'go env GOROOT' as a fallback,
		// assuming that the 'go' command in $PATH is the correct one.

		cmd := exec.Command("go", "env", "GOROOT")
		cmd.Stderr = os.Stderr
		out, err := cmd.Output()
		if err != nil {
			gorootErr = fmt.Errorf("%v: %w", cmd, err)
		}

		gorootPath = string(bytes.TrimSpace(out))
		if gorootPath == "" {
			gorootErr = errors.New("GOROOT not found")
		}
	})

	return gorootPath, gorootErr
}

func goTool() (string, error) {
	goroot, err := findGoroot()
	if err != nil {
		return "", err
	}
	return filepath.Join(goroot, "bin", "go"), nil
}

var (
	gorootOnce sync.Once
	gorootPath string
	gorootErr  error
)
```