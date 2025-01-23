Response: My goal is to analyze the provided Go code snippet and explain its functionality, provide usage examples, and point out potential pitfalls. Here's a breakdown of my thought process:

1. **Understand the Core Purpose:** The initial comment `// A Shell runs shell commands and performs shell-like file system operations.` immediately tells me the central theme. This isn't just about running external commands; it's also about file system manipulation within the context of the `go` build process.

2. **Identify Key Structures:** I see the `Shell` struct and its associated `shellShared` struct. The comments clearly explain the purpose of each field. `Shell` seems to represent a context for executing commands, possibly tied to a specific build action. `shellShared` appears to hold global state for a set of related `Shell` instances.

3. **Analyze Key Methods (Grouping by Functionality):** I'll go through the methods and categorize them to understand the different aspects of the `Shell`'s capabilities:

    * **Creation & Context:** `NewShell`, `WithAction`, `Shell` (on `Builder`), `BackgroundShell`. These are about creating and managing `Shell` instances, and how they relate to `Action`s and the `Builder`. The `Builder` methods suggest this `Shell` is part of the `go` build system's internal workings.

    * **Output & Error Reporting:** `Printf`, `printfLocked`, `Errorf`, `reportCmd`, `fmtCmd`, `ShowCmd`. These deal with displaying information (commands being executed, output of commands, errors) to the user, taking into account the `-n` and `-x` flags. The complexity of `reportCmd` suggests it handles subtleties of error presentation.

    * **File System Operations:** `moveOrCopyFile`, `CopyFile`, `writeFile`, `Mkdir`, `RemoveAll`, `Symlink`, `mayberemovefile`. These are standard file system operations, but their implementation might have specific considerations within the `go` build context (like handling build cache, permissions, etc.).

    * **Command Execution:** `run`, `runOut`, `joinUnambiguously`, `passLongArgsInResponseFiles` (though not directly in the snippet, its presence in `runOut` is noted). This is the core functionality of running external commands. The `runOut` method's return values (`[]byte`, `error`) are typical for command execution.

4. **Infer Go Functionality (Based on Clues):** The package name `cmd/go/internal/work` and the presence of `Builder` strongly suggest this is part of the `go build` command's internal implementation. The file system operations and command execution are necessary for compiling, linking, and managing build artifacts. The interaction with `Action` likely relates to the dependency graph and execution plan within the build process.

5. **Construct Go Examples:** Based on the identified functionalities, I can create illustrative examples. I'll focus on the more interesting methods, like those involving file system manipulation and command execution, and demonstrate how they might be used. Since it's internal API, I'll make the examples hypothetical, showing *how* the methods are used rather than expecting them to run directly outside the `go` tool's context. I need to invent plausible scenarios and input/output.

6. **Analyze Command-Line Parameter Handling:** The code explicitly checks `cfg.BuildN` (for `-n`, dry run) and `cfg.BuildX` (for `-x`, verbose). I'll detail how these flags affect the behavior of the `Shell` methods, particularly in terms of what is printed to the console.

7. **Identify Potential Pitfalls:** I'll consider common mistakes users might make *if* they were directly using this API (even though it's internal). For example, relying on specific permissions or file system behavior without understanding the nuances handled by `Shell` methods. The asynchronous nature of `mkdirCache` could also be a source of confusion if not understood. The error handling in `reportCmd` is complex and might lead to unexpected error messages if the subtleties aren't appreciated.

8. **Refine and Organize:** I will structure my answer clearly, using headings and bullet points to separate the different aspects of the analysis. I'll ensure the code examples are well-formatted and easy to understand. I will double-check that my inferences about the Go functionality align with the code's behavior.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe this is just a simple wrapper around `os/exec`.
* **Correction:** The file system operations and the intricate logic in methods like `moveOrCopyFile` and `reportCmd` indicate it's more than just that. It's managing file system operations within the constraints and requirements of the `go` build process.

* **Initial thought:**  Provide runnable examples.
* **Correction:**  Since it's an internal API, directly runnable examples are likely not feasible or meaningful. Focus on illustrating *how* the methods are used conceptually within the `go` tool.

* **Consider edge cases:** What happens with empty paths? How are errors from external commands handled? The code provides answers to these, so I'll incorporate those details.

By following these steps, I can systematically analyze the code and provide a comprehensive and accurate explanation of its functionality.
这段代码是 Go 语言 `go` 命令内部 `work` 包中 `shell.go` 文件的一部分。它定义了一个 `Shell` 结构体，该结构体用于执行 shell 命令和执行类似 shell 的文件系统操作。`Shell` 跟踪与运行命令相关的上下文，并形成一个类似于 `context.Context` 的树状结构。

**`Shell` 结构体的功能：**

1. **执行外部命令:**  `Shell` 提供了 `run` 和 `runOut` 方法来执行外部命令。这些方法处理命令的执行、参数传递、环境变量设置以及输出和错误捕获。

2. **文件系统操作:** `Shell` 封装了常见的文件系统操作，如 `moveOrCopyFile` (移动或复制文件), `CopyFile` (复制文件), `writeFile` (写入文件), `Mkdir` (创建目录), `RemoveAll` (删除文件或目录), `Symlink` (创建符号链接)。这些方法在执行时会考虑 `go build` 的特定需求，例如处理 build cache、权限问题以及在 `-n` 和 `-x` 模式下的行为。

3. **输出和错误管理:** `Shell` 提供了 `Printf` 和 `Errorf` 方法来向输出流打印信息和错误。`reportCmd` 方法用于处理命令执行的输出和错误，并以更友好的方式呈现给用户，例如将工作目录替换为 `$WORK`，将绝对路径替换为相对路径等。

4. **上下文管理:** `Shell` 结构体可以绑定到一个 `Action` 结构体（通过 `WithAction` 方法），这允许在执行命令或文件系统操作时关联特定的构建动作。`Builder` 结构体提供了创建和获取 `Shell` 实例的方法 (`Shell` 和 `BackgroundShell`)。

5. **模拟执行 (`-n` 模式):** 当使用 `go build -n` 命令时，`Shell` 会记录将要执行的命令，但实际不执行。这对于查看构建过程非常有用。

6. **详细执行 (`-x` 模式):** 当使用 `go build -x` 命令时，`Shell` 会打印出实际执行的命令，包括环境变量。

**推断 Go 语言功能的实现：**

这段代码是 `go build` 命令中执行构建步骤的核心部分。当 `go build` 需要编译、链接或者执行其他外部工具时，就会使用 `Shell` 结构体。它负责在指定的工作目录下执行命令，并管理相关的输入输出和错误信息。

**Go 代码举例说明:**

假设在 `go build` 过程中，需要编译一个 C 文件 `hello.c` 并生成一个目标文件 `hello.o`。以下代码展示了 `Shell` 可能如何执行这个操作：

```go
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"cmd/go/internal/load"
	"cmd/go/internal/work"
)

func main() {
	// 假设我们已经有了 Builder 实例 b 和 Action 实例 a
	// 这里为了演示，手动创建一个 Shell 实例
	workDir, err := os.MkdirTemp("", "go-build-test")
	if err != nil {
		fmt.Println("Error creating temp dir:", err)
		return
	}
	defer os.RemoveAll(workDir)

	printer := load.NewPrinter()
	sh := work.NewShell(workDir, printer)

	// 假设 hello.c 文件存在于当前目录
	cFilePath := "hello.c"
	objFilePath := filepath.Join(workDir, "hello.o")

	// 模拟执行 gcc 命令
	err = sh.Run(".", "compile hello.c", nil, "gcc", "-c", cFilePath, "-o", objFilePath)
	if err != nil {
		fmt.Println("Error compiling hello.c:", err)
		return
	}

	fmt.Println("Successfully compiled hello.c to", objFilePath)
}
```

**假设的输入与输出:**

**输入 (`hello.c` 文件内容):**

```c
#include <stdio.h>

int main() {
    printf("Hello from C!\n");
    return 0;
}
```

**输出 (假设 `go build` 没有使用 `-n` 或 `-x`):**

```
Successfully compiled hello.c to /tmp/go-build-testXXXX/hello.o  // XXXX 是随机字符
```

**输出 (如果使用 `go build -n`):**

```
cd .
gcc -c hello.c -o /tmp/go-build-testXXXX/hello.o # internal
Successfully compiled hello.c to /tmp/go-build-testXXXX/hello.o
```

**输出 (如果使用 `go build -x`):**

```
cd .
gcc -c hello.c -o /tmp/go-build-testXXXX/hello.o
Successfully compiled hello.c to /tmp/go-build-testXXXX/hello.o
```

**命令行参数的具体处理:**

`Shell` 结构体本身不直接处理命令行参数。但是，它会根据全局配置 (`cfg` 包) 中的 `BuildN` 和 `BuildX` 变量来调整其行为。

* **`cfg.BuildN` (对应 `go build -n`):**  当设置为 `true` 时，`Shell` 中的文件系统操作和命令执行方法会跳过实际的执行步骤，只打印将要执行的命令。`ShowCmd` 方法用于打印这些命令。

* **`cfg.BuildX` (对应 `go build -x`):** 当设置为 `true` 时，`Shell` 会在执行命令前通过 `ShowCmd` 方法打印出完整的命令，包括环境变量。这有助于了解构建过程中执行的具体操作。

**使用者易犯错的点 (虽然 `Shell` 是内部 API，但我们可以推测可能的错误):**

1. **不理解工作目录 (`workDir`):**  `Shell` 的操作通常发生在特定的工作目录下。如果用户（在 `go` 命令的开发或调试过程中）不理解当前的工作目录，可能会导致文件操作路径错误。

2. **忽略 `-n` 和 `-x` 的影响:**  在调试构建过程时，如果忘记 `-n` 和 `-x` 标志会影响 `Shell` 的行为，可能会对输出感到困惑。

3. **错误地假设命令的执行环境:**  `Shell` 负责设置命令的执行环境，包括环境变量。如果用户对这些环境变量的设置不了解，可能会导致命令执行失败。例如，依赖于某些未设置的环境变量。

4. **不理解 `reportCmd` 的错误处理逻辑:** `reportCmd` 有其特定的错误报告方式，它会尝试提供更友好的错误信息。如果用户不理解这种处理方式，可能会对最终的错误输出感到困惑。例如，当命令输出非空但返回错误时，`reportCmd` 倾向于使用命令输出来作为最终的错误信息。

例如，如果用户期望在命令执行失败时直接获取 `error` 对象，但 `reportCmd` 返回的是基于命令输出构建的 `cmdError`，这可能会导致一些困惑。

总而言之，`go/src/cmd/go/internal/work/shell.go` 中的 `Shell` 结构体是 `go build` 命令执行构建任务的核心组件，它封装了执行外部命令和文件系统操作的功能，并提供了一定的上下文管理和错误报告机制。理解其工作原理有助于深入了解 `go build` 的内部运作。

### 提示词
```
这是路径为go/src/cmd/go/internal/work/shell.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package work

import (
	"bytes"
	"cmd/go/internal/base"
	"cmd/go/internal/cache"
	"cmd/go/internal/cfg"
	"cmd/go/internal/load"
	"cmd/go/internal/str"
	"cmd/internal/par"
	"cmd/internal/pathcache"
	"errors"
	"fmt"
	"internal/lazyregexp"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// A Shell runs shell commands and performs shell-like file system operations.
//
// Shell tracks context related to running commands, and form a tree much like
// context.Context.
type Shell struct {
	action       *Action // nil for the root shell
	*shellShared         // per-Builder state shared across Shells
}

// shellShared is Shell state shared across all Shells derived from a single
// root shell (generally a single Builder).
type shellShared struct {
	workDir string // $WORK, immutable

	printLock sync.Mutex
	printer   load.Printer
	scriptDir string // current directory in printed script

	mkdirCache par.Cache[string, error] // a cache of created directories
}

// NewShell returns a new Shell.
//
// Shell will internally serialize calls to the printer.
// If printer is nil, it uses load.DefaultPrinter.
func NewShell(workDir string, printer load.Printer) *Shell {
	if printer == nil {
		printer = load.DefaultPrinter()
	}
	shared := &shellShared{
		workDir: workDir,
		printer: printer,
	}
	return &Shell{shellShared: shared}
}

func (sh *Shell) pkg() *load.Package {
	if sh.action == nil {
		return nil
	}
	return sh.action.Package
}

// Printf emits a to this Shell's output stream, formatting it like fmt.Printf.
// It is safe to call concurrently.
func (sh *Shell) Printf(format string, a ...any) {
	sh.printLock.Lock()
	defer sh.printLock.Unlock()
	sh.printer.Printf(sh.pkg(), format, a...)
}

func (sh *Shell) printfLocked(format string, a ...any) {
	sh.printer.Printf(sh.pkg(), format, a...)
}

// Errorf reports an error on sh's package and sets the process exit status to 1.
func (sh *Shell) Errorf(format string, a ...any) {
	sh.printLock.Lock()
	defer sh.printLock.Unlock()
	sh.printer.Errorf(sh.pkg(), format, a...)
}

// WithAction returns a Shell identical to sh, but bound to Action a.
func (sh *Shell) WithAction(a *Action) *Shell {
	sh2 := *sh
	sh2.action = a
	return &sh2
}

// Shell returns a shell for running commands on behalf of Action a.
func (b *Builder) Shell(a *Action) *Shell {
	if a == nil {
		// The root shell has a nil Action. The point of this method is to
		// create a Shell bound to an Action, so disallow nil Actions here.
		panic("nil Action")
	}
	if a.sh == nil {
		a.sh = b.backgroundSh.WithAction(a)
	}
	return a.sh
}

// BackgroundShell returns a Builder-wide Shell that's not bound to any Action.
// Try not to use this unless there's really no sensible Action available.
func (b *Builder) BackgroundShell() *Shell {
	return b.backgroundSh
}

// moveOrCopyFile is like 'mv src dst' or 'cp src dst'.
func (sh *Shell) moveOrCopyFile(dst, src string, perm fs.FileMode, force bool) error {
	if cfg.BuildN {
		sh.ShowCmd("", "mv %s %s", src, dst)
		return nil
	}

	// If we can update the mode and rename to the dst, do it.
	// Otherwise fall back to standard copy.

	// If the source is in the build cache, we need to copy it.
	dir, _ := cache.DefaultDir()
	if strings.HasPrefix(src, dir) {
		return sh.CopyFile(dst, src, perm, force)
	}

	// On Windows, always copy the file, so that we respect the NTFS
	// permissions of the parent folder. https://golang.org/issue/22343.
	// What matters here is not cfg.Goos (the system we are building
	// for) but runtime.GOOS (the system we are building on).
	if runtime.GOOS == "windows" {
		return sh.CopyFile(dst, src, perm, force)
	}

	// If the destination directory has the group sticky bit set,
	// we have to copy the file to retain the correct permissions.
	// https://golang.org/issue/18878
	if fi, err := os.Stat(filepath.Dir(dst)); err == nil {
		if fi.IsDir() && (fi.Mode()&fs.ModeSetgid) != 0 {
			return sh.CopyFile(dst, src, perm, force)
		}
	}

	// The perm argument is meant to be adjusted according to umask,
	// but we don't know what the umask is.
	// Create a dummy file to find out.
	// This avoids build tags and works even on systems like Plan 9
	// where the file mask computation incorporates other information.
	mode := perm
	f, err := os.OpenFile(filepath.Clean(dst)+"-go-tmp-umask", os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err == nil {
		fi, err := f.Stat()
		if err == nil {
			mode = fi.Mode() & 0777
		}
		name := f.Name()
		f.Close()
		os.Remove(name)
	}

	if err := os.Chmod(src, mode); err == nil {
		if err := os.Rename(src, dst); err == nil {
			if cfg.BuildX {
				sh.ShowCmd("", "mv %s %s", src, dst)
			}
			return nil
		}
	}

	return sh.CopyFile(dst, src, perm, force)
}

// copyFile is like 'cp src dst'.
func (sh *Shell) CopyFile(dst, src string, perm fs.FileMode, force bool) error {
	if cfg.BuildN || cfg.BuildX {
		sh.ShowCmd("", "cp %s %s", src, dst)
		if cfg.BuildN {
			return nil
		}
	}

	sf, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sf.Close()

	// Be careful about removing/overwriting dst.
	// Do not remove/overwrite if dst exists and is a directory
	// or a non-empty non-object file.
	if fi, err := os.Stat(dst); err == nil {
		if fi.IsDir() {
			return fmt.Errorf("build output %q already exists and is a directory", dst)
		}
		if !force && fi.Mode().IsRegular() && fi.Size() != 0 && !isObject(dst) {
			return fmt.Errorf("build output %q already exists and is not an object file", dst)
		}
	}

	// On Windows, remove lingering ~ file from last attempt.
	if runtime.GOOS == "windows" {
		if _, err := os.Stat(dst + "~"); err == nil {
			os.Remove(dst + "~")
		}
	}

	mayberemovefile(dst)
	df, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil && runtime.GOOS == "windows" {
		// Windows does not allow deletion of a binary file
		// while it is executing. Try to move it out of the way.
		// If the move fails, which is likely, we'll try again the
		// next time we do an install of this binary.
		if err := os.Rename(dst, dst+"~"); err == nil {
			os.Remove(dst + "~")
		}
		df, err = os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	}
	if err != nil {
		return fmt.Errorf("copying %s: %w", src, err) // err should already refer to dst
	}

	_, err = io.Copy(df, sf)
	df.Close()
	if err != nil {
		mayberemovefile(dst)
		return fmt.Errorf("copying %s to %s: %v", src, dst, err)
	}
	return nil
}

// mayberemovefile removes a file only if it is a regular file
// When running as a user with sufficient privileges, we may delete
// even device files, for example, which is not intended.
func mayberemovefile(s string) {
	if fi, err := os.Lstat(s); err == nil && !fi.Mode().IsRegular() {
		return
	}
	os.Remove(s)
}

// writeFile writes the text to file.
func (sh *Shell) writeFile(file string, text []byte) error {
	if cfg.BuildN || cfg.BuildX {
		switch {
		case len(text) == 0:
			sh.ShowCmd("", "echo -n > %s # internal", file)
		case bytes.IndexByte(text, '\n') == len(text)-1:
			// One line. Use a simpler "echo" command.
			sh.ShowCmd("", "echo '%s' > %s # internal", bytes.TrimSuffix(text, []byte("\n")), file)
		default:
			// Use the most general form.
			sh.ShowCmd("", "cat >%s << 'EOF' # internal\n%sEOF", file, text)
		}
	}
	if cfg.BuildN {
		return nil
	}
	return os.WriteFile(file, text, 0666)
}

// Mkdir makes the named directory.
func (sh *Shell) Mkdir(dir string) error {
	// Make Mkdir(a.Objdir) a no-op instead of an error when a.Objdir == "".
	if dir == "" {
		return nil
	}

	// We can be a little aggressive about being
	// sure directories exist. Skip repeated calls.
	return sh.mkdirCache.Do(dir, func() error {
		if cfg.BuildN || cfg.BuildX {
			sh.ShowCmd("", "mkdir -p %s", dir)
			if cfg.BuildN {
				return nil
			}
		}

		return os.MkdirAll(dir, 0777)
	})
}

// RemoveAll is like 'rm -rf'. It attempts to remove all paths even if there's
// an error, and returns the first error.
func (sh *Shell) RemoveAll(paths ...string) error {
	if cfg.BuildN || cfg.BuildX {
		// Don't say we are removing the directory if we never created it.
		show := func() bool {
			for _, path := range paths {
				if _, ok := sh.mkdirCache.Get(path); ok {
					return true
				}
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					return true
				}
			}
			return false
		}
		if show() {
			sh.ShowCmd("", "rm -rf %s", strings.Join(paths, " "))
		}
	}
	if cfg.BuildN {
		return nil
	}

	var err error
	for _, path := range paths {
		if err2 := os.RemoveAll(path); err2 != nil && err == nil {
			err = err2
		}
	}
	return err
}

// Symlink creates a symlink newname -> oldname.
func (sh *Shell) Symlink(oldname, newname string) error {
	// It's not an error to try to recreate an existing symlink.
	if link, err := os.Readlink(newname); err == nil && link == oldname {
		return nil
	}

	if cfg.BuildN || cfg.BuildX {
		sh.ShowCmd("", "ln -s %s %s", oldname, newname)
		if cfg.BuildN {
			return nil
		}
	}
	return os.Symlink(oldname, newname)
}

// fmtCmd formats a command in the manner of fmt.Sprintf but also:
//
//	fmtCmd replaces the value of b.WorkDir with $WORK.
func (sh *Shell) fmtCmd(dir string, format string, args ...any) string {
	cmd := fmt.Sprintf(format, args...)
	if sh.workDir != "" && !strings.HasPrefix(cmd, "cat ") {
		cmd = strings.ReplaceAll(cmd, sh.workDir, "$WORK")
		escaped := strconv.Quote(sh.workDir)
		escaped = escaped[1 : len(escaped)-1] // strip quote characters
		if escaped != sh.workDir {
			cmd = strings.ReplaceAll(cmd, escaped, "$WORK")
		}
	}
	return cmd
}

// ShowCmd prints the given command to standard output
// for the implementation of -n or -x.
//
// ShowCmd also replaces the name of the current script directory with dot (.)
// but only when it is at the beginning of a space-separated token.
//
// If dir is not "" or "/" and not the current script directory, ShowCmd first
// prints a "cd" command to switch to dir and updates the script directory.
func (sh *Shell) ShowCmd(dir string, format string, args ...any) {
	// Use the output lock directly so we can manage scriptDir.
	sh.printLock.Lock()
	defer sh.printLock.Unlock()

	cmd := sh.fmtCmd(dir, format, args...)

	if dir != "" && dir != "/" {
		if dir != sh.scriptDir {
			// Show changing to dir and update the current directory.
			sh.printfLocked("%s", sh.fmtCmd("", "cd %s\n", dir))
			sh.scriptDir = dir
		}
		// Replace scriptDir is our working directory. Replace it
		// with "." in the command.
		dot := " ."
		if dir[len(dir)-1] == filepath.Separator {
			dot += string(filepath.Separator)
		}
		cmd = strings.ReplaceAll(" "+cmd, " "+dir, dot)[1:]
	}

	sh.printfLocked("%s\n", cmd)
}

// reportCmd reports the output and exit status of a command. The cmdOut and
// cmdErr arguments are the output and exit error of the command, respectively.
//
// The exact reporting behavior is as follows:
//
//	cmdOut  cmdErr  Result
//	""      nil     print nothing, return nil
//	!=""    nil     print output, return nil
//	""      !=nil   print nothing, return cmdErr (later printed)
//	!=""    !=nil   print nothing, ignore err, return output as error (later printed)
//
// reportCmd returns a non-nil error if and only if cmdErr != nil. It assumes
// that the command output, if non-empty, is more detailed than the command
// error (which is usually just an exit status), so prefers using the output as
// the ultimate error. Typically, the caller should return this error from an
// Action, which it will be printed by the Builder.
//
// reportCmd formats the output as "# desc" followed by the given output. The
// output is expected to contain references to 'dir', usually the source
// directory for the package that has failed to build. reportCmd rewrites
// mentions of dir with a relative path to dir when the relative path is
// shorter. This is usually more pleasant. For example, if fmt doesn't compile
// and we are in src/html, the output is
//
//	$ go build
//	# fmt
//	../fmt/print.go:1090: undefined: asdf
//	$
//
// instead of
//
//	$ go build
//	# fmt
//	/usr/gopher/go/src/fmt/print.go:1090: undefined: asdf
//	$
//
// reportCmd also replaces references to the work directory with $WORK, replaces
// cgo file paths with the original file path, and replaces cgo-mangled names
// with "C.name".
//
// desc is optional. If "", a.Package.Desc() is used.
//
// dir is optional. If "", a.Package.Dir is used.
func (sh *Shell) reportCmd(desc, dir string, cmdOut []byte, cmdErr error) error {
	if len(cmdOut) == 0 && cmdErr == nil {
		// Common case
		return nil
	}
	if len(cmdOut) == 0 && cmdErr != nil {
		// Just return the error.
		//
		// TODO: This is what we've done for a long time, but it may be a
		// mistake because it loses all of the extra context and results in
		// ultimately less descriptive output. We should probably just take the
		// text of cmdErr as the output in this case and do everything we
		// otherwise would. We could chain the errors if we feel like it.
		return cmdErr
	}

	// Fetch defaults from the package.
	var p *load.Package
	a := sh.action
	if a != nil {
		p = a.Package
	}
	var importPath string
	if p != nil {
		importPath = p.ImportPath
		if desc == "" {
			desc = p.Desc()
		}
		if dir == "" {
			dir = p.Dir
		}
	}

	out := string(cmdOut)

	if !strings.HasSuffix(out, "\n") {
		out = out + "\n"
	}

	// Replace workDir with $WORK
	out = replacePrefix(out, sh.workDir, "$WORK")

	// Rewrite mentions of dir with a relative path to dir
	// when the relative path is shorter.
	for {
		// Note that dir starts out long, something like
		// /foo/bar/baz/root/a
		// The target string to be reduced is something like
		// (blah-blah-blah) /foo/bar/baz/root/sibling/whatever.go:blah:blah
		// /foo/bar/baz/root/a doesn't match /foo/bar/baz/root/sibling, but the prefix
		// /foo/bar/baz/root does.  And there may be other niblings sharing shorter
		// prefixes, the only way to find them is to look.
		// This doesn't always produce a relative path --
		// /foo is shorter than ../../.., for example.
		if reldir := base.ShortPath(dir); reldir != dir {
			out = replacePrefix(out, dir, reldir)
			if filepath.Separator == '\\' {
				// Don't know why, sometimes this comes out with slashes, not backslashes.
				wdir := strings.ReplaceAll(dir, "\\", "/")
				out = replacePrefix(out, wdir, reldir)
			}
		}
		dirP := filepath.Dir(dir)
		if dir == dirP {
			break
		}
		dir = dirP
	}

	// Fix up output referring to cgo-generated code to be more readable.
	// Replace x.go:19[/tmp/.../x.cgo1.go:18] with x.go:19.
	// Replace *[100]_Ctype_foo with *[100]C.foo.
	// If we're using -x, assume we're debugging and want the full dump, so disable the rewrite.
	if !cfg.BuildX && cgoLine.MatchString(out) {
		out = cgoLine.ReplaceAllString(out, "")
		out = cgoTypeSigRe.ReplaceAllString(out, "C.")
	}

	// Usually desc is already p.Desc(), but if not, signal cmdError.Error to
	// add a line explicitly mentioning the import path.
	needsPath := importPath != "" && p != nil && desc != p.Desc()

	err := &cmdError{desc, out, importPath, needsPath}
	if cmdErr != nil {
		// The command failed. Report the output up as an error.
		return err
	}
	// The command didn't fail, so just print the output as appropriate.
	if a != nil && a.output != nil {
		// The Action is capturing output.
		a.output = append(a.output, err.Error()...)
	} else {
		// Write directly to the Builder output.
		sh.Printf("%s", err)
	}
	return nil
}

// replacePrefix is like strings.ReplaceAll, but only replaces instances of old
// that are preceded by ' ', '\t', or appear at the beginning of a line.
func replacePrefix(s, old, new string) string {
	n := strings.Count(s, old)
	if n == 0 {
		return s
	}

	s = strings.ReplaceAll(s, " "+old, " "+new)
	s = strings.ReplaceAll(s, "\n"+old, "\n"+new)
	s = strings.ReplaceAll(s, "\n\t"+old, "\n\t"+new)
	if strings.HasPrefix(s, old) {
		s = new + s[len(old):]
	}
	return s
}

type cmdError struct {
	desc       string
	text       string
	importPath string
	needsPath  bool // Set if desc does not already include the import path
}

func (e *cmdError) Error() string {
	var msg string
	if e.needsPath {
		// Ensure the import path is part of the message.
		// Clearly distinguish the description from the import path.
		msg = fmt.Sprintf("# %s\n# [%s]\n", e.importPath, e.desc)
	} else {
		msg = "# " + e.desc + "\n"
	}
	return msg + e.text
}

func (e *cmdError) ImportPath() string {
	return e.importPath
}

var cgoLine = lazyregexp.New(`\[[^\[\]]+\.(cgo1|cover)\.go:[0-9]+(:[0-9]+)?\]`)
var cgoTypeSigRe = lazyregexp.New(`\b_C2?(type|func|var|macro)_\B`)

// run runs the command given by cmdline in the directory dir.
// If the command fails, run prints information about the failure
// and returns a non-nil error.
func (sh *Shell) run(dir string, desc string, env []string, cmdargs ...any) error {
	out, err := sh.runOut(dir, env, cmdargs...)
	if desc == "" {
		desc = sh.fmtCmd(dir, "%s", strings.Join(str.StringList(cmdargs...), " "))
	}
	return sh.reportCmd(desc, dir, out, err)
}

// runOut runs the command given by cmdline in the directory dir.
// It returns the command output and any errors that occurred.
// It accumulates execution time in a.
func (sh *Shell) runOut(dir string, env []string, cmdargs ...any) ([]byte, error) {
	a := sh.action

	cmdline := str.StringList(cmdargs...)

	for _, arg := range cmdline {
		// GNU binutils commands, including gcc and gccgo, interpret an argument
		// @foo anywhere in the command line (even following --) as meaning
		// "read and insert arguments from the file named foo."
		// Don't say anything that might be misinterpreted that way.
		if strings.HasPrefix(arg, "@") {
			return nil, fmt.Errorf("invalid command-line argument %s in command: %s", arg, joinUnambiguously(cmdline))
		}
	}

	if cfg.BuildN || cfg.BuildX {
		var envcmdline string
		for _, e := range env {
			if j := strings.IndexByte(e, '='); j != -1 {
				if strings.ContainsRune(e[j+1:], '\'') {
					envcmdline += fmt.Sprintf("%s=%q", e[:j], e[j+1:])
				} else {
					envcmdline += fmt.Sprintf("%s='%s'", e[:j], e[j+1:])
				}
				envcmdline += " "
			}
		}
		envcmdline += joinUnambiguously(cmdline)
		sh.ShowCmd(dir, "%s", envcmdline)
		if cfg.BuildN {
			return nil, nil
		}
	}

	var buf bytes.Buffer
	path, err := pathcache.LookPath(cmdline[0])
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(path, cmdline[1:]...)
	if cmd.Path != "" {
		cmd.Args[0] = cmd.Path
	}
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	cleanup := passLongArgsInResponseFiles(cmd)
	defer cleanup()
	if dir != "." {
		cmd.Dir = dir
	}
	cmd.Env = cmd.Environ() // Pre-allocate with correct PWD.

	// Add the TOOLEXEC_IMPORTPATH environment variable for -toolexec tools.
	// It doesn't really matter if -toolexec isn't being used.
	// Note that a.Package.Desc is not really an import path,
	// but this is consistent with 'go list -f {{.ImportPath}}'.
	// Plus, it is useful to uniquely identify packages in 'go list -json'.
	if a != nil && a.Package != nil {
		cmd.Env = append(cmd.Env, "TOOLEXEC_IMPORTPATH="+a.Package.Desc())
	}

	cmd.Env = append(cmd.Env, env...)
	start := time.Now()
	err = cmd.Run()
	if a != nil && a.json != nil {
		aj := a.json
		aj.Cmd = append(aj.Cmd, joinUnambiguously(cmdline))
		aj.CmdReal += time.Since(start)
		if ps := cmd.ProcessState; ps != nil {
			aj.CmdUser += ps.UserTime()
			aj.CmdSys += ps.SystemTime()
		}
	}

	// err can be something like 'exit status 1'.
	// Add information about what program was running.
	// Note that if buf.Bytes() is non-empty, the caller usually
	// shows buf.Bytes() and does not print err at all, so the
	// prefix here does not make most output any more verbose.
	if err != nil {
		err = errors.New(cmdline[0] + ": " + err.Error())
	}
	return buf.Bytes(), err
}

// joinUnambiguously prints the slice, quoting where necessary to make the
// output unambiguous.
// TODO: See issue 5279. The printing of commands needs a complete redo.
func joinUnambiguously(a []string) string {
	var buf strings.Builder
	for i, s := range a {
		if i > 0 {
			buf.WriteByte(' ')
		}
		q := strconv.Quote(s)
		// A gccgo command line can contain -( and -).
		// Make sure we quote them since they are special to the shell.
		// The trimpath argument can also contain > (part of =>) and ;. Quote those too.
		if s == "" || strings.ContainsAny(s, " ()>;") || len(q) > len(s)+2 {
			buf.WriteString(q)
		} else {
			buf.WriteString(s)
		}
	}
	return buf.String()
}
```