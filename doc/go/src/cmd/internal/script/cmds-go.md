Response: The user wants to understand the functionality of the provided Go code, which seems to define a set of commands for a scripting language. I need to analyze each command in the `DefaultCmds` map and describe its purpose. For some commands, providing a Go code example illustrating their usage would be beneficial. If a command involves processing command-line arguments, I need to explain how those arguments are handled. Finally, I need to identify any common mistakes users might make when using these commands.

Here's a breakdown of how to approach each requirement:

1. **List the functionalities:** Go through the `DefaultCmds` map and briefly describe what each command does based on its name and the associated `CmdUsage`.

2. **Infer Go language feature and provide examples:**  For some commands, their functionality clearly maps to standard Go library functions (e.g., `os.ReadFile` for `cat`, `os.Chdir` for `cd`). In these cases, I can provide a simple Go code snippet that demonstrates the equivalent operation. I need to consider hypothetical inputs and outputs for these examples.

3. **Explain command-line argument handling:** For commands that take arguments (most of them), I need to detail what kind of arguments they expect and how they are processed. The `CmdUsage` structure provides some clues here.

4. **Identify common user errors:** This requires thinking about how users might misuse the commands based on their functionality and argument structure. For instance, providing the wrong number of arguments or incorrect argument types are potential errors.
这段代码定义了一系列用于在脚本环境中执行的命令。这些命令类似于常见的 Unix shell 命令，但它们在 Go 语言的脚本环境中运行。

以下是每个命令的功能列表：

* **`cat`**: 连接文件并将其内容打印到脚本的 stdout 缓冲区。
* **`cd`**: 改变当前工作目录。
* **`chmod`**: 改变文件或目录的权限。
* **`cmp`**: 比较两个文件的内容是否相同。
* **`cmpenv`**: 比较两个文件的内容是否相同，但在比较前会进行环境变量替换。
* **`cp`**: 复制文件或目录到新的位置。
* **`echo`**: 将参数写入 stdout 缓冲区，并在末尾添加换行符。
* **`env`**: 设置或显示环境变量的值。
* **`exec`**: 作为一个子进程运行任意可执行文件。
* **`exists`**: 检查指定的文件是否存在。
* **`grep`**: 在文件中查找匹配正则表达式的行。
* **`help`**: 显示命令和条件的帮助信息。
* **`mkdir`**: 创建目录，如果父目录不存在也会一并创建。
* **`mv`**: 将文件或目录重命名到新的路径。
* **`rm`**: 删除文件或目录。如果目标是目录，则会递归删除其内容。
* **`replace`**: 替换文件中所有出现的字符串。
* **`sleep`**: 休眠指定的时间。
* **`stderr`**: 在 stderr 缓冲区中查找匹配正则表达式的行。
* **`stdout`**: 在 stdout 缓冲区中查找匹配正则表达式的行。
* **`stop`**: 停止脚本的执行。
* **`symlink`**: 创建一个符号链接。
* **`wait`**: 等待所有后台命令完成。

## Go 语言功能实现示例

### `cat` 命令

`cat` 命令使用了 Go 语言的 `os` 包中的 `os.ReadFile` 函数来读取文件内容，并使用 `strings.Builder` 来构建输出字符串。

```go
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <file1> [<file2> ...]")
		return
	}

	var content string
	for _, filename := range os.Args[1:] {
		data, err := os.ReadFile(filename)
		if err != nil {
			fmt.Println("Error reading file:", err)
			return
		}
		content += string(data)
	}
	fmt.Print(content)
}
```

**假设输入：**

创建两个文件 `file1.txt` 和 `file2.txt`:

`file1.txt` 内容:
```
Hello
```

`file2.txt` 内容:
```
World!
```

**命令行执行：**

```bash
go run main.go file1.txt file2.txt
```

**预期输出：**

```
Hello
World!
```

### `cd` 命令

`cd` 命令使用了 Go 语言的 `os` 包中的 `os.Chdir` 函数来改变当前工作目录。

```go
package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: go run main.go <directory>")
		return
	}

	newDir := os.Args[1]

	err := os.Chdir(newDir)
	if err != nil {
		fmt.Println("Error changing directory:", err)
		return
	}

	currentDir, err := os.Getwd()
	if err != nil {
		fmt.Println("Error getting current directory:", err)
		return
	}

	fmt.Println("Current directory:", currentDir)
}
```

**假设输入：**

假设当前目录下有一个名为 `testdir` 的目录。

**命令行执行：**

```bash
go run main.go testdir
```

**预期输出：**

（假设当前工作目录是 `/home/user/projects`）

```
Current directory: /home/user/projects/testdir
```

## 命令行参数处理

以下是一些命令及其命令行参数处理的详细介绍：

* **`cat files...`**: 接受一个或多个文件名作为参数，将这些文件的内容按顺序连接起来并输出到 stdout。
* **`cd dir`**: 接受一个目录路径作为参数，将当前工作目录更改为该路径。
* **`chmod perm paths...`**: 接受一个表示权限的数字字符串（例如 "777", "644"）和一个或多个文件或目录路径作为参数，将这些文件或目录的权限修改为指定的值。
* **`cmp [-q] file1 file2`**: 接受两个文件名作为参数，比较它们的内容。 `-q` 是一个可选的 flag，表示静默模式，不输出差异信息。`file1` 可以是 `"stdout"` 或 `"stderr"`，表示比较上一个命令的输出缓冲区与文件内容。
* **`cmpenv [-q] file1 file2`**: 与 `cmp` 类似，但在比较前会对 `file1` 和 `file2` 的内容进行环境变量替换。
* **`cp src... dst`**: 接受一个或多个源文件路径和一个目标路径作为参数。如果目标是目录，则将源文件复制到该目录下。`src` 可以是 `"stdout"` 或 `"stderr"`，表示复制上一个命令的输出缓冲区。
* **`echo string...`**: 接受任意数量的字符串作为参数，将它们连接起来并输出到 stdout，并在末尾添加换行符。
* **`env [key[=value]...]`**:  如果没有参数，则打印当前脚本环境的所有变量。如果参数是 `key=value` 的形式，则设置环境变量。如果参数是 `key` 的形式，则打印该环境变量的值。
* **`exec program [args...]`**: 接受一个可执行程序名和可选的参数列表，作为子进程执行该程序。
* **`exists [-readonly] [-exec] file...`**: 接受一个或多个文件名作为参数，检查它们是否存在。`-readonly` flag 检查文件是否存在且只读。`-exec` flag (非 Windows) 检查文件是否存在且可执行。
* **`grep [-count=N] [-q] 'pattern' file`**: 接受一个正则表达式模式和一个文件名作为参数，在文件中查找匹配该模式的行。`-count=N` 指定匹配的数量必须正好为 N。`-q` 表示静默模式，不打印匹配的行。
* **`help [-v] name...`**:  如果没有参数，列出所有可用的命令和条件。如果提供命令名作为参数，则显示该命令的详细帮助信息。如果提供 `-v` flag，则在列出所有命令时显示详细信息。可以使用 `[condition]` 的形式查看特定条件的帮助。
* **`mkdir path...`**: 接受一个或多个目录路径作为参数，创建这些目录。如果父目录不存在，也会一并创建。
* **`mv old new`**: 接受旧路径和新路径作为参数，将文件或目录从旧路径移动（重命名）到新路径。
* **`rm path...`**: 接受一个或多个文件或目录路径作为参数，删除这些文件或目录。如果是目录，则递归删除其内容。
* **`replace [old new]... file`**: 接受一系列的旧字符串和新字符串的配对，以及一个文件名作为参数。将文件中所有出现的旧字符串替换为对应的新字符串。旧字符串和新字符串的解析方式类似于 Go 语言的带引号的字符串。
* **`sleep duration`**: 接受一个表示持续时间的字符串（例如 "1s", "500ms"）作为参数，使脚本暂停执行指定的时间。
* **`stderr [-count=N] [-q] 'pattern'`**: 接受一个正则表达式模式作为参数，在 stderr 缓冲区中查找匹配该模式的行。参数与 `grep` 的匹配参数类似。
* **`stdout [-count=N] [-q] 'pattern'`**: 接受一个正则表达式模式作为参数，在 stdout 缓冲区中查找匹配该模式的行。参数与 `grep` 的匹配参数类似。
* **`stop [msg]`**: 接受一个可选的消息作为参数，停止脚本的执行。该消息会记录到脚本日志中。
* **`symlink path -> target`**: 接受三个参数：链接路径，固定的 "->" 字符串，以及目标路径。创建一个指向目标的符号链接。目标路径不会通过 `s.Path()` 进行解析，而是相对于链接文件所在的目录。
* **`wait`**:  不接受参数，等待所有后台命令完成执行。

## 使用者易犯错的点

* **`chmod` 的权限参数**: 用户可能会混淆数字权限的含义，或者提供非法的权限格式。例如，提供字母权限 (如 `rwxrwxrwx`) 会导致错误，因为该命令只支持数字权限。
    ```
    # 错误示例
    chmod rwxrwxrwx myfile.txt
    ```
* **`replace` 的字符串转义**: `replace` 命令的 `old` 和 `new` 参数会像 Go 语言的带引号字符串一样进行解析，用户可能会忘记对特殊字符进行转义。
    ```
    # 错误示例，希望替换包含反斜杠的字符串
    replace "\path\to\file" "newpath" myfile.txt
    # 正确示例
    replace "\\path\\to\\file" "newpath" myfile.txt
    ```
* **`symlink` 的目标路径理解**: 用户可能会认为 `symlink` 命令的目标路径会像其他命令的文件参数一样通过 `s.Path()` 进行解析，导致链接指向错误的位置。实际上，目标路径是相对于链接文件所在的目录的。
    ```
    # 假设当前工作目录是 /home/user，要创建 /tmp/mylink 指向 /opt/target
    # 脚本中当前工作目录是脚本执行的临时目录，而非 /home/user

    # 错误示例，假设脚本当前工作目录是 /tmp/script-workdir
    symlink /tmp/mylink -> /opt/target  # 这会在 /tmp/script-workdir 下创建一个指向 /opt/target 的链接

    # 正确示例 (通常需要在脚本中先 cd 到目标位置附近)
    cd /tmp
    symlink mylink -> /opt/target
    ```
* **`grep`, `stdout`, `stderr` 的正则表达式**: 用户可能会使用不符合 Go 语言 `regexp` 包语法的正则表达式，或者忘记使用 `(?m)` 启用多行模式。
    ```
    # 错误示例，POSIX 字符类在 Go 的 regexp 包中不直接支持
    grep '[[:digit:]]+' myfile.txt
    # 正确示例
    grep '\d+' myfile.txt

    # 错误示例，没有启用多行模式，^ 和 $ 只匹配整个字符串的开头和结尾
    echo "line1\nline2" | stdout '^line1$'
    # 正确示例
    echo "line1\nline2" | stdout '(?m)^line1$'
    ```
* **`mv` 的跨文件系统限制**: 用户可能会尝试在不同的文件系统之间移动文件，这在某些操作系统上可能会失败或有不同的行为。
* **忘记 `wait` 命令**: 如果脚本中使用了后台执行的命令 (通过某些机制，但这部分代码中没有直接体现)，用户可能会忘记使用 `wait` 命令来等待这些命令完成，导致脚本在后台命令完成之前就结束，可能会丢失输出或导致竞态条件。

总的来说，理解每个命令的参数类型、数量以及它们对路径的解析方式是避免错误的关键。仔细阅读 `CmdUsage` 中的说明可以帮助用户正确使用这些命令。

Prompt: 
```
这是路径为go/src/cmd/internal/script/cmds.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package script

import (
	"cmd/internal/pathcache"
	"cmd/internal/robustio"
	"errors"
	"fmt"
	"internal/diff"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultCmds returns a set of broadly useful script commands.
//
// Run the 'help' command within a script engine to view a list of the available
// commands.
func DefaultCmds() map[string]Cmd {
	return map[string]Cmd{
		"cat":     Cat(),
		"cd":      Cd(),
		"chmod":   Chmod(),
		"cmp":     Cmp(),
		"cmpenv":  Cmpenv(),
		"cp":      Cp(),
		"echo":    Echo(),
		"env":     Env(),
		"exec":    Exec(func(cmd *exec.Cmd) error { return cmd.Process.Signal(os.Interrupt) }, 100*time.Millisecond), // arbitrary grace period
		"exists":  Exists(),
		"grep":    Grep(),
		"help":    Help(),
		"mkdir":   Mkdir(),
		"mv":      Mv(),
		"rm":      Rm(),
		"replace": Replace(),
		"sleep":   Sleep(),
		"stderr":  Stderr(),
		"stdout":  Stdout(),
		"stop":    Stop(),
		"symlink": Symlink(),
		"wait":    Wait(),
	}
}

// Command returns a new Cmd with a Usage method that returns a copy of the
// given CmdUsage and a Run method calls the given function.
func Command(usage CmdUsage, run func(*State, ...string) (WaitFunc, error)) Cmd {
	return &funcCmd{
		usage: usage,
		run:   run,
	}
}

// A funcCmd implements Cmd using a function value.
type funcCmd struct {
	usage CmdUsage
	run   func(*State, ...string) (WaitFunc, error)
}

func (c *funcCmd) Run(s *State, args ...string) (WaitFunc, error) {
	return c.run(s, args...)
}

func (c *funcCmd) Usage() *CmdUsage { return &c.usage }

// firstNonFlag returns a slice containing the index of the first argument in
// rawArgs that is not a flag, or nil if all arguments are flags.
func firstNonFlag(rawArgs ...string) []int {
	for i, arg := range rawArgs {
		if !strings.HasPrefix(arg, "-") {
			return []int{i}
		}
		if arg == "--" {
			return []int{i + 1}
		}
	}
	return nil
}

// Cat writes the concatenated contents of the named file(s) to the script's
// stdout buffer.
func Cat() Cmd {
	return Command(
		CmdUsage{
			Summary: "concatenate files and print to the script's stdout buffer",
			Args:    "files...",
		},
		func(s *State, args ...string) (WaitFunc, error) {
			if len(args) == 0 {
				return nil, ErrUsage
			}

			paths := make([]string, 0, len(args))
			for _, arg := range args {
				paths = append(paths, s.Path(arg))
			}

			var buf strings.Builder
			errc := make(chan error, 1)
			go func() {
				for _, p := range paths {
					b, err := os.ReadFile(p)
					buf.Write(b)
					if err != nil {
						errc <- err
						return
					}
				}
				errc <- nil
			}()

			wait := func(*State) (stdout, stderr string, err error) {
				err = <-errc
				return buf.String(), "", err
			}
			return wait, nil
		})
}

// Cd changes the current working directory.
func Cd() Cmd {
	return Command(
		CmdUsage{
			Summary: "change the working directory",
			Args:    "dir",
		},
		func(s *State, args ...string) (WaitFunc, error) {
			if len(args) != 1 {
				return nil, ErrUsage
			}
			return nil, s.Chdir(args[0])
		})
}

// Chmod changes the permissions of a file or a directory..
func Chmod() Cmd {
	return Command(
		CmdUsage{
			Summary: "change file mode bits",
			Args:    "perm paths...",
			Detail: []string{
				"Changes the permissions of the named files or directories to be equal to perm.",
				"Only numerical permissions are supported.",
			},
		},
		func(s *State, args ...string) (WaitFunc, error) {
			if len(args) < 2 {
				return nil, ErrUsage
			}

			perm, err := strconv.ParseUint(args[0], 0, 32)
			if err != nil || perm&uint64(fs.ModePerm) != perm {
				return nil, fmt.Errorf("invalid mode: %s", args[0])
			}

			for _, arg := range args[1:] {
				err := os.Chmod(s.Path(arg), fs.FileMode(perm))
				if err != nil {
					return nil, err
				}
			}
			return nil, nil
		})
}

// Cmp compares the contents of two files, or the contents of either the
// "stdout" or "stderr" buffer and a file, returning a non-nil error if the
// contents differ.
func Cmp() Cmd {
	return Command(
		CmdUsage{
			Args:    "[-q] file1 file2",
			Summary: "compare files for differences",
			Detail: []string{
				"By convention, file1 is the actual data and file2 is the expected data.",
				"The command succeeds if the file contents are identical.",
				"File1 can be 'stdout' or 'stderr' to compare the stdout or stderr buffer from the most recent command.",
			},
		},
		func(s *State, args ...string) (WaitFunc, error) {
			return nil, doCompare(s, false, args...)
		})
}

// Cmpenv is like Compare, but also performs environment substitutions
// on the contents of both arguments.
func Cmpenv() Cmd {
	return Command(
		CmdUsage{
			Args:    "[-q] file1 file2",
			Summary: "compare files for differences, with environment expansion",
			Detail: []string{
				"By convention, file1 is the actual data and file2 is the expected data.",
				"The command succeeds if the file contents are identical after substituting variables from the script environment.",
				"File1 can be 'stdout' or 'stderr' to compare the script's stdout or stderr buffer.",
			},
		},
		func(s *State, args ...string) (WaitFunc, error) {
			return nil, doCompare(s, true, args...)
		})
}

func doCompare(s *State, env bool, args ...string) error {
	quiet := false
	if len(args) > 0 && args[0] == "-q" {
		quiet = true
		args = args[1:]
	}
	if len(args) != 2 {
		return ErrUsage
	}

	name1, name2 := args[0], args[1]
	var text1, text2 string
	switch name1 {
	case "stdout":
		text1 = s.Stdout()
	case "stderr":
		text1 = s.Stderr()
	default:
		data, err := os.ReadFile(s.Path(name1))
		if err != nil {
			return err
		}
		text1 = string(data)
	}

	data, err := os.ReadFile(s.Path(name2))
	if err != nil {
		return err
	}
	text2 = string(data)

	if env {
		text1 = s.ExpandEnv(text1, false)
		text2 = s.ExpandEnv(text2, false)
	}

	if text1 != text2 {
		if !quiet {
			diffText := diff.Diff(name1, []byte(text1), name2, []byte(text2))
			s.Logf("%s\n", diffText)
		}
		return fmt.Errorf("%s and %s differ", name1, name2)
	}
	return nil
}

// Cp copies one or more files to a new location.
func Cp() Cmd {
	return Command(
		CmdUsage{
			Summary: "copy files to a target file or directory",
			Args:    "src... dst",
			Detail: []string{
				"src can include 'stdout' or 'stderr' to copy from the script's stdout or stderr buffer.",
			},
		},
		func(s *State, args ...string) (WaitFunc, error) {
			if len(args) < 2 {
				return nil, ErrUsage
			}

			dst := s.Path(args[len(args)-1])
			info, err := os.Stat(dst)
			dstDir := err == nil && info.IsDir()
			if len(args) > 2 && !dstDir {
				return nil, &fs.PathError{Op: "cp", Path: dst, Err: errors.New("destination is not a directory")}
			}

			for _, arg := range args[:len(args)-1] {
				var (
					src  string
					data []byte
					mode fs.FileMode
				)
				switch arg {
				case "stdout":
					src = arg
					data = []byte(s.Stdout())
					mode = 0666
				case "stderr":
					src = arg
					data = []byte(s.Stderr())
					mode = 0666
				default:
					src = s.Path(arg)
					info, err := os.Stat(src)
					if err != nil {
						return nil, err
					}
					mode = info.Mode() & 0777
					data, err = os.ReadFile(src)
					if err != nil {
						return nil, err
					}
				}
				targ := dst
				if dstDir {
					targ = filepath.Join(dst, filepath.Base(src))
				}
				err := os.WriteFile(targ, data, mode)
				if err != nil {
					return nil, err
				}
			}

			return nil, nil
		})
}

// Echo writes its arguments to stdout, followed by a newline.
func Echo() Cmd {
	return Command(
		CmdUsage{
			Summary: "display a line of text",
			Args:    "string...",
		},
		func(s *State, args ...string) (WaitFunc, error) {
			var buf strings.Builder
			for i, arg := range args {
				if i > 0 {
					buf.WriteString(" ")
				}
				buf.WriteString(arg)
			}
			buf.WriteString("\n")
			out := buf.String()

			// Stuff the result into a callback to satisfy the OutputCommandFunc
			// interface, even though it isn't really asynchronous even if run in the
			// background.
			//
			// Nobody should be running 'echo' as a background command, but it's not worth
			// defining yet another interface, and also doesn't seem worth shoehorning
			// into a SimpleCommand the way we did with Wait.
			return func(*State) (stdout, stderr string, err error) {
				return out, "", nil
			}, nil
		})
}

// Env sets or logs the values of environment variables.
//
// With no arguments, Env reports all variables in the environment.
// "key=value" arguments set variables, and arguments without "="
// cause the corresponding value to be printed to the stdout buffer.
func Env() Cmd {
	return Command(
		CmdUsage{
			Summary: "set or log the values of environment variables",
			Args:    "[key[=value]...]",
			Detail: []string{
				"With no arguments, print the script environment to the log.",
				"Otherwise, add the listed key=value pairs to the environment or print the listed keys.",
			},
		},
		func(s *State, args ...string) (WaitFunc, error) {
			out := new(strings.Builder)
			if len(args) == 0 {
				for _, kv := range s.env {
					fmt.Fprintf(out, "%s\n", kv)
				}
			} else {
				for _, env := range args {
					i := strings.Index(env, "=")
					if i < 0 {
						// Display value instead of setting it.
						fmt.Fprintf(out, "%s=%s\n", env, s.envMap[env])
						continue
					}
					if err := s.Setenv(env[:i], env[i+1:]); err != nil {
						return nil, err
					}
				}
			}
			var wait WaitFunc
			if out.Len() > 0 || len(args) == 0 {
				wait = func(*State) (stdout, stderr string, err error) {
					return out.String(), "", nil
				}
			}
			return wait, nil
		})
}

// Exec runs an arbitrary executable as a subprocess.
//
// When the Script's context is canceled, Exec sends the interrupt signal, then
// waits for up to the given delay for the subprocess to flush output before
// terminating it with os.Kill.
func Exec(cancel func(*exec.Cmd) error, waitDelay time.Duration) Cmd {
	return Command(
		CmdUsage{
			Summary: "run an executable program with arguments",
			Args:    "program [args...]",
			Detail: []string{
				"Note that 'exec' does not terminate the script (unlike Unix shells).",
			},
			Async: true,
		},
		func(s *State, args ...string) (WaitFunc, error) {
			if len(args) < 1 {
				return nil, ErrUsage
			}

			// Use the script's PATH to look up the command (if it does not contain a separator)
			// instead of the test process's PATH (see lookPath).
			// Don't use filepath.Clean, since that changes "./foo" to "foo".
			name := filepath.FromSlash(args[0])
			path := name
			if !strings.Contains(name, string(filepath.Separator)) {
				var err error
				path, err = lookPath(s, name)
				if err != nil {
					return nil, err
				}
			}

			return startCommand(s, name, path, args[1:], cancel, waitDelay)
		})
}

func startCommand(s *State, name, path string, args []string, cancel func(*exec.Cmd) error, waitDelay time.Duration) (WaitFunc, error) {
	var (
		cmd                  *exec.Cmd
		stdoutBuf, stderrBuf strings.Builder
	)
	for {
		cmd = exec.CommandContext(s.Context(), path, args...)
		if cancel == nil {
			cmd.Cancel = nil
		} else {
			cmd.Cancel = func() error { return cancel(cmd) }
		}
		cmd.WaitDelay = waitDelay
		cmd.Args[0] = name
		cmd.Dir = s.Getwd()
		cmd.Env = s.env
		cmd.Stdout = &stdoutBuf
		cmd.Stderr = &stderrBuf
		err := cmd.Start()
		if err == nil {
			break
		}
		if isETXTBSY(err) {
			// If the script (or its host process) just wrote the executable we're
			// trying to run, a fork+exec in another thread may be holding open the FD
			// that we used to write the executable (see https://go.dev/issue/22315).
			// Since the descriptor should have CLOEXEC set, the problem should
			// resolve as soon as the forked child reaches its exec call.
			// Keep retrying until that happens.
		} else {
			return nil, err
		}
	}

	wait := func(s *State) (stdout, stderr string, err error) {
		err = cmd.Wait()
		return stdoutBuf.String(), stderrBuf.String(), err
	}
	return wait, nil
}

// lookPath is (roughly) like exec.LookPath, but it uses the script's current
// PATH to find the executable.
func lookPath(s *State, command string) (string, error) {
	var strEqual func(string, string) bool
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		// Using GOOS as a proxy for case-insensitive file system.
		// TODO(bcmills): Remove this assumption.
		strEqual = strings.EqualFold
	} else {
		strEqual = func(a, b string) bool { return a == b }
	}

	var pathExt []string
	var searchExt bool
	var isExecutable func(os.FileInfo) bool
	if runtime.GOOS == "windows" {
		// Use the test process's PathExt instead of the script's.
		// If PathExt is set in the command's environment, cmd.Start fails with
		// "parameter is invalid". Not sure why.
		// If the command already has an extension in PathExt (like "cmd.exe")
		// don't search for other extensions (not "cmd.bat.exe").
		pathExt = strings.Split(os.Getenv("PathExt"), string(filepath.ListSeparator))
		searchExt = true
		cmdExt := filepath.Ext(command)
		for _, ext := range pathExt {
			if strEqual(cmdExt, ext) {
				searchExt = false
				break
			}
		}
		isExecutable = func(fi os.FileInfo) bool {
			return fi.Mode().IsRegular()
		}
	} else {
		isExecutable = func(fi os.FileInfo) bool {
			return fi.Mode().IsRegular() && fi.Mode().Perm()&0111 != 0
		}
	}

	pathEnv, _ := s.LookupEnv(pathEnvName())
	for _, dir := range strings.Split(pathEnv, string(filepath.ListSeparator)) {
		if dir == "" {
			continue
		}

		// Determine whether dir needs a trailing path separator.
		// Note: we avoid filepath.Join in this function because it cleans the
		// result: we want to preserve the exact dir prefix from the environment.
		sep := string(filepath.Separator)
		if os.IsPathSeparator(dir[len(dir)-1]) {
			sep = ""
		}

		if searchExt {
			ents, err := os.ReadDir(dir)
			if err != nil {
				continue
			}
			for _, ent := range ents {
				for _, ext := range pathExt {
					if !ent.IsDir() && strEqual(ent.Name(), command+ext) {
						return dir + sep + ent.Name(), nil
					}
				}
			}
		} else {
			path := dir + sep + command
			if fi, err := os.Stat(path); err == nil && isExecutable(fi) {
				return path, nil
			}
		}
	}
	return "", &exec.Error{Name: command, Err: exec.ErrNotFound}
}

// pathEnvName returns the platform-specific variable used by os/exec.LookPath
// to look up executable names (either "PATH" or "path").
//
// TODO(bcmills): Investigate whether we can instead use PATH uniformly and
// rewrite it to $path when executing subprocesses.
func pathEnvName() string {
	switch runtime.GOOS {
	case "plan9":
		return "path"
	default:
		return "PATH"
	}
}

// Exists checks that the named file(s) exist.
func Exists() Cmd {
	return Command(
		CmdUsage{
			Summary: "check that files exist",
			Args:    "[-readonly] [-exec] file...",
		},
		func(s *State, args ...string) (WaitFunc, error) {
			var readonly, exec bool
		loop:
			for len(args) > 0 {
				switch args[0] {
				case "-readonly":
					readonly = true
					args = args[1:]
				case "-exec":
					exec = true
					args = args[1:]
				default:
					break loop
				}
			}
			if len(args) == 0 {
				return nil, ErrUsage
			}

			for _, file := range args {
				file = s.Path(file)
				info, err := os.Stat(file)
				if err != nil {
					return nil, err
				}
				if readonly && info.Mode()&0222 != 0 {
					return nil, fmt.Errorf("%s exists but is writable", file)
				}
				if exec && runtime.GOOS != "windows" && info.Mode()&0111 == 0 {
					return nil, fmt.Errorf("%s exists but is not executable", file)
				}
			}

			return nil, nil
		})
}

// Grep checks that file content matches a regexp.
// Like stdout/stderr and unlike Unix grep, it accepts Go regexp syntax.
//
// Grep does not modify the State's stdout or stderr buffers.
// (Its output goes to the script log, not stdout.)
func Grep() Cmd {
	return Command(
		CmdUsage{
			Summary: "find lines in a file that match a pattern",
			Args:    matchUsage + " file",
			Detail: []string{
				"The command succeeds if at least one match (or the exact count, if given) is found.",
				"The -q flag suppresses printing of matches.",
			},
			RegexpArgs: firstNonFlag,
		},
		func(s *State, args ...string) (WaitFunc, error) {
			return nil, match(s, args, "", "grep")
		})
}

const matchUsage = "[-count=N] [-q] 'pattern'"

// match implements the Grep, Stdout, and Stderr commands.
func match(s *State, args []string, text, name string) error {
	n := 0
	if len(args) >= 1 && strings.HasPrefix(args[0], "-count=") {
		var err error
		n, err = strconv.Atoi(args[0][len("-count="):])
		if err != nil {
			return fmt.Errorf("bad -count=: %v", err)
		}
		if n < 1 {
			return fmt.Errorf("bad -count=: must be at least 1")
		}
		args = args[1:]
	}
	quiet := false
	if len(args) >= 1 && args[0] == "-q" {
		quiet = true
		args = args[1:]
	}

	isGrep := name == "grep"

	wantArgs := 1
	if isGrep {
		wantArgs = 2
	}
	if len(args) != wantArgs {
		return ErrUsage
	}

	pattern := `(?m)` + args[0]
	re, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}

	if isGrep {
		name = args[1] // for error messages
		data, err := os.ReadFile(s.Path(args[1]))
		if err != nil {
			return err
		}
		text = string(data)
	}

	if n > 0 {
		count := len(re.FindAllString(text, -1))
		if count != n {
			return fmt.Errorf("found %d matches for %#q in %s", count, pattern, name)
		}
		return nil
	}

	if !re.MatchString(text) {
		return fmt.Errorf("no match for %#q in %s", pattern, name)
	}

	if !quiet {
		// Print the lines containing the match.
		loc := re.FindStringIndex(text)
		for loc[0] > 0 && text[loc[0]-1] != '\n' {
			loc[0]--
		}
		for loc[1] < len(text) && text[loc[1]] != '\n' {
			loc[1]++
		}
		lines := strings.TrimSuffix(text[loc[0]:loc[1]], "\n")
		s.Logf("matched: %s\n", lines)
	}
	return nil
}

// Help writes command documentation to the script log.
func Help() Cmd {
	return Command(
		CmdUsage{
			Summary: "log help text for commands and conditions",
			Args:    "[-v] name...",
			Detail: []string{
				"To display help for a specific condition, enclose it in brackets: 'help [amd64]'.",
				"To display complete documentation when listing all commands, pass the -v flag.",
			},
		},
		func(s *State, args ...string) (WaitFunc, error) {
			if s.engine == nil {
				return nil, errors.New("no engine configured")
			}

			verbose := false
			if len(args) > 0 {
				verbose = true
				if args[0] == "-v" {
					args = args[1:]
				}
			}

			var cmds, conds []string
			for _, arg := range args {
				if strings.HasPrefix(arg, "[") && strings.HasSuffix(arg, "]") {
					conds = append(conds, arg[1:len(arg)-1])
				} else {
					cmds = append(cmds, arg)
				}
			}

			out := new(strings.Builder)

			if len(conds) > 0 || (len(args) == 0 && len(s.engine.Conds) > 0) {
				if conds == nil {
					out.WriteString("conditions:\n\n")
				}
				s.engine.ListConds(out, s, conds...)
			}

			if len(cmds) > 0 || len(args) == 0 {
				if len(args) == 0 {
					out.WriteString("\ncommands:\n\n")
				}
				s.engine.ListCmds(out, verbose, cmds...)
			}

			wait := func(*State) (stdout, stderr string, err error) {
				return out.String(), "", nil
			}
			return wait, nil
		})
}

// Mkdir creates a directory and any needed parent directories.
func Mkdir() Cmd {
	return Command(
		CmdUsage{
			Summary: "create directories, if they do not already exist",
			Args:    "path...",
			Detail: []string{
				"Unlike Unix mkdir, parent directories are always created if needed.",
			},
		},
		func(s *State, args ...string) (WaitFunc, error) {
			if len(args) < 1 {
				return nil, ErrUsage
			}
			for _, arg := range args {
				if err := os.MkdirAll(s.Path(arg), 0777); err != nil {
					return nil, err
				}
			}
			return nil, nil
		})
}

// Mv renames an existing file or directory to a new path.
func Mv() Cmd {
	return Command(
		CmdUsage{
			Summary: "rename a file or directory to a new path",
			Args:    "old new",
			Detail: []string{
				"OS-specific restrictions may apply when old and new are in different directories.",
			},
		},
		func(s *State, args ...string) (WaitFunc, error) {
			if len(args) != 2 {
				return nil, ErrUsage
			}
			return nil, os.Rename(s.Path(args[0]), s.Path(args[1]))
		})
}

// Program returns a new command that runs the named program, found from the
// host process's PATH (not looked up in the script's PATH).
func Program(name string, cancel func(*exec.Cmd) error, waitDelay time.Duration) Cmd {
	var (
		shortName    string
		summary      string
		lookPathOnce sync.Once
		path         string
		pathErr      error
	)
	if filepath.IsAbs(name) {
		lookPathOnce.Do(func() { path = filepath.Clean(name) })
		shortName = strings.TrimSuffix(filepath.Base(path), ".exe")
		summary = "run the '" + shortName + "' program provided by the script host"
	} else {
		shortName = name
		summary = "run the '" + shortName + "' program from the script host's PATH"
	}

	return Command(
		CmdUsage{
			Summary: summary,
			Args:    "[args...]",
			Async:   true,
		},
		func(s *State, args ...string) (WaitFunc, error) {
			lookPathOnce.Do(func() {
				path, pathErr = pathcache.LookPath(name)
			})
			if pathErr != nil {
				return nil, pathErr
			}
			return startCommand(s, shortName, path, args, cancel, waitDelay)
		})
}

// Replace replaces all occurrences of a string in a file with another string.
func Replace() Cmd {
	return Command(
		CmdUsage{
			Summary: "replace strings in a file",
			Args:    "[old new]... file",
			Detail: []string{
				"The 'old' and 'new' arguments are unquoted as if in quoted Go strings.",
			},
		},
		func(s *State, args ...string) (WaitFunc, error) {
			if len(args)%2 != 1 {
				return nil, ErrUsage
			}

			oldNew := make([]string, 0, len(args)-1)
			for _, arg := range args[:len(args)-1] {
				s, err := strconv.Unquote(`"` + arg + `"`)
				if err != nil {
					return nil, err
				}
				oldNew = append(oldNew, s)
			}

			r := strings.NewReplacer(oldNew...)
			file := s.Path(args[len(args)-1])

			data, err := os.ReadFile(file)
			if err != nil {
				return nil, err
			}
			replaced := r.Replace(string(data))

			return nil, os.WriteFile(file, []byte(replaced), 0666)
		})
}

// Rm removes a file or directory.
//
// If a directory, Rm also recursively removes that directory's
// contents.
func Rm() Cmd {
	return Command(
		CmdUsage{
			Summary: "remove a file or directory",
			Args:    "path...",
			Detail: []string{
				"If the path is a directory, its contents are removed recursively.",
			},
		},
		func(s *State, args ...string) (WaitFunc, error) {
			if len(args) < 1 {
				return nil, ErrUsage
			}
			for _, arg := range args {
				if err := removeAll(s.Path(arg)); err != nil {
					return nil, err
				}
			}
			return nil, nil
		})
}

// removeAll removes dir and all files and directories it contains.
//
// Unlike os.RemoveAll, removeAll attempts to make the directories writable if
// needed in order to remove their contents.
func removeAll(dir string) error {
	// module cache has 0444 directories;
	// make them writable in order to remove content.
	filepath.WalkDir(dir, func(path string, info fs.DirEntry, err error) error {
		// chmod not only directories, but also things that we couldn't even stat
		// due to permission errors: they may also be unreadable directories.
		if err != nil || info.IsDir() {
			os.Chmod(path, 0777)
		}
		return nil
	})
	return robustio.RemoveAll(dir)
}

// Sleep sleeps for the given Go duration or until the script's context is
// canceled, whichever happens first.
func Sleep() Cmd {
	return Command(
		CmdUsage{
			Summary: "sleep for a specified duration",
			Args:    "duration",
			Detail: []string{
				"The duration must be given as a Go time.Duration string.",
			},
			Async: true,
		},
		func(s *State, args ...string) (WaitFunc, error) {
			if len(args) != 1 {
				return nil, ErrUsage
			}

			d, err := time.ParseDuration(args[0])
			if err != nil {
				return nil, err
			}

			timer := time.NewTimer(d)
			wait := func(s *State) (stdout, stderr string, err error) {
				ctx := s.Context()
				select {
				case <-ctx.Done():
					timer.Stop()
					return "", "", ctx.Err()
				case <-timer.C:
					return "", "", nil
				}
			}
			return wait, nil
		})
}

// Stderr searches for a regular expression in the stderr buffer.
func Stderr() Cmd {
	return Command(
		CmdUsage{
			Summary: "find lines in the stderr buffer that match a pattern",
			Args:    matchUsage + " file",
			Detail: []string{
				"The command succeeds if at least one match (or the exact count, if given) is found.",
				"The -q flag suppresses printing of matches.",
			},
			RegexpArgs: firstNonFlag,
		},
		func(s *State, args ...string) (WaitFunc, error) {
			return nil, match(s, args, s.Stderr(), "stderr")
		})
}

// Stdout searches for a regular expression in the stdout buffer.
func Stdout() Cmd {
	return Command(
		CmdUsage{
			Summary: "find lines in the stdout buffer that match a pattern",
			Args:    matchUsage + " file",
			Detail: []string{
				"The command succeeds if at least one match (or the exact count, if given) is found.",
				"The -q flag suppresses printing of matches.",
			},
			RegexpArgs: firstNonFlag,
		},
		func(s *State, args ...string) (WaitFunc, error) {
			return nil, match(s, args, s.Stdout(), "stdout")
		})
}

// Stop returns a sentinel error that causes script execution to halt
// and s.Execute to return with a nil error.
func Stop() Cmd {
	return Command(
		CmdUsage{
			Summary: "stop execution of the script",
			Args:    "[msg]",
			Detail: []string{
				"The message is written to the script log, but no error is reported from the script engine.",
			},
		},
		func(s *State, args ...string) (WaitFunc, error) {
			if len(args) > 1 {
				return nil, ErrUsage
			}
			// TODO(bcmills): The argument passed to stop seems redundant with comments.
			// Either use it systematically or remove it.
			if len(args) == 1 {
				return nil, stopError{msg: args[0]}
			}
			return nil, stopError{}
		})
}

// stopError is the sentinel error type returned by the Stop command.
type stopError struct {
	msg string
}

func (s stopError) Error() string {
	if s.msg == "" {
		return "stop"
	}
	return "stop: " + s.msg
}

// Symlink creates a symbolic link.
func Symlink() Cmd {
	return Command(
		CmdUsage{
			Summary: "create a symlink",
			Args:    "path -> target",
			Detail: []string{
				"Creates path as a symlink to target.",
				"The '->' token (like in 'ls -l' output on Unix) is required.",
			},
		},
		func(s *State, args ...string) (WaitFunc, error) {
			if len(args) != 3 || args[1] != "->" {
				return nil, ErrUsage
			}

			// Note that the link target args[2] is not interpreted with s.Path:
			// it will be interpreted relative to the directory file is in.
			return nil, os.Symlink(filepath.FromSlash(args[2]), s.Path(args[0]))
		})
}

// Wait waits for the completion of background commands.
//
// When Wait returns, the stdout and stderr buffers contain the concatenation of
// the background commands' respective outputs in the order in which those
// commands were started.
func Wait() Cmd {
	return Command(
		CmdUsage{
			Summary: "wait for completion of background commands",
			Args:    "",
			Detail: []string{
				"Waits for all background commands to complete.",
				"The output (and any error) from each command is printed to the log in the order in which the commands were started.",
				"After the call to 'wait', the script's stdout and stderr buffers contain the concatenation of the background commands' outputs.",
			},
		},
		func(s *State, args ...string) (WaitFunc, error) {
			if len(args) > 0 {
				return nil, ErrUsage
			}

			var stdouts, stderrs []string
			var errs []*CommandError
			for _, bg := range s.background {
				stdout, stderr, err := bg.wait(s)

				beforeArgs := ""
				if len(bg.args) > 0 {
					beforeArgs = " "
				}
				s.Logf("[background] %s%s%s\n", bg.name, beforeArgs, quoteArgs(bg.args))

				if stdout != "" {
					s.Logf("[stdout]\n%s", stdout)
					stdouts = append(stdouts, stdout)
				}
				if stderr != "" {
					s.Logf("[stderr]\n%s", stderr)
					stderrs = append(stderrs, stderr)
				}
				if err != nil {
					s.Logf("[%v]\n", err)
				}
				if cmdErr := checkStatus(bg.command, err); cmdErr != nil {
					errs = append(errs, cmdErr.(*CommandError))
				}
			}

			s.stdout = strings.Join(stdouts, "")
			s.stderr = strings.Join(stderrs, "")
			s.background = nil
			if len(errs) > 0 {
				return nil, waitError{errs: errs}
			}
			return nil, nil
		})
}

// A waitError wraps one or more errors returned by background commands.
type waitError struct {
	errs []*CommandError
}

func (w waitError) Error() string {
	b := new(strings.Builder)
	for i, err := range w.errs {
		if i != 0 {
			b.WriteString("\n")
		}
		b.WriteString(err.Error())
	}
	return b.String()
}

func (w waitError) Unwrap() error {
	if len(w.errs) == 1 {
		return w.errs[0]
	}
	return nil
}

"""



```