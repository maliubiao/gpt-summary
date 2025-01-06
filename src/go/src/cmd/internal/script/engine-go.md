Response: The user wants to understand the functionality of the provided Go code snippet. The code defines a small scripting language within Go. I need to analyze the code to:

1. **List the functionalities:** Describe what the `Engine` and its related components do.
2. **Infer the Go feature:** Based on the functionalities, deduce what kind of Go feature this code implements.
3. **Provide a Go code example:** Illustrate how this scripting engine can be used within Go code.
4. **Explain code inference:** Detail the reasoning behind the code example, including assumed inputs and outputs.
5. **Describe command-line argument handling:** Analyze if the code directly handles command-line arguments and how.
6. **Point out common mistakes:** Identify potential pitfalls users might encounter while using this scripting engine.

**Functionality Breakdown:**

*   **`Engine`**:  Manages the execution of scripts. Holds available commands (`Cmds`) and conditions (`Conds`).
*   **`Cmd`**: Interface for commands that can be executed within the scripts. Includes `Run` and `Usage`.
*   **`WaitFunc`**:  Function to retrieve the result of an asynchronous command.
*   **`CmdUsage`**:  Describes the usage of a command.
*   **`Cond`**: Interface for conditions that determine if a command should be executed. Includes `Eval` and `Usage`.
*   **`CondUsage`**: Describes the usage of a condition.
*   **`Execute`**: Reads and executes a script line by line. Handles comments, conditional execution, and error checking.
*   **Script Language:** Defines the syntax for writing scripts, including variable expansion, quoting, and special command prefixes (`!`, `?`, `[...]`).
*   **Parsing (`parse`)**:  Breaks down a script line into a command and its arguments.
*   **Argument Expansion (`expandArgs`)**:  Handles environment variable expansion within arguments.
*   **Condition Evaluation (`conditionsActive`)**: Checks if the conditions for a command are met.
*   **Command Execution (`runCommand`)**:  Executes a command, handling synchronous and asynchronous commands.
*   **Error Handling**:  Manages expected and unexpected errors during command execution.
*   **Listing Commands and Conditions (`ListCmds`, `ListConds`)**:  Provides introspection capabilities.

**Inference and Example Plan:**

The code implements a **custom scripting language embedded within Go**. I can demonstrate this by creating an `Engine`, defining a custom command, and then executing a simple script using that command.

**Command-line Argument Handling:**

The code itself doesn't seem to directly handle OS-level command-line arguments. It processes the "arguments" *within the script language*.

**Common Mistakes:**

Users might struggle with the specific quoting rules or the nuances of the conditional syntax.

Let's start by drafting the functionalities.
`go/src/cmd/internal/script/engine.go` 文件实现了一个小型的、可定制的、平台无关的脚本语言的引擎。 它的主要功能可以归纳为：

1. **脚本解析和执行:**
    *   **读取脚本:**  `Engine.Execute` 方法负责读取脚本内容（通过 `bufio.Reader`）。
    *   **逐行解析:** 将脚本的每一行解析成命令和参数，并处理注释 (`#`)。
    *   **命令识别:**  识别每一行的命令名称。
    *   **参数解析:**  解析命令的参数，包括处理空格分隔、单引号引用以及环境变量扩展。
    *   **条件判断:**  支持基于条件的命令执行，使用 `[...]` 语法指定条件，并根据配置的 `Cond` 接口进行评估。
    *   **命令执行:**  根据解析出的命令名称，查找已注册的 `Cmd` 实现并执行。
    *   **错误处理:**  检查每个命令的执行结果，并在发生错误时停止脚本执行（除非使用了 `?` 前缀）。
    *   **后台执行:** 支持使用 `&` 符号将命令放入后台执行。
    *   **输出捕获:**  捕获并记录每个命令的标准输出和标准错误。
    *   **状态管理:**  维护一个 `State` 对象，用于跟踪当前脚本的执行状态，包括工作目录、环境变量以及上一个命令的输出。
    *   **停止命令:**  支持 `stop` 命令来提前结束脚本的执行。

2. **命令和条件的可扩展性:**
    *   **`Cmd` 接口:**  定义了命令需要实现的接口，允许用户自定义命令。
    *   **`Cond` 接口:**  定义了条件需要实现的接口，允许用户自定义条件。
    *   **`Engine` 配置:**  `Engine` 结构体包含 `Cmds` 和 `Conds` 字段，用于存储已注册的命令和条件，可以通过 `NewEngine` 创建带有默认命令和条件的引擎，也可以自定义。

3. **脚本语言特性:**
    *   **环境变量扩展:**  支持在命令参数中扩展环境变量。
    *   **特殊变量:**  支持扩展特殊变量 `:` (路径列表分隔符) 和 `/` (路径分隔符)。
    *   **单引号引用:**  使用单引号可以防止空格分隔参数和环境变量扩展。
    *   **命令前缀:**
        *   `!`:  表示后面的命令必须执行失败。
        *   `?`:  表示后面的命令可以执行成功或失败，脚本都会继续执行。
        *   `[cond]`: 表示只有当条件满足时才执行后面的命令。

4. **日志记录:**
    *   `Engine.Execute` 方法接收一个 `io.Writer` 作为日志输出，用于记录脚本执行过程中的信息，包括执行的命令、输出和错误。
    *   支持按节记录日志，使用 `#` 开头的行作为节的开始，并记录每节的执行时间。

**这个 `engine.go` 实现了一个用于自动化测试或者构建流程的内部脚本语言。**  它类似于一个简化的 shell，但专注于提供可编程和可扩展的命令执行环境。

**Go 代码示例:**

假设我们想测试一个名为 `mytool` 的 Go 程序。我们可以定义一个自定义的命令来运行它，并使用脚本来验证其行为。

```go
package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"

	"cmd/internal/script"
)

// MyToolCmd 实现了运行 mytool 的命令
type MyToolCmd struct{}

func (m MyToolCmd) Run(s *script.State, args ...string) (script.WaitFunc, error) {
	cmd := exec.CommandContext(s.Context(), "mytool", args...)
	cmd.Dir = s.Dir()
	cmd.Env = s.Env()
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf
	err := cmd.Run()
	return func(s *script.State) (string, string, error) {
		return stdoutBuf.String(), stderrBuf.String(), err
	}, nil
}

func (m MyToolCmd) Usage() *script.CmdUsage {
	return &script.CmdUsage{
		Summary: "Runs the mytool command with the given arguments.",
		Args:    "[arguments...]",
	}
}

func main() {
	engine := script.NewEngine()
	engine.Cmds["mytool"] = MyToolCmd{} // 注册自定义命令

	scriptText := `# 测试 mytool 是否正常工作
mytool --version
`

	state := script.NewState(context.Background(), os.Getenv("PWD"), nil)
	var logOutput bytes.Buffer
	reader := bufio.NewReader(strings.NewReader(scriptText))

	err := engine.Execute(state, "test_script.txt", reader, &logOutput)
	if err != nil {
		fmt.Fprintf(os.Stderr, "脚本执行失败: %v\n", err)
		fmt.Println("日志输出:")
		fmt.Println(logOutput.String())
		os.Exit(1)
	}

	fmt.Println("脚本执行成功!")
	fmt.Println("日志输出:")
	fmt.Println(logOutput.String())
}
```

**假设的输入与输出:**

*   **假设 `mytool` 命令存在，并且当执行 `mytool --version` 时，会输出其版本信息到标准输出。**
*   **输入脚本 (`scriptText`):**
    ```
    # 测试 mytool 是否正常工作
    mytool --version
    ```
*   **可能的日志输出 (`logOutput`):**
    ```
    # 测试 mytool 是否正常工作
    > mytool --version
    [stdout]
    mytool version 1.0.0
    ```
*   **如果 `mytool` 命令不存在或执行失败，则会输出错误信息到标准错误，并显示详细的日志。**

**命令行参数的具体处理:**

`engine.go` 本身并不直接处理程序的命令行参数。它的作用是解释和执行脚本文件中的命令。  脚本中调用的命令（如上面的 `mytool`）可以接收参数，这些参数在脚本解析时会被处理，并传递给相应的 `Cmd` 实现。

**使用者易犯错的点:**

1. **单引号的使用:**  容易混淆单引号的作用，例如忘记单引号会阻止环境变量扩展，或者不理解 `'` 的转义规则 (`''` 表示一个字面的单引号)。

    ```go
    // 错误示例：期望输出 "Hello $USER"，但实际上会进行环境变量扩展
    scriptText := `echo 'Hello $USER'`

    // 正确示例：输出字面字符串 "Hello $USER"
    scriptText := `echo 'Hello $USER'`
    ```

2. **条件表达式的语法:**  忘记在条件中使用方括号 `[]`，或者条件表达式内部的空格处理不当。

    ```go
    // 错误示例：条件没有放在方括号中
    scriptText := `linux echo "Running on Linux"`

    // 正确示例
    scriptText := `[linux] echo "Running on Linux"`
    ```

3. **对 `!` 和 `?` 前缀的误解:**  不清楚 `!` 用于断言命令失败，而 `?` 用于忽略命令的执行结果。

    ```go
    // 错误示例：期望命令失败，但不使用 ! 前缀
    scriptText := `go build -invalid-flag`

    // 正确示例：断言 go build 命令会失败
    scriptText := `! go build -invalid-flag`
    ```

4. **后台命令的管理:**  启动后台命令后，忘记使用 `Wait` 命令等待其完成，可能导致资源泄露或未完成的操作。

    ```go
    // 示例：启动后台命令
    scriptText := `long_running_process &`
    ```
    使用者需要知道后续可以使用 `Wait` 命令来等待 `long_running_process` 完成。

5. **自定义命令和条件的注册:**  忘记将自定义的 `Cmd` 或 `Cond` 注册到 `Engine` 中，导致脚本执行时找不到相应的命令或条件。

    ```go
    // 错误示例：定义了 MyToolCmd 但没有注册
    engine := script.NewEngine()
    // engine.Cmds["mytool"] = MyToolCmd{} // 忘记注册

    scriptText := `mytool --version` // 执行会失败
    ```

Prompt: 
```
这是路径为go/src/cmd/internal/script/engine.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package script implements a small, customizable, platform-agnostic scripting
// language.
//
// Scripts are run by an [Engine] configured with a set of available commands
// and conditions that guard those commands. Each script has an associated
// working directory and environment, along with a buffer containing the stdout
// and stderr output of a prior command, tracked in a [State] that commands can
// inspect and modify.
//
// The default commands configured by [NewEngine] resemble a simplified Unix
// shell.
//
// # Script Language
//
// Each line of a script is parsed into a sequence of space-separated command
// words, with environment variable expansion within each word and # marking an
// end-of-line comment. Additional variables named ':' and '/' are expanded
// within script arguments (expanding to the value of os.PathListSeparator and
// os.PathSeparator respectively) but are not inherited in subprocess
// environments.
//
// Adding single quotes around text keeps spaces in that text from being treated
// as word separators and also disables environment variable expansion.
// Inside a single-quoted block of text, a repeated single quote indicates
// a literal single quote, as in:
//
//	'Don''t communicate by sharing memory.'
//
// A line beginning with # is a comment and conventionally explains what is
// being done or tested at the start of a new section of the script.
//
// Commands are executed one at a time, and errors are checked for each command;
// if any command fails unexpectedly, no subsequent commands in the script are
// executed. The command prefix ! indicates that the command on the rest of the
// line (typically go or a matching predicate) must fail instead of succeeding.
// The command prefix ? indicates that the command may or may not succeed, but
// the script should continue regardless.
//
// The command prefix [cond] indicates that the command on the rest of the line
// should only run when the condition is satisfied.
//
// A condition can be negated: [!root] means to run the rest of the line only if
// the user is not root. Multiple conditions may be given for a single command,
// for example, '[linux] [amd64] skip'. The command will run if all conditions
// are satisfied.
package script

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// An Engine stores the configuration for executing a set of scripts.
//
// The same Engine may execute multiple scripts concurrently.
type Engine struct {
	Cmds  map[string]Cmd
	Conds map[string]Cond

	// If Quiet is true, Execute deletes log prints from the previous
	// section when starting a new section.
	Quiet bool
}

// NewEngine returns an Engine configured with a basic set of commands and conditions.
func NewEngine() *Engine {
	return &Engine{
		Cmds:  DefaultCmds(),
		Conds: DefaultConds(),
	}
}

// A Cmd is a command that is available to a script.
type Cmd interface {
	// Run begins running the command.
	//
	// If the command produces output or can be run in the background, run returns
	// a WaitFunc that will be called to obtain the result of the command and
	// update the engine's stdout and stderr buffers.
	//
	// Run itself and the returned WaitFunc may inspect and/or modify the State,
	// but the State's methods must not be called concurrently after Run has
	// returned.
	//
	// Run may retain and access the args slice until the WaitFunc has returned.
	Run(s *State, args ...string) (WaitFunc, error)

	// Usage returns the usage for the command, which the caller must not modify.
	Usage() *CmdUsage
}

// A WaitFunc is a function called to retrieve the results of a Cmd.
type WaitFunc func(*State) (stdout, stderr string, err error)

// A CmdUsage describes the usage of a Cmd, independent of its name
// (which can change based on its registration).
type CmdUsage struct {
	Summary string   // in the style of the Name section of a Unix 'man' page, omitting the name
	Args    string   // a brief synopsis of the command's arguments (only)
	Detail  []string // zero or more sentences in the style of the Description section of a Unix 'man' page

	// If Async is true, the Cmd is meaningful to run in the background, and its
	// Run method must return either a non-nil WaitFunc or a non-nil error.
	Async bool

	// RegexpArgs reports which arguments, if any, should be treated as regular
	// expressions. It takes as input the raw, unexpanded arguments and returns
	// the list of argument indices that will be interpreted as regular
	// expressions.
	//
	// If RegexpArgs is nil, all arguments are assumed not to be regular
	// expressions.
	RegexpArgs func(rawArgs ...string) []int
}

// A Cond is a condition deciding whether a command should be run.
type Cond interface {
	// Eval reports whether the condition applies to the given State.
	//
	// If the condition's usage reports that it is a prefix,
	// the condition must be used with a suffix.
	// Otherwise, the passed-in suffix argument is always the empty string.
	Eval(s *State, suffix string) (bool, error)

	// Usage returns the usage for the condition, which the caller must not modify.
	Usage() *CondUsage
}

// A CondUsage describes the usage of a Cond, independent of its name
// (which can change based on its registration).
type CondUsage struct {
	Summary string // a single-line summary of when the condition is true

	// If Prefix is true, the condition is a prefix and requires a
	// colon-separated suffix (like "[GOOS:linux]" for the "GOOS" condition).
	// The suffix may be the empty string (like "[prefix:]").
	Prefix bool
}

// Execute reads and executes script, writing the output to log.
//
// Execute stops and returns an error at the first command that does not succeed.
// The returned error's text begins with "file:line: ".
//
// If the script runs to completion or ends by a 'stop' command,
// Execute returns nil.
//
// Execute does not stop background commands started by the script
// before returning. To stop those, use [State.CloseAndWait] or the
// [Wait] command.
func (e *Engine) Execute(s *State, file string, script *bufio.Reader, log io.Writer) (err error) {
	defer func(prev *Engine) { s.engine = prev }(s.engine)
	s.engine = e

	var sectionStart time.Time
	// endSection flushes the logs for the current section from s.log to log.
	// ok indicates whether all commands in the section succeeded.
	endSection := func(ok bool) error {
		var err error
		if sectionStart.IsZero() {
			// We didn't write a section header or record a timestamp, so just dump the
			// whole log without those.
			if s.log.Len() > 0 {
				err = s.flushLog(log)
			}
		} else if s.log.Len() == 0 {
			// Adding elapsed time for doing nothing is meaningless, so don't.
			_, err = io.WriteString(log, "\n")
		} else {
			// Insert elapsed time for section at the end of the section's comment.
			_, err = fmt.Fprintf(log, " (%.3fs)\n", time.Since(sectionStart).Seconds())

			if err == nil && (!ok || !e.Quiet) {
				err = s.flushLog(log)
			} else {
				s.log.Reset()
			}
		}

		sectionStart = time.Time{}
		return err
	}

	var lineno int
	lineErr := func(err error) error {
		if errors.As(err, new(*CommandError)) {
			return err
		}
		return fmt.Errorf("%s:%d: %w", file, lineno, err)
	}

	// In case of failure or panic, flush any pending logs for the section.
	defer func() {
		if sErr := endSection(false); sErr != nil && err == nil {
			err = lineErr(sErr)
		}
	}()

	for {
		if err := s.ctx.Err(); err != nil {
			// This error wasn't produced by any particular command,
			// so don't wrap it in a CommandError.
			return lineErr(err)
		}

		line, err := script.ReadString('\n')
		if err == io.EOF {
			if line == "" {
				break // Reached the end of the script.
			}
			// If the script doesn't end in a newline, interpret the final line.
		} else if err != nil {
			return lineErr(err)
		}
		line = strings.TrimSuffix(line, "\n")
		lineno++

		// The comment character "#" at the start of the line delimits a section of
		// the script.
		if strings.HasPrefix(line, "#") {
			// If there was a previous section, the fact that we are starting a new
			// one implies the success of the previous one.
			//
			// At the start of the script, the state may also contain accumulated logs
			// from commands executed on the State outside of the engine in order to
			// set it up; flush those logs too.
			if err := endSection(true); err != nil {
				return lineErr(err)
			}

			// Log the section start without a newline so that we can add
			// a timestamp for the section when it ends.
			_, err = fmt.Fprintf(log, "%s", line)
			sectionStart = time.Now()
			if err != nil {
				return lineErr(err)
			}
			continue
		}

		cmd, err := parse(file, lineno, line)
		if cmd == nil && err == nil {
			continue // Ignore blank lines.
		}
		s.Logf("> %s\n", line)
		if err != nil {
			return lineErr(err)
		}

		// Evaluate condition guards.
		ok, err := e.conditionsActive(s, cmd.conds)
		if err != nil {
			return lineErr(err)
		}
		if !ok {
			s.Logf("[condition not met]\n")
			continue
		}

		impl := e.Cmds[cmd.name]

		// Expand variables in arguments.
		var regexpArgs []int
		if impl != nil {
			usage := impl.Usage()
			if usage.RegexpArgs != nil {
				// First join rawArgs without expansion to pass to RegexpArgs.
				rawArgs := make([]string, 0, len(cmd.rawArgs))
				for _, frags := range cmd.rawArgs {
					var b strings.Builder
					for _, frag := range frags {
						b.WriteString(frag.s)
					}
					rawArgs = append(rawArgs, b.String())
				}
				regexpArgs = usage.RegexpArgs(rawArgs...)
			}
		}
		cmd.args = expandArgs(s, cmd.rawArgs, regexpArgs)

		// Run the command.
		err = e.runCommand(s, cmd, impl)
		if err != nil {
			if stop := (stopError{}); errors.As(err, &stop) {
				// Since the 'stop' command halts execution of the entire script,
				// log its message separately from the section in which it appears.
				err = endSection(true)
				s.Logf("%v\n", stop)
				if err == nil {
					return nil
				}
			}
			return lineErr(err)
		}
	}

	if err := endSection(true); err != nil {
		return lineErr(err)
	}
	return nil
}

// A command is a complete command parsed from a script.
type command struct {
	file       string
	line       int
	want       expectedStatus
	conds      []condition // all must be satisfied
	name       string      // the name of the command; must be non-empty
	rawArgs    [][]argFragment
	args       []string // shell-expanded arguments following name
	background bool     // command should run in background (ends with a trailing &)
}

// An expectedStatus describes the expected outcome of a command.
// Script execution halts when a command does not match its expected status.
type expectedStatus string

const (
	success          expectedStatus = ""
	failure          expectedStatus = "!"
	successOrFailure expectedStatus = "?"
)

type argFragment struct {
	s      string
	quoted bool // if true, disable variable expansion for this fragment
}

type condition struct {
	want bool
	tag  string
}

const argSepChars = " \t\r\n#"

// parse parses a single line as a list of space-separated arguments.
// subject to environment variable expansion (but not resplitting).
// Single quotes around text disable splitting and expansion.
// To embed a single quote, double it:
//
//	'Don''t communicate by sharing memory.'
func parse(filename string, lineno int, line string) (cmd *command, err error) {
	cmd = &command{file: filename, line: lineno}
	var (
		rawArg []argFragment // text fragments of current arg so far (need to add line[start:i])
		start  = -1          // if >= 0, position where current arg text chunk starts
		quoted = false       // currently processing quoted text
	)

	flushArg := func() error {
		if len(rawArg) == 0 {
			return nil // Nothing to flush.
		}
		defer func() { rawArg = nil }()

		if cmd.name == "" && len(rawArg) == 1 && !rawArg[0].quoted {
			arg := rawArg[0].s

			// Command prefix ! means negate the expectations about this command:
			// go command should fail, match should not be found, etc.
			// Prefix ? means allow either success or failure.
			switch want := expectedStatus(arg); want {
			case failure, successOrFailure:
				if cmd.want != "" {
					return errors.New("duplicated '!' or '?' token")
				}
				cmd.want = want
				return nil
			}

			// Command prefix [cond] means only run this command if cond is satisfied.
			if strings.HasPrefix(arg, "[") && strings.HasSuffix(arg, "]") {
				want := true
				arg = strings.TrimSpace(arg[1 : len(arg)-1])
				if strings.HasPrefix(arg, "!") {
					want = false
					arg = strings.TrimSpace(arg[1:])
				}
				if arg == "" {
					return errors.New("empty condition")
				}
				cmd.conds = append(cmd.conds, condition{want: want, tag: arg})
				return nil
			}

			if arg == "" {
				return errors.New("empty command")
			}
			cmd.name = arg
			return nil
		}

		cmd.rawArgs = append(cmd.rawArgs, rawArg)
		return nil
	}

	for i := 0; ; i++ {
		if !quoted && (i >= len(line) || strings.ContainsRune(argSepChars, rune(line[i]))) {
			// Found arg-separating space.
			if start >= 0 {
				rawArg = append(rawArg, argFragment{s: line[start:i], quoted: false})
				start = -1
			}
			if err := flushArg(); err != nil {
				return nil, err
			}
			if i >= len(line) || line[i] == '#' {
				break
			}
			continue
		}
		if i >= len(line) {
			return nil, errors.New("unterminated quoted argument")
		}
		if line[i] == '\'' {
			if !quoted {
				// starting a quoted chunk
				if start >= 0 {
					rawArg = append(rawArg, argFragment{s: line[start:i], quoted: false})
				}
				start = i + 1
				quoted = true
				continue
			}
			// 'foo''bar' means foo'bar, like in rc shell and Pascal.
			if i+1 < len(line) && line[i+1] == '\'' {
				rawArg = append(rawArg, argFragment{s: line[start:i], quoted: true})
				start = i + 1
				i++ // skip over second ' before next iteration
				continue
			}
			// ending a quoted chunk
			rawArg = append(rawArg, argFragment{s: line[start:i], quoted: true})
			start = i + 1
			quoted = false
			continue
		}
		// found character worth saving; make sure we're saving
		if start < 0 {
			start = i
		}
	}

	if cmd.name == "" {
		if cmd.want != "" || len(cmd.conds) > 0 || len(cmd.rawArgs) > 0 || cmd.background {
			// The line contains a command prefix or suffix, but no actual command.
			return nil, errors.New("missing command")
		}

		// The line is blank, or contains only a comment.
		return nil, nil
	}

	if n := len(cmd.rawArgs); n > 0 {
		last := cmd.rawArgs[n-1]
		if len(last) == 1 && !last[0].quoted && last[0].s == "&" {
			cmd.background = true
			cmd.rawArgs = cmd.rawArgs[:n-1]
		}
	}
	return cmd, nil
}

// expandArgs expands the shell variables in rawArgs and joins them to form the
// final arguments to pass to a command.
func expandArgs(s *State, rawArgs [][]argFragment, regexpArgs []int) []string {
	args := make([]string, 0, len(rawArgs))
	for i, frags := range rawArgs {
		isRegexp := false
		for _, j := range regexpArgs {
			if i == j {
				isRegexp = true
				break
			}
		}

		var b strings.Builder
		for _, frag := range frags {
			if frag.quoted {
				b.WriteString(frag.s)
			} else {
				b.WriteString(s.ExpandEnv(frag.s, isRegexp))
			}
		}
		args = append(args, b.String())
	}
	return args
}

// quoteArgs returns a string that parse would parse as args when passed to a command.
//
// TODO(bcmills): This function should have a fuzz test.
func quoteArgs(args []string) string {
	var b strings.Builder
	for i, arg := range args {
		if i > 0 {
			b.WriteString(" ")
		}
		if strings.ContainsAny(arg, "'"+argSepChars) {
			// Quote the argument to a form that would be parsed as a single argument.
			b.WriteString("'")
			b.WriteString(strings.ReplaceAll(arg, "'", "''"))
			b.WriteString("'")
		} else {
			b.WriteString(arg)
		}
	}
	return b.String()
}

func (e *Engine) conditionsActive(s *State, conds []condition) (bool, error) {
	for _, cond := range conds {
		var impl Cond
		prefix, suffix, ok := strings.Cut(cond.tag, ":")
		if ok {
			impl = e.Conds[prefix]
			if impl == nil {
				return false, fmt.Errorf("unknown condition prefix %q", prefix)
			}
			if !impl.Usage().Prefix {
				return false, fmt.Errorf("condition %q cannot be used with a suffix", prefix)
			}
		} else {
			impl = e.Conds[cond.tag]
			if impl == nil {
				return false, fmt.Errorf("unknown condition %q", cond.tag)
			}
			if impl.Usage().Prefix {
				return false, fmt.Errorf("condition %q requires a suffix", cond.tag)
			}
		}
		active, err := impl.Eval(s, suffix)

		if err != nil {
			return false, fmt.Errorf("evaluating condition %q: %w", cond.tag, err)
		}
		if active != cond.want {
			return false, nil
		}
	}

	return true, nil
}

func (e *Engine) runCommand(s *State, cmd *command, impl Cmd) error {
	if impl == nil {
		return cmdError(cmd, errors.New("unknown command"))
	}

	async := impl.Usage().Async
	if cmd.background && !async {
		return cmdError(cmd, errors.New("command cannot be run in background"))
	}

	wait, runErr := impl.Run(s, cmd.args...)
	if wait == nil {
		if async && runErr == nil {
			return cmdError(cmd, errors.New("internal error: async command returned a nil WaitFunc"))
		}
		return checkStatus(cmd, runErr)
	}
	if runErr != nil {
		return cmdError(cmd, errors.New("internal error: command returned both an error and a WaitFunc"))
	}

	if cmd.background {
		s.background = append(s.background, backgroundCmd{
			command: cmd,
			wait:    wait,
		})
		// Clear stdout and stderr, since they no longer correspond to the last
		// command executed.
		s.stdout = ""
		s.stderr = ""
		return nil
	}

	if wait != nil {
		stdout, stderr, waitErr := wait(s)
		s.stdout = stdout
		s.stderr = stderr
		if stdout != "" {
			s.Logf("[stdout]\n%s", stdout)
		}
		if stderr != "" {
			s.Logf("[stderr]\n%s", stderr)
		}
		if cmdErr := checkStatus(cmd, waitErr); cmdErr != nil {
			return cmdErr
		}
		if waitErr != nil {
			// waitErr was expected (by cmd.want), so log it instead of returning it.
			s.Logf("[%v]\n", waitErr)
		}
	}
	return nil
}

func checkStatus(cmd *command, err error) error {
	if err == nil {
		if cmd.want == failure {
			return cmdError(cmd, ErrUnexpectedSuccess)
		}
		return nil
	}

	if s := (stopError{}); errors.As(err, &s) {
		// This error originated in the Stop command.
		// Propagate it as-is.
		return cmdError(cmd, err)
	}

	if w := (waitError{}); errors.As(err, &w) {
		// This error was surfaced from a background process by a call to Wait.
		// Add a call frame for Wait itself, but ignore its "want" field.
		// (Wait itself cannot fail to wait on commands or else it would leak
		// processes and/or goroutines — so a negative assertion for it would be at
		// best ambiguous.)
		return cmdError(cmd, err)
	}

	if cmd.want == success {
		return cmdError(cmd, err)
	}

	if cmd.want == failure && (errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)) {
		// The command was terminated because the script is no longer interested in
		// its output, so we don't know what it would have done had it run to
		// completion — for all we know, it could have exited without error if it
		// ran just a smidge faster.
		return cmdError(cmd, err)
	}

	return nil
}

// ListCmds prints to w a list of the named commands,
// annotating each with its arguments and a short usage summary.
// If verbose is true, ListCmds prints full details for each command.
//
// Each of the name arguments should be a command name.
// If no names are passed as arguments, ListCmds lists all the
// commands registered in e.
func (e *Engine) ListCmds(w io.Writer, verbose bool, names ...string) error {
	if names == nil {
		names = make([]string, 0, len(e.Cmds))
		for name := range e.Cmds {
			names = append(names, name)
		}
		sort.Strings(names)
	}

	for _, name := range names {
		cmd := e.Cmds[name]
		usage := cmd.Usage()

		suffix := ""
		if usage.Async {
			suffix = " [&]"
		}

		_, err := fmt.Fprintf(w, "%s %s%s\n\t%s\n", name, usage.Args, suffix, usage.Summary)
		if err != nil {
			return err
		}

		if verbose {
			if _, err := io.WriteString(w, "\n"); err != nil {
				return err
			}
			for _, line := range usage.Detail {
				if err := wrapLine(w, line, 60, "\t"); err != nil {
					return err
				}
			}
			if _, err := io.WriteString(w, "\n"); err != nil {
				return err
			}
		}
	}

	return nil
}

func wrapLine(w io.Writer, line string, cols int, indent string) error {
	line = strings.TrimLeft(line, " ")
	for len(line) > cols {
		bestSpace := -1
		for i, r := range line {
			if r == ' ' {
				if i <= cols || bestSpace < 0 {
					bestSpace = i
				}
				if i > cols {
					break
				}
			}
		}
		if bestSpace < 0 {
			break
		}

		if _, err := fmt.Fprintf(w, "%s%s\n", indent, line[:bestSpace]); err != nil {
			return err
		}
		line = line[bestSpace+1:]
	}

	_, err := fmt.Fprintf(w, "%s%s\n", indent, line)
	return err
}

// ListConds prints to w a list of conditions, one per line,
// annotating each with a description and whether the condition
// is true in the state s (if s is non-nil).
//
// Each of the tag arguments should be a condition string of
// the form "name" or "name:suffix". If no tags are passed as
// arguments, ListConds lists all conditions registered in
// the engine e.
func (e *Engine) ListConds(w io.Writer, s *State, tags ...string) error {
	if tags == nil {
		tags = make([]string, 0, len(e.Conds))
		for name := range e.Conds {
			tags = append(tags, name)
		}
		sort.Strings(tags)
	}

	for _, tag := range tags {
		if prefix, suffix, ok := strings.Cut(tag, ":"); ok {
			cond := e.Conds[prefix]
			if cond == nil {
				return fmt.Errorf("unknown condition prefix %q", prefix)
			}
			usage := cond.Usage()
			if !usage.Prefix {
				return fmt.Errorf("condition %q cannot be used with a suffix", prefix)
			}

			activeStr := ""
			if s != nil {
				if active, _ := cond.Eval(s, suffix); active {
					activeStr = " (active)"
				}
			}
			_, err := fmt.Fprintf(w, "[%s]%s\n\t%s\n", tag, activeStr, usage.Summary)
			if err != nil {
				return err
			}
			continue
		}

		cond := e.Conds[tag]
		if cond == nil {
			return fmt.Errorf("unknown condition %q", tag)
		}
		var err error
		usage := cond.Usage()
		if usage.Prefix {
			_, err = fmt.Fprintf(w, "[%s:*]\n\t%s\n", tag, usage.Summary)
		} else {
			activeStr := ""
			if s != nil {
				if ok, _ := cond.Eval(s, ""); ok {
					activeStr = " (active)"
				}
			}
			_, err = fmt.Fprintf(w, "[%s]%s\n\t%s\n", tag, activeStr, usage.Summary)
		}
		if err != nil {
			return err
		}
	}

	return nil
}

"""



```