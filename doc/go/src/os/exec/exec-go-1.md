Response:
Let's break down the thought process for summarizing the provided Go code.

**1. Understanding the Goal:** The request is to summarize the functionality of the given Go code snippet, which is a part of `go/src/os/exec/exec.go`. The focus should be on what it *does*, any relevant Go features used, examples, handling of command-line arguments (though this part seems less prominent in this specific snippet), potential pitfalls for users, and finally, a concise overall summary.

**2. Initial Scan and Keyword Identification:**  I'll quickly scan the code for recognizable function names and keywords: `WaitDelay`, `Output`, `CombinedOutput`, `StdinPipe`, `StdoutPipe`, `StderrPipe`, `prefixSuffixSaver`, `environ`, `Environ`, `dedupEnv`, `addCriticalEnv`, `ErrDot`. These names provide strong clues about the code's purpose.

**3. Functional Grouping:** Based on the function names, I can start to group related functionalities:

    * **Timeout/Delay:** The `WaitDelay` section clearly deals with handling timeouts when waiting for a command to finish.
    * **Output Capture:** `Output`, `CombinedOutput` are about capturing the standard output and error streams of the executed command.
    * **Piping:**  `StdinPipe`, `StdoutPipe`, `StderrPipe` are concerned with setting up pipes for inter-process communication.
    * **Environment Handling:** `environ`, `Environ`, `dedupEnv`, `addCriticalEnv` are all related to managing the environment variables of the command.
    * **Error Handling:** `prefixSuffixSaver` seems related to formatting error messages, especially when capturing output. `ErrDot` is a specific error type.

**4. Detailed Analysis of Each Group:**

    * **Timeout/Delay:** The code waits for a command to finish, with a possible delay. It uses a `select` statement with a timer to enforce a timeout. If the timeout occurs, it closes pipes and returns `ErrWaitDelay`.
    * **Output Capture:**
        * `Output`: Captures standard output. If standard error is not set, it captures it into a special buffer (`prefixSuffixSaver`) and includes it in the `ExitError` if the command fails.
        * `CombinedOutput`: Captures both standard output and standard error into the same buffer.
    * **Piping:**  These functions create pipes connected to the child process's standard input, output, or error. They prevent setting these pipes if they're already set or the process has started. The documentation within these functions is helpful. I note the crucial point about not calling `Wait` or `Run` prematurely when using pipes.
    * **Environment Handling:**
        * `environ`:  Gets the environment for the command, considering `c.Env`, default system environment, and potentially updating `PWD`. It also calls `dedupEnv`.
        * `Environ`: A simpler wrapper around `environ` that ignores errors.
        * `dedupEnv`: Removes duplicate environment variables, keeping the later occurrences. It handles case-insensitivity (for Windows) and NUL characters (with exceptions for Plan 9).
        * `addCriticalEnv`: Adds essential environment variables (currently only `SYSTEMROOT` on Windows).
    * **Error Handling (`prefixSuffixSaver`):** This structure is used to store the beginning and end of captured output, especially standard error, to create more informative error messages when output is large. It handles skipping large chunks of output.
    * **Error Handling (`ErrDot`):** This is a specific error indicating execution from the current directory when `.` is in the path.

**5. Identifying Go Language Features:**  As I analyze, I identify key Go features:

    * **`struct` and Methods:**  The `Cmd` struct and its associated methods are the core of this code.
    * **Interfaces:** `io.Writer`, `io.ReadCloser`, `io.WriteCloser` are used for handling input and output streams.
    * **Channels and Goroutines:** The timeout mechanism uses channels (`timer.C`, `c.goroutineErr`) and likely involves goroutines (though the goroutine creation isn't in this snippet).
    * **Error Handling:** The use of `error` interface and `errors.New`, type assertions (`err.(*ExitError)`), and `errors.Is`.
    * **`bytes.Buffer`:** Used for efficiently building up output strings.
    * **`select` statement:**  Used for multiplexing on channel operations in the timeout logic.
    * **`os.Pipe`:** Used to create pipes for inter-process communication.

**6. Developing Examples:**  For each main functionality, I think about simple illustrative examples.

    * **Timeout:** Running a command that takes a long time and demonstrating the `ErrWaitDelay`.
    * **Output/CombinedOutput:**  Running a simple command like `ls` or `echo` and capturing its output. Demonstrating the `ExitError` and captured stderr.
    * **Pipes:**  A classic example is piping the output of one command to the input of another (e.g., `ls | grep`).
    * **Environment:** Showing how to set and get environment variables for the command.

**7. Considering Command Line Arguments:** While the core snippet doesn't explicitly parse command-line arguments for the *Go program itself*, it's crucial to understand that the *executed commands* will have their own arguments. The `Cmd` struct likely stores the command and its arguments.

**8. Identifying Potential Pitfalls:** Based on the code and documentation, I consider common mistakes:

    * Setting `Stdout`, `Stderr`, or `Stdin` multiple times.
    * Calling `Wait` or `Run` prematurely when using pipes, leading to deadlocks.

**9. Structuring the Answer:** I'll organize the answer logically, starting with a general overview, then detailing each functional group with explanations, Go feature examples, and pitfalls. Finally, I'll provide a concise summary.

**10. Refining and Reviewing:**  After drafting the answer, I'll review it for clarity, accuracy, and completeness, ensuring it addresses all parts of the original request. I'll check that the examples are correct and easy to understand. I'll also ensure the language is clear and concise. For example, initially, I might just say "handles output," but refining it to "captures standard output and standard error" is more specific.

This detailed breakdown allows me to systematically understand the code and generate a comprehensive and accurate response.
这是 `go/src/os/exec/exec.go` 文件中关于 `Cmd` 结构体及其相关方法的一部分，主要负责执行外部命令并处理其输入、输出以及一些执行时的属性。

**功能归纳:**

这部分代码主要实现了以下功能，用于控制和获取外部命令执行的结果：

1. **设置执行超时:**  如果命令执行时间超过 `WaitDelay`，则会返回 `ErrWaitDelay` 错误，表明等待超时。这是一种防止外部命令无限期运行导致程序阻塞的机制。
2. **捕获标准输出:** `Output()` 方法执行命令并返回其标准输出的内容。如果命令执行出错（非零退出码），则会返回 `*ExitError` 类型的错误，并且如果 `Stderr` 没有被显式设置，`Output()` 会尝试捕获标准错误并将其添加到 `*ExitError` 中，方便用户查看错误信息。
3. **捕获标准输出和标准错误:** `CombinedOutput()` 方法执行命令并返回其标准输出和标准错误合并后的内容。
4. **获取标准输入管道:** `StdinPipe()` 方法返回一个 `io.WriteCloser`，你可以向这个管道写入数据，这些数据将作为被执行命令的标准输入。
5. **获取标准输出管道:** `StdoutPipe()` 方法返回一个 `io.ReadCloser`，你可以从这个管道读取被执行命令的标准输出。
6. **获取标准错误管道:** `StderrPipe()` 方法返回一个 `io.ReadCloser`，你可以从这个管道读取被执行命令的标准错误。
7. **临时存储输出/错误信息:** `prefixSuffixSaver` 结构体是一个自定义的 `io.Writer`，用于保存写入其中的数据的前 `N` 字节和后 `N` 字节。这主要用于在捕获标准错误时，如果错误信息过长，可以截取开头和结尾部分，方便用户了解错误的大致内容。
8. **获取命令执行时的环境变量:** `environ()` 方法返回一个命令执行时应该使用的环境变量切片。它会考虑 `Cmd` 结构体中设置的 `Env`，以及系统默认的环境变量，并处理工作目录 `Dir` 的影响（例如更新 `PWD` 环境变量）。
9. **获取命令执行时的环境变量 (公开方法):** `Environ()` 方法是 `environ()` 的公开版本，返回命令执行时的环境变量切片。
10. **去除重复的环境变量:** `dedupEnv()` 和 `dedupEnvCase()` 函数用于去除环境变量列表中重复的条目，保留最后出现的条目。
11. **添加关键环境变量:** `addCriticalEnv()` 函数用于添加一些操作系统必需的环境变量，目前主要用于 Windows 系统，确保 `SYSTEMROOT` 环境变量存在。
12. **表示当前目录执行的错误:** `ErrDot` 是一个预定义的错误，表示尝试执行当前目录下的可执行文件（如果 `.` 在 `PATH` 环境变量中），这通常出于安全考虑被禁止。

**Go 语言功能实现举例:**

**1. 使用 `Output()` 捕获命令的标准输出:**

```go
package main

import (
	"fmt"
	"os/exec"
)

func main() {
	cmd := exec.Command("ls", "-l")
	output, err := cmd.Output()
	if err != nil {
		fmt.Println("执行命令出错:", err)
		return
	}
	fmt.Println("命令输出:\n", string(output))
}

// 假设输入（当前目录下有文件 file1.txt）: 无
// 预期输出:
// 命令输出:
// total ...
// -rw-r--r--  1 user  group        ... file1.txt
// ... (其他文件信息)
```

**2. 使用 `CombinedOutput()` 捕获标准输出和标准错误:**

```go
package main

import (
	"fmt"
	"os/exec"
)

func main() {
	cmd := exec.Command("sh", "-c", "echo 'hello' && ls /nonexistent")
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println("执行命令出错:", err)
		fmt.Println("合并的输出:\n", string(output))
		return
	}
	fmt.Println("合并的输出:\n", string(output))
}

// 假设输入: 无
// 预期输出 (可能因系统而异):
// 执行命令出错: exit status 2
// 合并的输出:
// hello
// ls: /nonexistent: No such file or directory
```

**3. 使用 `StdoutPipe()` 将命令的输出连接到 Go 程序:**

```go
package main

import (
	"fmt"
	"io"
	"os/exec"
)

func main() {
	cmd := exec.Command("cat")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Println("获取标准输出管道出错:", err)
		return
	}

	if err := cmd.Start(); err != nil {
		fmt.Println("启动命令出错:", err)
		return
	}

	go func() {
		if _, err := io.Copy(io.Discard, stdout); err != nil { // 读取完输出
			fmt.Println("读取标准输出出错:", err)
		}
	}()

	// 向 cat 命令的标准输入写入数据
	stdin, err := cmd.StdinPipe()
	if err != nil {
		fmt.Println("获取标准输入管道出错:", err)
		return
	}
	_, err = stdin.Write([]byte("Hello from Go!\n"))
	if err != nil {
		fmt.Println("写入标准输入出错:", err)
		return
	}
	stdin.Close() // 关闭标准输入，cat 命令会结束

	if err := cmd.Wait(); err != nil {
		fmt.Println("等待命令结束出错:", err)
	}
	fmt.Println("命令执行完毕")
}

// 假设输入: 无
// 预期输出 (取决于 io.Copy 的速度，顺序可能略有不同):
// 命令执行完毕
```

**代码推理 (关于 `prefixSuffixSaver`):**

假设我们执行一个命令，其标准错误输出非常长，超过了 `prefixSuffixSaver` 的 `N` 值 (例如 32KB)。

```go
package main

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

func main() {
	// 构造一个产生大量标准错误的命令
	errorString := strings.Repeat("This is an error message. ", 10000)
	cmd := exec.Command("sh", "-c", fmt.Sprintf("echo '%s' 1>&2", errorString))

	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf

	err := cmd.Run()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.Stderr != nil {
			fmt.Printf("标准错误 (截取):\n%s\n", string(exitErr.Stderr))
		} else {
			fmt.Println("执行命令出错:", err)
		}
		return
	}
	fmt.Println("命令执行成功")
}

// 假设输入: 无
// 预期输出 (截取了开头和结尾部分):
// 标准错误 (截取):
// This is an error message. This is an error message. ... (开头部分)
// ... omitting 很多字节 ...
//  This is an error message. This is an error message. (结尾部分)
```

在这个例子中，`prefixSuffixSaver` 会捕获标准错误输出的开头和结尾部分，并在 `ExitError.Stderr` 中返回，中间部分会被省略，并显示省略了多少字节。

**命令行参数的具体处理:**

这部分代码本身没有直接处理 Go 程序的命令行参数。它关注的是如何执行*外部命令*，而外部命令的参数是通过 `exec.Command("命令名", "参数1", "参数2", ...)` 传递的。

例如，`exec.Command("ls", "-l", "/home")` 中，`-l` 和 `/home` 就是传递给 `ls` 命令的参数。

**使用者易犯错的点:**

* **多次设置标准输入/输出/错误管道或缓冲区:**  在同一个 `Cmd` 对象上多次调用 `StdinPipe`、`StdoutPipe`、`StderrPipe` 或直接设置 `Stdin`、`Stdout`、`Stderr` 可能会导致错误。
   ```go
   cmd := exec.Command("ls")
   _, err1 := cmd.StdoutPipe()
   _, err2 := cmd.StdoutPipe() // 错误: Stdout already set
   ```
* **在进程启动后尝试获取管道:**  在调用 `cmd.Start()` 或 `cmd.Run()` 之后再尝试获取管道也会导致错误。
   ```go
   cmd := exec.Command("ls")
   cmd.Start()
   _, err := cmd.StdoutPipe() // 错误: StdoutPipe after process started
   ```
* **在使用管道时过早调用 `Wait()`:** 如果使用 `StdoutPipe` 或 `StderrPipe` 读取命令的输出，必须确保在所有数据读取完毕后再调用 `Wait()`。过早调用 `Wait()` 可能会导致管道关闭，数据丢失或程序死锁。
* **假设 `CombinedOutput()` 或 `Output()` 返回的错误一定是 `*ExitError`:** 虽然通常是这样，但如果命令启动失败（例如找不到命令），返回的错误可能是其他类型。应该使用类型断言来安全地访问 `Stderr` 字段。

总而言之，这部分代码是 Go 语言 `os/exec` 包中用于执行外部命令并灵活地处理其输入输出的核心组成部分，提供了多种方式来与子进程进行交互和获取执行结果。

Prompt: 
```
这是路径为go/src/os/exec/exec.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

"""
/ No existing timer was started: either there is no Context associated with
		// the command, or c.Process.Wait completed before the Context was done.
		timer = time.NewTimer(c.WaitDelay)
	}

	select {
	case <-timer.C:
		closeDescriptors(c.parentIOPipes)
		// Wait for the copying goroutines to finish, but ignore any error
		// (since it was probably caused by closing the pipes).
		_ = <-c.goroutineErr
		return ErrWaitDelay

	case err := <-c.goroutineErr:
		return err
	}
}

// Output runs the command and returns its standard output.
// Any returned error will usually be of type [*ExitError].
// If c.Stderr was nil and the returned error is of type
// [*ExitError], Output populates the Stderr field of the
// returned error.
func (c *Cmd) Output() ([]byte, error) {
	if c.Stdout != nil {
		return nil, errors.New("exec: Stdout already set")
	}
	var stdout bytes.Buffer
	c.Stdout = &stdout

	captureErr := c.Stderr == nil
	if captureErr {
		c.Stderr = &prefixSuffixSaver{N: 32 << 10}
	}

	err := c.Run()
	if err != nil && captureErr {
		if ee, ok := err.(*ExitError); ok {
			ee.Stderr = c.Stderr.(*prefixSuffixSaver).Bytes()
		}
	}
	return stdout.Bytes(), err
}

// CombinedOutput runs the command and returns its combined standard
// output and standard error.
func (c *Cmd) CombinedOutput() ([]byte, error) {
	if c.Stdout != nil {
		return nil, errors.New("exec: Stdout already set")
	}
	if c.Stderr != nil {
		return nil, errors.New("exec: Stderr already set")
	}
	var b bytes.Buffer
	c.Stdout = &b
	c.Stderr = &b
	err := c.Run()
	return b.Bytes(), err
}

// StdinPipe returns a pipe that will be connected to the command's
// standard input when the command starts.
// The pipe will be closed automatically after [Cmd.Wait] sees the command exit.
// A caller need only call Close to force the pipe to close sooner.
// For example, if the command being run will not exit until standard input
// is closed, the caller must close the pipe.
func (c *Cmd) StdinPipe() (io.WriteCloser, error) {
	if c.Stdin != nil {
		return nil, errors.New("exec: Stdin already set")
	}
	if c.Process != nil {
		return nil, errors.New("exec: StdinPipe after process started")
	}
	pr, pw, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	c.Stdin = pr
	c.childIOFiles = append(c.childIOFiles, pr)
	c.parentIOPipes = append(c.parentIOPipes, pw)
	return pw, nil
}

// StdoutPipe returns a pipe that will be connected to the command's
// standard output when the command starts.
//
// [Cmd.Wait] will close the pipe after seeing the command exit, so most callers
// need not close the pipe themselves. It is thus incorrect to call Wait
// before all reads from the pipe have completed.
// For the same reason, it is incorrect to call [Cmd.Run] when using StdoutPipe.
// See the example for idiomatic usage.
func (c *Cmd) StdoutPipe() (io.ReadCloser, error) {
	if c.Stdout != nil {
		return nil, errors.New("exec: Stdout already set")
	}
	if c.Process != nil {
		return nil, errors.New("exec: StdoutPipe after process started")
	}
	pr, pw, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	c.Stdout = pw
	c.childIOFiles = append(c.childIOFiles, pw)
	c.parentIOPipes = append(c.parentIOPipes, pr)
	return pr, nil
}

// StderrPipe returns a pipe that will be connected to the command's
// standard error when the command starts.
//
// [Cmd.Wait] will close the pipe after seeing the command exit, so most callers
// need not close the pipe themselves. It is thus incorrect to call Wait
// before all reads from the pipe have completed.
// For the same reason, it is incorrect to use [Cmd.Run] when using StderrPipe.
// See the StdoutPipe example for idiomatic usage.
func (c *Cmd) StderrPipe() (io.ReadCloser, error) {
	if c.Stderr != nil {
		return nil, errors.New("exec: Stderr already set")
	}
	if c.Process != nil {
		return nil, errors.New("exec: StderrPipe after process started")
	}
	pr, pw, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	c.Stderr = pw
	c.childIOFiles = append(c.childIOFiles, pw)
	c.parentIOPipes = append(c.parentIOPipes, pr)
	return pr, nil
}

// prefixSuffixSaver is an io.Writer which retains the first N bytes
// and the last N bytes written to it. The Bytes() methods reconstructs
// it with a pretty error message.
type prefixSuffixSaver struct {
	N         int // max size of prefix or suffix
	prefix    []byte
	suffix    []byte // ring buffer once len(suffix) == N
	suffixOff int    // offset to write into suffix
	skipped   int64

	// TODO(bradfitz): we could keep one large []byte and use part of it for
	// the prefix, reserve space for the '... Omitting N bytes ...' message,
	// then the ring buffer suffix, and just rearrange the ring buffer
	// suffix when Bytes() is called, but it doesn't seem worth it for
	// now just for error messages. It's only ~64KB anyway.
}

func (w *prefixSuffixSaver) Write(p []byte) (n int, err error) {
	lenp := len(p)
	p = w.fill(&w.prefix, p)

	// Only keep the last w.N bytes of suffix data.
	if overage := len(p) - w.N; overage > 0 {
		p = p[overage:]
		w.skipped += int64(overage)
	}
	p = w.fill(&w.suffix, p)

	// w.suffix is full now if p is non-empty. Overwrite it in a circle.
	for len(p) > 0 { // 0, 1, or 2 iterations.
		n := copy(w.suffix[w.suffixOff:], p)
		p = p[n:]
		w.skipped += int64(n)
		w.suffixOff += n
		if w.suffixOff == w.N {
			w.suffixOff = 0
		}
	}
	return lenp, nil
}

// fill appends up to len(p) bytes of p to *dst, such that *dst does not
// grow larger than w.N. It returns the un-appended suffix of p.
func (w *prefixSuffixSaver) fill(dst *[]byte, p []byte) (pRemain []byte) {
	if remain := w.N - len(*dst); remain > 0 {
		add := min(len(p), remain)
		*dst = append(*dst, p[:add]...)
		p = p[add:]
	}
	return p
}

func (w *prefixSuffixSaver) Bytes() []byte {
	if w.suffix == nil {
		return w.prefix
	}
	if w.skipped == 0 {
		return append(w.prefix, w.suffix...)
	}
	var buf bytes.Buffer
	buf.Grow(len(w.prefix) + len(w.suffix) + 50)
	buf.Write(w.prefix)
	buf.WriteString("\n... omitting ")
	buf.WriteString(strconv.FormatInt(w.skipped, 10))
	buf.WriteString(" bytes ...\n")
	buf.Write(w.suffix[w.suffixOff:])
	buf.Write(w.suffix[:w.suffixOff])
	return buf.Bytes()
}

// environ returns a best-effort copy of the environment in which the command
// would be run as it is currently configured. If an error occurs in computing
// the environment, it is returned alongside the best-effort copy.
func (c *Cmd) environ() ([]string, error) {
	var err error

	env := c.Env
	if env == nil {
		env, err = execenv.Default(c.SysProcAttr)
		if err != nil {
			env = os.Environ()
			// Note that the non-nil err is preserved despite env being overridden.
		}

		if c.Dir != "" {
			switch runtime.GOOS {
			case "windows", "plan9":
				// Windows and Plan 9 do not use the PWD variable, so we don't need to
				// keep it accurate.
			default:
				// On POSIX platforms, PWD represents “an absolute pathname of the
				// current working directory.” Since we are changing the working
				// directory for the command, we should also update PWD to reflect that.
				//
				// Unfortunately, we didn't always do that, so (as proposed in
				// https://go.dev/issue/50599) to avoid unintended collateral damage we
				// only implicitly update PWD when Env is nil. That way, we're much
				// less likely to override an intentional change to the variable.
				if pwd, absErr := filepath.Abs(c.Dir); absErr == nil {
					env = append(env, "PWD="+pwd)
				} else if err == nil {
					err = absErr
				}
			}
		}
	}

	env, dedupErr := dedupEnv(env)
	if err == nil {
		err = dedupErr
	}
	return addCriticalEnv(env), err
}

// Environ returns a copy of the environment in which the command would be run
// as it is currently configured.
func (c *Cmd) Environ() []string {
	//  Intentionally ignore errors: environ returns a best-effort environment no matter what.
	env, _ := c.environ()
	return env
}

// dedupEnv returns a copy of env with any duplicates removed, in favor of
// later values.
// Items not of the normal environment "key=value" form are preserved unchanged.
// Except on Plan 9, items containing NUL characters are removed, and
// an error is returned along with the remaining values.
func dedupEnv(env []string) ([]string, error) {
	return dedupEnvCase(runtime.GOOS == "windows", runtime.GOOS == "plan9", env)
}

// dedupEnvCase is dedupEnv with a case option for testing.
// If caseInsensitive is true, the case of keys is ignored.
// If nulOK is false, items containing NUL characters are allowed.
func dedupEnvCase(caseInsensitive, nulOK bool, env []string) ([]string, error) {
	// Construct the output in reverse order, to preserve the
	// last occurrence of each key.
	var err error
	out := make([]string, 0, len(env))
	saw := make(map[string]bool, len(env))
	for n := len(env); n > 0; n-- {
		kv := env[n-1]

		// Reject NUL in environment variables to prevent security issues (#56284);
		// except on Plan 9, which uses NUL as os.PathListSeparator (#56544).
		if !nulOK && strings.IndexByte(kv, 0) != -1 {
			err = errors.New("exec: environment variable contains NUL")
			continue
		}

		i := strings.Index(kv, "=")
		if i == 0 {
			// We observe in practice keys with a single leading "=" on Windows.
			// TODO(#49886): Should we consume only the first leading "=" as part
			// of the key, or parse through arbitrarily many of them until a non-"="?
			i = strings.Index(kv[1:], "=") + 1
		}
		if i < 0 {
			if kv != "" {
				// The entry is not of the form "key=value" (as it is required to be).
				// Leave it as-is for now.
				// TODO(#52436): should we strip or reject these bogus entries?
				out = append(out, kv)
			}
			continue
		}
		k := kv[:i]
		if caseInsensitive {
			k = strings.ToLower(k)
		}
		if saw[k] {
			continue
		}

		saw[k] = true
		out = append(out, kv)
	}

	// Now reverse the slice to restore the original order.
	for i := 0; i < len(out)/2; i++ {
		j := len(out) - i - 1
		out[i], out[j] = out[j], out[i]
	}

	return out, err
}

// addCriticalEnv adds any critical environment variables that are required
// (or at least almost always required) on the operating system.
// Currently this is only used for Windows.
func addCriticalEnv(env []string) []string {
	if runtime.GOOS != "windows" {
		return env
	}
	for _, kv := range env {
		k, _, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		if strings.EqualFold(k, "SYSTEMROOT") {
			// We already have it.
			return env
		}
	}
	return append(env, "SYSTEMROOT="+os.Getenv("SYSTEMROOT"))
}

// ErrDot indicates that a path lookup resolved to an executable
// in the current directory due to ‘.’ being in the path, either
// implicitly or explicitly. See the package documentation for details.
//
// Note that functions in this package do not return ErrDot directly.
// Code should use errors.Is(err, ErrDot), not err == ErrDot,
// to test whether a returned error err is due to this condition.
var ErrDot = errors.New("cannot run executable found relative to current directory")

"""




```