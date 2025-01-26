Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Understanding the Goal:**

The core request is to analyze a Go test file (`example_test.go`) related to the `os/exec` package. The objective is to identify the functionalities demonstrated by the examples, explain the underlying Go features, provide illustrative code examples, and highlight potential pitfalls.

**2. Initial Scan and Keyword Recognition:**

The first step is to quickly scan the code, looking for keywords and function names that hint at the functionality being demonstrated. Key things to notice:

* `package exec_test`:  This clearly indicates it's a test package for the `os/exec` package.
* `import "os/exec"`:  Confirms the focus on external command execution.
* Function names starting with `Example`:  Go's convention for example functions, which serve as both documentation and test cases. Each `Example` function will likely showcase a specific aspect of the `os/exec` package.
* Common command names like `fortune`, `tr`, `date`, `sleep`, `echo`, `cat`, `sh`, `pwd`: These immediately suggest the examples involve running external commands.
* Methods like `LookPath`, `Command`, `Run`, `Output`, `Start`, `Wait`, `StdoutPipe`, `StdinPipe`, `StderrPipe`, `CombinedOutput`, `Environ`, `CommandContext`:  These are the core functions of the `os/exec` package being demonstrated.

**3. Analyzing Each Example Function:**

Now, the process is to go through each `Example` function individually and determine its purpose.

* **`ExampleLookPath()`:**  The name and the code `exec.LookPath("fortune")` clearly indicate that this example demonstrates finding the executable path of a command.

* **`ExampleCommand()`:**  `exec.Command("tr", "a-z", "A-Z")` suggests running the `tr` command. The setting of `Stdin` and `Stdout` points to redirecting standard input and output.

* **`ExampleCommand_environment()`:**  The name and the manipulation of `cmd.Env` suggest this example deals with setting environment variables for the executed command. The comment `// ignored` and `// this value is used` is crucial for understanding the behavior.

* **`ExampleCmd_Output()`:**  `exec.Command("date").Output()` indicates capturing the standard output of a command.

* **`ExampleCmd_Run()`:**  `exec.Command("sleep", "1").Run()` shows how to simply run a command and wait for it to finish.

* **`ExampleCmd_Start()` and `ExampleCmd_Wait()`:** These together demonstrate the non-blocking execution of a command using `Start()` followed by waiting for its completion with `Wait()`.

* **`ExampleCmd_StdoutPipe()`:** The use of `cmd.StdoutPipe()` and subsequent JSON decoding implies capturing the standard output of a command and processing it.

* **`ExampleCmd_StdinPipe()`:**  `cmd.StdinPipe()` and writing to it indicate feeding input to the standard input of a command. `CombinedOutput()` shows how to get both standard output and standard error.

* **`ExampleCmd_StderrPipe()`:** `cmd.StderrPipe()` points to capturing the standard error stream of a command.

* **`ExampleCmd_CombinedOutput()`:** The name and the code directly show how to capture both standard output and standard error together.

* **`ExampleCmd_Environ()`:**  The manipulation of `cmd.Dir` and `cmd.Env` before calling `cmd.Output()` shows how to modify the working directory and environment variables of the command. The comment about `PWD` is important.

* **`ExampleCommandContext()`:**  The use of `context.WithTimeout` and `exec.CommandContext` clearly demonstrates how to run a command with a timeout.

**4. Identifying Go Features:**

As each example is analyzed, the relevant Go features should be noted:

* **`os/exec` package:** The core functionality for running external commands.
* **`exec.LookPath()`:**  Finding executable paths.
* **`exec.Command()`:** Creating a command object.
* **`cmd.Run()`:** Running a command and waiting for completion.
* **`cmd.Output()`:** Running a command and capturing standard output.
* **`cmd.Start()` and `cmd.Wait()`:**  Non-blocking execution.
* **`cmd.StdoutPipe()`, `cmd.StdinPipe()`, `cmd.StderrPipe()`:**  Accessing standard streams.
* **`cmd.CombinedOutput()`:** Capturing both standard output and error.
* **`cmd.Env`:**  Manipulating environment variables.
* **`cmd.Dir`:** Setting the working directory.
* **`context` package and `exec.CommandContext()`:**  Managing command execution with timeouts and cancellations.
* **`strings.NewReader()`:** Creating an `io.Reader` from a string.
* **`strings.Builder`:**  Efficient string building.
* **`io.WriteString()`:** Writing to an `io.Writer`.
* **`io.ReadAll()`:** Reading all data from an `io.Reader`.
* **`encoding/json`:** Encoding and decoding JSON data.
* **Goroutines:** Used in `ExampleCmd_StdinPipe()` for asynchronous writing to `stdin`.

**5. Constructing Illustrative Code Examples:**

For each feature, create a simple, focused Go code snippet that demonstrates the concept. Keep the examples concise and easy to understand. Include comments to explain what's happening. Think about realistic, albeit simplified, use cases.

**6. Defining Assumptions for Code Examples:**

When providing concrete input and output examples, make sure to state the assumptions clearly. This avoids confusion and makes the examples reproducible (as much as possible given the dependency on external commands). For example, assuming the `date` command outputs a specific format.

**7. Explaining Command-Line Arguments:**

When an example involves command-line arguments, explain their purpose and how they affect the behavior of the external command. For example, explaining the `-n` flag in `echo -n`.

**8. Identifying Common Mistakes:**

Think about potential pitfalls users might encounter when working with `os/exec`. Common mistakes include:

* **Not handling errors:**  Crucial when running external commands.
* **Forgetting to `Wait()` after `Start()`:**  Leading to resource leaks.
* **Incorrectly handling standard streams:**  Especially closing pipes.
* **Security vulnerabilities:** If user input is directly used in command construction. (While not directly in this example, it's a generally good point to consider.)
* **Timeout issues:** Not setting or handling timeouts for long-running commands.

**9. Structuring the Answer in Chinese:**

Finally, organize the information logically and present it clearly in Chinese, following the instructions in the prompt. Use clear headings and formatting to improve readability.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe focus on the low-level details of process creation.
* **Correction:** Realize the examples are higher-level and focus on the common use cases of `os/exec`.
* **Initial thought:** Just list the function names.
* **Correction:** Explain what each function *does* and how it's used.
* **Initial thought:** Assume all commands are available.
* **Correction:** Acknowledge that the availability of external commands is an assumption.

By following this systematic approach, the provided code snippet can be thoroughly analyzed, and a comprehensive and helpful answer can be generated.
这段代码是 Go 语言 `os/exec` 包的示例测试代码，它主要用于演示如何使用 `os/exec` 包来执行外部命令。

以下是它包含的各项功能以及相关的 Go 语言功能实现示例：

**1. 查找可执行文件的路径 (`exec.LookPath`)**

该功能用于在系统的 PATH 环境变量中查找指定可执行文件的完整路径。

```go
func ExampleLookPath() {
	path, err := exec.LookPath("fortune")
	if err != nil {
		log.Fatal("installing fortune is in your future")
	}
	fmt.Printf("fortune is available at %s\n", path)
}
```

**功能实现说明:** `exec.LookPath("fortune")` 会在系统的 PATH 环境变量中查找名为 "fortune" 的可执行文件。如果找到，则返回其完整路径；否则，返回一个错误。

**假设输入与输出:**

* **假设:** 你的系统安装了 `fortune` 命令。
* **预期输出:** `fortune is available at /usr/bin/fortune` (实际路径可能不同)

**2. 执行外部命令并重定向标准输入/输出 (`exec.Command`)**

该功能用于创建一个 `Cmd` 对象，表示要执行的命令。你可以通过修改 `Cmd` 对象的字段来控制命令的执行，例如设置标准输入、输出等。

```go
func ExampleCommand() {
	cmd := exec.Command("tr", "a-z", "A-Z")
	cmd.Stdin = strings.NewReader("some input")
	var out strings.Builder
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("in all caps: %q\n", out.String())
}
```

**功能实现说明:**
* `exec.Command("tr", "a-z", "A-Z")` 创建一个执行 `tr` 命令的 `Cmd` 对象，并将 "a-z" 和 "A-Z" 作为 `tr` 命令的参数。 `tr` 命令用于字符转换。
* `cmd.Stdin = strings.NewReader("some input")` 将字符串 "some input" 设置为 `tr` 命令的标准输入。
* `var out strings.Builder; cmd.Stdout = &out` 创建一个 `strings.Builder` 用于接收命令的标准输出。
* `cmd.Run()` 执行命令并等待其完成。

**假设输入与输出:**

* **假设:** 系统安装了 `tr` 命令。
* **预期输出:** `in all caps: "SOME INPUT"`

**3. 执行外部命令并设置环境变量 (`cmd.Env`)**

该功能演示了如何为要执行的外部命令设置环境变量。

```go
func ExampleCommand_environment() {
	cmd := exec.Command("prog")
	cmd.Env = append(os.Environ(),
		"FOO=duplicate_value", // ignored
		"FOO=actual_value",    // this value is used
	)
	if err := cmd.Run(); err != nil {
		log.Fatal(err)
	}
}
```

**功能实现说明:**
* `cmd := exec.Command("prog")` 创建一个执行名为 "prog" 的命令的 `Cmd` 对象。
* `cmd.Env = append(os.Environ(), "FOO=duplicate_value", "FOO=actual_value")`  首先复制当前进程的环境变量 (`os.Environ()`)，然后添加或覆盖名为 "FOO" 的环境变量。注意，如果多次设置相同的环境变量，后面的值会覆盖前面的值。
* `cmd.Run()` 执行命令。

**假设输入与输出:**

* **假设:** 存在一个名为 "prog" 的可执行文件，它可以读取环境变量 "FOO"。
* **假设:** "prog" 会打印环境变量 "FOO" 的值到标准输出。
* **预期输出:** `actual_value` (如果 "prog" 按照假设运行)

**4. 执行外部命令并获取标准输出 (`cmd.Output`)**

该功能演示了如何执行命令并获取其标准输出。

```go
func ExampleCmd_Output() {
	out, err := exec.Command("date").Output()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("The date is %s\n", out)
}
```

**功能实现说明:**
* `exec.Command("date").Output()` 执行 `date` 命令并返回其标准输出 (作为一个字节切片) 和可能的错误。

**假设输入与输出:**

* **假设:** 系统安装了 `date` 命令。
* **预期输出:** `The date is Mon Oct 23 10:00:00 CST 2023\n` (日期和时间会根据当前系统时间而变化)

**5. 执行外部命令并等待其完成 (`cmd.Run`)**

该功能展示了如何执行一个命令并等待其执行完成。

```go
func ExampleCmd_Run() {
	cmd := exec.Command("sleep", "1")
	log.Printf("Running command and waiting for it to finish...")
	err := cmd.Run()
	log.Printf("Command finished with error: %v", err)
}
```

**功能实现说明:**
* `exec.Command("sleep", "1")` 创建一个执行 `sleep` 命令的 `Cmd` 对象，参数 "1" 表示睡眠 1 秒。
* `cmd.Run()` 执行命令并阻塞当前进程，直到命令执行完成。

**假设输入与输出:**

* **假设:** 系统安装了 `sleep` 命令。
* **预期输出:**
```
Running command and waiting for it to finish...
Command finished with error: <nil>
```
(输出时间会有延迟)

**6. 异步执行外部命令并等待其完成 (`cmd.Start`, `cmd.Wait`)**

该功能演示了如何先启动命令（不等待完成），然后再等待其完成。

```go
func ExampleCmd_Start() {
	cmd := exec.Command("sleep", "5")
	err := cmd.Start()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Waiting for command to finish...")
	err = cmd.Wait()
	log.Printf("Command finished with error: %v", err)
}
```

**功能实现说明:**
* `cmd := exec.Command("sleep", "5")` 创建一个执行 `sleep` 命令的 `Cmd` 对象，参数 "5" 表示睡眠 5 秒。
* `cmd.Start()` 启动命令，但不会阻塞当前进程。
* `cmd.Wait()` 阻塞当前进程，直到先前启动的命令执行完成。

**假设输入与输出:**

* **假设:** 系统安装了 `sleep` 命令。
* **预期输出:**
```
Waiting for command to finish...
Command finished with error: <nil>
```
(输出时间会有延迟，大约 5 秒后)

**7. 执行外部命令并获取标准输出，并将其解码为 JSON (`cmd.StdoutPipe`)**

该功能展示了如何获取命令的标准输出作为一个 `io.ReadCloser`，并可以对其进行进一步处理，例如解码 JSON 数据。

```go
func ExampleCmd_StdoutPipe() {
	cmd := exec.Command("echo", "-n", `{"Name": "Bob", "Age": 32}`)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		log.Fatal(err)
	}
	var person struct {
		Name string
		Age  int
	}
	if err := json.NewDecoder(stdout).Decode(&person); err != nil {
		log.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s is %d years old\n", person.Name, person.Age)
}
```

**功能实现说明:**
* `exec.Command("echo", "-n", `{"Name": "Bob", "Age": 32}`)` 创建一个执行 `echo` 命令的 `Cmd` 对象，其标准输出将是 JSON 字符串。 `-n` 参数告诉 `echo` 不要输出尾部的换行符。
* `cmd.StdoutPipe()` 返回一个 `io.ReadCloser`，可以从中读取命令的标准输出。
* `cmd.Start()` 启动命令。
* `json.NewDecoder(stdout).Decode(&person)` 创建一个 JSON 解码器，从命令的标准输出读取数据并将其解码到 `person` 结构体中。
* `cmd.Wait()` 等待命令完成。

**假设输入与输出:**

* **假设:** 系统安装了 `echo` 命令。
* **预期输出:** `Bob is 32 years old`

**8. 执行外部命令并向其标准输入写入数据 (`cmd.StdinPipe`)**

该功能演示了如何获取命令的标准输入作为一个 `io.WriteCloser`，并可以向其写入数据。

```go
func ExampleCmd_StdinPipe() {
	cmd := exec.Command("cat")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		defer stdin.Close()
		io.WriteString(stdin, "values written to stdin are passed to cmd's standard input")
	}()

	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%s\n", out)
}
```

**功能实现说明:**
* `exec.Command("cat")` 创建一个执行 `cat` 命令的 `Cmd` 对象。 `cat` 命令会将标准输入的内容输出到标准输出。
* `cmd.StdinPipe()` 返回一个 `io.WriteCloser`，可以向其写入数据作为命令的标准输入。
* 使用一个 goroutine 向 `stdin` 写入字符串。 `defer stdin.Close()` 确保在 goroutine 退出时关闭管道。
* `cmd.CombinedOutput()` 执行命令并获取其标准输出和标准错误。

**假设输入与输出:**

* **假设:** 系统安装了 `cat` 命令。
* **预期输出:** `values written to stdin are passed to cmd's standard input\n`

**9. 执行外部命令并获取标准错误 (`cmd.StderrPipe`)**

该功能演示了如何获取命令的标准错误作为一个 `io.ReadCloser`。

```go
func ExampleCmd_StderrPipe() {
	cmd := exec.Command("sh", "-c", "echo stdout; echo 1>&2 stderr")
	stderr, err := cmd.StderrPipe()
	if err != nil {
		log.Fatal(err)
	}

	if err := cmd.Start(); err != nil {
		log.Fatal(err)
	}

	slurp, _ := io.ReadAll(stderr)
	fmt.Printf("%s\n", slurp)

	if err := cmd.Wait(); err != nil {
		log.Fatal(err)
	}
}
```

**功能实现说明:**
* `exec.Command("sh", "-c", "echo stdout; echo 1>&2 stderr")` 创建一个执行 shell 命令的 `Cmd` 对象。该 shell 命令会将 "stdout" 输出到标准输出，将 "stderr" 输出到标准错误。
* `cmd.StderrPipe()` 返回一个 `io.ReadCloser`，可以从中读取命令的标准错误。
* `cmd.Start()` 启动命令。
* `io.ReadAll(stderr)` 从标准错误管道读取所有数据。
* `cmd.Wait()` 等待命令完成。

**假设输入与输出:**

* **假设:** 系统安装了 `sh` 命令。
* **预期输出:** `stderr\n`

**10. 执行外部命令并同时获取标准输出和标准错误 (`cmd.CombinedOutput`)**

该功能演示了如何一次性获取命令的标准输出和标准错误。

```go
func ExampleCmd_CombinedOutput() {
	cmd := exec.Command("sh", "-c", "echo stdout; echo 1>&2 stderr")
	stdoutStderr, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", stdoutStderr)
}
```

**功能实现说明:**
* `exec.Command("sh", "-c", "echo stdout; echo 1>&2 stderr")` 创建一个执行 shell 命令的 `Cmd` 对象。
* `cmd.CombinedOutput()` 执行命令并返回其标准输出和标准错误合并后的结果 (作为一个字节切片) 和可能的错误。

**假设输入与输出:**

* **假设:** 系统安装了 `sh` 命令。
* **预期输出:**
```
stdout
stderr
```

**11. 获取和修改命令的环境变量 (`cmd.Environ`)**

该功能演示了如何获取命令的当前环境变量，并对其进行修改。

```go
func ExampleCmd_Environ() {
	cmd := exec.Command("pwd")

	// Set Dir before calling cmd.Environ so that it will include an
	// updated PWD variable (on platforms where that is used).
	cmd.Dir = ".."
	cmd.Env = append(cmd.Environ(), "POSIXLY_CORRECT=1")

	out, err := cmd.Output()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", out)
}
```

**功能实现说明:**
* `exec.Command("pwd")` 创建一个执行 `pwd` 命令的 `Cmd` 对象。 `pwd` 命令用于打印当前工作目录。
* `cmd.Dir = ".."` 设置命令的工作目录为上一级目录。
* `cmd.Env = append(cmd.Environ(), "POSIXLY_CORRECT=1")`  获取命令的初始环境变量，并添加一个新的环境变量 "POSIXLY_CORRECT"。
* `cmd.Output()` 执行命令并获取其标准输出。

**假设输入与输出:**

* **假设:** 当前工作目录是 `/home/user/go/src/os/exec`。
* **假设:** 系统安装了 `pwd` 命令。
* **预期输出:** `/home/user/go/src/os\n`

**12. 使用上下文控制命令的执行 (`exec.CommandContext`)**

该功能演示了如何使用 `context.Context` 来控制命令的执行，例如设置超时时间。

```go
func ExampleCommandContext() {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	if err := exec.CommandContext(ctx, "sleep", "5").Run(); err != nil {
		// This will fail after 100 milliseconds. The 5 second sleep
		// will be interrupted.
	}
}
```

**功能实现说明:**
* `ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)` 创建一个带有超时时间的 `context.Context`。如果操作在 100 毫秒内没有完成，`ctx.Done()` channel 将会被关闭，并且关联的操作应该被取消。
* `exec.CommandContext(ctx, "sleep", "5")` 创建一个带有上下文的 `Cmd` 对象来执行 `sleep 5` 命令。
* `cmd.Run()` 尝试运行命令。由于上下文设置了 100 毫秒的超时时间，而 `sleep 5` 需要 5 秒才能完成，因此 `cmd.Run()` 将会返回一个错误，表明命令执行超时被中断。

**使用者易犯错的点:**

* **忘记处理错误:**  执行外部命令可能会失败，例如命令不存在、权限不足等。必须检查 `err` 的值，并进行适当的处理。

  ```go
  cmd := exec.Command("nonexistent_command")
  err := cmd.Run()
  if err != nil {
      log.Println("执行命令失败:", err) // 正确处理错误
  }
  ```

* **未正确处理标准输入/输出/错误管道的关闭:**  在使用 `StdoutPipe`, `StdinPipe`, `StderrPipe` 时，需要确保在使用完毕后关闭这些管道，以释放资源，避免程序 hang 住。

  ```go
  cmd := exec.Command("cat")
  stdin, err := cmd.StdinPipe()
  if err != nil {
      log.Fatal(err)
  }
  defer stdin.Close() // 确保关闭 stdin

  // ... 向 stdin 写入数据 ...

  out, err := cmd.CombinedOutput()
  // ...
  ```

* **直接拼接用户输入到命令字符串中导致安全问题:**  应该避免直接将用户输入拼接到要执行的命令字符串中，这可能导致命令注入漏洞。应该使用 `exec.Command` 的参数形式来传递用户输入。

  **错误示例:**
  ```go
  // 假设 userInput 是用户提供的输入
  command := fmt.Sprintf("ls -l %s", userInput)
  cmd := exec.Command("sh", "-c", command) // 存在安全风险
  ```

  **正确示例:**
  ```go
  // 假设 userInput 是用户提供的文件名
  cmd := exec.Command("ls", "-l", userInput)
  ```

总而言之，这段代码通过多个示例清晰地展示了 `os/exec` 包的各种常用功能，帮助开发者理解如何在 Go 语言中执行和管理外部命令。

Prompt: 
```
这是路径为go/src/os/exec/example_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package exec_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
)

func ExampleLookPath() {
	path, err := exec.LookPath("fortune")
	if err != nil {
		log.Fatal("installing fortune is in your future")
	}
	fmt.Printf("fortune is available at %s\n", path)
}

func ExampleCommand() {
	cmd := exec.Command("tr", "a-z", "A-Z")
	cmd.Stdin = strings.NewReader("some input")
	var out strings.Builder
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("in all caps: %q\n", out.String())
}

func ExampleCommand_environment() {
	cmd := exec.Command("prog")
	cmd.Env = append(os.Environ(),
		"FOO=duplicate_value", // ignored
		"FOO=actual_value",    // this value is used
	)
	if err := cmd.Run(); err != nil {
		log.Fatal(err)
	}
}

func ExampleCmd_Output() {
	out, err := exec.Command("date").Output()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("The date is %s\n", out)
}

func ExampleCmd_Run() {
	cmd := exec.Command("sleep", "1")
	log.Printf("Running command and waiting for it to finish...")
	err := cmd.Run()
	log.Printf("Command finished with error: %v", err)
}

func ExampleCmd_Start() {
	cmd := exec.Command("sleep", "5")
	err := cmd.Start()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Waiting for command to finish...")
	err = cmd.Wait()
	log.Printf("Command finished with error: %v", err)
}

func ExampleCmd_StdoutPipe() {
	cmd := exec.Command("echo", "-n", `{"Name": "Bob", "Age": 32}`)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		log.Fatal(err)
	}
	var person struct {
		Name string
		Age  int
	}
	if err := json.NewDecoder(stdout).Decode(&person); err != nil {
		log.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s is %d years old\n", person.Name, person.Age)
}

func ExampleCmd_StdinPipe() {
	cmd := exec.Command("cat")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		defer stdin.Close()
		io.WriteString(stdin, "values written to stdin are passed to cmd's standard input")
	}()

	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%s\n", out)
}

func ExampleCmd_StderrPipe() {
	cmd := exec.Command("sh", "-c", "echo stdout; echo 1>&2 stderr")
	stderr, err := cmd.StderrPipe()
	if err != nil {
		log.Fatal(err)
	}

	if err := cmd.Start(); err != nil {
		log.Fatal(err)
	}

	slurp, _ := io.ReadAll(stderr)
	fmt.Printf("%s\n", slurp)

	if err := cmd.Wait(); err != nil {
		log.Fatal(err)
	}
}

func ExampleCmd_CombinedOutput() {
	cmd := exec.Command("sh", "-c", "echo stdout; echo 1>&2 stderr")
	stdoutStderr, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", stdoutStderr)
}

func ExampleCmd_Environ() {
	cmd := exec.Command("pwd")

	// Set Dir before calling cmd.Environ so that it will include an
	// updated PWD variable (on platforms where that is used).
	cmd.Dir = ".."
	cmd.Env = append(cmd.Environ(), "POSIXLY_CORRECT=1")

	out, err := cmd.Output()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", out)
}

func ExampleCommandContext() {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	if err := exec.CommandContext(ctx, "sleep", "5").Run(); err != nil {
		// This will fail after 100 milliseconds. The 5 second sleep
		// will be interrupted.
	}
}

"""



```