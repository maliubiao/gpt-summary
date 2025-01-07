Response:
Let's break down the thought process for analyzing the provided Go code.

1. **Identify the Core Purpose:** The first thing I notice is the `package race_test` and the `//go:build race` directive. This strongly suggests that this code is about testing the Go race detector. The function `TestOutput` further reinforces this idea.

2. **Understand the Test Structure:** The `TestOutput` function iterates through a slice of `tests`. Each `test` struct seems to define a specific scenario for testing the race detector. This iterative structure is a common pattern for table-driven testing in Go.

3. **Analyze the `test` struct:** The fields within the `test` struct provide clues about the test cases:
    * `name`: A descriptive name for the test.
    * `run`:  Indicates whether to run the code using `go run` or `go test`.
    * `goos`: Allows specifying the operating system for the test.
    * `gorace`:  This is a crucial field. It likely configures the race detector's behavior using comma-separated key-value pairs.
    * `source`: The actual Go code to be executed for the test.
    * `re`: A slice of regular expressions to match against the output of the executed code.

4. **Examine the `TestOutput` function's logic:**
    * **`go install -race`:**  The code starts by installing the `testing` package with the `-race` flag. This makes the race detector available for the subsequent tests. The `-pkgdir` flag is used to isolate the installed package.
    * **Iteration and Setup:**  The loop iterates through each test case. It creates a temporary directory for each test. It then writes the `test.source` code into a file (`main.go` or `main_test.go`).
    * **Command Execution:** It constructs a `go run` or `go test` command with the `-race` flag and the temporary source file. Crucially, it manipulates the environment variables, removing `GODEBUG`, `GOMAXPROCS`, and existing `GORACE` settings, and then adds `GOMAXPROCS=1` and the `test.gorace` settings. `GOMAXPROCS=1` is important for making race conditions more reproducible.
    * **Output Capture and Matching:**  It executes the command and captures the output. It then attempts to match the captured output against the regular expressions defined in `test.re`.
    * **Failure Handling:** If no regular expression matches the output, the test fails.

5. **Inferring the Purpose (Race Detector Testing):** Based on the above analysis, it's clear that this code's primary function is to systematically test the Go race detector. It does this by creating small Go programs with known data races and verifying that the race detector correctly identifies them and outputs the expected warning messages.

6. **Go Code Examples (with Reasoning):** Now, let's create examples based on the test cases:

    * **Basic Data Race:**  The "simple" test case directly demonstrates a data race. Two goroutines are accessing and modifying the same shared variable without proper synchronization.

    * **Race Detector Configuration:** The `gorace` field is key. The "exitcode" test shows how to configure the race detector to change the exit code when a race is detected. The "strip_path_prefix" test shows how to simplify the output by removing a common path prefix. "halt_on_error" shows how to make the program exit immediately upon detecting a race.

    * **Testing in Test Files:** The "test_fails_on_race" case demonstrates that the race detector also works within `go test` and causes tests to fail if races are found during test execution.

    * **CGO Interaction:** The "external_cgo_thread" test demonstrates the race detector's ability to detect races involving threads created by C code called through CGO. This is a more advanced scenario.

7. **Command-Line Argument Handling:** The code doesn't directly *parse* command-line arguments of the test program. Instead, it *constructs* and *executes* `go` commands with specific flags (`-race`, `-pkgdir`). The `gorace` field configures the *race detector itself* rather than the test program. The `test.run` field determines whether `go run` or `go test` is used.

8. **Common Mistakes:**
    * **Incorrect `gorace` syntax:**  The `gorace` string needs to be in the correct key-value format. Typos or incorrect keys would lead to unexpected behavior or the race detector not working as intended.
    * **Assuming deterministic output:** Race conditions are inherently non-deterministic. While the tests try to make them reproducible (e.g., with `GOMAXPROCS=1`), the exact memory addresses and goroutine IDs in the output can vary. Therefore, the tests rely on regular expressions for matching.
    * **Not understanding the impact of environment variables:**  The code explicitly clears `GODEBUG`, `GOMAXPROCS`, and existing `GORACE` to ensure a consistent testing environment. Users manually running code might have these set, affecting race detection.

By following these steps, I can accurately understand the functionality of the given Go code and provide a comprehensive explanation with relevant examples. The key is to break down the code into smaller parts, understand the purpose of each part, and then synthesize that understanding into a coherent explanation.
这个go语言源文件 `go/src/runtime/race/output_test.go` 的主要功能是**测试 Go 语言的竞态检测器（race detector）的输出结果是否符合预期**。

具体来说，它通过运行包含已知数据竞争的 Go 程序，并使用竞态检测器来执行这些程序，然后比对竞态检测器产生的输出信息是否与预定义的正则表达式匹配。

**以下是详细的功能分解：**

1. **安装带有竞态检测的 `testing` 包:**
   - 代码首先使用 `go install -race -pkgdir=<tempdir> testing` 命令安装了带有竞态检测功能的 `testing` 包。
   - `-race` 标志指示 `go` 工具链编译时启用竞态检测。
   - `-pkgdir` 标志指定了一个临时目录用于存放编译后的包，以避免影响其他测试环境。

2. **定义测试用例:**
   - `tests` 变量是一个结构体切片，每个结构体定义了一个测试用例。
   - 每个测试用例包含以下字段：
     - `name`: 测试用例的名称。
     - `run`:  指定运行方式，可以是 "run" (使用 `go run`) 或 "test" (使用 `go test`)。
     - `goos`:  指定测试用例运行的操作系统，如果为空则在所有操作系统上运行。
     - `gorace`:  一个字符串，用于配置竞态检测器的行为，例如设置 `atexit_sleep_ms` (退出前休眠时间), `exitcode` (发现竞态时的退出码), `strip_path_prefix` (去除路径前缀), `halt_on_error` (发现错误立即停止) 等。
     - `source`:  包含可能存在数据竞争的 Go 源代码。
     - `re`:  一个字符串切片，包含用于匹配竞态检测器输出的正则表达式。

3. **动态生成并运行测试程序:**
   - 对于每个测试用例，代码会创建一个临时目录。
   - 根据 `test.run` 的值，将 `test.source` 的代码写入名为 `main.go` 或 `main_test.go` 的文件中。
   - 使用 `exec.Command` 构建并执行 `go run` 或 `go test` 命令，并带上 `-race` 标志和之前安装的 `testing` 包的路径 (`-pkgdir`).
   - 代码会过滤掉一些可能影响竞态检测器输出的环境变量，如 `GODEBUG`, `GOMAXPROCS`, `GORACE`，然后添加 `GOMAXPROCS=1` (强制单线程执行，更容易触发竞态) 和 `GORACE` 配置。

4. **比对竞态检测器的输出:**
   - 获取命令执行的输出 (`got`).
   - 遍历 `test.re` 中的正则表达式，检查是否至少有一个正则表达式匹配 `got`。
   - 如果没有匹配的正则表达式，则测试失败，并输出期望的正则表达式和实际的输出信息。

**推理其实现的 Go 语言功能：**

这个文件主要是为了测试 **Go 语言的竞态检测器 (race detector)**。 竞态检测器是一个在运行时检测并发程序中是否存在数据竞争的工具。

**Go 代码示例说明:**

假设我们有以下简单的 Go 程序 `main.go`，其中存在明显的数据竞争：

```go
package main

import (
	"fmt"
	"sync"
)

var counter int
var wg sync.WaitGroup

func increment() {
	defer wg.Done()
	for i := 0; i < 1000; i++ {
		counter++ // 多个 goroutine 同时写 counter，存在数据竞争
	}
}

func main() {
	wg.Add(2)
	go increment()
	go increment()
	wg.Wait()
	fmt.Println("Counter:", counter)
}
```

如果我们使用竞态检测器运行这个程序：

```bash
go run -race main.go
```

竞态检测器很可能会输出类似以下的警告信息：

```
==================
WARNING: DATA RACE
Write at 0x00c00008e008 by goroutine 7:
  main.increment()
      /path/to/your/main.go:11 +0x39

Previous write at 0x00c00008e008 by goroutine 6:
  main.increment()
      /path/to/your/main.go:11 +0x39

Goroutine 7 (running) created at:
  main.main()
      /path/to/your/main.go:18 +0x8d

Goroutine 6 (running) created at:
  main.main()
      /path/to/your/main.go:17 +0x78
==================
Found 1 data race(s)
exit status 66
```

`output_test.go` 中的测试用例就是为了验证这种输出的格式和内容是否符合预期。 例如，`simple` 测试用例就模拟了类似的场景。

**假设的输入与输出（基于 `simple` 测试用例）：**

**假设输入 `test.source` (来自 `simple` 测试用例):**

```go
package main
import "time"
var xptr *int
var donechan chan bool
func main() {
	done := make(chan bool)
	x := 0
	startRacer(&x, done)
	store(&x, 43)
	<-done
}
func store(x *int, v int) {
	*x = v
}
func startRacer(x *int, done chan bool) {
	xptr = x
	donechan = done
	go racer()
}
func racer() {
	time.Sleep(10*time.Millisecond)
	store(xptr, 42)
	donechan <- true
}
```

**假设 `test.gorace` 为 `"atexit_sleep_ms=0"`**

**预期输出 (部分，对应 `simple` 测试用例的 `re`):**

```
==================
WARNING: DATA RACE
Write at 0x[0-9,a-f]+ by goroutine [0-9]:
  main\.store\(\)
      .+/main\.go:14 \+0x[0-9,a-f]+
  main\.racer\(\)
      .+/main\.go:23 \+0x[0-9,a-f]+

Previous write at 0x[0-9,a-f]+ by main goroutine:
  main\.store\(\)
      .+/main\.go:14 \+0x[0-9,a-f]+
  main\.main\(\)
      .+/main\.go:10 \+0x[0-9,a-f]+

Goroutine [0-9] \(running\) created at:
  main\.startRacer\(\)
      .+/main\.go:19 \+0x[0-9,a-f]+
  main\.main\(\)
      .+/main\.go:9 \+0x[0-9,a-f]+
==================
Found 1 data race\(s\)
exit status 66
```

**命令行参数的具体处理：**

该文件本身并不直接处理命令行参数。 它主要是构建并执行 `go` 工具链的命令。

- **`go install -race -pkgdir=<tempdir> testing`**:  这个命令使用 `go install` 工具，`-race` 参数指示编译时启用竞态检测，`-pkgdir` 指定安装路径。
- **`go run -race -pkgdir=<pkgdir> src`**:  这个命令使用 `go run` 工具运行指定的源文件 (`src`)，`-race` 启用竞态检测，`-pkgdir` 指定依赖包的查找路径。
- **`go test -race -pkgdir=<pkgdir> src`**: 这个命令使用 `go test` 工具运行测试，参数含义同 `go run`。

`test.gorace` 字段中的字符串会被设置为 `GORACE` 环境变量，用于配置竞态检测器的行为。例如：

- `atexit_sleep_ms=0`: 设置竞态检测器在程序退出前不休眠。
- `exitcode=13`: 设置竞态检测器在发现竞态时的退出码为 13。
- `strip_path_prefix=/main.`:  让竞态检测器的输出中去除匹配到的路径前缀，使输出更简洁。
- `halt_on_error=1`:  让竞态检测器在发现第一个错误时立即停止程序。

**使用者易犯错的点：**

在编写或理解此类测试时，一个常见的错误是 **对正则表达式的理解不准确**。  竞态检测器的输出可能包含动态的内存地址和 goroutine ID，因此需要使用正则表达式来匹配这些模式。 如果正则表达式写得过于严格，可能会导致测试意外失败。

例如，在 `simple` 测试用例中，输出中的内存地址 (`0x[0-9,a-f]+`) 和 goroutine ID (`[0-9]+`) 都使用了正则表达式来匹配，因为这些值在每次运行时都可能不同。

另一个易错点是 **对 `GORACE` 环境变量配置项的理解不足**。  不同的配置项会影响竞态检测器的行为和输出，需要仔细查阅相关文档才能正确使用。 例如，错误地设置 `halt_on_error` 可能会导致程序在检测到竞态时立即退出，从而无法收集到完整的输出信息。

Prompt: 
```
这是路径为go/src/runtime/race/output_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build race

package race_test

import (
	"fmt"
	"internal/testenv"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func TestOutput(t *testing.T) {
	pkgdir := t.TempDir()
	out, err := exec.Command(testenv.GoToolPath(t), "install", "-race", "-pkgdir="+pkgdir, "testing").CombinedOutput()
	if err != nil {
		t.Fatalf("go install -race: %v\n%s", err, out)
	}

	for _, test := range tests {
		if test.goos != "" && test.goos != runtime.GOOS {
			t.Logf("test %v runs only on %v, skipping: ", test.name, test.goos)
			continue
		}
		dir := t.TempDir()
		source := "main.go"
		if test.run == "test" {
			source = "main_test.go"
		}
		src := filepath.Join(dir, source)
		f, err := os.Create(src)
		if err != nil {
			t.Fatalf("failed to create file: %v", err)
		}
		_, err = f.WriteString(test.source)
		if err != nil {
			f.Close()
			t.Fatalf("failed to write: %v", err)
		}
		if err := f.Close(); err != nil {
			t.Fatalf("failed to close file: %v", err)
		}

		cmd := exec.Command(testenv.GoToolPath(t), test.run, "-race", "-pkgdir="+pkgdir, src)
		// GODEBUG spoils program output, GOMAXPROCS makes it flaky.
		for _, env := range os.Environ() {
			if strings.HasPrefix(env, "GODEBUG=") ||
				strings.HasPrefix(env, "GOMAXPROCS=") ||
				strings.HasPrefix(env, "GORACE=") {
				continue
			}
			cmd.Env = append(cmd.Env, env)
		}
		cmd.Env = append(cmd.Env,
			"GOMAXPROCS=1", // see comment in race_test.go
			"GORACE="+test.gorace,
		)
		got, _ := cmd.CombinedOutput()
		matched := false
		for _, re := range test.re {
			if regexp.MustCompile(re).MatchString(string(got)) {
				matched = true
				break
			}
		}
		if !matched {
			exp := fmt.Sprintf("expect:\n%v\n", test.re[0])
			if len(test.re) > 1 {
				exp = fmt.Sprintf("expected one of %d patterns:\n",
					len(test.re))
				for k, re := range test.re {
					exp += fmt.Sprintf("pattern %d:\n%v\n", k, re)
				}
			}
			t.Fatalf("failed test case %v, %sgot:\n%s",
				test.name, exp, got)
		}
	}
}

var tests = []struct {
	name   string
	run    string
	goos   string
	gorace string
	source string
	re     []string
}{
	{"simple", "run", "", "atexit_sleep_ms=0", `
package main
import "time"
var xptr *int
var donechan chan bool
func main() {
	done := make(chan bool)
	x := 0
	startRacer(&x, done)
	store(&x, 43)
	<-done
}
func store(x *int, v int) {
	*x = v
}
func startRacer(x *int, done chan bool) {
	xptr = x
	donechan = done
	go racer()
}
func racer() {
	time.Sleep(10*time.Millisecond)
	store(xptr, 42)
	donechan <- true
}
`, []string{`==================
WARNING: DATA RACE
Write at 0x[0-9,a-f]+ by goroutine [0-9]:
  main\.store\(\)
      .+/main\.go:14 \+0x[0-9,a-f]+
  main\.racer\(\)
      .+/main\.go:23 \+0x[0-9,a-f]+

Previous write at 0x[0-9,a-f]+ by main goroutine:
  main\.store\(\)
      .+/main\.go:14 \+0x[0-9,a-f]+
  main\.main\(\)
      .+/main\.go:10 \+0x[0-9,a-f]+

Goroutine [0-9] \(running\) created at:
  main\.startRacer\(\)
      .+/main\.go:19 \+0x[0-9,a-f]+
  main\.main\(\)
      .+/main\.go:9 \+0x[0-9,a-f]+
==================
Found 1 data race\(s\)
exit status 66
`}},

	{"exitcode", "run", "", "atexit_sleep_ms=0 exitcode=13", `
package main
func main() {
	done := make(chan bool)
	x := 0; _ = x
	go func() {
		x = 42
		done <- true
	}()
	x = 43
	<-done
}
`, []string{`exit status 13`}},

	{"strip_path_prefix", "run", "", "atexit_sleep_ms=0 strip_path_prefix=/main.", `
package main
func main() {
	done := make(chan bool)
	x := 0; _ = x
	go func() {
		x = 42
		done <- true
	}()
	x = 43
	<-done
}
`, []string{`
      go:7 \+0x[0-9,a-f]+
`}},

	{"halt_on_error", "run", "", "atexit_sleep_ms=0 halt_on_error=1", `
package main
func main() {
	done := make(chan bool)
	x := 0; _ = x
	go func() {
		x = 42
		done <- true
	}()
	x = 43
	<-done
}
`, []string{`
==================
exit status 66
`}},

	{"test_fails_on_race", "test", "", "atexit_sleep_ms=0", `
package main_test
import "testing"
func TestFail(t *testing.T) {
	done := make(chan bool)
	x := 0
	_ = x
	go func() {
		x = 42
		done <- true
	}()
	x = 43
	<-done
	t.Log(t.Failed())
}
`, []string{`
==================
--- FAIL: TestFail \([0-9.]+s\)
.*testing.go:.*: race detected during execution of test
.*main_test.go:14: true
FAIL`}},

	{"slicebytetostring_pc", "run", "", "atexit_sleep_ms=0", `
package main
func main() {
	done := make(chan string)
	data := make([]byte, 10)
	go func() {
		done <- string(data)
	}()
	data[0] = 1
	<-done
}
`, []string{`
  runtime\.slicebytetostring\(\)
      .*/runtime/string\.go:.*
  main\.main\.func1\(\)
      .*/main.go:7`}},

	// Test for https://golang.org/issue/33309
	{"midstack_inlining_traceback", "run", "linux", "atexit_sleep_ms=0", `
package main

var x int
var c chan int
func main() {
	c = make(chan int)
	go f()
	x = 1
	<-c
}

func f() {
	g(c)
}

func g(c chan int) {
	h(c)
}

func h(c chan int) {
	c <- x
}
`, []string{`==================
WARNING: DATA RACE
Read at 0x[0-9,a-f]+ by goroutine [0-9]:
  main\.h\(\)
      .+/main\.go:22 \+0x[0-9,a-f]+
  main\.g\(\)
      .+/main\.go:18 \+0x[0-9,a-f]+
  main\.f\(\)
      .+/main\.go:14 \+0x[0-9,a-f]+

Previous write at 0x[0-9,a-f]+ by main goroutine:
  main\.main\(\)
      .+/main\.go:9 \+0x[0-9,a-f]+

Goroutine [0-9] \(running\) created at:
  main\.main\(\)
      .+/main\.go:8 \+0x[0-9,a-f]+
==================
Found 1 data race\(s\)
exit status 66
`}},

	// Test for https://golang.org/issue/17190
	{"external_cgo_thread", "run", "linux", "atexit_sleep_ms=0", `
package main

/*
#include <pthread.h>
typedef struct cb {
        int foo;
} cb;
extern void goCallback();
static inline void *threadFunc(void *p) {
	goCallback();
	return 0;
}
static inline void startThread(cb* c) {
	pthread_t th;
	pthread_create(&th, 0, threadFunc, 0);
}
*/
import "C"

var done chan bool
var racy int

//export goCallback
func goCallback() {
	racy++
	done <- true
}

func main() {
	done = make(chan bool)
	var c C.cb
	C.startThread(&c)
	racy++
	<- done
}
`, []string{`==================
WARNING: DATA RACE
Read at 0x[0-9,a-f]+ by main goroutine:
  main\.main\(\)
      .*/main\.go:34 \+0x[0-9,a-f]+

Previous write at 0x[0-9,a-f]+ by goroutine [0-9]:
  main\.goCallback\(\)
      .*/main\.go:27 \+0x[0-9,a-f]+
  _cgoexp_[0-9a-z]+_goCallback\(\)
      .*_cgo_gotypes\.go:[0-9]+ \+0x[0-9,a-f]+
  _cgoexp_[0-9a-z]+_goCallback\(\)
      <autogenerated>:1 \+0x[0-9,a-f]+

Goroutine [0-9] \(running\) created at:
  runtime\.newextram\(\)
      .*/runtime/proc.go:[0-9]+ \+0x[0-9,a-f]+
==================`,
		`==================
WARNING: DATA RACE
Read at 0x[0-9,a-f]+ by .*:
  main\..*
      .*/main\.go:[0-9]+ \+0x[0-9,a-f]+(?s).*

Previous write at 0x[0-9,a-f]+ by .*:
  main\..*
      .*/main\.go:[0-9]+ \+0x[0-9,a-f]+(?s).*

Goroutine [0-9] \(running\) created at:
  runtime\.newextram\(\)
      .*/runtime/proc.go:[0-9]+ \+0x[0-9,a-f]+
==================`}},
	{"second_test_passes", "test", "", "atexit_sleep_ms=0", `
package main_test
import "testing"
func TestFail(t *testing.T) {
	done := make(chan bool)
	x := 0
	_ = x
	go func() {
		x = 42
		done <- true
	}()
	x = 43
	<-done
}

func TestPass(t *testing.T) {
}
`, []string{`
==================
--- FAIL: TestFail \([0-9.]+s\)
.*testing.go:.*: race detected during execution of test
FAIL`}},
	{"mutex", "run", "", "atexit_sleep_ms=0", `
package main
import (
	"sync"
	"fmt"
)
func main() {
	c := make(chan bool, 1)
	threads := 1
	iterations := 20000
	data := 0
	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				c <- true
				data += 1
				<- c
			}
		}()
	}
	for i := 0; i < iterations; i++ {
		c <- true
		data += 1
		<- c
	}
	wg.Wait()
	if (data == iterations*(threads+1)) { fmt.Println("pass") }
}`, []string{`pass`}},
	// Test for https://github.com/golang/go/issues/37355
	{"chanmm", "run", "", "atexit_sleep_ms=0", `
package main
import (
	"sync"
	"time"
)
func main() {
	c := make(chan bool, 1)
	var data uint64
	var wg sync.WaitGroup
	wg.Add(2)
	c <- true
	go func() {
		defer wg.Done()
		c <- true
	}()
	go func() {
		defer wg.Done()
		time.Sleep(time.Second)
		<-c
		data = 2
	}()
	data = 1
	<-c
	wg.Wait()
	_ = data
}
`, []string{`==================
WARNING: DATA RACE
Write at 0x[0-9,a-f]+ by goroutine [0-9]:
  main\.main\.func2\(\)
      .*/main\.go:21 \+0x[0-9,a-f]+

Previous write at 0x[0-9,a-f]+ by main goroutine:
  main\.main\(\)
      .*/main\.go:23 \+0x[0-9,a-f]+

Goroutine [0-9] \(running\) created at:
  main\.main\(\)
      .*/main.go:[0-9]+ \+0x[0-9,a-f]+
==================`}},
	// Test symbolizing wrappers. Both (*T).f and main.gowrap1 are wrappers.
	// go.dev/issue/60245
	{"wrappersym", "run", "", "atexit_sleep_ms=0", `
package main
import "sync"
var wg sync.WaitGroup
var x int
func main() {
	f := (*T).f
	wg.Add(2)
	go f(new(T))
	f(new(T))
	wg.Wait()
}
type T struct{}
func (t T) f() {
	x = 42
	wg.Done()
}
`, []string{`==================
WARNING: DATA RACE
Write at 0x[0-9,a-f]+ by goroutine [0-9]:
  main\.T\.f\(\)
      .*/main.go:15 \+0x[0-9,a-f]+
  main\.\(\*T\)\.f\(\)
      <autogenerated>:1 \+0x[0-9,a-f]+
  main\.main\.gowrap1\(\)
      .*/main.go:9 \+0x[0-9,a-f]+

Previous write at 0x[0-9,a-f]+ by main goroutine:
  main\.T\.f\(\)
      .*/main.go:15 \+0x[0-9,a-f]+
  main\.\(\*T\)\.f\(\)
      <autogenerated>:1 \+0x[0-9,a-f]+
  main\.main\(\)
      .*/main.go:10 \+0x[0-9,a-f]+

`}},
	{"non_inline_array_compare", "run", "", "atexit_sleep_ms=0", `
package main

import (
	"math/rand/v2"
)

var x = [1024]byte{}

var ch = make(chan bool)

func main() {
	started := make(chan struct{})
	go func() {
		close(started)
		var y = [len(x)]byte{}
		eq := x == y
		ch <- eq
	}()
	<-started
	x[rand.IntN(len(x))]++
	println(<-ch)
}
`, []string{`==================
WARNING: DATA RACE
`}},
	{"non_inline_struct_compare", "run", "", "atexit_sleep_ms=0", `
package main

import "math/rand/v2"

type S struct {
	a [1024]byte
}

var x = S{a: [1024]byte{}}

var ch = make(chan bool)

func main() {
	started := make(chan struct{})
	go func() {
		close(started)
		var y = S{a: [len(x.a)]byte{}}
		eq := x == y
		ch <- eq
	}()
	<-started
	x.a[rand.IntN(len(x.a))]++
	println(<-ch)
}
`, []string{`==================
WARNING: DATA RACE
`}},
}

"""



```