Response:
Let's break down the thought process for analyzing the provided Go code.

**1. Initial Understanding and Goal:**

The first step is to recognize that this is a Go test file (`_test.go`) for the `slog` package. The name `logger_test.go` strongly suggests it's testing the core logging functionalities. The primary goal is to understand *what* specific aspects of logging are being tested here.

**2. Identifying Key Functions and Test Scenarios:**

Scan the file for functions starting with `Test`. These are the individual test cases. Each test function usually focuses on a specific feature or scenario. As I go through them, I'll try to summarize their purpose:

* `TestLogTextHandler`:  Seems to be testing the output format of the `TextHandler`.
* `TestConnections`:  Likely testing how `slog` interacts with the standard `log` package, especially with `SetDefault`.
* `TestAttrs`:  Probably testing how attributes (`Attr`) are handled and propagated in loggers.
* `TestCallDepth`:  Focuses on the accuracy of source code information (file, line number, function name) in logs.
* `TestAlloc`:  Tests memory allocation behavior during logging. This is often a performance consideration.
* `TestSetAttrs`:  Testing the `Add` method of the `Record` type, which is how key-value pairs are added.
* `TestSetDefault`:  Specifically tests the behavior of `slog.SetDefault`.
* `TestLogLoggerLevelForDefaultHandler`:  Testing how the log level filtering works when using the default handler.
* `TestLogLoggerLevelForHandlerWriter`:  Similar to the above, but likely tests level filtering with a custom handler.
* `TestLoggerError`:  Testing how errors and invalid key-value pairs are handled during logging.
* `TestNewLogLogger`:  Testing the functionality of creating a `log.Logger` that writes to a `slog.Handler`.
* `TestLoggerNoOps`:  Testing methods that should return the receiver without creating new objects (for efficiency).
* `TestContext`:  Verifying that context information is passed correctly during logging.
* `BenchmarkNopLog`:  A benchmark to measure the performance of logging.
* `TestPanics`:  Testing how the logging system handles panics that might occur when formatting log values.

**3. Analyzing Specific Test Cases in Detail (Examples):**

Let's take `TestLogTextHandler` as an example of deeper analysis:

* **Initialization:** `var buf bytes.Buffer`, `l := New(NewTextHandler(&buf, nil))`. This tells me we're capturing the log output into a buffer and using the `TextHandler` without any special options.
* **`check` function:** This is a helper function to verify the output. It prefixes the expected output with a timestamp pattern.
* **Log calls:** `l.Info("msg", ...)` , `l.Debug(...)`, etc. These are the actual logging calls being tested.
* **Expected Output:** The `check()` calls specify the expected format of the text log output for different log levels and data. Notice the `level=`, `msg=`, and key-value pairs. The debug message not appearing confirms the default level.
* **Inference:**  This test confirms the basic formatting of the `TextHandler`, including the inclusion of level, message, and key-value attributes. It also shows the default behavior of not logging debug messages.

Now consider `TestConnections`:

* **Focus:**  The comments explicitly mention testing the interaction between `slog` and the standard `log` package.
* **`SetDefault`:** This function plays a central role. The test first reverts and later sets the default `slog.Logger`.
* **`log.Print` vs. `slog.Info`:** The test makes calls to both `log.Print` and `slog.Info` to see where the output goes depending on the `SetDefault` state.
* **Inference:**  This test demonstrates how `slog.SetDefault` redirects the output of the standard `log` package to the `slog` handler, and vice-versa. It also checks the default logging level of the standard `log` package when integrated with `slog`.

**4. Identifying Go Language Features:**

While analyzing the tests, certain Go features become apparent:

* **Interfaces:** The `Handler` interface is central to the design.
* **Structs:**  `Logger`, `Record`, `HandlerOptions`, `Attr`, etc., are structs.
* **Methods:**  The test code calls methods on `Logger` and `Handler` instances.
* **Context:** The `context` package is used for passing request-scoped information.
* **Error Handling:** `io.EOF` is used as a test value.
* **Regular Expressions:** The `regexp` package is used for verifying log output.
* **Concurrency (Implicit):** Although not explicitly tested for race conditions in the core logic here (those are skipped), the presence of `sync.Mutex` in `captureHandler` suggests that concurrency is a consideration in the actual implementation.
* **Testing Framework:**  The `testing` package is used for writing the tests themselves.
* **Closures:** The `check` helper function and the anonymous functions in the `TestAlloc` are examples of closures.

**5. Code Inference and Examples:**

Based on the tests, I can infer how certain `slog` functionalities might be implemented and provide code examples. For instance, the `TestAttrs` function suggests the `With` method on a `Logger` likely creates a new `Logger` (or a wrapper) with additional attributes.

**6. Identifying Potential Mistakes:**

Looking at the test cases, I can infer potential pitfalls for users:

* **Forgetting to set the log level:** The `TestLogTextHandler` shows that debug messages are not printed by default. Users need to configure the handler's level.
* **Misunderstanding `SetDefault`:** The `TestConnections` highlights the interaction between `slog` and `log`. Users might be surprised by how `SetDefault` redirects output.

**7. Structuring the Answer:**

Finally, I organize the findings into the requested categories:

* **Functionality:** List the different aspects of logging being tested.
* **Go Language Feature Implementation:** Provide Go code examples to illustrate how the inferred functionalities work.
* **Code Inference with Input/Output:** Give specific examples from the test cases and their expected outcomes.
* **Command-Line Arguments:**  Review the code for any command-line argument processing (none found in this snippet).
* **Common Mistakes:** List potential errors based on the tests.

This structured approach allows for a comprehensive and accurate analysis of the provided Go test code.
这段代码是 Go 语言标准库 `log/slog` 包的一部分，专门用于测试 `slog.Logger` 的功能。它涵盖了 `slog` 提供的多种日志记录方法以及与标准库 `log` 包的集成。

以下是它主要测试的功能点：

1. **基础日志记录:**
   - 测试使用 `Info`, `Debug`, `Warn`, `Error`, `Log`, `LogAttrs` 等方法记录不同级别的日志信息。
   - 验证日志输出的格式，包括时间戳、日志级别、消息内容和属性（key-value 对）。
   - 检查默认情况下 `Debug` 级别的日志是否会被打印。

2. **日志处理器的使用 (Handler):**
   - 测试 `TextHandler` 的输出格式，包括时间戳、级别、消息和属性的呈现方式。
   - 测试如何通过 `HandlerOptions` 自定义处理器的行为，例如添加 source 信息。
   - 验证 `wrappingHandler` 这种自定义 Handler 的使用，以及它如何与默认 Handler 协同工作。

3. **与标准库 `log` 包的连接:**
   - 测试 `slog.SetDefault` 函数的功能，以及它如何影响标准库 `log` 包的输出。
   - 验证在调用 `slog.SetDefault` 后，标准库 `log.Print` 等函数的输出会通过 `slog` 的 Handler 进行处理。
   - 测试重新设置标准库 `log` 的输出是否会断开与 `slog` 的连接。

4. **日志属性 (Attributes):**
   - 测试 `With` 方法用于添加全局属性的功能，以及这些属性如何在不同的 Logger 之间传递。
   - 验证 `Log` 和 `LogAttrs` 方法处理不同类型属性值的方式，包括基本类型、`Duration`、`Attr` 切片和 `GroupValue`。
   - 测试 `NewRecord` 和 `r.Add` 方法用于创建和添加属性的功能。

5. **调用深度 (Call Depth):**
   - 测试日志输出中 `source` 信息的准确性，包括文件名、函数名和行号。
   - 验证不同日志记录方法是否能正确报告调用它们的源代码位置。

6. **内存分配 (Allocations):**
   - 使用 `testing.AllocsPerRun` 测试不同日志记录场景下的内存分配情况。
   - 目标是优化日志记录的性能，尽量减少不必要的内存分配。
   - 测试在日志级别被禁用时，是否会避免不必要的属性处理和内存分配。

7. **设置默认 Logger:**
   - 测试多次调用 `SetDefault` 的行为，确保不会导致死锁。

8. **日志级别控制:**
   - 测试 `SetLogLoggerLevel` 函数的功能，用于控制 `slog` 内部使用的 `log` 包的日志级别。
   - 验证在没有调用 `slog.SetDefault` 的情况下，如何通过设置 `logLoggerLevel` 来过滤默认 Handler 的输出。
   - 测试通过 `slog.SetDefault` 设置了 Handler 后，`logLoggerLevel` 如何影响标准库 `log` 包通过该 Handler 输出的日志。

9. **错误处理:**
   - 测试在日志记录过程中遇到错误 (例如 `io.EOF`) 时的输出格式。
   - 验证当传入 `Log` 方法的 key-value 对数量不匹配时，如何处理错误的 key。

10. **创建基于 Handler 的 `log.Logger`:**
    - 测试 `NewLogLogger` 函数，用于创建一个标准的 `log.Logger`，其输出会传递给 `slog.Handler`。

11. **空操作 (No-Ops):**
    - 测试 `With` 和 `WithGroup` 方法在没有添加任何属性或分组时，是否返回调用者本身，以避免不必要的对象创建。

12. **上下文 (Context):**
    - 测试日志记录方法是否能正确接收并传递 `context.Context`。
    - 验证传递给日志记录方法的 Context 会传递给 Handler。

13. **处理 `Marshaler` 接口的 Panic:**
    - 测试当日志属性的值实现了 `encoding.TextMarshaler` 或 `json.Marshaler` 接口，并且这些接口的 `MarshalText` 或 `MarshalJSON` 方法发生 panic 时，`slog` 如何处理并输出信息。

**Go 语言功能实现示例:**

**1. 使用 `TextHandler` 记录 Info 级别的日志:**

```go
package main

import (
	"bytes"
	"log/slog"
	"os"
)

func main() {
	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, nil)
	logger := slog.New(handler)

	logger.Info("用户登录", "用户名", "testuser", "IP地址", "192.168.1.1")

	os.Stdout.Write(buf.Bytes())
}
```

**假设输出:**

```
time=2023-10-27T10:00:00.000Z level=INFO msg="用户登录" 用户名=testuser IP地址=192.168.1.1
```

**2. 使用 `SetDefault` 将标准库 `log` 的输出重定向到 `slog`:**

```go
package main

import (
	"log"
	"log/slog"
	"os"
)

func main() {
	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelWarn})
	slog.SetDefault(slog.New(handler))

	log.Println("这是一条标准库的 log 输出，但是会被 slog 处理 (因为级别低于 Warn)")
	slog.Warn("这是一条 slog 的 Warn 级别输出")
}
```

**假设输出:**

```
time=2023-10-27T10:00:00.000Z level=WARN msg="这是一条 slog 的 Warn 级别输出"
```

**代码推理示例:**

**假设输入:** 调用 `l.Info("用户操作", "操作", "删除", "ID", 123)`，其中 `l` 是使用 `TextHandler` 创建的 `slog.Logger`。

**推理:**  `TextHandler` 会将日志信息格式化为文本，包含时间戳、级别、消息和属性。

**预期输出:**

```
time=... level=INFO msg="用户操作" 操作=删除 ID=123
```

**命令行参数处理:**

这段测试代码本身并没有直接处理命令行参数。它主要关注的是 `slog` 包内部的逻辑和功能。`slog` 包本身的设计目标是通过代码配置来控制日志行为，而不是依赖命令行参数。例如，可以通过 `HandlerOptions` 结构体来配置 Handler 的行为，例如日志级别、是否添加 source 信息等。

**使用者易犯错的点:**

1. **忘记设置日志级别:**  默认情况下，`TextHandler` 的 `Level` 为 `Info`，这意味着 `Debug` 级别的日志不会被输出。使用者可能会忘记根据需要调整 `HandlerOptions` 中的 `Level`。

   **错误示例:**

   ```go
   package main

   import (
   	"bytes"
   	"log/slog"
   	"os"
   )

   func main() {
   	var buf bytes.Buffer
   	handler := slog.NewTextHandler(&buf, nil) // 默认 Info 级别
   	logger := slog.New(handler)

   	logger.Debug("调试信息", "变量", 42) // 这条日志不会被输出
   	logger.Info("普通信息")
   	os.Stdout.Write(buf.Bytes())
   }
   ```

   **输出 (可能):**

   ```
   time=... level=INFO msg=普通信息
   ```

2. **误解 `slog.SetDefault` 的作用域:**  `slog.SetDefault` 设置的是全局的默认 Logger。如果在不同的包或goroutine中使用了标准库的 `log` 包，可能会因为全局默认 Logger 的改变而产生意想不到的结果。

   **错误示例 (假设在不同的包中使用了 `log`):**

   ```go
   // main.go
   package main

   import (
   	"log/slog"
   	"os"
   	"myutil"
   )

   func main() {
   	handler := slog.NewTextHandler(os.Stdout, nil)
   	slog.SetDefault(slog.New(handler))

   	myutil.LogSomething()
   }

   // myutil/myutil.go
   package myutil

   import "log"

   func LogSomething() {
   	log.Println("来自 myutil 的日志")
   }
   ```

   **如果 `slog.SetDefault` 在 `main` 函数中被调用，`myutil.LogSomething()` 的输出也会通过 `slog` 的 Handler 进行处理。如果使用者没有意识到这一点，可能会导致日志格式不一致或者级别过滤的问题。**

这段测试代码非常全面地覆盖了 `slog.Logger` 的各种功能和使用场景，是理解 `slog` 包工作原理的很好的参考资料。

Prompt: 
```
这是路径为go/src/log/slog/logger_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package slog

import (
	"bytes"
	"context"
	"internal/asan"
	"internal/msan"
	"internal/race"
	"internal/testenv"
	"io"
	"log"
	loginternal "log/internal"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// textTimeRE is a regexp to match log timestamps for Text handler.
// This is RFC3339Nano with the fixed 3 digit sub-second precision.
const textTimeRE = `\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}(Z|[+-]\d{2}:\d{2})`

// jsonTimeRE is a regexp to match log timestamps for Text handler.
// This is RFC3339Nano with an arbitrary sub-second precision.
const jsonTimeRE = `\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})`

func TestLogTextHandler(t *testing.T) {
	ctx := context.Background()
	var buf bytes.Buffer

	l := New(NewTextHandler(&buf, nil))

	check := func(want string) {
		t.Helper()
		if want != "" {
			want = "time=" + textTimeRE + " " + want
		}
		checkLogOutput(t, buf.String(), want)
		buf.Reset()
	}

	l.Info("msg", "a", 1, "b", 2)
	check(`level=INFO msg=msg a=1 b=2`)

	// By default, debug messages are not printed.
	l.Debug("bg", Int("a", 1), "b", 2)
	check("")

	l.Warn("w", Duration("dur", 3*time.Second))
	check(`level=WARN msg=w dur=3s`)

	l.Error("bad", "a", 1)
	check(`level=ERROR msg=bad a=1`)

	l.Log(ctx, LevelWarn+1, "w", Int("a", 1), String("b", "two"))
	check(`level=WARN\+1 msg=w a=1 b=two`)

	l.LogAttrs(ctx, LevelInfo+1, "a b c", Int("a", 1), String("b", "two"))
	check(`level=INFO\+1 msg="a b c" a=1 b=two`)

	l.Info("info", "a", []Attr{Int("i", 1)})
	check(`level=INFO msg=info a.i=1`)

	l.Info("info", "a", GroupValue(Int("i", 1)))
	check(`level=INFO msg=info a.i=1`)
}

func TestConnections(t *testing.T) {
	var logbuf, slogbuf bytes.Buffer

	// Revert any changes to the default logger. This is important because other
	// tests might change the default logger using SetDefault. Also ensure we
	// restore the default logger at the end of the test.
	currentLogger := Default()
	currentLogWriter := log.Writer()
	currentLogFlags := log.Flags()
	SetDefault(New(newDefaultHandler(loginternal.DefaultOutput)))
	t.Cleanup(func() {
		SetDefault(currentLogger)
		log.SetOutput(currentLogWriter)
		log.SetFlags(currentLogFlags)
	})

	// The default slog.Logger's handler uses the log package's default output.
	log.SetOutput(&logbuf)
	log.SetFlags(log.Lshortfile &^ log.LstdFlags)
	Info("msg", "a", 1)
	checkLogOutput(t, logbuf.String(), `logger_test.go:\d+: INFO msg a=1`)
	logbuf.Reset()
	Info("msg", "p", nil)
	checkLogOutput(t, logbuf.String(), `logger_test.go:\d+: INFO msg p=<nil>`)
	logbuf.Reset()
	var r *regexp.Regexp
	Info("msg", "r", r)
	checkLogOutput(t, logbuf.String(), `logger_test.go:\d+: INFO msg r=<nil>`)
	logbuf.Reset()
	Warn("msg", "b", 2)
	checkLogOutput(t, logbuf.String(), `logger_test.go:\d+: WARN msg b=2`)
	logbuf.Reset()
	Error("msg", "err", io.EOF, "c", 3)
	checkLogOutput(t, logbuf.String(), `logger_test.go:\d+: ERROR msg err=EOF c=3`)

	// Levels below Info are not printed.
	logbuf.Reset()
	Debug("msg", "c", 3)
	checkLogOutput(t, logbuf.String(), "")

	t.Run("wrap default handler", func(t *testing.T) {
		// It should be possible to wrap the default handler and get the right output.
		// This works because the default handler uses the pc in the Record
		// to get the source line, rather than a call depth.
		logger := New(wrappingHandler{Default().Handler()})
		logger.Info("msg", "d", 4)
		checkLogOutput(t, logbuf.String(), `logger_test.go:\d+: INFO msg d=4`)
	})

	// Once slog.SetDefault is called, the direction is reversed: the default
	// log.Logger's output goes through the handler.
	SetDefault(New(NewTextHandler(&slogbuf, &HandlerOptions{AddSource: true})))
	log.Print("msg2")
	checkLogOutput(t, slogbuf.String(), "time="+textTimeRE+` level=INFO source=.*logger_test.go:\d{3}"? msg=msg2`)

	// The default log.Logger always outputs at Info level.
	slogbuf.Reset()
	SetDefault(New(NewTextHandler(&slogbuf, &HandlerOptions{Level: LevelWarn})))
	log.Print("should not appear")
	if got := slogbuf.String(); got != "" {
		t.Errorf("got %q, want empty", got)
	}

	// Setting log's output again breaks the connection.
	logbuf.Reset()
	slogbuf.Reset()
	log.SetOutput(&logbuf)
	log.SetFlags(log.Lshortfile &^ log.LstdFlags)
	log.Print("msg3")
	checkLogOutput(t, logbuf.String(), `logger_test.go:\d+: msg3`)
	if got := slogbuf.String(); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

type wrappingHandler struct {
	h Handler
}

func (h wrappingHandler) Enabled(ctx context.Context, level Level) bool {
	return h.h.Enabled(ctx, level)
}
func (h wrappingHandler) WithGroup(name string) Handler              { return h.h.WithGroup(name) }
func (h wrappingHandler) WithAttrs(as []Attr) Handler                { return h.h.WithAttrs(as) }
func (h wrappingHandler) Handle(ctx context.Context, r Record) error { return h.h.Handle(ctx, r) }

func TestAttrs(t *testing.T) {
	check := func(got []Attr, want ...Attr) {
		t.Helper()
		if !attrsEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	}

	l1 := New(&captureHandler{}).With("a", 1)
	l2 := New(l1.Handler()).With("b", 2)
	l2.Info("m", "c", 3)
	h := l2.Handler().(*captureHandler)
	check(h.attrs, Int("a", 1), Int("b", 2))
	check(attrsSlice(h.r), Int("c", 3))
}

func TestCallDepth(t *testing.T) {
	ctx := context.Background()
	h := &captureHandler{}
	var startLine int

	check := func(count int) {
		t.Helper()
		const wantFunc = "log/slog.TestCallDepth"
		const wantFile = "logger_test.go"
		wantLine := startLine + count*2
		got := h.r.source()
		gotFile := filepath.Base(got.File)
		if got.Function != wantFunc || gotFile != wantFile || got.Line != wantLine {
			t.Errorf("got (%s, %s, %d), want (%s, %s, %d)",
				got.Function, gotFile, got.Line, wantFunc, wantFile, wantLine)
		}
	}

	defer SetDefault(Default()) // restore
	logger := New(h)
	SetDefault(logger)

	// Calls to check must be one line apart.
	// Determine line where calls start.
	f, _ := runtime.CallersFrames([]uintptr{callerPC(2)}).Next()
	startLine = f.Line + 4
	// Do not change the number of lines between here and the call to check(0).

	logger.Log(ctx, LevelInfo, "")
	check(0)
	logger.LogAttrs(ctx, LevelInfo, "")
	check(1)
	logger.Debug("")
	check(2)
	logger.Info("")
	check(3)
	logger.Warn("")
	check(4)
	logger.Error("")
	check(5)
	Debug("")
	check(6)
	Info("")
	check(7)
	Warn("")
	check(8)
	Error("")
	check(9)
	Log(ctx, LevelInfo, "")
	check(10)
	LogAttrs(ctx, LevelInfo, "")
	check(11)
}

func TestAlloc(t *testing.T) {
	ctx := context.Background()
	dl := New(discardTestHandler{})
	defer SetDefault(Default()) // restore
	SetDefault(dl)

	t.Run("Info", func(t *testing.T) {
		wantAllocs(t, 0, func() { Info("hello") })
	})
	t.Run("Error", func(t *testing.T) {
		wantAllocs(t, 0, func() { Error("hello") })
	})
	t.Run("logger.Info", func(t *testing.T) {
		wantAllocs(t, 0, func() { dl.Info("hello") })
	})
	t.Run("logger.Log", func(t *testing.T) {
		wantAllocs(t, 0, func() { dl.Log(ctx, LevelDebug, "hello") })
	})
	t.Run("2 pairs", func(t *testing.T) {
		s := "abc"
		i := 2000
		wantAllocs(t, 2, func() {
			dl.Info("hello",
				"n", i,
				"s", s,
			)
		})
	})
	t.Run("2 pairs disabled inline", func(t *testing.T) {
		l := New(DiscardHandler)
		s := "abc"
		i := 2000
		wantAllocs(t, 2, func() {
			l.Log(ctx, LevelInfo, "hello",
				"n", i,
				"s", s,
			)
		})
	})
	t.Run("2 pairs disabled", func(t *testing.T) {
		l := New(DiscardHandler)
		s := "abc"
		i := 2000
		wantAllocs(t, 0, func() {
			if l.Enabled(ctx, LevelInfo) {
				l.Log(ctx, LevelInfo, "hello",
					"n", i,
					"s", s,
				)
			}
		})
	})
	t.Run("9 kvs", func(t *testing.T) {
		s := "abc"
		i := 2000
		d := time.Second
		wantAllocs(t, 10, func() {
			dl.Info("hello",
				"n", i, "s", s, "d", d,
				"n", i, "s", s, "d", d,
				"n", i, "s", s, "d", d)
		})
	})
	t.Run("pairs", func(t *testing.T) {
		wantAllocs(t, 0, func() { dl.Info("", "error", io.EOF) })
	})
	t.Run("attrs1", func(t *testing.T) {
		wantAllocs(t, 0, func() { dl.LogAttrs(ctx, LevelInfo, "", Int("a", 1)) })
		wantAllocs(t, 0, func() { dl.LogAttrs(ctx, LevelInfo, "", Any("error", io.EOF)) })
	})
	t.Run("attrs3", func(t *testing.T) {
		wantAllocs(t, 0, func() {
			dl.LogAttrs(ctx, LevelInfo, "hello", Int("a", 1), String("b", "two"), Duration("c", time.Second))
		})
	})
	t.Run("attrs3 disabled", func(t *testing.T) {
		logger := New(DiscardHandler)
		wantAllocs(t, 0, func() {
			logger.LogAttrs(ctx, LevelInfo, "hello", Int("a", 1), String("b", "two"), Duration("c", time.Second))
		})
	})
	t.Run("attrs6", func(t *testing.T) {
		wantAllocs(t, 1, func() {
			dl.LogAttrs(ctx, LevelInfo, "hello",
				Int("a", 1), String("b", "two"), Duration("c", time.Second),
				Int("d", 1), String("e", "two"), Duration("f", time.Second))
		})
	})
	t.Run("attrs9", func(t *testing.T) {
		wantAllocs(t, 1, func() {
			dl.LogAttrs(ctx, LevelInfo, "hello",
				Int("a", 1), String("b", "two"), Duration("c", time.Second),
				Int("d", 1), String("e", "two"), Duration("f", time.Second),
				Int("d", 1), String("e", "two"), Duration("f", time.Second))
		})
	})
}

func TestSetAttrs(t *testing.T) {
	for _, test := range []struct {
		args []any
		want []Attr
	}{
		{nil, nil},
		{[]any{"a", 1}, []Attr{Int("a", 1)}},
		{[]any{"a", 1, "b", "two"}, []Attr{Int("a", 1), String("b", "two")}},
		{[]any{"a"}, []Attr{String(badKey, "a")}},
		{[]any{"a", 1, "b"}, []Attr{Int("a", 1), String(badKey, "b")}},
		{[]any{"a", 1, 2, 3}, []Attr{Int("a", 1), Int(badKey, 2), Int(badKey, 3)}},
	} {
		r := NewRecord(time.Time{}, 0, "", 0)
		r.Add(test.args...)
		got := attrsSlice(r)
		if !attrsEqual(got, test.want) {
			t.Errorf("%v:\ngot  %v\nwant %v", test.args, got, test.want)
		}
	}
}

func TestSetDefault(t *testing.T) {
	// Verify that setting the default to itself does not result in deadlock.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	defer func(w io.Writer) { log.SetOutput(w) }(log.Writer())
	log.SetOutput(io.Discard)
	go func() {
		Info("A")
		SetDefault(Default())
		Info("B")
		cancel()
	}()
	<-ctx.Done()
	if err := ctx.Err(); err != context.Canceled {
		t.Errorf("wanted canceled, got %v", err)
	}
}

// Test defaultHandler minimum level without calling slog.SetDefault.
func TestLogLoggerLevelForDefaultHandler(t *testing.T) {
	// Revert any changes to the default logger, flags, and level of log and slog.
	currentLogLoggerLevel := logLoggerLevel.Level()
	currentLogWriter := log.Writer()
	currentLogFlags := log.Flags()
	t.Cleanup(func() {
		logLoggerLevel.Set(currentLogLoggerLevel)
		log.SetOutput(currentLogWriter)
		log.SetFlags(currentLogFlags)
	})

	var logBuf bytes.Buffer
	log.SetOutput(&logBuf)
	log.SetFlags(0)

	for _, test := range []struct {
		logLevel Level
		logFn    func(string, ...any)
		want     string
	}{
		{LevelDebug, Debug, "DEBUG a"},
		{LevelDebug, Info, "INFO a"},
		{LevelInfo, Debug, ""},
		{LevelInfo, Info, "INFO a"},
	} {
		SetLogLoggerLevel(test.logLevel)
		test.logFn("a")
		checkLogOutput(t, logBuf.String(), test.want)
		logBuf.Reset()
	}
}

// Test handlerWriter minimum level by calling slog.SetDefault.
func TestLogLoggerLevelForHandlerWriter(t *testing.T) {
	removeTime := func(_ []string, a Attr) Attr {
		if a.Key == TimeKey {
			return Attr{}
		}
		return a
	}

	// Revert any changes to the default logger. This is important because other
	// tests might change the default logger using SetDefault. Also ensure we
	// restore the default logger at the end of the test.
	currentLogger := Default()
	currentLogLoggerLevel := logLoggerLevel.Level()
	currentLogWriter := log.Writer()
	currentFlags := log.Flags()
	t.Cleanup(func() {
		SetDefault(currentLogger)
		logLoggerLevel.Set(currentLogLoggerLevel)
		log.SetOutput(currentLogWriter)
		log.SetFlags(currentFlags)
	})

	var logBuf bytes.Buffer
	log.SetOutput(&logBuf)
	log.SetFlags(0)
	SetLogLoggerLevel(LevelError)
	SetDefault(New(NewTextHandler(&logBuf, &HandlerOptions{ReplaceAttr: removeTime})))
	log.Print("error")
	checkLogOutput(t, logBuf.String(), `level=ERROR msg=error`)
}

func TestLoggerError(t *testing.T) {
	var buf bytes.Buffer

	removeTime := func(_ []string, a Attr) Attr {
		if a.Key == TimeKey {
			return Attr{}
		}
		return a
	}
	l := New(NewTextHandler(&buf, &HandlerOptions{ReplaceAttr: removeTime}))
	l.Error("msg", "err", io.EOF, "a", 1)
	checkLogOutput(t, buf.String(), `level=ERROR msg=msg err=EOF a=1`)
	buf.Reset()
	// use local var 'args' to defeat vet check
	args := []any{"err", io.EOF, "a"}
	l.Error("msg", args...)
	checkLogOutput(t, buf.String(), `level=ERROR msg=msg err=EOF !BADKEY=a`)
}

func TestNewLogLogger(t *testing.T) {
	var buf bytes.Buffer
	h := NewTextHandler(&buf, nil)
	ll := NewLogLogger(h, LevelWarn)
	ll.Print("hello")
	checkLogOutput(t, buf.String(), "time="+textTimeRE+` level=WARN msg=hello`)
}

func TestLoggerNoOps(t *testing.T) {
	l := Default()
	if l.With() != l {
		t.Error("wanted receiver, didn't get it")
	}
	if With() != l {
		t.Error("wanted receiver, didn't get it")
	}
	if l.WithGroup("") != l {
		t.Error("wanted receiver, didn't get it")
	}
}

func TestContext(t *testing.T) {
	// Verify that the context argument to log output methods is passed to the handler.
	// Also check the level.
	h := &captureHandler{}
	l := New(h)
	defer SetDefault(Default()) // restore
	SetDefault(l)

	for _, test := range []struct {
		f         func(context.Context, string, ...any)
		wantLevel Level
	}{
		{l.DebugContext, LevelDebug},
		{l.InfoContext, LevelInfo},
		{l.WarnContext, LevelWarn},
		{l.ErrorContext, LevelError},
		{DebugContext, LevelDebug},
		{InfoContext, LevelInfo},
		{WarnContext, LevelWarn},
		{ErrorContext, LevelError},
	} {
		h.clear()
		ctx := context.WithValue(context.Background(), "L", test.wantLevel)

		test.f(ctx, "msg")
		if gv := h.ctx.Value("L"); gv != test.wantLevel || h.r.Level != test.wantLevel {
			t.Errorf("got context value %v, level %s; want %s for both", gv, h.r.Level, test.wantLevel)
		}
	}
}

func checkLogOutput(t *testing.T, got, wantRegexp string) {
	t.Helper()
	got = clean(got)
	wantRegexp = "^" + wantRegexp + "$"
	matched, err := regexp.MatchString(wantRegexp, got)
	if err != nil {
		t.Fatal(err)
	}
	if !matched {
		t.Errorf("\ngot  %s\nwant %s", got, wantRegexp)
	}
}

// clean prepares log output for comparison.
func clean(s string) string {
	if len(s) > 0 && s[len(s)-1] == '\n' {
		s = s[:len(s)-1]
	}
	return strings.ReplaceAll(s, "\n", "~")
}

type captureHandler struct {
	mu     sync.Mutex
	ctx    context.Context
	r      Record
	attrs  []Attr
	groups []string
}

func (h *captureHandler) Handle(ctx context.Context, r Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.ctx = ctx
	h.r = r
	return nil
}

func (*captureHandler) Enabled(context.Context, Level) bool { return true }

func (c *captureHandler) WithAttrs(as []Attr) Handler {
	c.mu.Lock()
	defer c.mu.Unlock()
	var c2 captureHandler
	c2.r = c.r
	c2.groups = c.groups
	c2.attrs = concat(c.attrs, as)
	return &c2
}

func (c *captureHandler) WithGroup(name string) Handler {
	c.mu.Lock()
	defer c.mu.Unlock()
	var c2 captureHandler
	c2.r = c.r
	c2.attrs = c.attrs
	c2.groups = append(slices.Clip(c.groups), name)
	return &c2
}

func (c *captureHandler) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ctx = nil
	c.r = Record{}
}

type discardTestHandler struct {
	attrs []Attr
}

func (d discardTestHandler) Enabled(context.Context, Level) bool { return true }
func (discardTestHandler) Handle(context.Context, Record) error  { return nil }
func (d discardTestHandler) WithAttrs(as []Attr) Handler {
	d.attrs = concat(d.attrs, as)
	return d
}
func (h discardTestHandler) WithGroup(name string) Handler {
	return h
}

// concat returns a new slice with the elements of s1 followed
// by those of s2. The slice has no additional capacity.
func concat[T any](s1, s2 []T) []T {
	s := make([]T, len(s1)+len(s2))
	copy(s, s1)
	copy(s[len(s1):], s2)
	return s
}

// This is a simple benchmark. See the benchmarks subdirectory for more extensive ones.
func BenchmarkNopLog(b *testing.B) {
	ctx := context.Background()
	l := New(&captureHandler{})
	b.Run("no attrs", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			l.LogAttrs(ctx, LevelInfo, "msg")
		}
	})
	b.Run("attrs", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			l.LogAttrs(ctx, LevelInfo, "msg", Int("a", 1), String("b", "two"), Bool("c", true))
		}
	})
	b.Run("attrs-parallel", func(b *testing.B) {
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				l.LogAttrs(ctx, LevelInfo, "msg", Int("a", 1), String("b", "two"), Bool("c", true))
			}
		})
	})
	b.Run("keys-values", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			l.Log(ctx, LevelInfo, "msg", "a", 1, "b", "two", "c", true)
		}
	})
	b.Run("WithContext", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			l.LogAttrs(ctx, LevelInfo, "msg2", Int("a", 1), String("b", "two"), Bool("c", true))
		}
	})
	b.Run("WithContext-parallel", func(b *testing.B) {
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				l.LogAttrs(ctx, LevelInfo, "msg", Int("a", 1), String("b", "two"), Bool("c", true))
			}
		})
	})
}

// callerPC returns the program counter at the given stack depth.
func callerPC(depth int) uintptr {
	var pcs [1]uintptr
	runtime.Callers(depth, pcs[:])
	return pcs[0]
}

func wantAllocs(t *testing.T, want int, f func()) {
	if race.Enabled || asan.Enabled || msan.Enabled {
		t.Skip("skipping test in race, asan, and msan modes")
	}
	testenv.SkipIfOptimizationOff(t)
	t.Helper()
	got := int(testing.AllocsPerRun(5, f))
	if got != want {
		t.Errorf("got %d allocs, want %d", got, want)
	}
}

// panicTextAndJsonMarshaler is a type that panics in MarshalText and MarshalJSON.
type panicTextAndJsonMarshaler struct {
	msg any
}

func (p panicTextAndJsonMarshaler) MarshalText() ([]byte, error) {
	panic(p.msg)
}

func (p panicTextAndJsonMarshaler) MarshalJSON() ([]byte, error) {
	panic(p.msg)
}

func TestPanics(t *testing.T) {
	// Revert any changes to the default logger. This is important because other
	// tests might change the default logger using SetDefault. Also ensure we
	// restore the default logger at the end of the test.
	currentLogger := Default()
	currentLogWriter := log.Writer()
	currentLogFlags := log.Flags()
	t.Cleanup(func() {
		SetDefault(currentLogger)
		log.SetOutput(currentLogWriter)
		log.SetFlags(currentLogFlags)
	})

	var logBuf bytes.Buffer
	log.SetOutput(&logBuf)
	log.SetFlags(log.Lshortfile &^ log.LstdFlags)

	SetDefault(New(newDefaultHandler(loginternal.DefaultOutput)))
	for _, pt := range []struct {
		in  any
		out string
	}{
		{(*panicTextAndJsonMarshaler)(nil), `logger_test.go:\d+: INFO msg p=<nil>`},
		{panicTextAndJsonMarshaler{io.ErrUnexpectedEOF}, `logger_test.go:\d+: INFO msg p="!PANIC: unexpected EOF"`},
		{panicTextAndJsonMarshaler{"panicking"}, `logger_test.go:\d+: INFO msg p="!PANIC: panicking"`},
		{panicTextAndJsonMarshaler{42}, `logger_test.go:\d+: INFO msg p="!PANIC: 42"`},
	} {
		Info("msg", "p", pt.in)
		checkLogOutput(t, logBuf.String(), pt.out)
		logBuf.Reset()
	}

	SetDefault(New(NewJSONHandler(&logBuf, nil)))
	for _, pt := range []struct {
		in  any
		out string
	}{
		{(*panicTextAndJsonMarshaler)(nil), `{"time":"` + jsonTimeRE + `","level":"INFO","msg":"msg","p":null}`},
		{panicTextAndJsonMarshaler{io.ErrUnexpectedEOF}, `{"time":"` + jsonTimeRE + `","level":"INFO","msg":"msg","p":"!PANIC: unexpected EOF"}`},
		{panicTextAndJsonMarshaler{"panicking"}, `{"time":"` + jsonTimeRE + `","level":"INFO","msg":"msg","p":"!PANIC: panicking"}`},
		{panicTextAndJsonMarshaler{42}, `{"time":"` + jsonTimeRE + `","level":"INFO","msg":"msg","p":"!PANIC: 42"}`},
	} {
		Info("msg", "p", pt.in)
		checkLogOutput(t, logBuf.String(), pt.out)
		logBuf.Reset()
	}
}

"""



```