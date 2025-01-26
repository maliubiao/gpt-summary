Response:
Let's break down the thought process for analyzing the provided Go code snippet from `handler_test.go`.

**1. Initial Scan and Purpose Identification:**

The first thing I do is scan the import statements and function names. Keywords like `Test`, `Handler`, `JSON`, `Text`, `Concurrent`, `ReplaceAttr` immediately suggest this is a testing file for the `slog` package, specifically focused on testing different aspects of how log handlers work. The file name itself, `handler_test.go`, reinforces this.

**2. Deconstructing Test Functions:**

I then look at each `Test...` function individually to understand its specific purpose.

* **`TestDefaultHandle`:** The name suggests testing the *default* handling behavior. The loop iterates through various scenarios (no attributes, with attributes, groups, `WithAttrs`, `WithGroup`). The `want` field in the test cases hints at testing the *formatted output* of the default handler. The `newDefaultHandler` function within the test confirms this.

* **`TestConcurrentWrites`:**  The name is a strong indicator. The test uses `sync.WaitGroup` and `go func()` to perform concurrent logging. The check for the number of occurrences of "hello from sub1/2" in the buffer verifies thread-safety and correct output under concurrency.

* **`TestJSONAndTextHandlers`:** The name explicitly mentions JSON and Text handlers. The presence of `wantText` and `wantJSON` fields in the test cases confirms it's testing the output format of these two handlers. The extensive list of test cases covers various aspects: basic logging, key handling (empty, capitalized, removed), preformatted attributes, groups, escaping, `LogValuer` interface, `WithGroup`, `ReplaceAttr`, `Source` information, and edge cases with empty or partially empty attributes.

* **`TestHandlerEnabled`:** The name and the content of the test clearly show it's testing the `enabled` method of a handler, which determines if a log message with a given level will be processed based on the handler's configured level.

* **`TestSecondWith`:** This test focuses on the behavior of calling `Logger.With` multiple times. It specifically checks that the first `With` call isn't mutated by the subsequent calls.

* **`TestReplaceAttrGroups`:** The name and the logic involving the `ReplaceAttr` function and checking the `got` slice indicate that this test is verifying that the `ReplaceAttr` function receives the correct group path when nested groups are involved.

* **`TestWriteTimeRFC3339`:** The name and the use of `time.Format(rfc3339Millis)` clearly indicate that this test verifies the correct formatting of timestamps according to the RFC3339 standard, specifically including milliseconds.

* **`BenchmarkWriteTime`:** The `Benchmark` prefix indicates a performance test. It measures the time it takes to format a timestamp repeatedly.

* **`TestDiscardHandler`:**  The name suggests testing a handler that discards log output. The test attempts to log various messages and checks that no panics occur, confirming its basic functionality. The temporary disabling of `os.Stdout` and `os.Stderr` is a clever way to ensure that the `DiscardHandler` truly doesn't output anything.

**3. Identifying Core Functionality:**

Based on the tests, I can infer the core functionalities being implemented:

* **Handling Log Records:** The `Handler` interface and its implementations are responsible for receiving and processing `Record` objects.
* **Formatting Output:** The `TextHandler` and `JSONHandler` format log records into text and JSON formats, respectively.
* **Attribute Management:** The `WithAttrs` and `WithGroup` methods allow adding contextual information to log messages.
* **Filtering Log Levels:** The `Leveler` interface and the `enabled` method allow filtering log messages based on their severity.
* **Customizing Output:** The `ReplaceAttr` option provides a mechanism to modify attributes before they are output.
* **Handling Groups:** The code demonstrates the ability to group attributes hierarchically.
* **Concurrency Safety:** The `TestConcurrentWrites` test confirms that the handlers are designed to be thread-safe.

**4. Code Example Construction:**

To illustrate the functionality, I choose examples that demonstrate key aspects:

* **Basic Logging:** Shows the simple usage of a logger with different log levels and attributes.
* **Structured Logging (Groups):** Demonstrates how to use groups to organize related attributes.
* **Customizing Output (ReplaceAttr):** Illustrates how to use `ReplaceAttr` to modify attribute keys.

**5. Identifying Potential Pitfalls:**

I look for common mistakes users might make:

* **Modifying Attributes Directly:** The `Attr` type is a value type. Modifying it after passing it to a logging function will not affect the logged output.
* **Incorrect `ReplaceAttr` Usage:**  Not returning the original `Attr` or a new `Attr` correctly in the `ReplaceAttr` function can lead to unexpected behavior (like attributes being dropped).

**6. Command-Line Arguments:**

Since the code doesn't explicitly show command-line argument processing, I correctly identify that it's not a primary focus of this particular code snippet. It's important to acknowledge what *isn't* present as well as what is.

**7. Language and Structure:**

Finally, I ensure the answer is in Chinese as requested and organize the information logically, starting with a summary of functionality, followed by detailed explanations with code examples, and ending with potential pitfalls. Using clear headings and bullet points helps in readability.
这段代码是 Go 语言标准库 `log/slog` 包中 `handler_test.go` 文件的一部分，它主要用于测试 `slog` 包中不同 `Handler` 的功能，特别是 `TextHandler` 和 `JSONHandler`。

以下是它主要的功能点：

1. **测试默认 Handler 的行为 (`TestDefaultHandle` 函数):**
   - 测试在没有额外配置的情况下，默认 `Handler` 如何处理日志记录（`Record`）。
   - 测试添加不同的属性（`Attr`）和分组（`Group`）后，输出的格式是否符合预期。
   - 测试使用 `WithAttrs` 和 `WithGroup` 方法预先格式化属性对最终输出的影响。

   **Go 代码举例说明:**

   ```go
   package main

   import (
       "context"
       "log/slog"
       "os"
   )

   func main() {
       logger := slog.New(slog.NewTextHandler(os.Stdout, nil)) // 使用默认 TextHandler

       logger.Info("基本消息")
       logger.Info("带属性的消息", slog.Int("用户ID", 123), slog.String("用户名", "Alice"))

       // 使用 WithAttrs 预先添加属性
       withAttrsLogger := logger.With(slog.String("应用", "我的应用"))
       withAttrsLogger.Info("使用 WithAttrs 的消息", slog.Int("请求ID", 456))

       // 使用 WithGroup 添加分组
       withGroupLogger := logger.WithGroup("数据库").With(slog.String("连接状态", "已连接"))
       withGroupLogger.Info("使用 WithGroup 的消息", slog.String("表名", "用户表"))
   }
   ```

   **假设的输出:**

   ```
   time=... level=INFO msg=基本消息
   time=... level=INFO msg=带属性的消息 用户ID=123 用户名=Alice
   time=... level=INFO msg=使用 WithAttrs 的消息 应用=我的应用 请求ID=456
   time=... level=INFO msg=使用 WithGroup 的消息 应用=我的应用 数据库.连接状态=已连接 数据库.表名=用户表
   ```

2. **测试并发写入的安全性 (`TestConcurrentWrites` 函数):**
   - 验证 `TextHandler` 和 `JSONHandler` 在多个 goroutine 同时写入时是否线程安全，不会出现数据竞争或输出错乱。
   - 通过并发写入大量日志，然后检查最终输出中是否包含了所有预期的日志信息。

   **Go 代码举例说明:**

   ```go
   package main

   import (
       "bytes"
       "context"
       "log/slog"
       "sync"
       "testing"
   )

   func TestConcurrentLogging(t *testing.T) {
       var buf bytes.Buffer
       handler := slog.NewTextHandler(&buf, nil)
       logger := slog.New(handler)

       var wg sync.WaitGroup
       numGoroutines := 100

       for i := 0; i < numGoroutines; i++ {
           wg.Add(1)
           go func(id int) {
               defer wg.Done()
               logger.Info("并发消息", slog.Int("goroutine_id", id))
           }(i)
       }
       wg.Wait()

       // 这里可以添加断言，检查 buf 中是否包含了预期的日志条目
       // 例如，检查是否包含了 numGoroutines 条 "并发消息"
       numMessages := 0
       // ... (遍历 buf 的内容进行计数) ...
       // if numMessages != numGoroutines {
       //     t.Errorf("期望 %d 条消息，但得到 %d 条", numGoroutines, numMessages)
       // }
   }
   ```

   **代码推理:**  该测试创建了一个 `TextHandler` 并将其与 `slog.Logger` 关联。然后启动多个 goroutine 并发地写入日志。最终通过检查 `bytes.Buffer` 的内容来验证是否所有日志都被正确写入。假设每个 goroutine 都成功写入了一条 "并发消息"，那么 `buf.String()` 中应该包含 100 条 "并发消息"。

3. **测试 `TextHandler` 和 `JSONHandler` 的通用功能 (`TestJSONAndTextHandlers` 函数):**
   - 测试两种 `Handler` 在处理不同类型的属性（字符串、整数、空值等）时的输出格式。
   - 测试使用 `ReplaceAttr` 选项自定义属性的处理方式，例如修改键名、移除属性等。
   - 测试 `WithGroup` 方法如何影响分组属性的输出格式。
   - 测试 `LogValuer` 接口的使用，允许自定义类型控制其日志输出。
   - 测试 `AddSource` 选项是否正确添加了调用者的源文件和行号信息。

   **Go 代码举例说明 (ReplaceAttr 功能):**

   ```go
   package main

   import (
       "log/slog"
       "os"
       "strings"
   )

   func main() {
       replaceFunc := func(groups []string, a slog.Attr) slog.Attr {
           if a.Key == "敏感信息" {
               return slog.String(a.Key, "***已屏蔽***")
           }
           if a.Key == "用户ID" {
               return slog.Attr{} // 移除该属性
           }
           return a
       }

       opts := &slog.HandlerOptions{ReplaceAttr: replaceFunc}
       handler := slog.NewTextHandler(os.Stdout, opts)
       logger := slog.New(handler)

       logger.Info("用户信息", slog.Int("用户ID", 123), slog.String("用户名", "Alice"), slog.String("敏感信息", "用户的银行卡号"))
   }
   ```

   **假设的输出:**

   ```
   time=... level=INFO msg=用户信息 用户名=Alice 敏感信息=***已屏蔽***
   ```

   **代码推理:**  `replaceFunc` 接收属性的键值对，并根据键名修改或移除属性。在这个例子中，"敏感信息" 的值被替换为 "***已屏蔽***"，而 "用户ID" 属性被完全移除。

4. **测试 `Handler` 的 `Enabled` 方法 (`TestHandlerEnabled` 函数):**
   - 验证 `Handler` 是否根据配置的日志级别正确判断是否应该处理某个级别的日志消息。

   **Go 代码举例说明:**

   ```go
   package main

   import (
       "context"
       "log/slog"
       "os"
   )

   func main() {
       opts := &slog.HandlerOptions{Level: slog.LevelWarn} // 设置 Handler 只处理 Warn 及以上级别的日志
       handler := slog.NewTextHandler(os.Stdout, opts)
       logger := slog.New(handler)

       logger.Debug("这是一条调试信息") // 不会被输出
       logger.Info("这是一条普通信息")  // 不会被输出
       logger.Warn("这是一条警告信息")  // 会被输出
       logger.Error("这是一条错误信息") // 会被输出
   }
   ```

   **假设的输出:**

   ```
   time=... level=WARN msg=这是一条警告信息
   time=... level=ERROR msg=这是一条错误信息
   ```

5. **测试多次调用 `With` 方法的行为 (`TestSecondWith` 函数):**
   - 确保多次调用 `Logger.With` 不会相互影响，每次调用都会创建一个新的派生 Logger，而不会修改原始 Logger 的属性。

   **Go 代码举例说明:**

   ```go
   package main

   import (
       "log/slog"
       "os"
   )

   func main() {
       logger := slog.New(slog.NewTextHandler(os.Stdout, nil)).With(slog.String("component", "main"))
       logger1 := logger.With(slog.Int("request_id", 1))
       logger2 := logger.With(slog.String("user", "Bob"))

       logger1.Info("处理请求") // 输出会包含 component 和 request_id
       logger2.Info("用户信息") // 输出会包含 component 和 user

       // 原始的 logger 仍然只有 component 属性
       logger.Info("基本信息") // 输出只会包含 component
   }
   ```

   **假设的输出 (部分):**

   ```
   time=... level=INFO msg=处理请求 component=main request_id=1
   time=... level=INFO msg=用户信息 component=main user=Bob
   time=... level=INFO msg=基本信息 component=main
   ```

6. **测试 `ReplaceAttr` 在处理分组属性时的行为 (`TestReplaceAttrGroups` 函数):**
   - 验证 `ReplaceAttr` 函数的第一个参数 `groups` 是否正确反映了当前处理的属性所属的分组路径。

7. **测试时间戳的 RFC3339 格式化 (`TestWriteTimeRFC3339` 函数):**
   - 确保时间戳按照 RFC3339 格式（包括毫秒）正确输出。

8. **基准测试时间戳写入性能 (`BenchmarkWriteTime` 函数):**
   - 衡量时间戳格式化操作的性能。

9. **测试 `DiscardHandler` (`TestDiscardHandler` 函数):**
    - 验证 `DiscardHandler` 会丢弃所有日志，不会有任何输出，并且在尝试写入时不会引发 panic。

**关于命令行参数的具体处理:**

这段代码本身并没有直接涉及命令行参数的处理。`slog` 包的 `Handler` 主要负责格式化和输出日志，而命令行参数的处理通常发生在应用程序的入口点，用于配置日志级别、输出目标等。应用程序可以使用标准库的 `flag` 包或者第三方库来解析命令行参数，然后根据参数配置 `slog.HandlerOptions`。

**使用者易犯错的点 (基于代码推理):**

1. **在 `ReplaceAttr` 函数中不返回 `Attr`:** 如果在 `ReplaceAttr` 函数中，对于某些情况没有返回有效的 `slog.Attr`，可能会导致该属性丢失。例如，错误地返回 `nil` 或者不返回任何值。

   ```go
   // 错误示例
   replaceFunc := func(groups []string, a slog.Attr) slog.Attr {
       if a.Key == "不要记录的属性" {
           return slog.Attr{} // 正确的做法是返回一个空的 Attr
           // return nil // 错误的做法，会导致 panic 或其他不可预测的行为
       }
       return a
   }
   ```

2. **在并发场景下直接操作共享的 `HandlerOptions`:**  `HandlerOptions` 中的某些字段（例如 `ReplaceAttr`）是函数类型。如果在多个 goroutine 中同时修改这些选项，可能会导致数据竞争。应该在创建 `Handler` 时就确定其配置，或者使用线程安全的方式进行修改（虽然 `slog` 包本身没有提供直接的方法来安全地修改已创建的 `Handler` 的选项）。

总而言之，这段测试代码覆盖了 `slog` 包中 `Handler` 的核心功能，特别是针对 `TextHandler` 和 `JSONHandler` 的输出格式、并发安全性和可配置性进行了全面的测试。它为理解 `slog` 包的 `Handler` 的工作原理提供了很好的参考。

Prompt: 
```
这是路径为go/src/log/slog/handler_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// TODO: verify that the output of Marshal{Text,JSON} is suitably escaped.

package slog

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDefaultHandle(t *testing.T) {
	ctx := context.Background()
	preAttrs := []Attr{Int("pre", 0)}
	attrs := []Attr{Int("a", 1), String("b", "two")}
	for _, test := range []struct {
		name  string
		with  func(Handler) Handler
		attrs []Attr
		want  string
	}{
		{
			name: "no attrs",
			want: "INFO message",
		},
		{
			name:  "attrs",
			attrs: attrs,
			want:  "INFO message a=1 b=two",
		},
		{
			name:  "preformatted",
			with:  func(h Handler) Handler { return h.WithAttrs(preAttrs) },
			attrs: attrs,
			want:  "INFO message pre=0 a=1 b=two",
		},
		{
			name: "groups",
			attrs: []Attr{
				Int("a", 1),
				Group("g",
					Int("b", 2),
					Group("h", Int("c", 3)),
					Int("d", 4)),
				Int("e", 5),
			},
			want: "INFO message a=1 g.b=2 g.h.c=3 g.d=4 e=5",
		},
		{
			name:  "group",
			with:  func(h Handler) Handler { return h.WithAttrs(preAttrs).WithGroup("s") },
			attrs: attrs,
			want:  "INFO message pre=0 s.a=1 s.b=two",
		},
		{
			name: "preformatted groups",
			with: func(h Handler) Handler {
				return h.WithAttrs([]Attr{Int("p1", 1)}).
					WithGroup("s1").
					WithAttrs([]Attr{Int("p2", 2)}).
					WithGroup("s2")
			},
			attrs: attrs,
			want:  "INFO message p1=1 s1.p2=2 s1.s2.a=1 s1.s2.b=two",
		},
		{
			name: "two with-groups",
			with: func(h Handler) Handler {
				return h.WithAttrs([]Attr{Int("p1", 1)}).
					WithGroup("s1").
					WithGroup("s2")
			},
			attrs: attrs,
			want:  "INFO message p1=1 s1.s2.a=1 s1.s2.b=two",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var got string
			var h Handler = newDefaultHandler(func(_ uintptr, b []byte) error {
				got = string(b)
				return nil
			})
			if test.with != nil {
				h = test.with(h)
			}
			r := NewRecord(time.Time{}, LevelInfo, "message", 0)
			r.AddAttrs(test.attrs...)
			if err := h.Handle(ctx, r); err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Errorf("\ngot  %s\nwant %s", got, test.want)
			}
		})
	}
}

func TestConcurrentWrites(t *testing.T) {
	ctx := context.Background()
	count := 1000
	for _, handlerType := range []string{"text", "json"} {
		t.Run(handlerType, func(t *testing.T) {
			var buf bytes.Buffer
			var h Handler
			switch handlerType {
			case "text":
				h = NewTextHandler(&buf, nil)
			case "json":
				h = NewJSONHandler(&buf, nil)
			default:
				t.Fatalf("unexpected handlerType %q", handlerType)
			}
			sub1 := h.WithAttrs([]Attr{Bool("sub1", true)})
			sub2 := h.WithAttrs([]Attr{Bool("sub2", true)})
			var wg sync.WaitGroup
			for i := 0; i < count; i++ {
				sub1Record := NewRecord(time.Time{}, LevelInfo, "hello from sub1", 0)
				sub1Record.AddAttrs(Int("i", i))
				sub2Record := NewRecord(time.Time{}, LevelInfo, "hello from sub2", 0)
				sub2Record.AddAttrs(Int("i", i))
				wg.Add(1)
				go func() {
					defer wg.Done()
					if err := sub1.Handle(ctx, sub1Record); err != nil {
						t.Error(err)
					}
					if err := sub2.Handle(ctx, sub2Record); err != nil {
						t.Error(err)
					}
				}()
			}
			wg.Wait()
			for i := 1; i <= 2; i++ {
				want := "hello from sub" + strconv.Itoa(i)
				n := strings.Count(buf.String(), want)
				if n != count {
					t.Fatalf("want %d occurrences of %q, got %d", count, want, n)
				}
			}
		})
	}
}

// Verify the common parts of TextHandler and JSONHandler.
func TestJSONAndTextHandlers(t *testing.T) {
	// remove all Attrs
	removeAll := func(_ []string, a Attr) Attr { return Attr{} }

	attrs := []Attr{String("a", "one"), Int("b", 2), Any("", nil)}
	preAttrs := []Attr{Int("pre", 3), String("x", "y")}

	for _, test := range []struct {
		name      string
		replace   func([]string, Attr) Attr
		addSource bool
		with      func(Handler) Handler
		preAttrs  []Attr
		attrs     []Attr
		wantText  string
		wantJSON  string
	}{
		{
			name:     "basic",
			attrs:    attrs,
			wantText: "time=2000-01-02T03:04:05.000Z level=INFO msg=message a=one b=2",
			wantJSON: `{"time":"2000-01-02T03:04:05Z","level":"INFO","msg":"message","a":"one","b":2}`,
		},
		{
			name:     "empty key",
			attrs:    append(slices.Clip(attrs), Any("", "v")),
			wantText: `time=2000-01-02T03:04:05.000Z level=INFO msg=message a=one b=2 ""=v`,
			wantJSON: `{"time":"2000-01-02T03:04:05Z","level":"INFO","msg":"message","a":"one","b":2,"":"v"}`,
		},
		{
			name:     "cap keys",
			replace:  upperCaseKey,
			attrs:    attrs,
			wantText: "TIME=2000-01-02T03:04:05.000Z LEVEL=INFO MSG=message A=one B=2",
			wantJSON: `{"TIME":"2000-01-02T03:04:05Z","LEVEL":"INFO","MSG":"message","A":"one","B":2}`,
		},
		{
			name:     "remove all",
			replace:  removeAll,
			attrs:    attrs,
			wantText: "",
			wantJSON: `{}`,
		},
		{
			name:     "preformatted",
			with:     func(h Handler) Handler { return h.WithAttrs(preAttrs) },
			preAttrs: preAttrs,
			attrs:    attrs,
			wantText: "time=2000-01-02T03:04:05.000Z level=INFO msg=message pre=3 x=y a=one b=2",
			wantJSON: `{"time":"2000-01-02T03:04:05Z","level":"INFO","msg":"message","pre":3,"x":"y","a":"one","b":2}`,
		},
		{
			name:     "preformatted cap keys",
			replace:  upperCaseKey,
			with:     func(h Handler) Handler { return h.WithAttrs(preAttrs) },
			preAttrs: preAttrs,
			attrs:    attrs,
			wantText: "TIME=2000-01-02T03:04:05.000Z LEVEL=INFO MSG=message PRE=3 X=y A=one B=2",
			wantJSON: `{"TIME":"2000-01-02T03:04:05Z","LEVEL":"INFO","MSG":"message","PRE":3,"X":"y","A":"one","B":2}`,
		},
		{
			name:     "preformatted remove all",
			replace:  removeAll,
			with:     func(h Handler) Handler { return h.WithAttrs(preAttrs) },
			preAttrs: preAttrs,
			attrs:    attrs,
			wantText: "",
			wantJSON: "{}",
		},
		{
			name:     "remove built-in",
			replace:  removeKeys(TimeKey, LevelKey, MessageKey),
			attrs:    attrs,
			wantText: "a=one b=2",
			wantJSON: `{"a":"one","b":2}`,
		},
		{
			name:     "preformatted remove built-in",
			replace:  removeKeys(TimeKey, LevelKey, MessageKey),
			with:     func(h Handler) Handler { return h.WithAttrs(preAttrs) },
			attrs:    attrs,
			wantText: "pre=3 x=y a=one b=2",
			wantJSON: `{"pre":3,"x":"y","a":"one","b":2}`,
		},
		{
			name:    "groups",
			replace: removeKeys(TimeKey, LevelKey), // to simplify the result
			attrs: []Attr{
				Int("a", 1),
				Group("g",
					Int("b", 2),
					Group("h", Int("c", 3)),
					Int("d", 4)),
				Int("e", 5),
			},
			wantText: "msg=message a=1 g.b=2 g.h.c=3 g.d=4 e=5",
			wantJSON: `{"msg":"message","a":1,"g":{"b":2,"h":{"c":3},"d":4},"e":5}`,
		},
		{
			name:     "empty group",
			replace:  removeKeys(TimeKey, LevelKey),
			attrs:    []Attr{Group("g"), Group("h", Int("a", 1))},
			wantText: "msg=message h.a=1",
			wantJSON: `{"msg":"message","h":{"a":1}}`,
		},
		{
			name:    "nested empty group",
			replace: removeKeys(TimeKey, LevelKey),
			attrs: []Attr{
				Group("g",
					Group("h",
						Group("i"), Group("j"))),
			},
			wantText: `msg=message`,
			wantJSON: `{"msg":"message"}`,
		},
		{
			name:    "nested non-empty group",
			replace: removeKeys(TimeKey, LevelKey),
			attrs: []Attr{
				Group("g",
					Group("h",
						Group("i"), Group("j", Int("a", 1)))),
			},
			wantText: `msg=message g.h.j.a=1`,
			wantJSON: `{"msg":"message","g":{"h":{"j":{"a":1}}}}`,
		},
		{
			name:    "escapes",
			replace: removeKeys(TimeKey, LevelKey),
			attrs: []Attr{
				String("a b", "x\t\n\000y"),
				Group(" b.c=\"\\x2E\t",
					String("d=e", "f.g\""),
					Int("m.d", 1)), // dot is not escaped
			},
			wantText: `msg=message "a b"="x\t\n\x00y" " b.c=\"\\x2E\t.d=e"="f.g\"" " b.c=\"\\x2E\t.m.d"=1`,
			wantJSON: `{"msg":"message","a b":"x\t\n\u0000y"," b.c=\"\\x2E\t":{"d=e":"f.g\"","m.d":1}}`,
		},
		{
			name:    "LogValuer",
			replace: removeKeys(TimeKey, LevelKey),
			attrs: []Attr{
				Int("a", 1),
				Any("name", logValueName{"Ren", "Hoek"}),
				Int("b", 2),
			},
			wantText: "msg=message a=1 name.first=Ren name.last=Hoek b=2",
			wantJSON: `{"msg":"message","a":1,"name":{"first":"Ren","last":"Hoek"},"b":2}`,
		},
		{
			// Test resolution when there is no ReplaceAttr function.
			name: "resolve",
			attrs: []Attr{
				Any("", &replace{Value{}}), // should be elided
				Any("name", logValueName{"Ren", "Hoek"}),
			},
			wantText: "time=2000-01-02T03:04:05.000Z level=INFO msg=message name.first=Ren name.last=Hoek",
			wantJSON: `{"time":"2000-01-02T03:04:05Z","level":"INFO","msg":"message","name":{"first":"Ren","last":"Hoek"}}`,
		},
		{
			name:     "with-group",
			replace:  removeKeys(TimeKey, LevelKey),
			with:     func(h Handler) Handler { return h.WithAttrs(preAttrs).WithGroup("s") },
			attrs:    attrs,
			wantText: "msg=message pre=3 x=y s.a=one s.b=2",
			wantJSON: `{"msg":"message","pre":3,"x":"y","s":{"a":"one","b":2}}`,
		},
		{
			name:    "preformatted with-groups",
			replace: removeKeys(TimeKey, LevelKey),
			with: func(h Handler) Handler {
				return h.WithAttrs([]Attr{Int("p1", 1)}).
					WithGroup("s1").
					WithAttrs([]Attr{Int("p2", 2)}).
					WithGroup("s2").
					WithAttrs([]Attr{Int("p3", 3)})
			},
			attrs:    attrs,
			wantText: "msg=message p1=1 s1.p2=2 s1.s2.p3=3 s1.s2.a=one s1.s2.b=2",
			wantJSON: `{"msg":"message","p1":1,"s1":{"p2":2,"s2":{"p3":3,"a":"one","b":2}}}`,
		},
		{
			name:    "two with-groups",
			replace: removeKeys(TimeKey, LevelKey),
			with: func(h Handler) Handler {
				return h.WithAttrs([]Attr{Int("p1", 1)}).
					WithGroup("s1").
					WithGroup("s2")
			},
			attrs:    attrs,
			wantText: "msg=message p1=1 s1.s2.a=one s1.s2.b=2",
			wantJSON: `{"msg":"message","p1":1,"s1":{"s2":{"a":"one","b":2}}}`,
		},
		{
			name:    "empty with-groups",
			replace: removeKeys(TimeKey, LevelKey),
			with: func(h Handler) Handler {
				return h.WithGroup("x").WithGroup("y")
			},
			wantText: "msg=message",
			wantJSON: `{"msg":"message"}`,
		},
		{
			name:    "empty with-groups, no non-empty attrs",
			replace: removeKeys(TimeKey, LevelKey),
			with: func(h Handler) Handler {
				return h.WithGroup("x").WithAttrs([]Attr{Group("g")}).WithGroup("y")
			},
			wantText: "msg=message",
			wantJSON: `{"msg":"message"}`,
		},
		{
			name:    "one empty with-group",
			replace: removeKeys(TimeKey, LevelKey),
			with: func(h Handler) Handler {
				return h.WithGroup("x").WithAttrs([]Attr{Int("a", 1)}).WithGroup("y")
			},
			attrs:    []Attr{Group("g", Group("h"))},
			wantText: "msg=message x.a=1",
			wantJSON: `{"msg":"message","x":{"a":1}}`,
		},
		{
			name:     "GroupValue as Attr value",
			replace:  removeKeys(TimeKey, LevelKey),
			attrs:    []Attr{{"v", AnyValue(IntValue(3))}},
			wantText: "msg=message v=3",
			wantJSON: `{"msg":"message","v":3}`,
		},
		{
			name:     "byte slice",
			replace:  removeKeys(TimeKey, LevelKey),
			attrs:    []Attr{Any("bs", []byte{1, 2, 3, 4})},
			wantText: `msg=message bs="\x01\x02\x03\x04"`,
			wantJSON: `{"msg":"message","bs":"AQIDBA=="}`,
		},
		{
			name:     "json.RawMessage",
			replace:  removeKeys(TimeKey, LevelKey),
			attrs:    []Attr{Any("bs", json.RawMessage([]byte("1234")))},
			wantText: `msg=message bs="1234"`,
			wantJSON: `{"msg":"message","bs":1234}`,
		},
		{
			name:    "inline group",
			replace: removeKeys(TimeKey, LevelKey),
			attrs: []Attr{
				Int("a", 1),
				Group("", Int("b", 2), Int("c", 3)),
				Int("d", 4),
			},
			wantText: `msg=message a=1 b=2 c=3 d=4`,
			wantJSON: `{"msg":"message","a":1,"b":2,"c":3,"d":4}`,
		},
		{
			name: "Source",
			replace: func(gs []string, a Attr) Attr {
				if a.Key == SourceKey {
					s := a.Value.Any().(*Source)
					s.File = filepath.Base(s.File)
					return Any(a.Key, s)
				}
				return removeKeys(TimeKey, LevelKey)(gs, a)
			},
			addSource: true,
			wantText:  `source=handler_test.go:$LINE msg=message`,
			wantJSON:  `{"source":{"function":"log/slog.TestJSONAndTextHandlers","file":"handler_test.go","line":$LINE},"msg":"message"}`,
		},
		{
			name: "replace built-in with group",
			replace: func(_ []string, a Attr) Attr {
				if a.Key == TimeKey {
					return Group(TimeKey, "mins", 3, "secs", 2)
				}
				if a.Key == LevelKey {
					return Attr{}
				}
				return a
			},
			wantText: `time.mins=3 time.secs=2 msg=message`,
			wantJSON: `{"time":{"mins":3,"secs":2},"msg":"message"}`,
		},
		{
			name:     "replace empty",
			replace:  func([]string, Attr) Attr { return Attr{} },
			attrs:    []Attr{Group("g", Int("a", 1))},
			wantText: "",
			wantJSON: `{}`,
		},
		{
			name: "replace empty 1",
			with: func(h Handler) Handler {
				return h.WithGroup("g").WithAttrs([]Attr{Int("a", 1)})
			},
			replace:  func([]string, Attr) Attr { return Attr{} },
			attrs:    []Attr{Group("h", Int("b", 2))},
			wantText: "",
			wantJSON: `{}`,
		},
		{
			name: "replace empty 2",
			with: func(h Handler) Handler {
				return h.WithGroup("g").WithAttrs([]Attr{Int("a", 1)}).WithGroup("h").WithAttrs([]Attr{Int("b", 2)})
			},
			replace:  func([]string, Attr) Attr { return Attr{} },
			attrs:    []Attr{Group("i", Int("c", 3))},
			wantText: "",
			wantJSON: `{}`,
		},
		{
			name:     "replace empty 3",
			with:     func(h Handler) Handler { return h.WithGroup("g") },
			replace:  func([]string, Attr) Attr { return Attr{} },
			attrs:    []Attr{Int("a", 1)},
			wantText: "",
			wantJSON: `{}`,
		},
		{
			name: "replace empty inline",
			with: func(h Handler) Handler {
				return h.WithGroup("g").WithAttrs([]Attr{Int("a", 1)}).WithGroup("h").WithAttrs([]Attr{Int("b", 2)})
			},
			replace:  func([]string, Attr) Attr { return Attr{} },
			attrs:    []Attr{Group("", Int("c", 3))},
			wantText: "",
			wantJSON: `{}`,
		},
		{
			name: "replace partial empty attrs 1",
			with: func(h Handler) Handler {
				return h.WithGroup("g").WithAttrs([]Attr{Int("a", 1)}).WithGroup("h").WithAttrs([]Attr{Int("b", 2)})
			},
			replace: func(groups []string, attr Attr) Attr {
				return removeKeys(TimeKey, LevelKey, MessageKey, "a")(groups, attr)
			},
			attrs:    []Attr{Group("i", Int("c", 3))},
			wantText: "g.h.b=2 g.h.i.c=3",
			wantJSON: `{"g":{"h":{"b":2,"i":{"c":3}}}}`,
		},
		{
			name: "replace partial empty attrs 2",
			with: func(h Handler) Handler {
				return h.WithGroup("g").WithAttrs([]Attr{Int("a", 1)}).WithAttrs([]Attr{Int("n", 4)}).WithGroup("h").WithAttrs([]Attr{Int("b", 2)})
			},
			replace: func(groups []string, attr Attr) Attr {
				return removeKeys(TimeKey, LevelKey, MessageKey, "a", "b")(groups, attr)
			},
			attrs:    []Attr{Group("i", Int("c", 3))},
			wantText: "g.n=4 g.h.i.c=3",
			wantJSON: `{"g":{"n":4,"h":{"i":{"c":3}}}}`,
		},
		{
			name: "replace partial empty attrs 3",
			with: func(h Handler) Handler {
				return h.WithGroup("g").WithAttrs([]Attr{Int("x", 0)}).WithAttrs([]Attr{Int("a", 1)}).WithAttrs([]Attr{Int("n", 4)}).WithGroup("h").WithAttrs([]Attr{Int("b", 2)})
			},
			replace: func(groups []string, attr Attr) Attr {
				return removeKeys(TimeKey, LevelKey, MessageKey, "a", "c")(groups, attr)
			},
			attrs:    []Attr{Group("i", Int("c", 3))},
			wantText: "g.x=0 g.n=4 g.h.b=2",
			wantJSON: `{"g":{"x":0,"n":4,"h":{"b":2}}}`,
		},
		{
			name: "replace resolved group",
			replace: func(groups []string, a Attr) Attr {
				if a.Value.Kind() == KindGroup {
					return Attr{"bad", IntValue(1)}
				}
				return removeKeys(TimeKey, LevelKey, MessageKey)(groups, a)
			},
			attrs:    []Attr{Any("name", logValueName{"Perry", "Platypus"})},
			wantText: "name.first=Perry name.last=Platypus",
			wantJSON: `{"name":{"first":"Perry","last":"Platypus"}}`,
		},
	} {
		r := NewRecord(testTime, LevelInfo, "message", callerPC(2))
		line := strconv.Itoa(r.source().Line)
		r.AddAttrs(test.attrs...)
		var buf bytes.Buffer
		opts := HandlerOptions{ReplaceAttr: test.replace, AddSource: test.addSource}
		t.Run(test.name, func(t *testing.T) {
			for _, handler := range []struct {
				name string
				h    Handler
				want string
			}{
				{"text", NewTextHandler(&buf, &opts), test.wantText},
				{"json", NewJSONHandler(&buf, &opts), test.wantJSON},
			} {
				t.Run(handler.name, func(t *testing.T) {
					h := handler.h
					if test.with != nil {
						h = test.with(h)
					}
					buf.Reset()
					if err := h.Handle(nil, r); err != nil {
						t.Fatal(err)
					}
					want := strings.ReplaceAll(handler.want, "$LINE", line)
					got := strings.TrimSuffix(buf.String(), "\n")
					if got != want {
						t.Errorf("\ngot  %s\nwant %s\n", got, want)
					}
				})
			}
		})
	}
}

// removeKeys returns a function suitable for HandlerOptions.ReplaceAttr
// that removes all Attrs with the given keys.
func removeKeys(keys ...string) func([]string, Attr) Attr {
	return func(_ []string, a Attr) Attr {
		for _, k := range keys {
			if a.Key == k {
				return Attr{}
			}
		}
		return a
	}
}

func upperCaseKey(_ []string, a Attr) Attr {
	a.Key = strings.ToUpper(a.Key)
	return a
}

type logValueName struct {
	first, last string
}

func (n logValueName) LogValue() Value {
	return GroupValue(
		String("first", n.first),
		String("last", n.last))
}

func TestHandlerEnabled(t *testing.T) {
	levelVar := func(l Level) *LevelVar {
		var al LevelVar
		al.Set(l)
		return &al
	}

	for _, test := range []struct {
		leveler Leveler
		want    bool
	}{
		{nil, true},
		{LevelWarn, false},
		{&LevelVar{}, true}, // defaults to Info
		{levelVar(LevelWarn), false},
		{LevelDebug, true},
		{levelVar(LevelDebug), true},
	} {
		h := &commonHandler{opts: HandlerOptions{Level: test.leveler}}
		got := h.enabled(LevelInfo)
		if got != test.want {
			t.Errorf("%v: got %t, want %t", test.leveler, got, test.want)
		}
	}
}

func TestSecondWith(t *testing.T) {
	// Verify that a second call to Logger.With does not corrupt
	// the original.
	var buf bytes.Buffer
	h := NewTextHandler(&buf, &HandlerOptions{ReplaceAttr: removeKeys(TimeKey)})
	logger := New(h).With(
		String("app", "playground"),
		String("role", "tester"),
		Int("data_version", 2),
	)
	appLogger := logger.With("type", "log") // this becomes type=met
	_ = logger.With("type", "metric")
	appLogger.Info("foo")
	got := strings.TrimSpace(buf.String())
	want := `level=INFO msg=foo app=playground role=tester data_version=2 type=log`
	if got != want {
		t.Errorf("\ngot  %s\nwant %s", got, want)
	}
}

func TestReplaceAttrGroups(t *testing.T) {
	// Verify that ReplaceAttr is called with the correct groups.
	type ga struct {
		groups string
		key    string
		val    string
	}

	var got []ga

	h := NewTextHandler(io.Discard, &HandlerOptions{ReplaceAttr: func(gs []string, a Attr) Attr {
		v := a.Value.String()
		if a.Key == TimeKey {
			v = "<now>"
		}
		got = append(got, ga{strings.Join(gs, ","), a.Key, v})
		return a
	}})
	New(h).
		With(Int("a", 1)).
		WithGroup("g1").
		With(Int("b", 2)).
		WithGroup("g2").
		With(
			Int("c", 3),
			Group("g3", Int("d", 4)),
			Int("e", 5)).
		Info("m",
			Int("f", 6),
			Group("g4", Int("h", 7)),
			Int("i", 8))

	want := []ga{
		{"", "a", "1"},
		{"g1", "b", "2"},
		{"g1,g2", "c", "3"},
		{"g1,g2,g3", "d", "4"},
		{"g1,g2", "e", "5"},
		{"", "time", "<now>"},
		{"", "level", "INFO"},
		{"", "msg", "m"},
		{"g1,g2", "f", "6"},
		{"g1,g2,g4", "h", "7"},
		{"g1,g2", "i", "8"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("\ngot  %v\nwant %v", got, want)
	}
}

const rfc3339Millis = "2006-01-02T15:04:05.000Z07:00"

func TestWriteTimeRFC3339(t *testing.T) {
	for _, tm := range []time.Time{
		time.Date(2000, 1, 2, 3, 4, 5, 0, time.UTC),
		time.Date(2000, 1, 2, 3, 4, 5, 400, time.Local),
		time.Date(2000, 11, 12, 3, 4, 500, 5e7, time.UTC),
	} {
		got := string(appendRFC3339Millis(nil, tm))
		want := tm.Format(rfc3339Millis)
		if got != want {
			t.Errorf("got %s, want %s", got, want)
		}
	}
}

func BenchmarkWriteTime(b *testing.B) {
	tm := time.Date(2022, 3, 4, 5, 6, 7, 823456789, time.Local)
	b.ResetTimer()
	var buf []byte
	for i := 0; i < b.N; i++ {
		buf = appendRFC3339Millis(buf[:0], tm)
	}
}

func TestDiscardHandler(t *testing.T) {
	ctx := context.Background()
	stdout, stderr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = nil, nil // panic on write
	t.Cleanup(func() {
		os.Stdout, os.Stderr = stdout, stderr
	})

	// Just ensure nothing panics during normal usage
	l := New(DiscardHandler)
	l.Info("msg", "a", 1, "b", 2)
	l.Debug("bg", Int("a", 1), "b", 2)
	l.Warn("w", Duration("dur", 3*time.Second))
	l.Error("bad", "a", 1)
	l.Log(ctx, LevelWarn+1, "w", Int("a", 1), String("b", "two"))
	l.LogAttrs(ctx, LevelInfo+1, "a b c", Int("a", 1), String("b", "two"))
	l.Info("info", "a", []Attr{Int("i", 1)})
	l.Info("info", "a", GroupValue(Int("i", 1)))
}

"""



```