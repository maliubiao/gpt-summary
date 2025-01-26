Response:
Let's break down the thought process for analyzing the provided Go code snippet and generating the response.

1. **Understanding the Goal:** The primary goal is to analyze the provided Go code, which is a part of the `slog` package's `logger.go` file. The request asks for the functionality of this code, potential underlying Go features, code examples, handling of command-line arguments (though this file doesn't directly interact with them), and common mistakes users might make. The response should be in Chinese.

2. **Initial Code Scan and Keyword Spotting:**  The first step is to quickly read through the code, looking for key keywords and structures. This helps to get a high-level understanding of the code's purpose. Keywords like `package slog`, `import`, `func`, `struct`, `var`, `atomic.Pointer`, `Level`, `Handler`, `Logger`, `Default`, `SetDefault`, `With`, `Log`, `Debug`, `Info`, `Warn`, `Error`, `NewLogLogger`, and the comments themselves are important.

3. **Identifying Core Components:** Based on the keywords and structure, I can identify the main components:
    * **`Logger`:**  The central structure responsible for logging. It has a `Handler`.
    * **`Handler`:** An interface (implied, though not fully shown in this snippet) responsible for actually processing and outputting the log records.
    * **`Level`:**  Represents the severity of a log message.
    * **Default Logger:** A globally accessible logger.
    * **Bridging to `log` package:** Functionality to integrate with the standard `log` package.

4. **Function-by-Function Analysis:**  Next, I go through each function and method, trying to understand its specific role:
    * **`SetLogLoggerLevel`:**  Controls the logging level for the bridge between `slog` and the standard `log` package. It handles scenarios *before* and *after* `SetDefault` is called.
    * **`init`:** Initializes the default logger with a default handler.
    * **`Default`:** Returns the current default logger.
    * **`SetDefault`:**  Sets the global default logger and configures the `log` package to use the `slog` handler. The special handling for `defaultHandler` is crucial.
    * **`handlerWriter`:** An adapter to make a `slog.Handler` work as an `io.Writer` for the `log` package. It captures the calling information (PC).
    * **`Logger` struct and its methods (`clone`, `Handler`, `With`, `WithGroup`):**  These methods manipulate the `Logger` instance, adding attributes or groups.
    * **`New`:** Creates a new `Logger` with a given `Handler`.
    * **`With` (top-level):**  A convenience function to call `With` on the default logger.
    * **`Enabled`:** Checks if a given log level is enabled for the logger's handler.
    * **`NewLogLogger`:** Creates a standard `log.Logger` that forwards log messages to a `slog.Handler`. This is the reverse bridge.
    * **`Log`, `LogAttrs`:** The core logging methods. `Log` takes key-value pairs as arguments, while `LogAttrs` takes `Attr` slices.
    * **`Debug`, `Info`, `Warn`, `Error` (and their `Context` variants):** Convenience methods for logging at specific levels. They call the lower-level `log` and `logAttrs` methods.
    * **`log`, `logAttrs` (private):** The underlying implementation of the logging methods. They handle level checking, capturing the program counter (PC), creating a `Record`, and passing it to the `Handler`.
    * **Top-level `Debug`, `Info`, `Warn`, `Error`, `Log`, `LogAttrs` functions:** Convenience functions that operate on the default logger.

5. **Identifying Go Language Features:**  As I analyze each function, I consider the Go language features being used:
    * **Packages and Imports:** Obvious.
    * **Structs:** `Logger`, `handlerWriter`.
    * **Interfaces:** `Handler` and `Leveler` (implied).
    * **Functions and Methods:**  The core building blocks.
    * **Variadic Functions (`...any`, `...Attr`):** Used for flexible argument passing.
    * **Atomic Operations (`atomic.Pointer`):**  For thread-safe access to the default logger.
    * **Context:** For passing request-scoped information.
    * **`time.Time`:**  For timestamps in log records.
    * **`runtime.Callers`:** For obtaining the caller's information.
    * **`bytes.TrimSuffix`:** For removing trailing newlines.
    * **Closures (implicitly in `SetDefault` with `handlerWriter`):** Creating a function that uses variables from its surrounding scope.
    * **Type Assertions (`l.Handler().(*defaultHandler)`):** Checking the underlying type of an interface.

6. **Code Example Generation:**  Based on the identified functionalities, I devise relevant code examples:
    * **Basic Logging:**  Demonstrating `Info`, `Debug`, etc.
    * **Setting the Default Logger:** Showing how to use `SetDefault`.
    * **Adding Attributes:**  Illustrating `With`.
    * **Using Groups:**  Showing `WithGroup`.
    * **Bridging from `log`:** Demonstrating `SetDefault` and how `log.Print` is routed.
    * **Bridging to `log`:**  Showing `NewLogLogger`.
    * **Log Levels:**  Illustrating how levels filter log messages.

7. **Command-Line Arguments:** I recognize that this specific code snippet doesn't directly handle command-line arguments. However, I acknowledge that log levels are *often* configured via command-line flags or environment variables in real-world applications.

8. **Common Mistakes:**  I think about potential pitfalls:
    * **Forgetting to Set a Handler:**  Although the default logger has a handler, users might create custom loggers without a handler.
    * **Incorrectly Using `With`:**  Not understanding that `With` returns a *new* logger.
    * **Mixing `log` and `slog` without Understanding the Bridge:**  Being confused about how `SetLogLoggerLevel` affects both packages.
    * **Assuming `WithGroup` works like nested objects:** Clarifying how group names are handled by the handler.
    * **Passing an Odd Number of Arguments to `Log`:**  Highlighting the behavior of how arguments are converted to attributes.

9. **Structuring the Response in Chinese:**  Finally, I organize the information clearly, using appropriate headings and bullet points. I ensure the language is natural and accurate in Chinese. This involves translating technical terms correctly (e.g., 属性 for attribute, 处理器 for handler).

**Self-Correction/Refinement during the process:**

* **Initial thought:**  "Is there any interaction with external files or network?"  A quick scan reveals no direct interaction, so I focus on the core logging logic.
* **Considering edge cases:** "What happens if `SetDefault` is called multiple times?" The code handles this by updating the global variable. "What if `New` is called with a `nil` handler?"  The code explicitly panics, which is important to note.
* **Clarity of examples:** I try to make the examples as simple and illustrative as possible, focusing on one concept at a time.
* **Accuracy of terminology:** I double-check the Chinese translations of key terms to ensure they are standard and understandable.

By following these steps, the comprehensive and accurate Chinese response can be generated.
这段代码是 Go 语言标准库 `log/slog` 包中 `logger.go` 文件的一部分，它定义了结构化日志记录的核心功能。以下是它的主要功能：

**1. 定义了 `Logger` 类型:**

* `Logger` 结构体是结构化日志记录的核心载体。它包含一个 `Handler` 接口的实例。
* `Handler` 负责实际处理和输出日志记录（Record）。

**2. 提供了创建 `Logger` 的方法:**

* **`New(h Handler)`:** 创建一个新的 `Logger` 实例，需要传入一个非空的 `Handler`。
* **`Default() *Logger`:** 返回默认的 `Logger` 实例。
* **`SetDefault(l *Logger)`:** 设置全局默认的 `Logger`。  设置后，标准 `log` 包的输出（例如 `log.Print`）将会被路由到 `slog` 的 `Handler` 进行处理。

**3. 提供了基于现有 `Logger` 创建新 `Logger` 的方法 (具有上下文):**

* **`With(args ...any) *Logger`:** 返回一个新的 `Logger`，该 `Logger` 会在每次日志输出时包含指定的属性 (key-value 对)。
* **`WithGroup(name string) *Logger`:** 返回一个新的 `Logger`，该 `Logger` 输出的属性将会被分组到指定的 `name` 下。

**4. 提供了不同日志级别的方法:**

* **`Debug(msg string, args ...any)` / `DebugContext(ctx context.Context, msg string, args ...any)`:**  记录 `Debug` 级别的日志。
* **`Info(msg string, args ...any)` / `InfoContext(ctx context.Context, msg string, args ...any)`:** 记录 `Info` 级别的日志。
* **`Warn(msg string, args ...any)` / `WarnContext(ctx context.Context, msg string, args ...any)`:** 记录 `Warn` 级别的日志。
* **`Error(msg string, args ...any)` / `ErrorContext(ctx context.Context, msg string, args ...any)`:** 记录 `Error` 级别的日志。
* **`Log(ctx context.Context, level Level, msg string, args ...any)`:**  记录指定级别的日志。
* **`LogAttrs(ctx context.Context, level Level, msg string, attrs ...Attr)`:** 记录指定级别的日志，参数直接使用 `Attr` 切片，更高效。

**5. 提供了与标准 `log` 包的桥接功能:**

* **`SetLogLoggerLevel(level Level) (oldLevel Level)`:**  控制 `slog` 如何处理标准 `log` 包的输出。
    * 在调用 `SetDefault` 之前，它设置将传递给 `log.Logger` 的最低日志级别。
    * 在调用 `SetDefault` 之后，它设置从 `log.Logger` 桥接到 `slog` 的日志级别。
* **`NewLogLogger(h Handler, level Level) *log.Logger`:** 创建一个新的标准 `log.Logger`，其输出会被发送到指定的 `slog.Handler`。

**6. 提供了判断日志级别是否启用的方法:**

* **`Enabled(ctx context.Context, level Level) bool`:** 判断当前 `Logger` 的 `Handler` 是否会处理指定级别的日志。

**7. 内部机制:**

* 使用 `atomic.Pointer[Logger]` 来安全地管理全局默认的 `Logger`，保证并发安全。
* 使用 `handlerWriter` 结构体作为 `io.Writer`，将标准 `log` 包的输出重定向到 `slog.Handler`。
* 在记录日志时，会创建一个 `Record` 结构体，包含时间、级别、消息和属性。
* 使用 `runtime.Callers` 获取调用者的程序计数器 (PC)，用于记录日志的调用位置（可选）。

**它是什么 Go 语言功能的实现？**

这段代码主要实现了 Go 语言的**结构化日志记录**功能。它引入了 `Logger` 和 `Handler` 的概念，允许开发者以结构化的方式记录日志，而不是简单的字符串。

**Go 代码举例说明:**

```go
package main

import (
	"context"
	"log/slog"
	"os"
)

func main() {
	// 创建一个新的 Logger，使用 JSON 格式的 Handler 输出到标准输出
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	// 设置为默认的 Logger
	slog.SetDefault(logger)

	// 使用默认的 Logger 记录 Info 级别的日志
	slog.Info("hello", "name", "world", "count", 123)

	// 创建一个带有属性的 Logger
	loggerWithAttr := logger.With("request_id", "abc-123")
	loggerWithAttr.Info("processing request")

	// 创建一个带有分组属性的 Logger
	loggerWithGroup := logger.WithGroup("database").With("host", "localhost", "port", 5432)
	loggerWithGroup.Info("connecting to database")

	// 使用不同级别记录日志
	slog.Debug("this is a debug message")
	slog.Warn("this is a warning message", "file", "important.txt")
	slog.Error("an error occurred", "error", "file not found")

	// 使用 context
	ctx := context.WithValue(context.Background(), "trace_id", "xyz-456")
	slog.InfoContext(ctx, "processing with context", "user_id", 10)
}
```

**假设的输入与输出:**

如果运行上面的代码，输出（标准输出）将会是类似以下的 JSON 格式的日志记录：

```json
{"time":"2023-10-27T10:00:00.000Z","level":"INFO","msg":"hello","name":"world","count":123}
{"time":"2023-10-27T10:00:00.000Z","level":"INFO","msg":"processing request","request_id":"abc-123"}
{"time":"2023-10-27T10:00:00.000Z","level":"INFO","msg":"connecting to database","database":{"host":"localhost","port":5432}}
{"time":"2023-10-27T10:00:00.000Z","level":"DEBUG","msg":"this is a debug message"}
{"time":"2023-10-27T10:00:00.000Z","level":"WARN","msg":"this is a warning message","file":"important.txt"}
{"time":"2023-10-27T10:00:00.000Z","level":"ERROR","msg":"an error occurred","error":"file not found"}
{"time":"2023-10-27T10:00:00.000Z","level":"INFO","msg":"processing with context","user_id":10}
```

**命令行参数的具体处理:**

这段代码本身不直接处理命令行参数。通常，日志级别和其他日志配置是通过以下方式处理的，但这需要在 `main` 函数或其他初始化代码中完成：

1. **使用标准库 `flag` 包:** 可以定义命令行标志来设置日志级别或其他配置，例如：

   ```go
   package main

   import (
       "flag"
       "log/slog"
       "os"
   )

   var logLevel string

   func init() {
       flag.StringVar(&logLevel, "log-level", "INFO", "Set the logging level (DEBUG, INFO, WARN, ERROR)")
   }

   func main() {
       flag.Parse()

       var level slog.Level
       switch logLevel {
       case "DEBUG":
           level = slog.LevelDebug
       case "INFO":
           level = slog.LevelInfo
       case "WARN":
           level = slog.LevelWarn
       case "ERROR":
           level = slog.LevelError
       default:
           level = slog.LevelInfo
       }

       // 创建一个 Handler，根据级别过滤日志
       opts := &slog.HandlerOptions{Level: level}
       logger := slog.New(slog.NewTextHandler(os.Stdout, opts))
       slog.SetDefault(logger)

       slog.Info("application started")
       slog.Debug("this is a debug message, may not be shown")
   }
   ```

   运行命令时可以指定日志级别：

   ```bash
   go run main.go -log-level=DEBUG
   ```

2. **使用环境变量:** 可以读取环境变量来配置日志级别或其他选项。

3. **使用配置文件:** 可以读取配置文件（例如 YAML 或 JSON）来加载日志配置。

**使用者易犯错的点:**

1. **忘记设置 Handler 或使用默认 Handler 但未配置:**  如果创建了一个新的 `Logger` 但没有为其设置 `Handler`，或者使用了默认的 `Logger` 但没有根据需要配置 `Handler`，可能无法得到预期的日志输出。

2. **混淆 `Logger.With` 的行为:** `Logger.With` 方法会返回一个新的 `Logger` 实例，而不是修改原来的 `Logger`。使用者容易犯错，认为调用 `With` 后，原来的 `Logger` 也会添加上新的属性。

   ```go
   logger := slog.Default()
   logger.Info("initial log") // 输出时不带 name

   logger.With("name", "test") // 创建了一个新的 Logger，但原始 logger 没变
   logger.Info("another log")   // 输出时仍然不带 name
   ```

   正确的做法是使用 `With` 返回的新 `Logger`：

   ```go
   logger := slog.Default()
   logger.Info("initial log")

   loggerWithAttr := logger.With("name", "test")
   loggerWithAttr.Info("another log") // 输出时会带有 name:test
   ```

3. **不理解 `SetLogLoggerLevel` 的作用域:**  使用者可能不清楚 `SetLogLoggerLevel` 在调用 `SetDefault` 前后对 `log` 包的影响不同。

4. **误解 `WithGroup` 的作用:**  `WithGroup` 只是为后续添加的属性添加一个分组前缀，它本身不会输出任何东西。使用者可能误认为 `WithGroup` 可以像结构体一样创建嵌套的日志结构。具体的输出格式取决于 `Handler` 的实现。

总而言之，这段代码定义了 Go 语言结构化日志记录的基础框架，提供了灵活的方式来创建、配置和使用 Logger，并与传统的 `log` 包进行了集成。理解其核心概念和方法对于有效地使用 `slog` 包至关重要。

Prompt: 
```
这是路径为go/src/log/slog/logger.go的go语言实现的一部分， 请列举一下它的功能, 　
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
	"log"
	loginternal "log/internal"
	"log/slog/internal"
	"runtime"
	"sync/atomic"
	"time"
)

var defaultLogger atomic.Pointer[Logger]

var logLoggerLevel LevelVar

// SetLogLoggerLevel controls the level for the bridge to the [log] package.
//
// Before [SetDefault] is called, slog top-level logging functions call the default [log.Logger].
// In that mode, SetLogLoggerLevel sets the minimum level for those calls.
// By default, the minimum level is Info, so calls to [Debug]
// (as well as top-level logging calls at lower levels)
// will not be passed to the log.Logger. After calling
//
//	slog.SetLogLoggerLevel(slog.LevelDebug)
//
// calls to [Debug] will be passed to the log.Logger.
//
// After [SetDefault] is called, calls to the default [log.Logger] are passed to the
// slog default handler. In that mode,
// SetLogLoggerLevel sets the level at which those calls are logged.
// That is, after calling
//
//	slog.SetLogLoggerLevel(slog.LevelDebug)
//
// A call to [log.Printf] will result in output at level [LevelDebug].
//
// SetLogLoggerLevel returns the previous value.
func SetLogLoggerLevel(level Level) (oldLevel Level) {
	oldLevel = logLoggerLevel.Level()
	logLoggerLevel.Set(level)
	return
}

func init() {
	defaultLogger.Store(New(newDefaultHandler(loginternal.DefaultOutput)))
}

// Default returns the default [Logger].
func Default() *Logger { return defaultLogger.Load() }

// SetDefault makes l the default [Logger], which is used by
// the top-level functions [Info], [Debug] and so on.
// After this call, output from the log package's default Logger
// (as with [log.Print], etc.) will be logged using l's Handler,
// at a level controlled by [SetLogLoggerLevel].
func SetDefault(l *Logger) {
	defaultLogger.Store(l)
	// If the default's handler is a defaultHandler, then don't use a handleWriter,
	// or we'll deadlock as they both try to acquire the log default mutex.
	// The defaultHandler will use whatever the log default writer is currently
	// set to, which is correct.
	// This can occur with SetDefault(Default()).
	// See TestSetDefault.
	if _, ok := l.Handler().(*defaultHandler); !ok {
		capturePC := log.Flags()&(log.Lshortfile|log.Llongfile) != 0
		log.SetOutput(&handlerWriter{l.Handler(), &logLoggerLevel, capturePC})
		log.SetFlags(0) // we want just the log message, no time or location
	}
}

// handlerWriter is an io.Writer that calls a Handler.
// It is used to link the default log.Logger to the default slog.Logger.
type handlerWriter struct {
	h         Handler
	level     Leveler
	capturePC bool
}

func (w *handlerWriter) Write(buf []byte) (int, error) {
	level := w.level.Level()
	if !w.h.Enabled(context.Background(), level) {
		return 0, nil
	}
	var pc uintptr
	if !internal.IgnorePC && w.capturePC {
		// skip [runtime.Callers, w.Write, Logger.Output, log.Print]
		var pcs [1]uintptr
		runtime.Callers(4, pcs[:])
		pc = pcs[0]
	}

	// Remove final newline.
	origLen := len(buf) // Report that the entire buf was written.
	buf = bytes.TrimSuffix(buf, []byte{'\n'})
	r := NewRecord(time.Now(), level, string(buf), pc)
	return origLen, w.h.Handle(context.Background(), r)
}

// A Logger records structured information about each call to its
// Log, Debug, Info, Warn, and Error methods.
// For each call, it creates a [Record] and passes it to a [Handler].
//
// To create a new Logger, call [New] or a Logger method
// that begins "With".
type Logger struct {
	handler Handler // for structured logging
}

func (l *Logger) clone() *Logger {
	c := *l
	return &c
}

// Handler returns l's Handler.
func (l *Logger) Handler() Handler { return l.handler }

// With returns a Logger that includes the given attributes
// in each output operation. Arguments are converted to
// attributes as if by [Logger.Log].
func (l *Logger) With(args ...any) *Logger {
	if len(args) == 0 {
		return l
	}
	c := l.clone()
	c.handler = l.handler.WithAttrs(argsToAttrSlice(args))
	return c
}

// WithGroup returns a Logger that starts a group, if name is non-empty.
// The keys of all attributes added to the Logger will be qualified by the given
// name. (How that qualification happens depends on the [Handler.WithGroup]
// method of the Logger's Handler.)
//
// If name is empty, WithGroup returns the receiver.
func (l *Logger) WithGroup(name string) *Logger {
	if name == "" {
		return l
	}
	c := l.clone()
	c.handler = l.handler.WithGroup(name)
	return c
}

// New creates a new Logger with the given non-nil Handler.
func New(h Handler) *Logger {
	if h == nil {
		panic("nil Handler")
	}
	return &Logger{handler: h}
}

// With calls [Logger.With] on the default logger.
func With(args ...any) *Logger {
	return Default().With(args...)
}

// Enabled reports whether l emits log records at the given context and level.
func (l *Logger) Enabled(ctx context.Context, level Level) bool {
	if ctx == nil {
		ctx = context.Background()
	}
	return l.Handler().Enabled(ctx, level)
}

// NewLogLogger returns a new [log.Logger] such that each call to its Output method
// dispatches a Record to the specified handler. The logger acts as a bridge from
// the older log API to newer structured logging handlers.
func NewLogLogger(h Handler, level Level) *log.Logger {
	return log.New(&handlerWriter{h, level, true}, "", 0)
}

// Log emits a log record with the current time and the given level and message.
// The Record's Attrs consist of the Logger's attributes followed by
// the Attrs specified by args.
//
// The attribute arguments are processed as follows:
//   - If an argument is an Attr, it is used as is.
//   - If an argument is a string and this is not the last argument,
//     the following argument is treated as the value and the two are combined
//     into an Attr.
//   - Otherwise, the argument is treated as a value with key "!BADKEY".
func (l *Logger) Log(ctx context.Context, level Level, msg string, args ...any) {
	l.log(ctx, level, msg, args...)
}

// LogAttrs is a more efficient version of [Logger.Log] that accepts only Attrs.
func (l *Logger) LogAttrs(ctx context.Context, level Level, msg string, attrs ...Attr) {
	l.logAttrs(ctx, level, msg, attrs...)
}

// Debug logs at [LevelDebug].
func (l *Logger) Debug(msg string, args ...any) {
	l.log(context.Background(), LevelDebug, msg, args...)
}

// DebugContext logs at [LevelDebug] with the given context.
func (l *Logger) DebugContext(ctx context.Context, msg string, args ...any) {
	l.log(ctx, LevelDebug, msg, args...)
}

// Info logs at [LevelInfo].
func (l *Logger) Info(msg string, args ...any) {
	l.log(context.Background(), LevelInfo, msg, args...)
}

// InfoContext logs at [LevelInfo] with the given context.
func (l *Logger) InfoContext(ctx context.Context, msg string, args ...any) {
	l.log(ctx, LevelInfo, msg, args...)
}

// Warn logs at [LevelWarn].
func (l *Logger) Warn(msg string, args ...any) {
	l.log(context.Background(), LevelWarn, msg, args...)
}

// WarnContext logs at [LevelWarn] with the given context.
func (l *Logger) WarnContext(ctx context.Context, msg string, args ...any) {
	l.log(ctx, LevelWarn, msg, args...)
}

// Error logs at [LevelError].
func (l *Logger) Error(msg string, args ...any) {
	l.log(context.Background(), LevelError, msg, args...)
}

// ErrorContext logs at [LevelError] with the given context.
func (l *Logger) ErrorContext(ctx context.Context, msg string, args ...any) {
	l.log(ctx, LevelError, msg, args...)
}

// log is the low-level logging method for methods that take ...any.
// It must always be called directly by an exported logging method
// or function, because it uses a fixed call depth to obtain the pc.
func (l *Logger) log(ctx context.Context, level Level, msg string, args ...any) {
	if !l.Enabled(ctx, level) {
		return
	}
	var pc uintptr
	if !internal.IgnorePC {
		var pcs [1]uintptr
		// skip [runtime.Callers, this function, this function's caller]
		runtime.Callers(3, pcs[:])
		pc = pcs[0]
	}
	r := NewRecord(time.Now(), level, msg, pc)
	r.Add(args...)
	if ctx == nil {
		ctx = context.Background()
	}
	_ = l.Handler().Handle(ctx, r)
}

// logAttrs is like [Logger.log], but for methods that take ...Attr.
func (l *Logger) logAttrs(ctx context.Context, level Level, msg string, attrs ...Attr) {
	if !l.Enabled(ctx, level) {
		return
	}
	var pc uintptr
	if !internal.IgnorePC {
		var pcs [1]uintptr
		// skip [runtime.Callers, this function, this function's caller]
		runtime.Callers(3, pcs[:])
		pc = pcs[0]
	}
	r := NewRecord(time.Now(), level, msg, pc)
	r.AddAttrs(attrs...)
	if ctx == nil {
		ctx = context.Background()
	}
	_ = l.Handler().Handle(ctx, r)
}

// Debug calls [Logger.Debug] on the default logger.
func Debug(msg string, args ...any) {
	Default().log(context.Background(), LevelDebug, msg, args...)
}

// DebugContext calls [Logger.DebugContext] on the default logger.
func DebugContext(ctx context.Context, msg string, args ...any) {
	Default().log(ctx, LevelDebug, msg, args...)
}

// Info calls [Logger.Info] on the default logger.
func Info(msg string, args ...any) {
	Default().log(context.Background(), LevelInfo, msg, args...)
}

// InfoContext calls [Logger.InfoContext] on the default logger.
func InfoContext(ctx context.Context, msg string, args ...any) {
	Default().log(ctx, LevelInfo, msg, args...)
}

// Warn calls [Logger.Warn] on the default logger.
func Warn(msg string, args ...any) {
	Default().log(context.Background(), LevelWarn, msg, args...)
}

// WarnContext calls [Logger.WarnContext] on the default logger.
func WarnContext(ctx context.Context, msg string, args ...any) {
	Default().log(ctx, LevelWarn, msg, args...)
}

// Error calls [Logger.Error] on the default logger.
func Error(msg string, args ...any) {
	Default().log(context.Background(), LevelError, msg, args...)
}

// ErrorContext calls [Logger.ErrorContext] on the default logger.
func ErrorContext(ctx context.Context, msg string, args ...any) {
	Default().log(ctx, LevelError, msg, args...)
}

// Log calls [Logger.Log] on the default logger.
func Log(ctx context.Context, level Level, msg string, args ...any) {
	Default().log(ctx, level, msg, args...)
}

// LogAttrs calls [Logger.LogAttrs] on the default logger.
func LogAttrs(ctx context.Context, level Level, msg string, attrs ...Attr) {
	Default().logAttrs(ctx, level, msg, attrs...)
}

"""



```