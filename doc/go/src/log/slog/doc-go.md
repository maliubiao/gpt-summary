Response:
My thinking process to answer the request about `go/src/log/slog/doc.go` goes like this:

1. **Understand the Core Request:** The primary goal is to explain the functionality of the `slog` package based on its documentation. The request also asks for Go code examples, handling of command-line arguments (though the doc doesn't discuss this), potential user errors, and everything should be in Chinese.

2. **Identify Key Concepts:** I scanned the documentation for recurring themes and essential components. These jumped out:
    * Structured Logging: The fundamental purpose of the package.
    * `Logger`: The central type for emitting logs.
    * `Handler`: Responsible for processing log records. Different handlers offer different formats (text, JSON).
    * `Record`: The data structure holding log information.
    * Levels:  Severity levels for filtering logs (Debug, Info, Warn, Error).
    * Attributes (Key-Value Pairs):  The "structured" part of logging.
    * Default Logger:  Convenience for quick logging.
    * Custom Handlers:  Extensibility for different output formats.
    * `With`: Adding context to loggers.
    * Groups:  Organizing attributes.
    * Contexts:  Integrating with Go's context mechanism.
    * `Attr` and `Value`:  Types for structured data.
    * `LogValuer`: Customizing logging for specific types.
    * Performance Considerations: Tips for efficient logging.
    * Writing Handlers:  Brief mention of extending the package.

3. **Categorize Functionality:**  To structure the answer, I mentally grouped the functionalities. This helps in organizing the information logically:
    * Basic Logging: Emitting logs with different levels.
    * Structured Logging: Using key-value pairs.
    * Output Formatting: Using different handlers (Text, JSON).
    * Configuration: Setting the default logger and handler options.
    * Contextual Logging: Adding attributes and groups.
    * Advanced Features:  `LogValuer`, performance tips, custom handlers.

4. **Generate Code Examples:** For each significant piece of functionality, I considered how to demonstrate it with a simple Go code snippet. The examples should be clear, concise, and illustrate the core concept. For instance:
    * Basic logging:  `slog.Info`, `slog.Error`.
    * Structured logging:  `slog.Info("message", "key", value)`.
    * Different handlers:  Creating `TextHandler` and `JSONHandler`.
    * `With`:  Adding an attribute to a logger.
    * Groups:  Using `slog.Group`.
    * `LogValuer`:  A simple example of a type implementing `LogValuer`.

5. **Address Specific Requirements:**
    * **Go Language Features:**  The package implements structured logging, using interfaces (`Handler`, `LogValuer`), structs (`Logger`, `Record`, `HandlerOptions`), and functions. The examples directly demonstrate these.
    * **Command-Line Arguments:** The documentation doesn't discuss command-line arguments for configuration. So, I explicitly stated this and explained how configuration is typically done in code.
    * **Assumptions and Input/Output:**  For code examples, I implicitly assumed basic setup (importing `slog`, `fmt`, `os`). The output is based on the descriptions of `TextHandler` and `JSONHandler`.
    * **User Errors:**  I focused on the common mistake of modifying a `Record` directly without cloning, as highlighted in the documentation.

6. **Structure the Output in Chinese:**  I translated the functionality descriptions, code comments, and explanations into clear and understandable Chinese. I used appropriate technical terms in Chinese (e.g., 结构化日志 (structured logging), 处理器 (handler), 属性 (attribute)).

7. **Review and Refine:** I reread the generated answer to ensure accuracy, completeness, and clarity. I checked if the code examples were correct and if the explanations were easy to follow. I made sure to directly address all parts of the original request. For example, double-checking that I covered all the requested points (functionality, Go feature, code example, input/output, command-line, user errors).

**Self-Correction Example during the process:**

Initially, I might have focused too heavily on just listing the types and functions. However, the request emphasizes *functionality*. So, I shifted my focus to *what the package allows you to do* rather than just *what it contains*. This led to organizing the answer by concepts like "Basic Logging," "Structured Logging," etc., which is more user-friendly. Also, I initially forgot to explicitly mention the lack of command-line argument handling in the documentation and had to add that point. Similarly, I realized the importance of a concrete user error example and included the `Record` modification issue.
`go/src/log/slog/doc.go` 文件是 Go 语言 `slog` 标准库的文档，它详细介绍了 `slog` 包的功能和使用方法。以下是其主要功能的总结：

**核心功能：**

1. **提供结构化日志记录能力：**  `slog` 允许开发者记录包含消息、严重级别以及各种键值对属性的日志记录。这使得日志更容易被机器解析和分析，相较于传统的纯文本日志更加强大。

2. **定义 `Logger` 类型：**  `Logger` 是 `slog` 包的核心类型，提供了如 `Info`、`Error` 等方法用于报告不同严重级别的事件。

3. **引入 `Handler` 接口：** 每个 `Logger` 都关联一个 `Handler`。`Logger` 的输出方法会创建一个 `Record` 对象，并将其传递给 `Handler`，由 `Handler` 决定如何处理该记录，例如输出到控制台、文件或网络。

4. **提供默认的 `Logger` 和便捷函数：**  `slog` 包提供了可以通过顶级函数（如 `Info`、`Error`）访问的默认 `Logger`，方便快速开始使用。这些顶级函数实际上是调用默认 `Logger` 相应的方法。

5. **定义日志记录结构 `Record`：**  一个日志记录包含时间戳、级别、消息以及一组键值对属性。

6. **支持不同的 `Handler` 实现以实现不同的输出格式：**
    * **默认 Handler：** 将日志记录格式化为字符串，并传递给 `log` 标准库。
    * **`TextHandler`：**  以 `key=value` 对的形式输出结构化日志到指定的 `io.Writer` (例如 `os.Stderr`)。输出易于机器解析。
    * **`JSONHandler`：** 以 JSON 格式输出结构化日志到指定的 `io.Writer` (例如 `os.Stdout`)。

7. **提供 `HandlerOptions` 用于配置 `TextHandler` 和 `JSONHandler`：**  可以设置最小日志级别、是否显示调用日志的代码文件名和行号，以及修改属性的方法。

8. **允许设置全局默认 `Logger`：**  通过 `slog.SetDefault(logger)` 可以将一个自定义的 `Logger` 设置为默认，这样顶级函数如 `Info` 将使用该自定义 `Logger`。同时，`SetDefault` 也会更新 `log` 包使用的默认 logger，使得使用 `log.Printf` 的现有代码也能将日志发送到 `slog` 的 handler。

9. **支持使用 `Logger.With` 添加上下文属性：**  `With` 方法可以创建一个新的 `Logger`，它继承了原始 `Logger` 的 `Handler`，并添加了额外的属性。这些属性会出现在该 `Logger` 生成的每个日志记录中，避免在每次日志调用时重复添加相同的属性。

10. **引入日志级别 `Level` 的概念：**  `Level` 是一个整数，表示日志事件的重要性或严重程度。包中定义了常见的级别常量（Debug、Info、Warn、Error）。可以通过配置 `HandlerOptions.Level` 来设置 `Handler` 输出的最低级别。支持使用 `LevelVar` 动态调整日志级别。

11. **支持日志属性分组 `Group`：**  可以将多个属性组织成一个组，并为其命名。`TextHandler` 和 `JSONHandler` 会以不同的方式展示分组属性，例如 `TextHandler` 使用点号分隔，`JSONHandler` 使用嵌套对象。`Logger.WithGroup` 可以创建一个新的 `Logger`，其所有输出都带有指定的分组名称，有助于避免大型系统中重复的属性键。

12. **支持使用 `context.Context` 传递上下文信息：** `Logger.Log` 和 `Logger.LogAttrs` 方法以及对应的顶级函数接受 `context.Context` 作为第一个参数，以便 handler 可以从中提取有用的信息，例如追踪 ID。同时提供了 `InfoContext` 等带 `Context` 的便捷方法。

13. **提供 `Attr` 和 `Value` 类型用于更精细地控制属性：** `Attr` 是一个键值对。`Value` 可以持有任何 Go 值，并优化了常见类型的表示，避免不必要的内存分配。提供了 `Int`、`String`、`Bool`、`Any` 等构造 `Attr` 的便捷函数。`Logger.LogAttrs` 方法接受 `Attr` 切片，是最高效的日志输出方式。

14. **允许通过实现 `LogValuer` 接口自定义类型的日志行为：** 如果一个类型实现了 `LogValuer` 接口，其 `LogValue` 方法返回的 `Value` 将用于日志记录。这允许开发者控制类型在日志中的展现方式，例如脱敏敏感信息或将结构体字段分组。

15. **讨论了包装输出方法时可能出现的源文件和行号错误，并提供了解决方案。**

16. **提供了 `Record` 的克隆和创建方法，以及遍历属性的方法，方便自定义 Handler 处理和修改日志记录。**

17. **提供了一些性能优化的建议，例如使用 `Logger.With` 缓存常用属性，以及避免在日志被丢弃时进行不必要的计算，并介绍了使用 `LogValuer` 延迟计算的方法。**

18. **简要提及了编写自定义 Handler 的相关内容，并提供了外部链接指向更详细的指南。**

**它是什么 go 语言功能的实现？**

`slog` 包主要利用了 Go 语言的以下特性：

* **接口 (Interface)：** `Handler` 和 `LogValuer` 是接口，允许不同的实现方式，提供了灵活性和可扩展性。
* **结构体 (Struct)：** `Logger`, `Record`, `HandlerOptions`, `Attr`, `Value` 等都是结构体，用于组织和存储数据。
* **函数 (Function)：** 提供了各种用于日志记录和配置的函数，包括顶级函数和 `Logger` 的方法。
* **变长参数 (Variadic Arguments)：**  `Logger.Info` 等方法使用变长参数 `...any` 来接收任意数量的键值对。
* **类型断言和反射 (Type Assertion and Reflection)：**  在处理不同类型的属性值时可能会使用。
* **上下文 (Context)：**  与 `context` 包集成，允许传递和使用上下文信息。

**Go 代码举例说明：**

假设我们想使用 `slog` 记录一个包含用户 ID 和请求 URL 的 INFO 级别日志。

```go
package main

import (
	"log/slog"
	"os"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	userID := 123
	url := "https://example.com/api/data"

	slog.Info("处理请求", "user_id", userID, "url", url)

	// 使用 With 添加通用属性
	requestLogger := logger.With("request_id", "abc-123")
	requestLogger.Info("请求开始", "url", url)

	// 使用 Group 对属性进行分组
	slog.Info("请求详情", slog.Group("request", "method", "GET", "path", "/api/data"))
}
```

**假设的输入与输出：**

运行上述代码，`TextHandler` 的输出可能如下所示：

```
time=2023-10-27T10:00:00.000+08:00 level=INFO msg="处理请求" user_id=123 url=https://example.com/api/data
time=2023-10-27T10:00:00.000+08:00 level=INFO msg="请求开始" request_id=abc-123 url=https://example.com/api/data
time=2023-10-27T10:00:00.000+08:00 level=INFO msg="请求详情" request.method=GET request.path=/api/data
```

如果使用 `JSONHandler`，输出可能如下所示：

```json
{"time":"2023-10-27T10:00:00+08:00","level":"INFO","msg":"处理请求","user_id":123,"url":"https://example.com/api/data"}
{"time":"2023-10-27T10:00:00+08:00","level":"INFO","msg":"请求开始","request_id":"abc-123","url":"https://example.com/api/data"}
{"time":"2023-10-27T10:00:00+08:00","level":"INFO","msg":"请求详情","request":{"method":"GET","path":"/api/data"}}
```

**命令行参数的具体处理：**

`slog` 包本身**没有直接处理命令行参数的功能**。日志的配置通常在代码中完成，例如设置默认的 `Logger` 和 `Handler`，以及配置 `HandlerOptions`。

如果需要通过命令行参数来配置日志级别或其他选项，你需要：

1. **使用 `flag` 标准库或其他命令行参数解析库**来解析命令行参数。
2. **根据解析到的参数值，配置 `slog` 的相关选项**，例如设置 `HandlerOptions.Level`。

**示例：**

```go
package main

import (
	"flag"
	"log/slog"
	"os"
)

var logLevel = flag.String("log-level", "INFO", "设置日志级别 (DEBUG, INFO, WARN, ERROR)")

func main() {
	flag.Parse()

	var level slog.Level
	switch *logLevel {
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

	opts := &slog.HandlerOptions{Level: level}
	logger := slog.New(slog.NewTextHandler(os.Stdout, opts))
	slog.SetDefault(logger)

	slog.Debug("这是一条调试信息")
	slog.Info("这是一条普通信息")
}
```

运行命令时，可以使用 `--log-level` 参数设置日志级别：

```bash
go run main.go --log-level DEBUG
go run main.go --log-level WARN
```

**使用者易犯错的点：**

1. **直接修改 `Record` 对象而不克隆：** 文档中强调了，`Record` 对象包含指向状态的隐藏字段。直接修改一个复制的 `Record` 可能会对原始 `Record` 产生意想不到的影响。应该使用 `Record.Clone()` 创建副本后再进行修改，或者使用 `NewRecord` 创建新的 `Record` 并遍历旧的属性进行构建。

   ```go
   // 错误示例
   func modifyRecord(r slog.Record) {
       r.Add("modified", true) // 可能会影响原始 Record
   }

   // 正确示例
   func modifyRecordCorrectly(r slog.Record) slog.Record {
       newRecord := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
       r.Attrs(func(a slog.Attr) bool {
           newRecord.AddAttrs(a)
           return true
       })
       newRecord.AddAttrs(slog.Bool("modified", true))
       return newRecord
   }
   ```

2. **在日志被丢弃时进行昂贵的计算：**  即使日志级别设置较高，传递给日志函数的参数仍然会被求值。如果计算量很大，可能会影响性能。应该尽可能延迟计算，只有在日志实际需要输出时才进行。可以使用 `LogValuer` 接口来实现延迟计算。

   ```go
   // 可能造成性能问题
   slog.Debug("计算结果", "result", computeExpensiveValue())

   // 使用 LogValuer 延迟计算
   type ExpensiveResult struct { }

   func (e ExpensiveResult) LogValue() slog.Value {
       return slog.AnyValue(computeExpensiveValue())
   }

   slog.Debug("计算结果", "result", ExpensiveResult{})
   ```

希望以上解释能够帮助你理解 `go/src/log/slog/doc.go` 文件描述的功能。

Prompt: 
```
这是路径为go/src/log/slog/doc.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*
Package slog provides structured logging,
in which log records include a message,
a severity level, and various other attributes
expressed as key-value pairs.

It defines a type, [Logger],
which provides several methods (such as [Logger.Info] and [Logger.Error])
for reporting events of interest.

Each Logger is associated with a [Handler].
A Logger output method creates a [Record] from the method arguments
and passes it to the Handler, which decides how to handle it.
There is a default Logger accessible through top-level functions
(such as [Info] and [Error]) that call the corresponding Logger methods.

A log record consists of a time, a level, a message, and a set of key-value
pairs, where the keys are strings and the values may be of any type.
As an example,

	slog.Info("hello", "count", 3)

creates a record containing the time of the call,
a level of Info, the message "hello", and a single
pair with key "count" and value 3.

The [Info] top-level function calls the [Logger.Info] method on the default Logger.
In addition to [Logger.Info], there are methods for Debug, Warn and Error levels.
Besides these convenience methods for common levels,
there is also a [Logger.Log] method which takes the level as an argument.
Each of these methods has a corresponding top-level function that uses the
default logger.

The default handler formats the log record's message, time, level, and attributes
as a string and passes it to the [log] package.

	2022/11/08 15:28:26 INFO hello count=3

For more control over the output format, create a logger with a different handler.
This statement uses [New] to create a new logger with a [TextHandler]
that writes structured records in text form to standard error:

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

[TextHandler] output is a sequence of key=value pairs, easily and unambiguously
parsed by machine. This statement:

	logger.Info("hello", "count", 3)

produces this output:

	time=2022-11-08T15:28:26.000-05:00 level=INFO msg=hello count=3

The package also provides [JSONHandler], whose output is line-delimited JSON:

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	logger.Info("hello", "count", 3)

produces this output:

	{"time":"2022-11-08T15:28:26.000000000-05:00","level":"INFO","msg":"hello","count":3}

Both [TextHandler] and [JSONHandler] can be configured with [HandlerOptions].
There are options for setting the minimum level (see Levels, below),
displaying the source file and line of the log call, and
modifying attributes before they are logged.

Setting a logger as the default with

	slog.SetDefault(logger)

will cause the top-level functions like [Info] to use it.
[SetDefault] also updates the default logger used by the [log] package,
so that existing applications that use [log.Printf] and related functions
will send log records to the logger's handler without needing to be rewritten.

Some attributes are common to many log calls.
For example, you may wish to include the URL or trace identifier of a server request
with all log events arising from the request.
Rather than repeat the attribute with every log call, you can use [Logger.With]
to construct a new Logger containing the attributes:

	logger2 := logger.With("url", r.URL)

The arguments to With are the same key-value pairs used in [Logger.Info].
The result is a new Logger with the same handler as the original, but additional
attributes that will appear in the output of every call.

# Levels

A [Level] is an integer representing the importance or severity of a log event.
The higher the level, the more severe the event.
This package defines constants for the most common levels,
but any int can be used as a level.

In an application, you may wish to log messages only at a certain level or greater.
One common configuration is to log messages at Info or higher levels,
suppressing debug logging until it is needed.
The built-in handlers can be configured with the minimum level to output by
setting [HandlerOptions.Level].
The program's `main` function typically does this.
The default value is LevelInfo.

Setting the [HandlerOptions.Level] field to a [Level] value
fixes the handler's minimum level throughout its lifetime.
Setting it to a [LevelVar] allows the level to be varied dynamically.
A LevelVar holds a Level and is safe to read or write from multiple
goroutines.
To vary the level dynamically for an entire program, first initialize
a global LevelVar:

	var programLevel = new(slog.LevelVar) // Info by default

Then use the LevelVar to construct a handler, and make it the default:

	h := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: programLevel})
	slog.SetDefault(slog.New(h))

Now the program can change its logging level with a single statement:

	programLevel.Set(slog.LevelDebug)

# Groups

Attributes can be collected into groups.
A group has a name that is used to qualify the names of its attributes.
How this qualification is displayed depends on the handler.
[TextHandler] separates the group and attribute names with a dot.
[JSONHandler] treats each group as a separate JSON object, with the group name as the key.

Use [Group] to create a Group attribute from a name and a list of key-value pairs:

	slog.Group("request",
	    "method", r.Method,
	    "url", r.URL)

TextHandler would display this group as

	request.method=GET request.url=http://example.com

JSONHandler would display it as

	"request":{"method":"GET","url":"http://example.com"}

Use [Logger.WithGroup] to qualify all of a Logger's output
with a group name. Calling WithGroup on a Logger results in a
new Logger with the same Handler as the original, but with all
its attributes qualified by the group name.

This can help prevent duplicate attribute keys in large systems,
where subsystems might use the same keys.
Pass each subsystem a different Logger with its own group name so that
potential duplicates are qualified:

	logger := slog.Default().With("id", systemID)
	parserLogger := logger.WithGroup("parser")
	parseInput(input, parserLogger)

When parseInput logs with parserLogger, its keys will be qualified with "parser",
so even if it uses the common key "id", the log line will have distinct keys.

# Contexts

Some handlers may wish to include information from the [context.Context] that is
available at the call site. One example of such information
is the identifier for the current span when tracing is enabled.

The [Logger.Log] and [Logger.LogAttrs] methods take a context as a first
argument, as do their corresponding top-level functions.

Although the convenience methods on Logger (Info and so on) and the
corresponding top-level functions do not take a context, the alternatives ending
in "Context" do. For example,

	slog.InfoContext(ctx, "message")

It is recommended to pass a context to an output method if one is available.

# Attrs and Values

An [Attr] is a key-value pair. The Logger output methods accept Attrs as well as
alternating keys and values. The statement

	slog.Info("hello", slog.Int("count", 3))

behaves the same as

	slog.Info("hello", "count", 3)

There are convenience constructors for [Attr] such as [Int], [String], and [Bool]
for common types, as well as the function [Any] for constructing Attrs of any
type.

The value part of an Attr is a type called [Value].
Like an [any], a Value can hold any Go value,
but it can represent typical values, including all numbers and strings,
without an allocation.

For the most efficient log output, use [Logger.LogAttrs].
It is similar to [Logger.Log] but accepts only Attrs, not alternating
keys and values; this allows it, too, to avoid allocation.

The call

	logger.LogAttrs(ctx, slog.LevelInfo, "hello", slog.Int("count", 3))

is the most efficient way to achieve the same output as

	slog.InfoContext(ctx, "hello", "count", 3)

# Customizing a type's logging behavior

If a type implements the [LogValuer] interface, the [Value] returned from its LogValue
method is used for logging. You can use this to control how values of the type
appear in logs. For example, you can redact secret information like passwords,
or gather a struct's fields in a Group. See the examples under [LogValuer] for
details.

A LogValue method may return a Value that itself implements [LogValuer]. The [Value.Resolve]
method handles these cases carefully, avoiding infinite loops and unbounded recursion.
Handler authors and others may wish to use [Value.Resolve] instead of calling LogValue directly.

# Wrapping output methods

The logger functions use reflection over the call stack to find the file name
and line number of the logging call within the application. This can produce
incorrect source information for functions that wrap slog. For instance, if you
define this function in file mylog.go:

	func Infof(logger *slog.Logger, format string, args ...any) {
	    logger.Info(fmt.Sprintf(format, args...))
	}

and you call it like this in main.go:

	Infof(slog.Default(), "hello, %s", "world")

then slog will report the source file as mylog.go, not main.go.

A correct implementation of Infof will obtain the source location
(pc) and pass it to NewRecord.
The Infof function in the package-level example called "wrapping"
demonstrates how to do this.

# Working with Records

Sometimes a Handler will need to modify a Record
before passing it on to another Handler or backend.
A Record contains a mixture of simple public fields (e.g. Time, Level, Message)
and hidden fields that refer to state (such as attributes) indirectly. This
means that modifying a simple copy of a Record (e.g. by calling
[Record.Add] or [Record.AddAttrs] to add attributes)
may have unexpected effects on the original.
Before modifying a Record, use [Record.Clone] to
create a copy that shares no state with the original,
or create a new Record with [NewRecord]
and build up its Attrs by traversing the old ones with [Record.Attrs].

# Performance considerations

If profiling your application demonstrates that logging is taking significant time,
the following suggestions may help.

If many log lines have a common attribute, use [Logger.With] to create a Logger with
that attribute. The built-in handlers will format that attribute only once, at the
call to [Logger.With]. The [Handler] interface is designed to allow that optimization,
and a well-written Handler should take advantage of it.

The arguments to a log call are always evaluated, even if the log event is discarded.
If possible, defer computation so that it happens only if the value is actually logged.
For example, consider the call

	slog.Info("starting request", "url", r.URL.String())  // may compute String unnecessarily

The URL.String method will be called even if the logger discards Info-level events.
Instead, pass the URL directly:

	slog.Info("starting request", "url", &r.URL) // calls URL.String only if needed

The built-in [TextHandler] will call its String method, but only
if the log event is enabled.
Avoiding the call to String also preserves the structure of the underlying value.
For example [JSONHandler] emits the components of the parsed URL as a JSON object.
If you want to avoid eagerly paying the cost of the String call
without causing the handler to potentially inspect the structure of the value,
wrap the value in a fmt.Stringer implementation that hides its Marshal methods.

You can also use the [LogValuer] interface to avoid unnecessary work in disabled log
calls. Say you need to log some expensive value:

	slog.Debug("frobbing", "value", computeExpensiveValue(arg))

Even if this line is disabled, computeExpensiveValue will be called.
To avoid that, define a type implementing LogValuer:

	type expensive struct { arg int }

	func (e expensive) LogValue() slog.Value {
	    return slog.AnyValue(computeExpensiveValue(e.arg))
	}

Then use a value of that type in log calls:

	slog.Debug("frobbing", "value", expensive{arg})

Now computeExpensiveValue will only be called when the line is enabled.

The built-in handlers acquire a lock before calling [io.Writer.Write]
to ensure that exactly one [Record] is written at a time in its entirety.
Although each log record has a timestamp,
the built-in handlers do not use that time to sort the written records.
User-defined handlers are responsible for their own locking and sorting.

# Writing a handler

For a guide to writing a custom handler, see https://golang.org/s/slog-handler-guide.
*/
package slog

"""



```