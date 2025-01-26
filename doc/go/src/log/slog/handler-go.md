Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Identify the Core Purpose:** The first thing I noticed is the `package slog` and the `Handler` interface. This immediately signals that this code is about handling log records. The comments within the `Handler` interface further reinforce this.

2. **Analyze the `Handler` Interface:** I paid close attention to the methods in the `Handler` interface:
    * `Enabled`:  This is for filtering logs based on level. The context argument suggests that filtering might be dynamic or based on request-specific information.
    * `Handle`: This is the core logic for processing a log record. The comments about `r.Time`, `r.PC`, and `Attr` resolution are important hints about how handlers are expected to behave.
    * `WithAttrs`:  This suggests a way to add persistent attributes to a handler, influencing all subsequent log messages through that handler.
    * `WithGroup`:  This indicates a mechanism for structuring log output using groups of attributes.

3. **Examine the `defaultHandler`:**  This concrete implementation of `Handler` provides a basic understanding of how a handler might work.
    * The `output` field and the `newDefaultHandler` function tell me this handler likely writes to some output stream. The name `defaultHandler` hints it's a simple, built-in option.
    * The `Handle` method shows the basic process: formatting the log level and message, appending attributes, and then using the `output` function.

4. **Understand `HandlerOptions`:** This struct defines configurable options for more advanced handlers (`TextHandler` and `JSONHandler`).
    * `AddSource`: A common logging feature.
    * `Level`:  Explicit control over the minimum logging level. The mention of `LevelVar` is a good point for potentially advanced usage.
    * `ReplaceAttr`: This is a powerful mechanism for modifying attributes before logging. The example in the comments is crucial for understanding how it works with groups.

5. **Identify Key Constants:** The `TimeKey`, `LevelKey`, `MessageKey`, and `SourceKey` constants reveal the standard attribute names used by the built-in handlers. This is important for understanding the expected structure of log records.

6. **Delve into `commonHandler`:** This struct seems to be a base for more complex handlers.
    * The `json` flag suggests different output formats.
    * `opts`, `preformattedAttrs`, `groupPrefix`, and `groups` all point to mechanisms for handling attributes and groups. The `mu` field indicates that these handlers are designed to be thread-safe.

7. **Analyze `handleState`:** This struct is clearly used within the `Handle` method. It seems to hold temporary state necessary for formatting a single log record. The pooling of the `groups` slice is a performance optimization.

8. **Trace the `Handle` Logic (Key parts):**
    * The `handle` method in `commonHandler` is the core. It formats the built-in attributes first.
    * The `appendNonBuiltIns` method handles pre-formatted attributes and attributes directly attached to the record. The logic around opening and closing groups is important.
    * `appendAttr` and related functions like `appendKey`, `appendString`, and `appendValue` handle the actual formatting of individual attributes. The `ReplaceAttr` call happens here.

9. **Look for Specific Features/Patterns:**
    * **Attribute Handling:** The code heavily revolves around `Attr` and how they are processed, grouped, and potentially modified.
    * **Group Handling:**  The `WithGroup` method and the logic in `handleState` for opening and closing groups are significant.
    * **Output Formatting:** The `json` flag and the different `append...` functions indicate support for different output formats.
    * **Configuration:** `HandlerOptions` provides a way to customize the behavior of handlers.
    * **Thread Safety:** The `sync.Mutex` in `commonHandler` is a key indicator.

10. **Infer Potential Use Cases and Mistakes:** Based on the functionality, I started thinking about how users might interact with this code and what common mistakes they could make. For example, misuse of `ReplaceAttr` or confusion about how groups are formatted.

11. **Structure the Explanation:** Finally, I organized my findings into a coherent explanation covering the key aspects: functionality, inferred Go features, code examples (including assumptions and outputs), command-line arguments (or lack thereof), and potential pitfalls. I used clear headings and bullet points to make the information easy to digest.

**Self-Correction/Refinement during the Process:**

* Initially, I might have focused too much on the `defaultHandler`. Realizing that `commonHandler` and `HandlerOptions` are more central for understanding the broader picture helped me adjust my focus.
* I made sure to connect the code back to the comments in the `Handler` interface to ensure my interpretation aligned with the intended purpose.
*  When thinking about examples, I tried to choose scenarios that illustrate the core concepts, like attribute replacement and grouping.
* I specifically looked for places where user-provided functions (like `ReplaceAttr`) could lead to errors or unexpected behavior.

This iterative process of examining the code, understanding its structure and purpose, and then synthesizing that information into a comprehensive explanation is key to analyzing code like this effectively.
这段代码是 Go 语言标准库 `log/slog` 包中 `handler.go` 文件的一部分。它定义了处理日志记录的核心接口 `Handler` 以及一些相关的实现和辅助结构。

**功能列举:**

1. **定义了 `Handler` 接口:**  这是 `slog` 包中处理日志记录的关键抽象。任何实现了 `Handler` 接口的类型都可以用来处理 `Logger` 生成的日志记录。
2. **提供了 `defaultHandler` 结构体:**  这是一个简单的 `Handler` 实现，它使用 Go 标准库的 `log.Logger` 来输出日志。输出格式是简单的文本格式，包含日志级别和消息。
3. **定义了 `HandlerOptions` 结构体:** 用于配置更复杂的 `Handler` 实现，例如 `TextHandler` 和 `JSONHandler`。它允许用户自定义是否添加源代码信息、设置最低日志级别以及提供一个函数来修改日志属性。
4. **定义了内置属性的键 (常量):**  例如 `TimeKey`、`LevelKey`、`MessageKey` 和 `SourceKey`，用于标识日志记录中标准属性的名称。
5. **提供了 `commonHandler` 结构体:**  这是一个内部的、共享的 `Handler` 实现，为 `TextHandler` 和 `JSONHandler` 提供了通用的属性和分组处理逻辑。它负责格式化日志输出，支持 JSON 和文本两种格式。
6. **定义了 `handleState` 结构体:**  用于在 `commonHandler` 处理单个日志记录时保存临时状态，例如缓冲、分隔符、组信息等。这有助于提高性能并避免重复分配。
7. **提供了 `DiscardHandler` 常量:**  这是一个实现了 `Handler` 接口的空操作处理器，用于丢弃所有日志输出。
8. **实现了 `WithAttrs` 方法:**  允许创建一个新的 `Handler`，它会继承原有 `Handler` 的属性并添加新的属性。这是一种创建具有上下文信息的日志记录器的方式。
9. **实现了 `WithGroup` 方法:**  允许创建一个新的 `Handler`，它会将后续的属性添加到指定的组中。这有助于组织和结构化日志输出。
10. **实现了日志级别的过滤:**  `Enabled` 方法允许 `Handler` 根据配置的最低日志级别来决定是否处理某个日志记录。

**推理的 Go 语言功能实现:**

这段代码主要体现了以下 Go 语言功能：

* **接口 (Interfaces):** `Handler` 接口定义了一组方法，任何实现了这些方法的类型都可以被视为一个日志处理器，体现了 Go 的面向接口编程思想。
* **结构体 (Structs):** `defaultHandler`、`HandlerOptions` 和 `commonHandler` 等结构体用于组织和封装相关的数据和方法。
* **方法 (Methods):**  例如 `Enabled`、`Handle`、`WithAttrs` 和 `WithGroup` 是关联到结构体或接口的方法，用于实现特定的功能。
* **常量 (Constants):**  `TimeKey` 等常量用于定义固定的字符串值，提高代码的可读性和维护性。
* **函数 (Functions):**  例如 `newDefaultHandler` 用于创建 `defaultHandler` 实例。
* **互斥锁 (Mutex):** `commonHandler` 中的 `mu` 字段使用了 `sync.Mutex`，表明 `Handler` 的实现需要考虑并发安全。
* **缓冲 (Buffer):** 使用 `internal/buffer` 包中的 `buffer.Buffer` 来高效地构建日志字符串。
* **对象池 (Sync Pool):**  `handleState` 中使用了 `sync.Pool` 来复用 `groups` 切片，减少内存分配和 GC 的压力。
* **切片 (Slices):**  在 `WithAttrs` 和 `WithGroup` 等方法中，使用了切片来存储和操作属性和组信息。

**Go 代码举例说明:**

假设我们想使用 `defaultHandler` 来记录日志。

```go
package main

import (
	"context"
	"log/slog"
	"os"
)

func main() {
	// 创建一个使用 defaultHandler 的 Logger
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil)) // 实际上 defaultHandler 是 NewTextHandler 的默认行为

	logger.Info("Hello, world!", slog.String("name", "Go"))
}
```

**假设输入与输出:**

* **假设输入:**  上述代码被执行。
* **预期输出:**

```
INFO Hello, world! name=Go
```

**代码推理:**

1. `slog.NewTextHandler(os.Stdout, nil)` 创建了一个 `TextHandler` 实例，由于 `HandlerOptions` 为 `nil`，它会使用默认的配置，这类似于 `defaultHandler` 的行为（尽管 `defaultHandler` 本身没有直接导出）。
2. `logger.Info(...)` 调用会创建一个 `Record` 实例，包含日志级别（INFO）、消息和属性。
3. `TextHandler` 的 `Handle` 方法会被调用，它会将日志级别、消息和属性格式化成文本字符串。
4. 格式化后的字符串会被写入到 `os.Stdout`。

**涉及命令行参数的具体处理:**

这段代码本身没有直接处理命令行参数。`HandlerOptions` 结构体提供了一些配置选项，但这些通常是通过代码直接设置的。如果需要通过命令行参数来配置日志处理，你需要在你的应用程序中读取这些参数，并根据参数的值创建和配置 `Handler` 实例。

例如，你可以使用 `flag` 包来处理命令行参数，并根据参数的值来决定是否添加源代码信息或设置日志级别：

```go
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
)

var addSource = flag.Bool("add_source", false, "Add source information to logs")
var logLevel = flag.String("log_level", "INFO", "Log level (DEBUG, INFO, WARN, ERROR)")

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

	opts := &slog.HandlerOptions{
		AddSource: *addSource,
		Level:     level,
	}

	handler := slog.NewTextHandler(os.Stdout, opts)
	logger := slog.New(handler)

	logger.Info("Hello, world!", slog.String("name", "Go"))
}
```

在这个例子中，`add_source` 和 `log_level` 两个命令行参数被用来配置 `TextHandler` 的行为。

**使用者易犯错的点:**

1. **混淆 `Handler` 和 `Logger` 的职责:**  新手可能会尝试直接调用 `Handler` 的方法，例如 `Handle`。正确的做法是使用 `Logger` 的方法（例如 `Info`、`Error` 等），`Logger` 会负责调用关联 `Handler` 的方法。

   ```go
   // 错误的做法：
   // handler := slog.NewTextHandler(os.Stdout, nil)
   // record := slog.NewRecord(time.Now(), slog.LevelInfo, "message", 0)
   // handler.Handle(context.Background(), record) // 应该使用 Logger

   // 正确的做法：
   logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
   logger.Info("message")
   ```

2. **在 `ReplaceAttr` 函数中修改传入的 `groups` 切片:** `ReplaceAttr` 函数的文档明确指出，传入的 `groups` 切片不应该被保留或修改。这样做可能会导致意想不到的行为，因为这个切片可能在 `handleState` 中被复用。

   ```go
   // 错误的做法：
   opts := &slog.HandlerOptions{
       ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
           groups = append(groups, "modified") // 错误！不应该修改 groups
           return a
       },
   }
   ```

3. **误解 `WithGroup` 的作用域:**  `WithGroup` 返回一个新的 `Handler`，后续添加到这个 `Handler` 的属性才会被添加到指定的组中。如果在调用 `WithGroup` 之前添加了属性，这些属性不会被分组。

   ```go
   logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
   logger.Info("Message before group", slog.String("attr1", "value1")) // attr1 不在 group1 中

   groupedLogger := logger.WithGroup("group1")
   groupedLogger.Info("Message in group", slog.String("attr2", "value2")) // attr2 在 group1 中

   // 预期输出（文本格式）：
   // INFO Message before group attr1=value1
   // INFO Message in group group1.attr2=value2
   ```

4. **忘记 `ReplaceAttr` 会影响内置属性:** `ReplaceAttr` 函数也会被用来处理内置的属性，例如时间、级别和消息。如果提供了 `ReplaceAttr` 函数，需要考虑如何处理这些内置属性，否则可能会丢失或修改它们。

   ```go
   opts := &slog.HandlerOptions{
       ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
           if a.Key == slog.MessageKey {
               return slog.String("log_message", a.Value.String()) // 重命名 "msg" 为 "log_message"
           }
           return a
       },
   }
   ```

总而言之，这段代码是 Go `slog` 包中处理日志的核心组件，它通过接口和结构体的设计，提供了灵活和可扩展的日志处理能力。理解其功能和使用方式对于有效地使用 `slog` 包至关重要。

Prompt: 
```
这是路径为go/src/log/slog/handler.go的go语言实现的一部分， 请列举一下它的功能, 　
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
	"context"
	"fmt"
	"io"
	"log/slog/internal/buffer"
	"reflect"
	"slices"
	"strconv"
	"sync"
	"time"
)

// A Handler handles log records produced by a Logger.
//
// A typical handler may print log records to standard error,
// or write them to a file or database, or perhaps augment them
// with additional attributes and pass them on to another handler.
//
// Any of the Handler's methods may be called concurrently with itself
// or with other methods. It is the responsibility of the Handler to
// manage this concurrency.
//
// Users of the slog package should not invoke Handler methods directly.
// They should use the methods of [Logger] instead.
type Handler interface {
	// Enabled reports whether the handler handles records at the given level.
	// The handler ignores records whose level is lower.
	// It is called early, before any arguments are processed,
	// to save effort if the log event should be discarded.
	// If called from a Logger method, the first argument is the context
	// passed to that method, or context.Background() if nil was passed
	// or the method does not take a context.
	// The context is passed so Enabled can use its values
	// to make a decision.
	Enabled(context.Context, Level) bool

	// Handle handles the Record.
	// It will only be called when Enabled returns true.
	// The Context argument is as for Enabled.
	// It is present solely to provide Handlers access to the context's values.
	// Canceling the context should not affect record processing.
	// (Among other things, log messages may be necessary to debug a
	// cancellation-related problem.)
	//
	// Handle methods that produce output should observe the following rules:
	//   - If r.Time is the zero time, ignore the time.
	//   - If r.PC is zero, ignore it.
	//   - Attr's values should be resolved.
	//   - If an Attr's key and value are both the zero value, ignore the Attr.
	//     This can be tested with attr.Equal(Attr{}).
	//   - If a group's key is empty, inline the group's Attrs.
	//   - If a group has no Attrs (even if it has a non-empty key),
	//     ignore it.
	Handle(context.Context, Record) error

	// WithAttrs returns a new Handler whose attributes consist of
	// both the receiver's attributes and the arguments.
	// The Handler owns the slice: it may retain, modify or discard it.
	WithAttrs(attrs []Attr) Handler

	// WithGroup returns a new Handler with the given group appended to
	// the receiver's existing groups.
	// The keys of all subsequent attributes, whether added by With or in a
	// Record, should be qualified by the sequence of group names.
	//
	// How this qualification happens is up to the Handler, so long as
	// this Handler's attribute keys differ from those of another Handler
	// with a different sequence of group names.
	//
	// A Handler should treat WithGroup as starting a Group of Attrs that ends
	// at the end of the log event. That is,
	//
	//     logger.WithGroup("s").LogAttrs(ctx, level, msg, slog.Int("a", 1), slog.Int("b", 2))
	//
	// should behave like
	//
	//     logger.LogAttrs(ctx, level, msg, slog.Group("s", slog.Int("a", 1), slog.Int("b", 2)))
	//
	// If the name is empty, WithGroup returns the receiver.
	WithGroup(name string) Handler
}

type defaultHandler struct {
	ch *commonHandler
	// internal.DefaultOutput, except for testing
	output func(pc uintptr, data []byte) error
}

func newDefaultHandler(output func(uintptr, []byte) error) *defaultHandler {
	return &defaultHandler{
		ch:     &commonHandler{json: false},
		output: output,
	}
}

func (*defaultHandler) Enabled(_ context.Context, l Level) bool {
	return l >= logLoggerLevel.Level()
}

// Collect the level, attributes and message in a string and
// write it with the default log.Logger.
// Let the log.Logger handle time and file/line.
func (h *defaultHandler) Handle(ctx context.Context, r Record) error {
	buf := buffer.New()
	buf.WriteString(r.Level.String())
	buf.WriteByte(' ')
	buf.WriteString(r.Message)
	state := h.ch.newHandleState(buf, true, " ")
	defer state.free()
	state.appendNonBuiltIns(r)
	return h.output(r.PC, *buf)
}

func (h *defaultHandler) WithAttrs(as []Attr) Handler {
	return &defaultHandler{h.ch.withAttrs(as), h.output}
}

func (h *defaultHandler) WithGroup(name string) Handler {
	return &defaultHandler{h.ch.withGroup(name), h.output}
}

// HandlerOptions are options for a [TextHandler] or [JSONHandler].
// A zero HandlerOptions consists entirely of default values.
type HandlerOptions struct {
	// AddSource causes the handler to compute the source code position
	// of the log statement and add a SourceKey attribute to the output.
	AddSource bool

	// Level reports the minimum record level that will be logged.
	// The handler discards records with lower levels.
	// If Level is nil, the handler assumes LevelInfo.
	// The handler calls Level.Level for each record processed;
	// to adjust the minimum level dynamically, use a LevelVar.
	Level Leveler

	// ReplaceAttr is called to rewrite each non-group attribute before it is logged.
	// The attribute's value has been resolved (see [Value.Resolve]).
	// If ReplaceAttr returns a zero Attr, the attribute is discarded.
	//
	// The built-in attributes with keys "time", "level", "source", and "msg"
	// are passed to this function, except that time is omitted
	// if zero, and source is omitted if AddSource is false.
	//
	// The first argument is a list of currently open groups that contain the
	// Attr. It must not be retained or modified. ReplaceAttr is never called
	// for Group attributes, only their contents. For example, the attribute
	// list
	//
	//     Int("a", 1), Group("g", Int("b", 2)), Int("c", 3)
	//
	// results in consecutive calls to ReplaceAttr with the following arguments:
	//
	//     nil, Int("a", 1)
	//     []string{"g"}, Int("b", 2)
	//     nil, Int("c", 3)
	//
	// ReplaceAttr can be used to change the default keys of the built-in
	// attributes, convert types (for example, to replace a `time.Time` with the
	// integer seconds since the Unix epoch), sanitize personal information, or
	// remove attributes from the output.
	ReplaceAttr func(groups []string, a Attr) Attr
}

// Keys for "built-in" attributes.
const (
	// TimeKey is the key used by the built-in handlers for the time
	// when the log method is called. The associated Value is a [time.Time].
	TimeKey = "time"
	// LevelKey is the key used by the built-in handlers for the level
	// of the log call. The associated value is a [Level].
	LevelKey = "level"
	// MessageKey is the key used by the built-in handlers for the
	// message of the log call. The associated value is a string.
	MessageKey = "msg"
	// SourceKey is the key used by the built-in handlers for the source file
	// and line of the log call. The associated value is a *[Source].
	SourceKey = "source"
)

type commonHandler struct {
	json              bool // true => output JSON; false => output text
	opts              HandlerOptions
	preformattedAttrs []byte
	// groupPrefix is for the text handler only.
	// It holds the prefix for groups that were already pre-formatted.
	// A group will appear here when a call to WithGroup is followed by
	// a call to WithAttrs.
	groupPrefix string
	groups      []string // all groups started from WithGroup
	nOpenGroups int      // the number of groups opened in preformattedAttrs
	mu          *sync.Mutex
	w           io.Writer
}

func (h *commonHandler) clone() *commonHandler {
	// We can't use assignment because we can't copy the mutex.
	return &commonHandler{
		json:              h.json,
		opts:              h.opts,
		preformattedAttrs: slices.Clip(h.preformattedAttrs),
		groupPrefix:       h.groupPrefix,
		groups:            slices.Clip(h.groups),
		nOpenGroups:       h.nOpenGroups,
		w:                 h.w,
		mu:                h.mu, // mutex shared among all clones of this handler
	}
}

// enabled reports whether l is greater than or equal to the
// minimum level.
func (h *commonHandler) enabled(l Level) bool {
	minLevel := LevelInfo
	if h.opts.Level != nil {
		minLevel = h.opts.Level.Level()
	}
	return l >= minLevel
}

func (h *commonHandler) withAttrs(as []Attr) *commonHandler {
	// We are going to ignore empty groups, so if the entire slice consists of
	// them, there is nothing to do.
	if countEmptyGroups(as) == len(as) {
		return h
	}
	h2 := h.clone()
	// Pre-format the attributes as an optimization.
	state := h2.newHandleState((*buffer.Buffer)(&h2.preformattedAttrs), false, "")
	defer state.free()
	state.prefix.WriteString(h.groupPrefix)
	if pfa := h2.preformattedAttrs; len(pfa) > 0 {
		state.sep = h.attrSep()
		if h2.json && pfa[len(pfa)-1] == '{' {
			state.sep = ""
		}
	}
	// Remember the position in the buffer, in case all attrs are empty.
	pos := state.buf.Len()
	state.openGroups()
	if !state.appendAttrs(as) {
		state.buf.SetLen(pos)
	} else {
		// Remember the new prefix for later keys.
		h2.groupPrefix = state.prefix.String()
		// Remember how many opened groups are in preformattedAttrs,
		// so we don't open them again when we handle a Record.
		h2.nOpenGroups = len(h2.groups)
	}
	return h2
}

func (h *commonHandler) withGroup(name string) *commonHandler {
	h2 := h.clone()
	h2.groups = append(h2.groups, name)
	return h2
}

// handle is the internal implementation of Handler.Handle
// used by TextHandler and JSONHandler.
func (h *commonHandler) handle(r Record) error {
	state := h.newHandleState(buffer.New(), true, "")
	defer state.free()
	if h.json {
		state.buf.WriteByte('{')
	}
	// Built-in attributes. They are not in a group.
	stateGroups := state.groups
	state.groups = nil // So ReplaceAttrs sees no groups instead of the pre groups.
	rep := h.opts.ReplaceAttr
	// time
	if !r.Time.IsZero() {
		key := TimeKey
		val := r.Time.Round(0) // strip monotonic to match Attr behavior
		if rep == nil {
			state.appendKey(key)
			state.appendTime(val)
		} else {
			state.appendAttr(Time(key, val))
		}
	}
	// level
	key := LevelKey
	val := r.Level
	if rep == nil {
		state.appendKey(key)
		state.appendString(val.String())
	} else {
		state.appendAttr(Any(key, val))
	}
	// source
	if h.opts.AddSource {
		state.appendAttr(Any(SourceKey, r.source()))
	}
	key = MessageKey
	msg := r.Message
	if rep == nil {
		state.appendKey(key)
		state.appendString(msg)
	} else {
		state.appendAttr(String(key, msg))
	}
	state.groups = stateGroups // Restore groups passed to ReplaceAttrs.
	state.appendNonBuiltIns(r)
	state.buf.WriteByte('\n')

	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := h.w.Write(*state.buf)
	return err
}

func (s *handleState) appendNonBuiltIns(r Record) {
	// preformatted Attrs
	if pfa := s.h.preformattedAttrs; len(pfa) > 0 {
		s.buf.WriteString(s.sep)
		s.buf.Write(pfa)
		s.sep = s.h.attrSep()
		if s.h.json && pfa[len(pfa)-1] == '{' {
			s.sep = ""
		}
	}
	// Attrs in Record -- unlike the built-in ones, they are in groups started
	// from WithGroup.
	// If the record has no Attrs, don't output any groups.
	nOpenGroups := s.h.nOpenGroups
	if r.NumAttrs() > 0 {
		s.prefix.WriteString(s.h.groupPrefix)
		// The group may turn out to be empty even though it has attrs (for
		// example, ReplaceAttr may delete all the attrs).
		// So remember where we are in the buffer, to restore the position
		// later if necessary.
		pos := s.buf.Len()
		s.openGroups()
		nOpenGroups = len(s.h.groups)
		empty := true
		r.Attrs(func(a Attr) bool {
			if s.appendAttr(a) {
				empty = false
			}
			return true
		})
		if empty {
			s.buf.SetLen(pos)
			nOpenGroups = s.h.nOpenGroups
		}
	}
	if s.h.json {
		// Close all open groups.
		for range s.h.groups[:nOpenGroups] {
			s.buf.WriteByte('}')
		}
		// Close the top-level object.
		s.buf.WriteByte('}')
	}
}

// attrSep returns the separator between attributes.
func (h *commonHandler) attrSep() string {
	if h.json {
		return ","
	}
	return " "
}

// handleState holds state for a single call to commonHandler.handle.
// The initial value of sep determines whether to emit a separator
// before the next key, after which it stays true.
type handleState struct {
	h       *commonHandler
	buf     *buffer.Buffer
	freeBuf bool           // should buf be freed?
	sep     string         // separator to write before next key
	prefix  *buffer.Buffer // for text: key prefix
	groups  *[]string      // pool-allocated slice of active groups, for ReplaceAttr
}

var groupPool = sync.Pool{New: func() any {
	s := make([]string, 0, 10)
	return &s
}}

func (h *commonHandler) newHandleState(buf *buffer.Buffer, freeBuf bool, sep string) handleState {
	s := handleState{
		h:       h,
		buf:     buf,
		freeBuf: freeBuf,
		sep:     sep,
		prefix:  buffer.New(),
	}
	if h.opts.ReplaceAttr != nil {
		s.groups = groupPool.Get().(*[]string)
		*s.groups = append(*s.groups, h.groups[:h.nOpenGroups]...)
	}
	return s
}

func (s *handleState) free() {
	if s.freeBuf {
		s.buf.Free()
	}
	if gs := s.groups; gs != nil {
		*gs = (*gs)[:0]
		groupPool.Put(gs)
	}
	s.prefix.Free()
}

func (s *handleState) openGroups() {
	for _, n := range s.h.groups[s.h.nOpenGroups:] {
		s.openGroup(n)
	}
}

// Separator for group names and keys.
const keyComponentSep = '.'

// openGroup starts a new group of attributes
// with the given name.
func (s *handleState) openGroup(name string) {
	if s.h.json {
		s.appendKey(name)
		s.buf.WriteByte('{')
		s.sep = ""
	} else {
		s.prefix.WriteString(name)
		s.prefix.WriteByte(keyComponentSep)
	}
	// Collect group names for ReplaceAttr.
	if s.groups != nil {
		*s.groups = append(*s.groups, name)
	}
}

// closeGroup ends the group with the given name.
func (s *handleState) closeGroup(name string) {
	if s.h.json {
		s.buf.WriteByte('}')
	} else {
		(*s.prefix) = (*s.prefix)[:len(*s.prefix)-len(name)-1 /* for keyComponentSep */]
	}
	s.sep = s.h.attrSep()
	if s.groups != nil {
		*s.groups = (*s.groups)[:len(*s.groups)-1]
	}
}

// appendAttrs appends the slice of Attrs.
// It reports whether something was appended.
func (s *handleState) appendAttrs(as []Attr) bool {
	nonEmpty := false
	for _, a := range as {
		if s.appendAttr(a) {
			nonEmpty = true
		}
	}
	return nonEmpty
}

// appendAttr appends the Attr's key and value.
// It handles replacement and checking for an empty key.
// It reports whether something was appended.
func (s *handleState) appendAttr(a Attr) bool {
	a.Value = a.Value.Resolve()
	if rep := s.h.opts.ReplaceAttr; rep != nil && a.Value.Kind() != KindGroup {
		var gs []string
		if s.groups != nil {
			gs = *s.groups
		}
		// a.Value is resolved before calling ReplaceAttr, so the user doesn't have to.
		a = rep(gs, a)
		// The ReplaceAttr function may return an unresolved Attr.
		a.Value = a.Value.Resolve()
	}
	// Elide empty Attrs.
	if a.isEmpty() {
		return false
	}
	// Special case: Source.
	if v := a.Value; v.Kind() == KindAny {
		if src, ok := v.Any().(*Source); ok {
			if s.h.json {
				a.Value = src.group()
			} else {
				a.Value = StringValue(fmt.Sprintf("%s:%d", src.File, src.Line))
			}
		}
	}
	if a.Value.Kind() == KindGroup {
		attrs := a.Value.Group()
		// Output only non-empty groups.
		if len(attrs) > 0 {
			// The group may turn out to be empty even though it has attrs (for
			// example, ReplaceAttr may delete all the attrs).
			// So remember where we are in the buffer, to restore the position
			// later if necessary.
			pos := s.buf.Len()
			// Inline a group with an empty key.
			if a.Key != "" {
				s.openGroup(a.Key)
			}
			if !s.appendAttrs(attrs) {
				s.buf.SetLen(pos)
				return false
			}
			if a.Key != "" {
				s.closeGroup(a.Key)
			}
		}
	} else {
		s.appendKey(a.Key)
		s.appendValue(a.Value)
	}
	return true
}

func (s *handleState) appendError(err error) {
	s.appendString(fmt.Sprintf("!ERROR:%v", err))
}

func (s *handleState) appendKey(key string) {
	s.buf.WriteString(s.sep)
	if s.prefix != nil && len(*s.prefix) > 0 {
		// TODO: optimize by avoiding allocation.
		s.appendString(string(*s.prefix) + key)
	} else {
		s.appendString(key)
	}
	if s.h.json {
		s.buf.WriteByte(':')
	} else {
		s.buf.WriteByte('=')
	}
	s.sep = s.h.attrSep()
}

func (s *handleState) appendString(str string) {
	if s.h.json {
		s.buf.WriteByte('"')
		*s.buf = appendEscapedJSONString(*s.buf, str)
		s.buf.WriteByte('"')
	} else {
		// text
		if needsQuoting(str) {
			*s.buf = strconv.AppendQuote(*s.buf, str)
		} else {
			s.buf.WriteString(str)
		}
	}
}

func (s *handleState) appendValue(v Value) {
	defer func() {
		if r := recover(); r != nil {
			// If it panics with a nil pointer, the most likely cases are
			// an encoding.TextMarshaler or error fails to guard against nil,
			// in which case "<nil>" seems to be the feasible choice.
			//
			// Adapted from the code in fmt/print.go.
			if v := reflect.ValueOf(v.any); v.Kind() == reflect.Pointer && v.IsNil() {
				s.appendString("<nil>")
				return
			}

			// Otherwise just print the original panic message.
			s.appendString(fmt.Sprintf("!PANIC: %v", r))
		}
	}()

	var err error
	if s.h.json {
		err = appendJSONValue(s, v)
	} else {
		err = appendTextValue(s, v)
	}
	if err != nil {
		s.appendError(err)
	}
}

func (s *handleState) appendTime(t time.Time) {
	if s.h.json {
		appendJSONTime(s, t)
	} else {
		*s.buf = appendRFC3339Millis(*s.buf, t)
	}
}

func appendRFC3339Millis(b []byte, t time.Time) []byte {
	// Format according to time.RFC3339Nano since it is highly optimized,
	// but truncate it to use millisecond resolution.
	// Unfortunately, that format trims trailing 0s, so add 1/10 millisecond
	// to guarantee that there are exactly 4 digits after the period.
	const prefixLen = len("2006-01-02T15:04:05.000")
	n := len(b)
	t = t.Truncate(time.Millisecond).Add(time.Millisecond / 10)
	b = t.AppendFormat(b, time.RFC3339Nano)
	b = append(b[:n+prefixLen], b[n+prefixLen+1:]...) // drop the 4th digit
	return b
}

// DiscardHandler discards all log output.
// DiscardHandler.Enabled returns false for all Levels.
var DiscardHandler Handler = discardHandler{}

type discardHandler struct{}

func (dh discardHandler) Enabled(context.Context, Level) bool  { return false }
func (dh discardHandler) Handle(context.Context, Record) error { return nil }
func (dh discardHandler) WithAttrs(attrs []Attr) Handler       { return dh }
func (dh discardHandler) WithGroup(name string) Handler        { return dh }

"""



```