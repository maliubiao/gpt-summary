Response:
Let's break down the thought process for analyzing the Go `log` package code.

1. **Understand the Core Functionality:**  The first step is to read the package documentation comment. It clearly states the purpose: a simple logging package. Key takeaways are the `Logger` type, predefined standard logger, outputting to standard error with date/time, and the existence of `Fatal` and `Panic` functions.

2. **Identify Key Structures:** Scan the code for the main data structures. The `Logger` struct is central. Note its fields: `outMu` (mutex for thread safety), `out` (where logs go), `prefix` (for messages), `flag` (control output format), and `isDiscard` (optimization). Also, the `std` variable as the default logger is important.

3. **Analyze Public Interface:** Focus on the exported types and functions. This defines how users interact with the package. The `Logger` type and its methods (`New`, `SetOutput`, `SetPrefix`, `SetFlags`, `Writer`, `Output`, `Print`, `Printf`, `Println`, `Fatal`, `Fatalf`, `Fatalln`, `Panic`, `Panicf`, `Panicln`, `Flags`, `Prefix`) are the core API. The package-level functions (`Default`, `Print`, `Printf`, etc.) that use the standard logger are also key.

4. **Examine Core Logging Logic:**  The `Output` and `output` methods are the heart of the logging process. Trace the flow:
    * Check if logging is disabled (`isDiscard`).
    * Get the current time.
    * Load prefix and flags.
    * Determine file and line number (if flags require it).
    * Get a buffer from the pool.
    * Format the header using `formatHeader`.
    * Append the log message.
    * Add a newline if necessary.
    * Lock the output mutex.
    * Write to the output.
    * Release the mutex.
    * Return any errors.

5. **Understand the Flags:** The `const` block defining `Ldate`, `Ltime`, etc., is crucial for controlling the output format. Note the bitwise OR usage and how they affect the header.

6. **Infer Go Features:**  Based on the code, identify the Go features being used:
    * **Packages:** The fundamental organization of Go code.
    * **Structs:** `Logger` to group related data.
    * **Methods:** Functions associated with structs (e.g., `l.Print()`).
    * **Interfaces:** `io.Writer` for abstracting output destinations.
    * **Constants:** `Ldate`, `Ltime`, etc., for configuration.
    * **Variables:** `std` for the standard logger.
    * **Functions:** `New`, `Print`, `Output`, etc.
    * **Concurrency:** `sync.Mutex` for thread safety, `atomic.Pointer` and `atomic.Int32` for safe access to prefix and flags, and `sync.Pool` for buffer reuse.
    * **Error Handling:** Returning `error`.
    * **Time Handling:** `time.Time`.
    * **String Formatting:** `fmt` package.
    * **Runtime Information:** `runtime.Caller` and `runtime.CallersFrames`.
    * **Exiting the Program:** `os.Exit`.
    * **Panic and Recover (Implicit):** The `Panic` functions trigger panics.

7. **Construct Example Code:**  Choose a few key functionalities to illustrate with examples. Demonstrate creating a custom logger, using the standard logger, setting flags, and setting the prefix. This makes the explanation more concrete.

8. **Consider Command-Line Arguments:** While this specific code doesn't directly handle command-line arguments, note that the output destination could be influenced by them (e.g., logging to a file specified as an argument). Explain how a user might integrate command-line flags to control the logging behavior.

9. **Identify Potential Pitfalls:** Think about common mistakes users might make:
    * Modifying the standard logger's flags globally affecting other parts of the application.
    * Forgetting that `Fatal` and `Panic` terminate the program.
    * Not understanding the thread safety provided by the `Logger`.

10. **Structure the Answer:** Organize the information logically. Start with the core functionality, then delve into specific aspects like flags, example code, command-line arguments, and potential pitfalls. Use clear headings and bullet points for readability. Use code blocks for examples.

11. **Refine and Review:** Read through the answer to ensure clarity, accuracy, and completeness. Check for any inconsistencies or areas that could be explained better. Make sure the language is clear and easy to understand for someone learning about the `log` package.

By following this systematic approach, we can comprehensively analyze the given code snippet and provide a well-structured and informative answer.
这段代码是 Go 语言标准库 `log` 包的一部分，它实现了一个简单的日志记录功能。以下是它的主要功能：

**1. 提供基础的日志记录能力:**

* **`Logger` 类型:** 定义了一个 `Logger` 结构体，它是日志记录的核心对象。它可以将格式化的日志信息输出到指定的 `io.Writer`。
* **标准 Logger:**  预定义了一个名为 `std` 的标准 `Logger` 实例，它默认将日志输出到标准错误 (`os.Stderr`)，并包含日期和时间前缀。
* **辅助函数:** 提供了一系列辅助函数，如 `Print`, `Printf`, `Println`, `Fatal`, `Fatalf`, `Fatalln`, `Panic`, `Panicf`, `Panicln`，这些函数使用标准 `Logger` 进行日志记录，方便用户快速使用。

**2. 控制日志输出格式:**

* **Flags (标志位):**  定义了一组常量（`Ldate`, `Ltime`, `Lmicroseconds`, `Llongfile`, `Lshortfile`, `LUTC`, `Lmsgprefix`, `LstdFlags`），用于控制日志条目的前缀信息。用户可以通过组合这些标志位来定制日志输出的内容，例如是否包含日期、时间、毫秒、完整文件名、短文件名等。
* **Prefix (前缀):**  允许用户为每个 `Logger` 实例设置一个自定义的前缀字符串，用于标识日志来源。

**3. 支持自定义输出目标:**

* **`io.Writer` 接口:** `Logger` 的输出目标是一个实现了 `io.Writer` 接口的对象，这意味着可以将日志输出到任何实现了该接口的地方，例如文件、网络连接等。
* **`SetOutput` 方法:**  提供了 `SetOutput` 方法，可以更改 `Logger` 实例的输出目标。

**4. 提供程序终止选项:**

* **`Fatal` 系列函数:**  在输出日志信息后，会调用 `os.Exit(1)` 终止程序。
* **`Panic` 系列函数:** 在输出日志信息后，会调用 `panic()` 引发 panic。

**5. 线程安全:**

* **`sync.Mutex`:** 使用互斥锁 `outMu` 来保护对输出目标 `out` 的并发访问，确保在多 goroutine 环境下日志输出的原子性。
* **`atomic.Pointer` 和 `atomic.Int32`:** 使用原子操作来安全地访问和更新 `prefix` 和 `flag`，避免数据竞争。

**推理它是什么 go 语言功能的实现:**

这个 `log` 包实现了 **日志记录** 功能。  它允许开发者在程序运行时记录事件、错误信息等，方便调试和监控。

**Go 代码举例说明:**

```go
package main

import (
	"log"
	"os"
)

func main() {
	// 使用标准 logger 输出信息
	log.Println("这是一条使用标准 logger 的日志信息")

	// 使用 Printf 格式化输出
	name := "World"
	log.Printf("Hello, %s!\n", name)

	// 设置标准 logger 的 flags，包含完整文件名和行号
	log.SetFlags(log.LstdFlags | log.Llongfile)
	log.Println("这条日志包含了完整的文件名和行号")

	// 创建一个新的 logger，输出到文件
	file, err := os.OpenFile("my.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatal("无法打开日志文件:", err)
	}
	defer file.Close()

	myLogger := log.New(file, "MY-APP: ", log.Ldate|log.Ltime)
	myLogger.Println("这是一条来自 myLogger 的日志信息")

	// 使用 Fatal 函数输出并退出程序
	// log.Fatal("发生严重错误，程序退出")

	// 使用 Panic 函数输出并触发 panic
	// log.Panic("发生不可恢复的错误，程序 panic")
}
```

**假设的输入与输出:**

假设我们运行上面的 `main.go` 代码，并且当前日期是 2023年10月27日，时间是 10:30:00。

**标准 logger 输出 (到 stderr):**

```
2023/10/27 10:30:00 这是一条使用标准 logger 的日志信息
2023/10/27 10:30:00 Hello, World!
/path/to/your/main.go:16: 这条日志包含了完整的文件名和行号
```

**自定义 logger 输出 (到 my.log 文件):**

```
2023/10/27 10:30:00 MY-APP: 这是一条来自 myLogger 的日志信息
```

**命令行参数的具体处理:**

这个 `log` 包本身 **不直接处理命令行参数**。  它专注于提供日志记录功能。如果你需要根据命令行参数来配置日志行为（例如，设置日志级别、输出目标等），你需要 **在你的应用程序代码中** 解析命令行参数，并使用 `log` 包提供的 API 来配置 `Logger` 实例。

例如，你可以使用 `flag` 包来解析命令行参数，然后根据参数值调用 `log.SetOutput()` 或 `log.SetFlags()`：

```go
package main

import (
	"flag"
	"log"
	"os"
)

func main() {
	logFile := flag.String("log", "", "日志文件路径")
	debugMode := flag.Bool("debug", false, "开启调试模式")
	flag.Parse()

	if *logFile != "" {
		file, err := os.OpenFile(*logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			log.Fatalf("无法打开日志文件: %v", err)
		}
		defer file.Close()
		log.SetOutput(file)
	}

	if *debugMode {
		log.SetFlags(log.LstdFlags | log.Llongfile)
		log.Println("调试模式已开启")
	}

	log.Println("程序开始运行")
}
```

在这个例子中，用户可以通过 `--log` 参数指定日志文件路径，通过 `--debug` 参数开启调试模式（包含更详细的日志信息）。

**使用者易犯错的点:**

1. **全局修改标准 Logger 的配置:**  使用 `log.SetFlags()` 或 `log.SetPrefix()` 会影响 **全局的** 标准 `Logger` 实例。如果在多个包中使用标准 `Logger`，并且在一个地方修改了其配置，可能会影响到其他包的日志输出。

   ```go
   // package a
   import "log"

   func SomeFunctionA() {
       log.SetPrefix("[A] ")
       log.Println("来自 A 的日志")
   }

   // package b
   import "log"

   func SomeFunctionB() {
       log.Println("来自 B 的日志") // 这里的日志前缀也会受到 package a 的影响
   }
   ```

   **解决方法:** 如果需要在不同的模块中使用不同的日志配置，应该创建 **独立的 `Logger` 实例**。

2. **误用 `Fatal` 和 `Panic` 系列函数:**  `Fatal` 函数会调用 `os.Exit(1)` 立即终止程序，而 `Panic` 函数会引发 panic。  不恰当的使用会导致程序意外退出或崩溃。

   ```go
   // 错误示例：在不应该终止程序的情况下使用了 log.Fatal
   func processData(data string) {
       if data == "" {
           log.Fatal("数据为空，无法处理") // 这会导致整个程序退出
           return
       }
       // ... 处理数据
   }
   ```

   **解决方法:**  `Fatal` 和 `Panic` 应该仅用于处理 **无法恢复的严重错误**。对于可以处理的错误，应该使用 `log.Println` 或其他日志函数记录错误，并采取适当的恢复措施。

3. **忽略 `io.Writer` 的错误:** 当将日志输出到文件或其他 `io.Writer` 时，`Write` 方法可能会返回错误。  忽略这些错误可能导致日志丢失或其他问题。

   虽然 `log` 包的 `Output` 方法目前没有显式处理 `io.Writer.Write` 的错误并返回，但在实际应用中，当你自定义 `Logger` 并使用 `io.Writer` 时，你应该检查 `Write` 的返回值。

4. **在高并发场景下频繁调用标准 Logger 的设置方法:** 虽然 `Logger` 内部使用了锁来保证并发安全，但频繁地调用 `SetFlags` 或 `SetPrefix` 仍然可能带来性能损耗，因为这些操作会涉及到锁的竞争。如果你的应用程序需要高吞吐量的日志记录，并且需要动态调整日志配置，考虑使用专门为高性能日志记录设计的库。

Prompt: 
```
这是路径为go/src/log/log.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package log implements a simple logging package. It defines a type, [Logger],
// with methods for formatting output. It also has a predefined 'standard'
// Logger accessible through helper functions Print[f|ln], Fatal[f|ln], and
// Panic[f|ln], which are easier to use than creating a Logger manually.
// That logger writes to standard error and prints the date and time
// of each logged message.
// Every log message is output on a separate line: if the message being
// printed does not end in a newline, the logger will add one.
// The Fatal functions call [os.Exit](1) after writing the log message.
// The Panic functions call panic after writing the log message.
package log

import (
	"fmt"
	"io"
	"log/internal"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// These flags define which text to prefix to each log entry generated by the [Logger].
// Bits are or'ed together to control what's printed.
// With the exception of the Lmsgprefix flag, there is no
// control over the order they appear (the order listed here)
// or the format they present (as described in the comments).
// The prefix is followed by a colon only when Llongfile or Lshortfile
// is specified.
// For example, flags Ldate | Ltime (or LstdFlags) produce,
//
//	2009/01/23 01:23:23 message
//
// while flags Ldate | Ltime | Lmicroseconds | Llongfile produce,
//
//	2009/01/23 01:23:23.123123 /a/b/c/d.go:23: message
const (
	Ldate         = 1 << iota     // the date in the local time zone: 2009/01/23
	Ltime                         // the time in the local time zone: 01:23:23
	Lmicroseconds                 // microsecond resolution: 01:23:23.123123.  assumes Ltime.
	Llongfile                     // full file name and line number: /a/b/c/d.go:23
	Lshortfile                    // final file name element and line number: d.go:23. overrides Llongfile
	LUTC                          // if Ldate or Ltime is set, use UTC rather than the local time zone
	Lmsgprefix                    // move the "prefix" from the beginning of the line to before the message
	LstdFlags     = Ldate | Ltime // initial values for the standard logger
)

// A Logger represents an active logging object that generates lines of
// output to an [io.Writer]. Each logging operation makes a single call to
// the Writer's Write method. A Logger can be used simultaneously from
// multiple goroutines; it guarantees to serialize access to the Writer.
type Logger struct {
	outMu sync.Mutex
	out   io.Writer // destination for output

	prefix    atomic.Pointer[string] // prefix on each line to identify the logger (but see Lmsgprefix)
	flag      atomic.Int32           // properties
	isDiscard atomic.Bool
}

// New creates a new [Logger]. The out variable sets the
// destination to which log data will be written.
// The prefix appears at the beginning of each generated log line, or
// after the log header if the [Lmsgprefix] flag is provided.
// The flag argument defines the logging properties.
func New(out io.Writer, prefix string, flag int) *Logger {
	l := new(Logger)
	l.SetOutput(out)
	l.SetPrefix(prefix)
	l.SetFlags(flag)
	return l
}

// SetOutput sets the output destination for the logger.
func (l *Logger) SetOutput(w io.Writer) {
	l.outMu.Lock()
	defer l.outMu.Unlock()
	l.out = w
	l.isDiscard.Store(w == io.Discard)
}

var std = New(os.Stderr, "", LstdFlags)

// Default returns the standard logger used by the package-level output functions.
func Default() *Logger { return std }

// Cheap integer to fixed-width decimal ASCII. Give a negative width to avoid zero-padding.
func itoa(buf *[]byte, i int, wid int) {
	// Assemble decimal in reverse order.
	var b [20]byte
	bp := len(b) - 1
	for i >= 10 || wid > 1 {
		wid--
		q := i / 10
		b[bp] = byte('0' + i - q*10)
		bp--
		i = q
	}
	// i < 10
	b[bp] = byte('0' + i)
	*buf = append(*buf, b[bp:]...)
}

// formatHeader writes log header to buf in following order:
//   - l.prefix (if it's not blank and Lmsgprefix is unset),
//   - date and/or time (if corresponding flags are provided),
//   - file and line number (if corresponding flags are provided),
//   - l.prefix (if it's not blank and Lmsgprefix is set).
func formatHeader(buf *[]byte, t time.Time, prefix string, flag int, file string, line int) {
	if flag&Lmsgprefix == 0 {
		*buf = append(*buf, prefix...)
	}
	if flag&(Ldate|Ltime|Lmicroseconds) != 0 {
		if flag&LUTC != 0 {
			t = t.UTC()
		}
		if flag&Ldate != 0 {
			year, month, day := t.Date()
			itoa(buf, year, 4)
			*buf = append(*buf, '/')
			itoa(buf, int(month), 2)
			*buf = append(*buf, '/')
			itoa(buf, day, 2)
			*buf = append(*buf, ' ')
		}
		if flag&(Ltime|Lmicroseconds) != 0 {
			hour, min, sec := t.Clock()
			itoa(buf, hour, 2)
			*buf = append(*buf, ':')
			itoa(buf, min, 2)
			*buf = append(*buf, ':')
			itoa(buf, sec, 2)
			if flag&Lmicroseconds != 0 {
				*buf = append(*buf, '.')
				itoa(buf, t.Nanosecond()/1e3, 6)
			}
			*buf = append(*buf, ' ')
		}
	}
	if flag&(Lshortfile|Llongfile) != 0 {
		if flag&Lshortfile != 0 {
			short := file
			for i := len(file) - 1; i > 0; i-- {
				if file[i] == '/' {
					short = file[i+1:]
					break
				}
			}
			file = short
		}
		*buf = append(*buf, file...)
		*buf = append(*buf, ':')
		itoa(buf, line, -1)
		*buf = append(*buf, ": "...)
	}
	if flag&Lmsgprefix != 0 {
		*buf = append(*buf, prefix...)
	}
}

var bufferPool = sync.Pool{New: func() any { return new([]byte) }}

func getBuffer() *[]byte {
	p := bufferPool.Get().(*[]byte)
	*p = (*p)[:0]
	return p
}

func putBuffer(p *[]byte) {
	// Proper usage of a sync.Pool requires each entry to have approximately
	// the same memory cost. To obtain this property when the stored type
	// contains a variably-sized buffer, we add a hard limit on the maximum buffer
	// to place back in the pool.
	//
	// See https://go.dev/issue/23199
	if cap(*p) > 64<<10 {
		*p = nil
	}
	bufferPool.Put(p)
}

// Output writes the output for a logging event. The string s contains
// the text to print after the prefix specified by the flags of the
// Logger. A newline is appended if the last character of s is not
// already a newline. Calldepth is used to recover the PC and is
// provided for generality, although at the moment on all pre-defined
// paths it will be 2.
func (l *Logger) Output(calldepth int, s string) error {
	calldepth++ // +1 for this frame.
	return l.output(0, calldepth, func(b []byte) []byte {
		return append(b, s...)
	})
}

// output can take either a calldepth or a pc to get source line information.
// It uses the pc if it is non-zero.
func (l *Logger) output(pc uintptr, calldepth int, appendOutput func([]byte) []byte) error {
	if l.isDiscard.Load() {
		return nil
	}

	now := time.Now() // get this early.

	// Load prefix and flag once so that their value is consistent within
	// this call regardless of any concurrent changes to their value.
	prefix := l.Prefix()
	flag := l.Flags()

	var file string
	var line int
	if flag&(Lshortfile|Llongfile) != 0 {
		if pc == 0 {
			var ok bool
			_, file, line, ok = runtime.Caller(calldepth)
			if !ok {
				file = "???"
				line = 0
			}
		} else {
			fs := runtime.CallersFrames([]uintptr{pc})
			f, _ := fs.Next()
			file = f.File
			if file == "" {
				file = "???"
			}
			line = f.Line
		}
	}

	buf := getBuffer()
	defer putBuffer(buf)
	formatHeader(buf, now, prefix, flag, file, line)
	*buf = appendOutput(*buf)
	if len(*buf) == 0 || (*buf)[len(*buf)-1] != '\n' {
		*buf = append(*buf, '\n')
	}

	l.outMu.Lock()
	defer l.outMu.Unlock()
	_, err := l.out.Write(*buf)
	return err
}

func init() {
	internal.DefaultOutput = func(pc uintptr, data []byte) error {
		return std.output(pc, 0, func(buf []byte) []byte {
			return append(buf, data...)
		})
	}
}

// Print calls l.Output to print to the logger.
// Arguments are handled in the manner of [fmt.Print].
func (l *Logger) Print(v ...any) {
	l.output(0, 2, func(b []byte) []byte {
		return fmt.Append(b, v...)
	})
}

// Printf calls l.Output to print to the logger.
// Arguments are handled in the manner of [fmt.Printf].
func (l *Logger) Printf(format string, v ...any) {
	l.output(0, 2, func(b []byte) []byte {
		return fmt.Appendf(b, format, v...)
	})
}

// Println calls l.Output to print to the logger.
// Arguments are handled in the manner of [fmt.Println].
func (l *Logger) Println(v ...any) {
	l.output(0, 2, func(b []byte) []byte {
		return fmt.Appendln(b, v...)
	})
}

// Fatal is equivalent to l.Print() followed by a call to [os.Exit](1).
func (l *Logger) Fatal(v ...any) {
	l.Output(2, fmt.Sprint(v...))
	os.Exit(1)
}

// Fatalf is equivalent to l.Printf() followed by a call to [os.Exit](1).
func (l *Logger) Fatalf(format string, v ...any) {
	l.Output(2, fmt.Sprintf(format, v...))
	os.Exit(1)
}

// Fatalln is equivalent to l.Println() followed by a call to [os.Exit](1).
func (l *Logger) Fatalln(v ...any) {
	l.Output(2, fmt.Sprintln(v...))
	os.Exit(1)
}

// Panic is equivalent to l.Print() followed by a call to panic().
func (l *Logger) Panic(v ...any) {
	s := fmt.Sprint(v...)
	l.Output(2, s)
	panic(s)
}

// Panicf is equivalent to l.Printf() followed by a call to panic().
func (l *Logger) Panicf(format string, v ...any) {
	s := fmt.Sprintf(format, v...)
	l.Output(2, s)
	panic(s)
}

// Panicln is equivalent to l.Println() followed by a call to panic().
func (l *Logger) Panicln(v ...any) {
	s := fmt.Sprintln(v...)
	l.Output(2, s)
	panic(s)
}

// Flags returns the output flags for the logger.
// The flag bits are [Ldate], [Ltime], and so on.
func (l *Logger) Flags() int {
	return int(l.flag.Load())
}

// SetFlags sets the output flags for the logger.
// The flag bits are [Ldate], [Ltime], and so on.
func (l *Logger) SetFlags(flag int) {
	l.flag.Store(int32(flag))
}

// Prefix returns the output prefix for the logger.
func (l *Logger) Prefix() string {
	if p := l.prefix.Load(); p != nil {
		return *p
	}
	return ""
}

// SetPrefix sets the output prefix for the logger.
func (l *Logger) SetPrefix(prefix string) {
	l.prefix.Store(&prefix)
}

// Writer returns the output destination for the logger.
func (l *Logger) Writer() io.Writer {
	l.outMu.Lock()
	defer l.outMu.Unlock()
	return l.out
}

// SetOutput sets the output destination for the standard logger.
func SetOutput(w io.Writer) {
	std.SetOutput(w)
}

// Flags returns the output flags for the standard logger.
// The flag bits are [Ldate], [Ltime], and so on.
func Flags() int {
	return std.Flags()
}

// SetFlags sets the output flags for the standard logger.
// The flag bits are [Ldate], [Ltime], and so on.
func SetFlags(flag int) {
	std.SetFlags(flag)
}

// Prefix returns the output prefix for the standard logger.
func Prefix() string {
	return std.Prefix()
}

// SetPrefix sets the output prefix for the standard logger.
func SetPrefix(prefix string) {
	std.SetPrefix(prefix)
}

// Writer returns the output destination for the standard logger.
func Writer() io.Writer {
	return std.Writer()
}

// These functions write to the standard logger.

// Print calls Output to print to the standard logger.
// Arguments are handled in the manner of [fmt.Print].
func Print(v ...any) {
	std.output(0, 2, func(b []byte) []byte {
		return fmt.Append(b, v...)
	})
}

// Printf calls Output to print to the standard logger.
// Arguments are handled in the manner of [fmt.Printf].
func Printf(format string, v ...any) {
	std.output(0, 2, func(b []byte) []byte {
		return fmt.Appendf(b, format, v...)
	})
}

// Println calls Output to print to the standard logger.
// Arguments are handled in the manner of [fmt.Println].
func Println(v ...any) {
	std.output(0, 2, func(b []byte) []byte {
		return fmt.Appendln(b, v...)
	})
}

// Fatal is equivalent to [Print] followed by a call to [os.Exit](1).
func Fatal(v ...any) {
	std.Output(2, fmt.Sprint(v...))
	os.Exit(1)
}

// Fatalf is equivalent to [Printf] followed by a call to [os.Exit](1).
func Fatalf(format string, v ...any) {
	std.Output(2, fmt.Sprintf(format, v...))
	os.Exit(1)
}

// Fatalln is equivalent to [Println] followed by a call to [os.Exit](1).
func Fatalln(v ...any) {
	std.Output(2, fmt.Sprintln(v...))
	os.Exit(1)
}

// Panic is equivalent to [Print] followed by a call to panic().
func Panic(v ...any) {
	s := fmt.Sprint(v...)
	std.Output(2, s)
	panic(s)
}

// Panicf is equivalent to [Printf] followed by a call to panic().
func Panicf(format string, v ...any) {
	s := fmt.Sprintf(format, v...)
	std.Output(2, s)
	panic(s)
}

// Panicln is equivalent to [Println] followed by a call to panic().
func Panicln(v ...any) {
	s := fmt.Sprintln(v...)
	std.Output(2, s)
	panic(s)
}

// Output writes the output for a logging event. The string s contains
// the text to print after the prefix specified by the flags of the
// Logger. A newline is appended if the last character of s is not
// already a newline. Calldepth is the count of the number of
// frames to skip when computing the file name and line number
// if [Llongfile] or [Lshortfile] is set; a value of 1 will print the details
// for the caller of Output.
func Output(calldepth int, s string) error {
	return std.Output(calldepth+1, s) // +1 for this frame.
}

"""



```