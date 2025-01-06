Response:
My thought process to answer the request about `test2json.go` goes like this:

1. **Understand the Core Purpose:** The initial comments and the package name itself (`test2json`) clearly indicate that this code is responsible for converting the output of Go test binaries into a JSON format. This is the central function.

2. **Identify Key Data Structures:** I look for the main data structures that represent the input and output. The `Converter` struct is the primary actor, handling the conversion process. The `event` struct defines the structure of the JSON output. The `lineBuffer` is a utility for processing input line by line.

3. **Analyze the Conversion Process:** I trace the flow of data. Input comes into the `Write` method of the `Converter`. The `handleInputLine` function is the core logic for parsing the test output lines. It identifies different types of lines (start, run, pass, fail, output, etc.) and extracts relevant information. The parsed information is then used to create `event` structs, which are marshaled into JSON and written to the output `io.Writer`.

4. **Focus on Functionality:** I go through the methods of the `Converter` to list its capabilities:
    * Conversion of test output to JSON.
    * Handling different event types (start, output, pass, fail, skip, bench, pause, continue, name).
    * Including timestamps (optional).
    * Attributing output to specific tests/subtests.
    * Handling build failures.
    * Supporting concurrent test execution.

5. **Infer Go Language Features:**  Based on the code, I identify the Go features being used:
    * **`encoding/json`:** For marshaling Go structs into JSON.
    * **`io.Writer` and `io.WriteCloser`:** For handling input and output streams.
    * **`time` package:** For handling timestamps and elapsed times.
    * **String manipulation:** Using `strings` and `bytes` packages for parsing.
    * **`unicode/utf8`:** For handling UTF-8 encoded text, especially when splitting long lines.
    * **Bitwise operations:**  For the `Mode` type and its flags.
    * **Struct tags:**  For controlling JSON field names and omitempty behavior.
    * **Custom Marshaler (`MarshalText`):** The `textBytes` type demonstrates this for efficient string conversion of byte slices.

6. **Construct Code Examples:** For each inferred Go feature, I create concise examples that illustrate its usage within the context of `test2json.go`. This involves:
    * Showing how `json.Marshal` is used with the `event` struct.
    * Demonstrating the `io.Writer` interface.
    * Illustrating the `time.Now()` usage.
    * Showing basic string/byte manipulation like `strings.HasPrefix`.
    * Giving an example of the `Mode` flag.
    * Showing the `textBytes` custom marshaler.

7. **Address Command Line Parameters:** I examine how the `NewConverter` function is used. It takes an `io.Writer`, a package name (`pkg`), and a `Mode`. The `Mode` is the key to command-line influence. I explain how the `cmd/test2json` (or `go test -json`) tool would likely set the `Timestamp` flag to include timestamps in the JSON output.

8. **Identify Potential Pitfalls:** I consider common user errors:
    * **Incorrectly parsing the JSON:** Users might not understand the structure of the JSON output, especially the nested nature of subtests.
    * **Assuming order of output:**  While the tool aims to preserve order, relying on a strict, unbroken sequence of events might be problematic in highly concurrent tests.
    * **Not handling the `FailedBuild` field:** Users analyzing test failures might miss the `FailedBuild` information, which points to the root cause of a build problem.

9. **Structure the Answer:** I organize the information logically with clear headings and examples to make it easy to understand. I start with the core functionality and gradually delve into more specific details like Go features, command-line parameters, and potential pitfalls.

10. **Refine and Review:** I review my answer to ensure accuracy, clarity, and completeness. I check that the code examples are correct and relevant.

By following these steps, I can systematically analyze the provided Go code and generate a comprehensive and informative answer that addresses all aspects of the user's request.
`go/src/cmd/internal/test2json/test2json.go` 文件的主要功能是将 Go 测试二进制文件的输出转换为 JSON 格式。这使得测试输出更易于机器解析，方便构建各种测试报告、监控系统或集成到其他工具中。

以下是该文件的具体功能点：

**1. 转换测试输出为 JSON:**

这是该包的核心功能。它接收 Go 测试二进制文件的标准输出，并将其解析成一系列 JSON 事件。这些事件描述了测试的各个阶段，例如测试的开始、运行、暂停、继续、通过、失败、跳过以及输出信息等。

**2. 支持不同的事件类型:**

`test2json` 可以识别并转换以下类型的测试事件：

* **`start`:**  表示测试的开始。
* **`output`:** 表示测试产生的标准输出或标准错误输出。
* **`pass`:**  表示测试用例通过。
* **`fail`:**  表示测试用例失败。
* **`skip`:**  表示测试用例被跳过。
* **`bench`:** 表示基准测试的结果。
* **`run`:**   表示开始运行一个测试或子测试。
* **`pause`:** 表示测试执行暂停。
* **`cont`:**  表示测试执行继续。
* **`name`:**  用于内部跟踪当前运行的测试名称。

**3. 包含时间戳 (可选):**

通过 `Mode` 类型和 `Timestamp` 常量，可以选择在 JSON 事件中包含时间戳信息，记录事件发生的时间。

**4. 关联输出到具体的测试用例:**

对于测试过程中产生的输出，`test2json` 能够根据输出的缩进等信息，将其关联到正在运行的特定测试用例或子测试用例。

**5. 处理构建失败:**

`test2json` 可以记录导致测试失败的构建错误信息，并在最终的 "fail" 事件中包含 `FailedBuild` 字段，指示哪个包的构建失败导致了当前测试的失败。

**6. 支持并发测试:**

`NewConverter` 函数的文档说明了它可以安全地处理来自多个并发运行的测试的输出，并将事件按照执行顺序写入单一的 JSON 输出流。

**7. 使用特殊的标记 (marker) 进行同步:**

引入了 `marker` (ASCII 值为 0x16，即 ^V) 的概念。当测试输出中包含这个标记时，`test2json` 会将其作为测试框架行的开始标识，用于更可靠地解析测试事件。

**它是什么 Go 语言功能的实现？**

`test2json.go` 主要实现了将文本格式的测试输出转换为结构化的 JSON 数据。这可以被认为是 **数据转换** 或 **序列化** 的一种形式。更具体地说，它实现了从一种非结构化的文本流到结构化的 JSON 数据的转换。

**Go 代码示例：**

假设我们有一个简单的 Go 测试文件 `example_test.go`:

```go
package example

import "testing"

func TestAdd(t *testing.T) {
	println("--- Hello from TestAdd ---")
	if 2 + 2 != 4 {
		t.Errorf("expected 4 but got %d", 2+2)
	}
}

func TestSubtract(t *testing.T) {
	t.Skip("skipping subtraction test")
}

func TestDivide(t *testing.T) {
	t.Run("positive numbers", func(t *testing.T) {
		println("Running subtest: positive numbers")
		if 10 / 2 != 5 {
			t.Errorf("expected 5 but got %d", 10/2)
		}
	})
}
```

我们可以使用 `go test -json` 命令运行这个测试文件，并将输出传递给 `test2json` (实际上 `go test -json` 内部就使用了 `test2json`)。

**假设的输入 (来自 `go test` 的标准输出):**

```
=== RUN   TestAdd
--- Hello from TestAdd ---
=== PASS  TestAdd
=== SKIP  TestSubtract
=== RUN   TestDivide
=== RUN   TestDivide/positive_numbers
Running subtest: positive numbers
=== PASS  TestDivide/positive_numbers
=== PASS  TestDivide
PASS
```

**使用 `test2json` 处理后的假设的 JSON 输出:**

```json
{"Action":"start","Package":"example"}
{"Action":"run","Test":"TestAdd","Package":"example"}
{"Action":"output","Test":"TestAdd","Package":"example","Output":"--- Hello from TestAdd ---\n"}
{"Action":"pass","Test":"TestAdd","Package":"example"}
{"Action":"run","Test":"TestSubtract","Package":"example"}
{"Action":"skip","Test":"TestSubtract","Package":"example"}
{"Action":"run","Test":"TestDivide","Package":"example"}
{"Action":"run","Test":"TestDivide/positive_numbers","Package":"example"}
{"Action":"output","Test":"TestDivide/positive_numbers","Package":"example","Output":"Running subtest: positive numbers\n"}
{"Action":"pass","Test":"TestDivide/positive_numbers","Package":"example"}
{"Action":"pass","Test":"TestDivide","Package":"example"}
{"Action":"pass","Package":"example"}
```

**命令行参数的具体处理:**

该文件本身 (`test2json.go`) 并没有直接处理命令行参数。它的主要功能是提供一个库，用于执行测试输出到 JSON 的转换。

实际的命令行参数处理发生在 `cmd/test2json/test2json.go`  (注意路径不同) 和 `cmd/go/internal/test/test.go` 中。

* **`cmd/test2json/test2json.go`:**  这是一个独立的工具，它接收标准输入 (来自 `go test` 的输出) 并将其转换为 JSON 格式输出到标准输出。它可能有一些自己的命令行参数来控制行为，但这不在当前分析的文件范围内。

* **`cmd/go/internal/test/test.go`:** `go test` 命令会使用 `-json` 标志来指示将测试输出转换为 JSON 格式。当使用 `-json` 标志时，`go test` 内部会使用 `cmd/internal/test2json` 包来进行转换。  `-json` 本身就是一个影响 `test2json` 工作方式的“隐式”参数，因为它会触发 `go test` 使用 `test2json` 来处理输出。

在 `test2json.go` 中，`NewConverter` 函数接收一个 `Mode` 类型的参数，这个 `Mode` 可以通过位运算设置不同的选项。例如，`Timestamp` 常量可以用来控制是否在 JSON 输出中包含时间戳。虽然 `test2json.go` 没有直接解析命令行参数，但调用它的代码（例如 `cmd/go`）会根据命令行参数的值来设置 `Mode`。

**例如，在 `cmd/go/internal/test/test.go` 中，可能会有类似的代码 (简化示意):**

```go
// ...
import "cmd/internal/test2json"
// ...

func runTests(pkg string, args []string, stdout io.Writer) error {
	// ...
	var mode test2json.Mode
	if *jsonFlag { // 假设 jsonFlag 是 go test -json 对应的标志
		mode |= test2json.Timestamp
		converter := test2json.NewConverter(stdout, pkg, mode)
		// ... 执行测试并将输出传递给 converter
	} else {
		// 不使用 JSON 转换，直接输出到 stdout
	}
	// ...
}
```

这里的 `*jsonFlag` 就是 `go test -json` 对应的内部变量，它会影响 `Mode` 的设置，从而控制 `test2json` 的行为。

**使用者易犯错的点：**

* **不理解 JSON 输出的结构:**  用户可能不理解 JSON 输出中各个字段的含义，或者不清楚子测试是如何表示的。例如，`Test` 字段可能包含斜杠 `/` 来表示子测试的层级关系。

* **依赖于输出的顺序，但未启用时间戳:**  在并发测试中，如果没有启用时间戳，JSON 事件的顺序可能不完全反映实际的执行顺序。虽然 `test2json` 尽力维护顺序，但并发性可能导致细微的偏差。如果需要严格的事件顺序，应该使用 `Timestamp` 模式。

* **忽略 `FailedBuild` 字段:** 当测试因为构建错误而失败时，`FailedBuild` 字段会提供有价值的信息，指示哪个包的构建出了问题。用户可能只关注测试用例本身的 `fail` 事件，而忽略了这个字段，导致排查问题时走了弯路。

* **误解 `marker` 的作用:**  用户可能不清楚 `marker` ( ^V ) 的作用，以及为什么在某些情况下会看到它出现在测试输出中。理解 `marker` 是为了提高解析的可靠性，特别是在处理复杂的测试输出时。

总而言之，`go/src/cmd/internal/test2json/test2json.go` 是 Go 语言测试工具链中一个关键的组成部分，它负责将非结构化的测试输出转换为结构化的 JSON 数据，为后续的自动化处理和分析提供了便利。

Prompt: 
```
这是路径为go/src/cmd/internal/test2json/test2json.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package test2json implements conversion of test binary output to JSON.
// It is used by cmd/test2json and cmd/go.
//
// See the cmd/test2json documentation for details of the JSON encoding.
package test2json

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Mode controls details of the conversion.
type Mode int

const (
	Timestamp Mode = 1 << iota // include Time in events
)

// event is the JSON struct we emit.
type event struct {
	Time        *time.Time `json:",omitempty"`
	Action      string
	Package     string     `json:",omitempty"`
	Test        string     `json:",omitempty"`
	Elapsed     *float64   `json:",omitempty"`
	Output      *textBytes `json:",omitempty"`
	FailedBuild string     `json:",omitempty"`
}

// textBytes is a hack to get JSON to emit a []byte as a string
// without actually copying it to a string.
// It implements encoding.TextMarshaler, which returns its text form as a []byte,
// and then json encodes that text form as a string (which was our goal).
type textBytes []byte

func (b textBytes) MarshalText() ([]byte, error) { return b, nil }

// A Converter holds the state of a test-to-JSON conversion.
// It implements io.WriteCloser; the caller writes test output in,
// and the converter writes JSON output to w.
type Converter struct {
	w          io.Writer  // JSON output stream
	pkg        string     // package to name in events
	mode       Mode       // mode bits
	start      time.Time  // time converter started
	testName   string     // name of current test, for output attribution
	report     []*event   // pending test result reports (nested for subtests)
	result     string     // overall test result if seen
	input      lineBuffer // input buffer
	output     lineBuffer // output buffer
	needMarker bool       // require ^V marker to introduce test framing line

	// failedBuild is set to the package ID of the cause of a build failure,
	// if that's what caused this test to fail.
	failedBuild string
}

// inBuffer and outBuffer are the input and output buffer sizes.
// They're variables so that they can be reduced during testing.
//
// The input buffer needs to be able to hold any single test
// directive line we want to recognize, like:
//
//	<many spaces> --- PASS: very/nested/s/u/b/t/e/s/t
//
// If anyone reports a test directive line > 4k not working, it will
// be defensible to suggest they restructure their test or test names.
//
// The output buffer must be >= utf8.UTFMax, so that it can
// accumulate any single UTF8 sequence. Lines that fit entirely
// within the output buffer are emitted in single output events.
// Otherwise they are split into multiple events.
// The output buffer size therefore limits the size of the encoding
// of a single JSON output event. 1k seems like a reasonable balance
// between wanting to avoid splitting an output line and not wanting to
// generate enormous output events.
var (
	inBuffer  = 4096
	outBuffer = 1024
)

// NewConverter returns a "test to json" converter.
// Writes on the returned writer are written as JSON to w,
// with minimal delay.
//
// The writes to w are whole JSON events ending in \n,
// so that it is safe to run multiple tests writing to multiple converters
// writing to a single underlying output stream w.
// As long as the underlying output w can handle concurrent writes
// from multiple goroutines, the result will be a JSON stream
// describing the relative ordering of execution in all the concurrent tests.
//
// The mode flag adjusts the behavior of the converter.
// Passing ModeTime includes event timestamps and elapsed times.
//
// The pkg string, if present, specifies the import path to
// report in the JSON stream.
func NewConverter(w io.Writer, pkg string, mode Mode) *Converter {
	c := new(Converter)
	*c = Converter{
		w:     w,
		pkg:   pkg,
		mode:  mode,
		start: time.Now(),
		input: lineBuffer{
			b:    make([]byte, 0, inBuffer),
			line: c.handleInputLine,
			part: c.output.write,
		},
		output: lineBuffer{
			b:    make([]byte, 0, outBuffer),
			line: c.writeOutputEvent,
			part: c.writeOutputEvent,
		},
	}
	c.writeEvent(&event{Action: "start"})
	return c
}

// Write writes the test input to the converter.
func (c *Converter) Write(b []byte) (int, error) {
	c.input.write(b)
	return len(b), nil
}

// Exited marks the test process as having exited with the given error.
func (c *Converter) Exited(err error) {
	if err == nil {
		if c.result != "skip" {
			c.result = "pass"
		}
	} else {
		c.result = "fail"
	}
}

// SetFailedBuild sets the package ID that is the root cause of a build failure
// for this test. This will be reported in the final "fail" event's FailedBuild
// field.
func (c *Converter) SetFailedBuild(pkgID string) {
	c.failedBuild = pkgID
}

const marker = byte(0x16) // ^V

var (
	// printed by test on successful run.
	bigPass = []byte("PASS")

	// printed by test after a normal test failure.
	bigFail = []byte("FAIL")

	// printed by 'go test' along with an error if the test binary terminates
	// with an error.
	bigFailErrorPrefix = []byte("FAIL\t")

	// an === NAME line with no test name, if trailing spaces are deleted
	emptyName     = []byte("=== NAME")
	emptyNameLine = []byte("=== NAME  \n")

	updates = [][]byte{
		[]byte("=== RUN   "),
		[]byte("=== PAUSE "),
		[]byte("=== CONT  "),
		[]byte("=== NAME  "),
		[]byte("=== PASS  "),
		[]byte("=== FAIL  "),
		[]byte("=== SKIP  "),
	}

	reports = [][]byte{
		[]byte("--- PASS: "),
		[]byte("--- FAIL: "),
		[]byte("--- SKIP: "),
		[]byte("--- BENCH: "),
	}

	fourSpace = []byte("    ")

	skipLinePrefix = []byte("?   \t")
	skipLineSuffix = []byte("\t[no test files]")
)

// handleInputLine handles a single whole test output line.
// It must write the line to c.output but may choose to do so
// before or after emitting other events.
func (c *Converter) handleInputLine(line []byte) {
	if len(line) == 0 {
		return
	}
	sawMarker := false
	if c.needMarker && line[0] != marker {
		c.output.write(line)
		return
	}
	if line[0] == marker {
		c.output.flush()
		sawMarker = true
		line = line[1:]
	}

	// Trim is line without \n or \r\n.
	trim := line
	if len(trim) > 0 && trim[len(trim)-1] == '\n' {
		trim = trim[:len(trim)-1]
		if len(trim) > 0 && trim[len(trim)-1] == '\r' {
			trim = trim[:len(trim)-1]
		}
	}

	// === CONT followed by an empty test name can lose its trailing spaces.
	if bytes.Equal(trim, emptyName) {
		line = emptyNameLine
		trim = line[:len(line)-1]
	}

	// Final PASS or FAIL.
	if bytes.Equal(trim, bigPass) || bytes.Equal(trim, bigFail) || bytes.HasPrefix(trim, bigFailErrorPrefix) {
		c.flushReport(0)
		c.testName = ""
		c.needMarker = sawMarker
		c.output.write(line)
		if bytes.Equal(trim, bigPass) {
			c.result = "pass"
		} else {
			c.result = "fail"
		}
		return
	}

	// Special case for entirely skipped test binary: "?   \tpkgname\t[no test files]\n" is only line.
	// Report it as plain output but remember to say skip in the final summary.
	if bytes.HasPrefix(line, skipLinePrefix) && bytes.HasSuffix(trim, skipLineSuffix) && len(c.report) == 0 {
		c.result = "skip"
	}

	// "=== RUN   "
	// "=== PAUSE "
	// "=== CONT  "
	actionColon := false
	origLine := line
	ok := false
	indent := 0
	for _, magic := range updates {
		if bytes.HasPrefix(line, magic) {
			ok = true
			break
		}
	}
	if !ok {
		// "--- PASS: "
		// "--- FAIL: "
		// "--- SKIP: "
		// "--- BENCH: "
		// but possibly indented.
		for bytes.HasPrefix(line, fourSpace) {
			line = line[4:]
			indent++
		}
		for _, magic := range reports {
			if bytes.HasPrefix(line, magic) {
				actionColon = true
				ok = true
				break
			}
		}
	}

	// Not a special test output line.
	if !ok {
		// Lookup the name of the test which produced the output using the
		// indentation of the output as an index into the stack of the current
		// subtests.
		// If the indentation is greater than the number of current subtests
		// then the output must have included extra indentation. We can't
		// determine which subtest produced this output, so we default to the
		// old behaviour of assuming the most recently run subtest produced it.
		if indent > 0 && indent <= len(c.report) {
			c.testName = c.report[indent-1].Test
		}
		c.output.write(origLine)
		return
	}

	// Parse out action and test name.
	i := 0
	if actionColon {
		i = bytes.IndexByte(line, ':') + 1
	}
	if i == 0 {
		i = len(updates[0])
	}
	action := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(string(line[4:i])), ":"))
	name := strings.TrimSpace(string(line[i:]))

	e := &event{Action: action}
	if line[0] == '-' { // PASS or FAIL report
		// Parse out elapsed time.
		if i := strings.Index(name, " ("); i >= 0 {
			if strings.HasSuffix(name, "s)") {
				t, err := strconv.ParseFloat(name[i+2:len(name)-2], 64)
				if err == nil {
					if c.mode&Timestamp != 0 {
						e.Elapsed = &t
					}
				}
			}
			name = name[:i]
		}
		if len(c.report) < indent {
			// Nested deeper than expected.
			// Treat this line as plain output.
			c.output.write(origLine)
			return
		}
		// Flush reports at this indentation level or deeper.
		c.needMarker = sawMarker
		c.flushReport(indent)
		e.Test = name
		c.testName = name
		c.report = append(c.report, e)
		c.output.write(origLine)
		return
	}
	// === update.
	// Finish any pending PASS/FAIL reports.
	c.needMarker = sawMarker
	c.flushReport(0)
	c.testName = name

	if action == "name" {
		// This line is only generated to get c.testName right.
		// Don't emit an event.
		return
	}

	if action == "pause" {
		// For a pause, we want to write the pause notification before
		// delivering the pause event, just so it doesn't look like the test
		// is generating output immediately after being paused.
		c.output.write(origLine)
	}
	c.writeEvent(e)
	if action != "pause" {
		c.output.write(origLine)
	}

	return
}

// flushReport flushes all pending PASS/FAIL reports at levels >= depth.
func (c *Converter) flushReport(depth int) {
	c.testName = ""
	for len(c.report) > depth {
		e := c.report[len(c.report)-1]
		c.report = c.report[:len(c.report)-1]
		c.writeEvent(e)
	}
}

// Close marks the end of the go test output.
// It flushes any pending input and then output (only partial lines at this point)
// and then emits the final overall package-level pass/fail event.
func (c *Converter) Close() error {
	c.input.flush()
	c.output.flush()
	if c.result != "" {
		e := &event{Action: c.result}
		if c.mode&Timestamp != 0 {
			dt := time.Since(c.start).Round(1 * time.Millisecond).Seconds()
			e.Elapsed = &dt
		}
		if c.result == "fail" {
			e.FailedBuild = c.failedBuild
		}
		c.writeEvent(e)
	}
	return nil
}

// writeOutputEvent writes a single output event with the given bytes.
func (c *Converter) writeOutputEvent(out []byte) {
	c.writeEvent(&event{
		Action: "output",
		Output: (*textBytes)(&out),
	})
}

// writeEvent writes a single event.
// It adds the package, time (if requested), and test name (if needed).
func (c *Converter) writeEvent(e *event) {
	e.Package = c.pkg
	if c.mode&Timestamp != 0 {
		t := time.Now()
		e.Time = &t
	}
	if e.Test == "" {
		e.Test = c.testName
	}
	js, err := json.Marshal(e)
	if err != nil {
		// Should not happen - event is valid for json.Marshal.
		fmt.Fprintf(c.w, "testjson internal error: %v\n", err)
		return
	}
	js = append(js, '\n')
	c.w.Write(js)
}

// A lineBuffer is an I/O buffer that reacts to writes by invoking
// input-processing callbacks on whole lines or (for long lines that
// have been split) line fragments.
//
// It should be initialized with b set to a buffer of length 0 but non-zero capacity,
// and line and part set to the desired input processors.
// The lineBuffer will call line(x) for any whole line x (including the final newline)
// that fits entirely in cap(b). It will handle input lines longer than cap(b) by
// calling part(x) for sections of the line. The line will be split at UTF8 boundaries,
// and the final call to part for a long line includes the final newline.
type lineBuffer struct {
	b    []byte       // buffer
	mid  bool         // whether we're in the middle of a long line
	line func([]byte) // line callback
	part func([]byte) // partial line callback
}

// write writes b to the buffer.
func (l *lineBuffer) write(b []byte) {
	for len(b) > 0 {
		// Copy what we can into l.b.
		m := copy(l.b[len(l.b):cap(l.b)], b)
		l.b = l.b[:len(l.b)+m]
		b = b[m:]

		// Process lines in l.b.
		i := 0
		for i < len(l.b) {
			j, w := indexEOL(l.b[i:])
			if j < 0 {
				if !l.mid {
					if j := bytes.IndexByte(l.b[i:], '\t'); j >= 0 {
						if isBenchmarkName(bytes.TrimRight(l.b[i:i+j], " ")) {
							l.part(l.b[i : i+j+1])
							l.mid = true
							i += j + 1
						}
					}
				}
				break
			}
			e := i + j + w
			if l.mid {
				// Found the end of a partial line.
				l.part(l.b[i:e])
				l.mid = false
			} else {
				// Found a whole line.
				l.line(l.b[i:e])
			}
			i = e
		}

		// Whatever's left in l.b is a line fragment.
		if i == 0 && len(l.b) == cap(l.b) {
			// The whole buffer is a fragment.
			// Emit it as the beginning (or continuation) of a partial line.
			t := trimUTF8(l.b)
			l.part(l.b[:t])
			l.b = l.b[:copy(l.b, l.b[t:])]
			l.mid = true
		}

		// There's room for more input.
		// Slide it down in hope of completing the line.
		if i > 0 {
			l.b = l.b[:copy(l.b, l.b[i:])]
		}
	}
}

// indexEOL finds the index of a line ending,
// returning its position and output width.
// A line ending is either a \n or the empty string just before a ^V not beginning a line.
// The output width for \n is 1 (meaning it should be printed)
// but the output width for ^V is 0 (meaning it should be left to begin the next line).
func indexEOL(b []byte) (pos, wid int) {
	for i, c := range b {
		if c == '\n' {
			return i, 1
		}
		if c == marker && i > 0 { // test -v=json emits ^V at start of framing lines
			return i, 0
		}
	}
	return -1, 0
}

// flush flushes the line buffer.
func (l *lineBuffer) flush() {
	if len(l.b) > 0 {
		// Must be a line without a \n, so a partial line.
		l.part(l.b)
		l.b = l.b[:0]
	}
}

var benchmark = []byte("Benchmark")

// isBenchmarkName reports whether b is a valid benchmark name
// that might appear as the first field in a benchmark result line.
func isBenchmarkName(b []byte) bool {
	if !bytes.HasPrefix(b, benchmark) {
		return false
	}
	if len(b) == len(benchmark) { // just "Benchmark"
		return true
	}
	r, _ := utf8.DecodeRune(b[len(benchmark):])
	return !unicode.IsLower(r)
}

// trimUTF8 returns a length t as close to len(b) as possible such that b[:t]
// does not end in the middle of a possibly-valid UTF-8 sequence.
//
// If a large text buffer must be split before position i at the latest,
// splitting at position trimUTF(b[:i]) avoids splitting a UTF-8 sequence.
func trimUTF8(b []byte) int {
	// Scan backward to find non-continuation byte.
	for i := 1; i < utf8.UTFMax && i <= len(b); i++ {
		if c := b[len(b)-i]; c&0xc0 != 0x80 {
			switch {
			case c&0xe0 == 0xc0:
				if i < 2 {
					return len(b) - i
				}
			case c&0xf0 == 0xe0:
				if i < 3 {
					return len(b) - i
				}
			case c&0xf8 == 0xf0:
				if i < 4 {
					return len(b) - i
				}
			}
			break
		}
	}
	return len(b)
}

"""



```