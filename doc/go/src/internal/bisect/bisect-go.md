Response:
The user wants to understand the functionality of the provided Go code, which is part of the `internal/bisect` package. I need to:

1. **List the functionalities** provided by the code based on its comments and structure.
2. **Infer and illustrate the Go language feature it implements** with a code example. This likely involves conditional compilation or feature toggles controlled by the `bisect` tool.
3. **Explain the handling of command-line arguments**, focusing on how the bisect patterns are processed.
4. **Provide an example of common mistakes** users might make when integrating this package.
5. **Answer in Chinese.**

Let's break down the code and address each point:

**1. Functionalities:**

- Parsing and interpreting bisect patterns.
- Matching change IDs against bisect patterns to determine if a change should be enabled or printed.
- Generating unique change IDs using hashing.
- Providing markers to identify changes in output.
- Supporting different reporting modes (verbose, quiet, marker-only).
- Handling stack traces for change identification.
- Deduplicating stack trace reports to avoid redundancy.

**2. Go Language Feature:**

The code facilitates a form of **feature flagging or conditional execution** controlled by the external `bisect` tool. The `bisect` tool determines which code paths are active based on a pattern.

**3. Command-line Arguments:**

The code itself doesn't directly handle command-line arguments. It expects the target program to:

- Accept a bisect pattern, typically through a command-line flag or environment variable.
- Pass this pattern to `bisect.New()`.

The `bisect` package then parses this pattern. The pattern syntax is defined in the documentation and involves bit strings, `+`, `-`, `y`, `!`, `v`, and `q`.

**4. Common Mistakes:**

A common mistake could be not correctly integrating the `ShouldEnable` and `ShouldPrint` methods, leading to either unintended code execution or missing reports. Another potential issue is not understanding the pattern syntax correctly.

**Plan:**

- First, list the core functionalities clearly.
- Then, explain the inferred Go feature with a simple example.
- Detail how the pattern is handled, even though the code doesn't directly process command-line flags.
- Create an example of a common mistake related to `ShouldEnable` and `ShouldPrint`.
- Ensure the language is Chinese.
`go/src/internal/bisect/bisect.go` 文件的 Go 语言实现部分提供了一系列功能，用于支持通过 `bisect` 调试工具来定位引入问题的代码变更。以下是其主要功能：

**核心功能:**

1. **解析 bisect 模式 (Pattern):**  `New(pattern string)` 函数负责解析由 `bisect` 工具生成的模式字符串。这个模式字符串定义了哪些代码变更应该被启用或报告。
2. **匹配变更 ID:**  `Matcher` 结构体及其方法（如 `ShouldEnable(id uint64)` 和 `ShouldPrint(id uint64)`) 用于判断一个具有特定 ID 的代码变更是否应该被启用以及是否应该产生报告。
3. **生成变更 ID:** `Hash(data ...any)` 函数用于为代码变更生成唯一的 ID。通常会使用变更相关的信息（如文件名、行号或调用栈）作为输入。
4. **生成匹配标记 (Match Marker):** `Marker(id uint64)` 和 `AppendMarker(dst []byte, id uint64)` 函数生成一个特殊的标记字符串，用于在报告输出中标识匹配的变更。
5. **报告变更信息:**  `ShouldPrint(id uint64)` 判断是否需要报告某个变更，而辅助函数（如 `printFileLine` 和 `printStack`) 负责生成包含匹配标记的详细报告信息。
6. **支持不同的报告模式:**  通过模式字符串中的前缀（如 `v` 和 `q`），可以控制报告的详细程度和是否显示给用户。`MarkerOnly()` 方法判断是否只需要打印标记，而不需要详细信息。
7. **处理文件和行号相关的变更:** `FileLine(w Writer, file string, line int)` 方法提供了一种便捷的方式来处理基于文件名和行号的变更，集成了哈希、打印和启用的逻辑。
8. **处理调用栈相关的变更:** `Stack(w Writer)` 方法用于处理基于当前调用栈的变更，它可以捕获调用栈信息并生成相应的变更 ID。
9. **去重报告:**  `dedup` 结构体用于对调用栈报告进行去重，避免重复报告相同的调用栈信息。
10. **去除匹配标记:** `CutMarker(line string)` 函数用于从报告行中去除匹配标记，方便 `bisect` 工具分析结果。

**实现的 Go 语言功能：根据 bisect 模式控制代码行为**

`bisect` 包实现了一种基于模式匹配的条件执行或特征开关机制。程序可以根据 `bisect` 工具提供的模式，动态地启用或禁用某些代码变更。

**Go 代码示例：**

假设我们有一个程序，其中某些功能可以通过代码中的条件语句来启用或禁用。我们可以使用 `bisect` 包来控制这些条件。

```go
package main

import (
	"fmt"
	"log"
	"os"

	"internal/bisect" // 假设你的 internal 目录结构正确
)

var bisectPattern string // 可以通过命令行参数或环境变量设置

func shouldEnableFeatureA(file string, line int, m *bisect.Matcher) bool {
	if m == nil {
		return true
	}
	h := bisect.Hash(file, line)
	if m.ShouldPrint(h) {
		fmt.Fprintf(os.Stderr, "%v %s:%d: Feature A\n", bisect.Marker(h), file, line)
	}
	return m.ShouldEnable(h)
}

func main() {
	// 模拟从命令行参数获取 bisect 模式
	bisectPattern = os.Getenv("BISECT_PATTERN") // 或者使用 flag 包解析命令行参数

	m, err := bisect.New(bisectPattern)
	if err != nil {
		log.Fatal(err)
	}

	// 模拟一些可能需要根据 bisect 模式启用的代码
	const file = "main.go"

	if shouldEnableFeatureA(file, 20, m) { // 假设 Feature A 的标识
		fmt.Println("Feature A is enabled.")
		// 执行 Feature A 的代码
	} else {
		fmt.Println("Feature A is disabled.")
		// 执行 Feature A 被禁用时的代码
	}

	if m != nil && m.ShouldPrint(bisect.Hash(file, 28)) { // 假设需要报告的变更点
		fmt.Fprintf(os.Stderr, "%v %s:%d: Some other change\n", bisect.Marker(bisect.Hash(file, 28)), file, 28)
	}
}
```

**假设的输入与输出：**

**假设输入：**  `BISECT_PATTERN="0"` (启用以二进制 "0" 结尾的变更)

**预期输出：**

```
Feature A is disabled.
```

**假设输入：**  `BISECT_PATTERN="1"` (启用以二进制 "1" 结尾的变更)

**预期输出：**

```
Feature A is enabled.
```

**假设输入：**  `BISECT_PATTERN="v1"` (启用以二进制 "1" 结尾的变更，并显示报告)

**预期输出：**

```
[bisect-match 0x...] main.go:20: Feature A
Feature A is enabled.
```

**命令行参数的具体处理：**

`bisect.go` 本身并不直接处理命令行参数。它期望使用者（例如编译器或其他程序）从命令行参数或环境变量中获取 bisect 模式字符串，并将其传递给 `bisect.New()` 函数。

例如，一个编译器可能会定义一个 `-bisect` 标志来接收模式：

```go
// ... 在编译器的 main 函数中
var bisectPattern string
flag.StringVar(&bisectPattern, "bisect", "", "bisect pattern")
flag.Parse()

m, err := bisect.New(bisectPattern)
// ... 在编译过程中使用 m 来决定是否启用某些代码变更
```

然后用户可以通过命令行传递模式：

```bash
go build -bisect="01+10" myprogram.go
```

或者通过环境变量：

```bash
export BISECT_PATTERN="01+10"
go build myprogram.go
```

**使用者易犯错的点：**

1. **未能正确调用 `ShouldEnable` 和 `ShouldPrint`:**  开发者可能会忘记在需要条件执行的代码路径上调用 `ShouldEnable` 来判断是否应该执行该路径，或者忘记在需要报告的变更点调用 `ShouldPrint` 来生成报告。

   **错误示例：**

   ```go
   if someCondition { // 假设这是一个需要 bisect 控制的条件
       // 忘记调用 m.ShouldEnable 或直接假设启用
       fmt.Println("This code might be incorrectly executed.")
   }
   ```

2. **对 `bisect` 模式语法理解不足:**  用户可能不熟悉 `bisect` 模式的语法规则，导致提供的模式无法正确匹配到期望的变更。例如，混淆 `+` 和 `-` 的作用顺序，或者对 `y`、`!`、`v` 等特殊字符的含义理解有误。

   **错误示例：**  假设用户想启用 ID 以 `01` 或 `10` 结尾的变更，但错误地使用了 `01-10` 模式，这会导致与预期不同的行为。

3. **在 `Hash` 函数中使用了不可预测或不稳定的输入:**  `Hash` 函数的目的是为每个逻辑变更生成唯一的稳定 ID。如果传递给 `Hash` 的参数在不同的构建或运行环境下发生变化，那么 `bisect` 工具将无法正确地识别和跟踪这些变更。例如，直接使用内存地址作为 `Hash` 的输入是不可取的。

这个 `bisect` 包的核心思想是提供一种灵活的方式，让程序能够根据外部的 `bisect` 工具的指示，动态地调整其行为，从而辅助开发者定位引入问题的代码变更。

Prompt: 
```
这是路径为go/src/internal/bisect/bisect.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package bisect can be used by compilers and other programs
// to serve as a target for the bisect debugging tool.
// See [golang.org/x/tools/cmd/bisect] for details about using the tool.
//
// To be a bisect target, allowing bisect to help determine which of a set of independent
// changes provokes a failure, a program needs to:
//
//  1. Define a way to accept a change pattern on its command line or in its environment.
//     The most common mechanism is a command-line flag.
//     The pattern can be passed to [New] to create a [Matcher], the compiled form of a pattern.
//
//  2. Assign each change a unique ID. One possibility is to use a sequence number,
//     but the most common mechanism is to hash some kind of identifying information
//     like the file and line number where the change might be applied.
//     [Hash] hashes its arguments to compute an ID.
//
//  3. Enable each change that the pattern says should be enabled.
//     The [Matcher.ShouldEnable] method answers this question for a given change ID.
//
//  4. Print a report identifying each change that the pattern says should be printed.
//     The [Matcher.ShouldPrint] method answers this question for a given change ID.
//     The report consists of one more lines on standard error or standard output
//     that contain a “match marker”. [Marker] returns the match marker for a given ID.
//     When bisect reports a change as causing the failure, it identifies the change
//     by printing the report lines with the match marker removed.
//
// # Example Usage
//
// A program starts by defining how it receives the pattern. In this example, we will assume a flag.
// The next step is to compile the pattern:
//
//	m, err := bisect.New(patternFlag)
//	if err != nil {
//		log.Fatal(err)
//	}
//
// Then, each time a potential change is considered, the program computes
// a change ID by hashing identifying information (source file and line, in this case)
// and then calls m.ShouldPrint and m.ShouldEnable to decide whether to
// print and enable the change, respectively. The two can return different values
// depending on whether bisect is trying to find a minimal set of changes to
// disable or to enable to provoke the failure.
//
// It is usually helpful to write a helper function that accepts the identifying information
// and then takes care of hashing, printing, and reporting whether the identified change
// should be enabled. For example, a helper for changes identified by a file and line number
// would be:
//
//	func ShouldEnable(file string, line int) {
//		h := bisect.Hash(file, line)
//		if m.ShouldPrint(h) {
//			fmt.Fprintf(os.Stderr, "%v %s:%d\n", bisect.Marker(h), file, line)
//		}
//		return m.ShouldEnable(h)
//	}
//
// Finally, note that New returns a nil Matcher when there is no pattern,
// meaning that the target is not running under bisect at all,
// so all changes should be enabled and none should be printed.
// In that common case, the computation of the hash can be avoided entirely
// by checking for m == nil first:
//
//	func ShouldEnable(file string, line int) bool {
//		if m == nil {
//			return true
//		}
//		h := bisect.Hash(file, line)
//		if m.ShouldPrint(h) {
//			fmt.Fprintf(os.Stderr, "%v %s:%d\n", bisect.Marker(h), file, line)
//		}
//		return m.ShouldEnable(h)
//	}
//
// When the identifying information is expensive to format, this code can call
// [Matcher.MarkerOnly] to find out whether short report lines containing only the
// marker are permitted for a given run. (Bisect permits such lines when it is
// still exploring the space of possible changes and will not be showing the
// output to the user.) If so, the client can choose to print only the marker:
//
//	func ShouldEnable(file string, line int) bool {
//		if m == nil {
//			return true
//		}
//		h := bisect.Hash(file, line)
//		if m.ShouldPrint(h) {
//			if m.MarkerOnly() {
//				bisect.PrintMarker(os.Stderr, h)
//			} else {
//				fmt.Fprintf(os.Stderr, "%v %s:%d\n", bisect.Marker(h), file, line)
//			}
//		}
//		return m.ShouldEnable(h)
//	}
//
// This specific helper – deciding whether to enable a change identified by
// file and line number and printing about the change when necessary – is
// provided by the [Matcher.FileLine] method.
//
// Another common usage is deciding whether to make a change in a function
// based on the caller's stack, to identify the specific calling contexts that the
// change breaks. The [Matcher.Stack] method takes care of obtaining the stack,
// printing it when necessary, and reporting whether to enable the change
// based on that stack.
//
// # Pattern Syntax
//
// Patterns are generated by the bisect tool and interpreted by [New].
// Users should not have to understand the patterns except when
// debugging a target's bisect support or debugging the bisect tool itself.
//
// The pattern syntax selecting a change is a sequence of bit strings
// separated by + and - operators. Each bit string denotes the set of
// changes with IDs ending in those bits, + is set addition, - is set subtraction,
// and the expression is evaluated in the usual left-to-right order.
// The special binary number “y” denotes the set of all changes,
// standing in for the empty bit string.
// In the expression, all the + operators must appear before all the - operators.
// A leading + adds to an empty set. A leading - subtracts from the set of all
// possible suffixes.
//
// For example:
//
//   - “01+10” and “+01+10” both denote the set of changes
//     with IDs ending with the bits 01 or 10.
//
//   - “01+10-1001” denotes the set of changes with IDs
//     ending with the bits 01 or 10, but excluding those ending in 1001.
//
//   - “-01-1000” and “y-01-1000 both denote the set of all changes
//     with IDs not ending in 01 nor 1000.
//
//   - “0+1-01+001” is not a valid pattern, because all the + operators do not
//     appear before all the - operators.
//
// In the syntaxes described so far, the pattern specifies the changes to
// enable and report. If a pattern is prefixed by a “!”, the meaning
// changes: the pattern specifies the changes to DISABLE and report. This
// mode of operation is needed when a program passes with all changes
// enabled but fails with no changes enabled. In this case, bisect
// searches for minimal sets of changes to disable.
// Put another way, the leading “!” inverts the result from [Matcher.ShouldEnable]
// but does not invert the result from [Matcher.ShouldPrint].
//
// As a convenience for manual debugging, “n” is an alias for “!y”,
// meaning to disable and report all changes.
//
// Finally, a leading “v” in the pattern indicates that the reports will be shown
// to the user of bisect to describe the changes involved in a failure.
// At the API level, the leading “v” causes [Matcher.Visible] to return true.
// See the next section for details.
//
// # Match Reports
//
// The target program must enable only those changed matched
// by the pattern, and it must print a match report for each such change.
// A match report consists of one or more lines of text that will be
// printed by the bisect tool to describe a change implicated in causing
// a failure. Each line in the report for a given change must contain a
// match marker with that change ID, as returned by [Marker].
// The markers are elided when displaying the lines to the user.
//
// A match marker has the form “[bisect-match 0x1234]” where
// 0x1234 is the change ID in hexadecimal.
// An alternate form is “[bisect-match 010101]”, giving the change ID in binary.
//
// When [Matcher.Visible] returns false, the match reports are only
// being processed by bisect to learn the set of enabled changes,
// not shown to the user, meaning that each report can be a match
// marker on a line by itself, eliding the usual textual description.
// When the textual description is expensive to compute,
// checking [Matcher.Visible] can help the avoid that expense
// in most runs.
package bisect

import (
	"runtime"
	"sync"
	"sync/atomic"
)

// New creates and returns a new Matcher implementing the given pattern.
// The pattern syntax is defined in the package doc comment.
//
// In addition to the pattern syntax syntax, New("") returns nil, nil.
// The nil *Matcher is valid for use: it returns true from ShouldEnable
// and false from ShouldPrint for all changes. Callers can avoid calling
// [Hash], [Matcher.ShouldEnable], and [Matcher.ShouldPrint] entirely
// when they recognize the nil Matcher.
func New(pattern string) (*Matcher, error) {
	if pattern == "" {
		return nil, nil
	}

	m := new(Matcher)

	p := pattern
	// Special case for leading 'q' so that 'qn' quietly disables, e.g. fmahash=qn to disable fma
	// Any instance of 'v' disables 'q'.
	if len(p) > 0 && p[0] == 'q' {
		m.quiet = true
		p = p[1:]
		if p == "" {
			return nil, &parseError{"invalid pattern syntax: " + pattern}
		}
	}
	// Allow multiple v, so that “bisect cmd vPATTERN” can force verbose all the time.
	for len(p) > 0 && p[0] == 'v' {
		m.verbose = true
		m.quiet = false
		p = p[1:]
		if p == "" {
			return nil, &parseError{"invalid pattern syntax: " + pattern}
		}
	}

	// Allow multiple !, each negating the last, so that “bisect cmd !PATTERN” works
	// even when bisect chooses to add its own !.
	m.enable = true
	for len(p) > 0 && p[0] == '!' {
		m.enable = !m.enable
		p = p[1:]
		if p == "" {
			return nil, &parseError{"invalid pattern syntax: " + pattern}
		}
	}

	if p == "n" {
		// n is an alias for !y.
		m.enable = !m.enable
		p = "y"
	}

	// Parse actual pattern syntax.
	result := true
	bits := uint64(0)
	start := 0
	wid := 1 // 1-bit (binary); sometimes 4-bit (hex)
	for i := 0; i <= len(p); i++ {
		// Imagine a trailing - at the end of the pattern to flush final suffix
		c := byte('-')
		if i < len(p) {
			c = p[i]
		}
		if i == start && wid == 1 && c == 'x' { // leading x for hex
			start = i + 1
			wid = 4
			continue
		}
		switch c {
		default:
			return nil, &parseError{"invalid pattern syntax: " + pattern}
		case '2', '3', '4', '5', '6', '7', '8', '9':
			if wid != 4 {
				return nil, &parseError{"invalid pattern syntax: " + pattern}
			}
			fallthrough
		case '0', '1':
			bits <<= wid
			bits |= uint64(c - '0')
		case 'a', 'b', 'c', 'd', 'e', 'f', 'A', 'B', 'C', 'D', 'E', 'F':
			if wid != 4 {
				return nil, &parseError{"invalid pattern syntax: " + pattern}
			}
			bits <<= 4
			bits |= uint64(c&^0x20 - 'A' + 10)
		case 'y':
			if i+1 < len(p) && (p[i+1] == '0' || p[i+1] == '1') {
				return nil, &parseError{"invalid pattern syntax: " + pattern}
			}
			bits = 0
		case '+', '-':
			if c == '+' && result == false {
				// Have already seen a -. Should be - from here on.
				return nil, &parseError{"invalid pattern syntax (+ after -): " + pattern}
			}
			if i > 0 {
				n := (i - start) * wid
				if n > 64 {
					return nil, &parseError{"pattern bits too long: " + pattern}
				}
				if n <= 0 {
					return nil, &parseError{"invalid pattern syntax: " + pattern}
				}
				if p[start] == 'y' {
					n = 0
				}
				mask := uint64(1)<<n - 1
				m.list = append(m.list, cond{mask, bits, result})
			} else if c == '-' {
				// leading - subtracts from complete set
				m.list = append(m.list, cond{0, 0, true})
			}
			bits = 0
			result = c == '+'
			start = i + 1
			wid = 1
		}
	}
	return m, nil
}

// A Matcher is the parsed, compiled form of a PATTERN string.
// The nil *Matcher is valid: it has all changes enabled but none reported.
type Matcher struct {
	verbose bool   // annotate reporting with human-helpful information
	quiet   bool   // disables all reporting.  reset if verbose is true. use case is -d=fmahash=qn
	enable  bool   // when true, list is for “enable and report” (when false, “disable and report”)
	list    []cond // conditions; later ones win over earlier ones
	dedup   atomic.Pointer[dedup]
}

// A cond is a single condition in the matcher.
// Given an input id, if id&mask == bits, return the result.
type cond struct {
	mask   uint64
	bits   uint64
	result bool
}

// MarkerOnly reports whether it is okay to print only the marker for
// a given change, omitting the identifying information.
// MarkerOnly returns true when bisect is using the printed reports
// only for an intermediate search step, not for showing to users.
func (m *Matcher) MarkerOnly() bool {
	return !m.verbose
}

// ShouldEnable reports whether the change with the given id should be enabled.
func (m *Matcher) ShouldEnable(id uint64) bool {
	if m == nil {
		return true
	}
	return m.matchResult(id) == m.enable
}

// ShouldPrint reports whether to print identifying information about the change with the given id.
func (m *Matcher) ShouldPrint(id uint64) bool {
	if m == nil || m.quiet {
		return false
	}
	return m.matchResult(id)
}

// matchResult returns the result from the first condition that matches id.
func (m *Matcher) matchResult(id uint64) bool {
	for i := len(m.list) - 1; i >= 0; i-- {
		c := &m.list[i]
		if id&c.mask == c.bits {
			return c.result
		}
	}
	return false
}

// FileLine reports whether the change identified by file and line should be enabled.
// If the change should be printed, FileLine prints a one-line report to w.
func (m *Matcher) FileLine(w Writer, file string, line int) bool {
	if m == nil {
		return true
	}
	return m.fileLine(w, file, line)
}

// fileLine does the real work for FileLine.
// This lets FileLine's body handle m == nil and potentially be inlined.
func (m *Matcher) fileLine(w Writer, file string, line int) bool {
	h := Hash(file, line)
	if m.ShouldPrint(h) {
		if m.MarkerOnly() {
			PrintMarker(w, h)
		} else {
			printFileLine(w, h, file, line)
		}
	}
	return m.ShouldEnable(h)
}

// printFileLine prints a non-marker-only report for file:line to w.
func printFileLine(w Writer, h uint64, file string, line int) error {
	const markerLen = 40 // overestimate
	b := make([]byte, 0, markerLen+len(file)+24)
	b = AppendMarker(b, h)
	b = appendFileLine(b, file, line)
	b = append(b, '\n')
	_, err := w.Write(b)
	return err
}

// appendFileLine appends file:line to dst, returning the extended slice.
func appendFileLine(dst []byte, file string, line int) []byte {
	dst = append(dst, file...)
	dst = append(dst, ':')
	u := uint(line)
	if line < 0 {
		dst = append(dst, '-')
		u = -u
	}
	var buf [24]byte
	i := len(buf)
	for i == len(buf) || u > 0 {
		i--
		buf[i] = '0' + byte(u%10)
		u /= 10
	}
	dst = append(dst, buf[i:]...)
	return dst
}

// MatchStack assigns the current call stack a change ID.
// If the stack should be printed, MatchStack prints it.
// Then MatchStack reports whether a change at the current call stack should be enabled.
func (m *Matcher) Stack(w Writer) bool {
	if m == nil {
		return true
	}
	return m.stack(w)
}

// stack does the real work for Stack.
// This lets stack's body handle m == nil and potentially be inlined.
func (m *Matcher) stack(w Writer) bool {
	const maxStack = 16
	var stk [maxStack]uintptr
	n := runtime.Callers(2, stk[:])
	// caller #2 is not for printing; need it to normalize PCs if ASLR.
	if n <= 1 {
		return false
	}

	base := stk[0]
	// normalize PCs
	for i := range stk[:n] {
		stk[i] -= base
	}

	h := Hash(stk[:n])
	if m.ShouldPrint(h) {
		var d *dedup
		for {
			d = m.dedup.Load()
			if d != nil {
				break
			}
			d = new(dedup)
			if m.dedup.CompareAndSwap(nil, d) {
				break
			}
		}

		if m.MarkerOnly() {
			if !d.seenLossy(h) {
				PrintMarker(w, h)
			}
		} else {
			if !d.seen(h) {
				// Restore PCs in stack for printing
				for i := range stk[:n] {
					stk[i] += base
				}
				printStack(w, h, stk[1:n])
			}
		}
	}
	return m.ShouldEnable(h)
}

// Writer is the same interface as io.Writer.
// It is duplicated here to avoid importing io.
type Writer interface {
	Write([]byte) (int, error)
}

// PrintMarker prints to w a one-line report containing only the marker for h.
// It is appropriate to use when [Matcher.ShouldPrint] and [Matcher.MarkerOnly] both return true.
func PrintMarker(w Writer, h uint64) error {
	var buf [50]byte
	b := AppendMarker(buf[:0], h)
	b = append(b, '\n')
	_, err := w.Write(b)
	return err
}

// printStack prints to w a multi-line report containing a formatting of the call stack stk,
// with each line preceded by the marker for h.
func printStack(w Writer, h uint64, stk []uintptr) error {
	buf := make([]byte, 0, 2048)

	var prefixBuf [100]byte
	prefix := AppendMarker(prefixBuf[:0], h)

	frames := runtime.CallersFrames(stk)
	for {
		f, more := frames.Next()
		buf = append(buf, prefix...)
		buf = append(buf, f.Function...)
		buf = append(buf, "()\n"...)
		buf = append(buf, prefix...)
		buf = append(buf, '\t')
		buf = appendFileLine(buf, f.File, f.Line)
		buf = append(buf, '\n')
		if !more {
			break
		}
	}
	buf = append(buf, prefix...)
	buf = append(buf, '\n')
	_, err := w.Write(buf)
	return err
}

// Marker returns the match marker text to use on any line reporting details
// about a match of the given ID.
// It always returns the hexadecimal format.
func Marker(id uint64) string {
	return string(AppendMarker(nil, id))
}

// AppendMarker is like [Marker] but appends the marker to dst.
func AppendMarker(dst []byte, id uint64) []byte {
	const prefix = "[bisect-match 0x"
	var buf [len(prefix) + 16 + 1]byte
	copy(buf[:], prefix)
	for i := 0; i < 16; i++ {
		buf[len(prefix)+i] = "0123456789abcdef"[id>>60]
		id <<= 4
	}
	buf[len(prefix)+16] = ']'
	return append(dst, buf[:]...)
}

// CutMarker finds the first match marker in line and removes it,
// returning the shortened line (with the marker removed),
// the ID from the match marker,
// and whether a marker was found at all.
// If there is no marker, CutMarker returns line, 0, false.
func CutMarker(line string) (short string, id uint64, ok bool) {
	// Find first instance of prefix.
	prefix := "[bisect-match "
	i := 0
	for ; ; i++ {
		if i >= len(line)-len(prefix) {
			return line, 0, false
		}
		if line[i] == '[' && line[i:i+len(prefix)] == prefix {
			break
		}
	}

	// Scan to ].
	j := i + len(prefix)
	for j < len(line) && line[j] != ']' {
		j++
	}
	if j >= len(line) {
		return line, 0, false
	}

	// Parse id.
	idstr := line[i+len(prefix) : j]
	if len(idstr) >= 3 && idstr[:2] == "0x" {
		// parse hex
		if len(idstr) > 2+16 { // max 0x + 16 digits
			return line, 0, false
		}
		for i := 2; i < len(idstr); i++ {
			id <<= 4
			switch c := idstr[i]; {
			case '0' <= c && c <= '9':
				id |= uint64(c - '0')
			case 'a' <= c && c <= 'f':
				id |= uint64(c - 'a' + 10)
			case 'A' <= c && c <= 'F':
				id |= uint64(c - 'A' + 10)
			}
		}
	} else {
		if idstr == "" || len(idstr) > 64 { // min 1 digit, max 64 digits
			return line, 0, false
		}
		// parse binary
		for i := 0; i < len(idstr); i++ {
			id <<= 1
			switch c := idstr[i]; c {
			default:
				return line, 0, false
			case '0', '1':
				id |= uint64(c - '0')
			}
		}
	}

	// Construct shortened line.
	// Remove at most one space from around the marker,
	// so that "foo [marker] bar" shortens to "foo bar".
	j++ // skip ]
	if i > 0 && line[i-1] == ' ' {
		i--
	} else if j < len(line) && line[j] == ' ' {
		j++
	}
	short = line[:i] + line[j:]
	return short, id, true
}

// Hash computes a hash of the data arguments,
// each of which must be of type string, byte, int, uint, int32, uint32, int64, uint64, uintptr, or a slice of one of those types.
func Hash(data ...any) uint64 {
	h := offset64
	for _, v := range data {
		switch v := v.(type) {
		default:
			// Note: Not printing the type, because reflect.ValueOf(v)
			// would make the interfaces prepared by the caller escape
			// and therefore allocate. This way, Hash(file, line) runs
			// without any allocation. It should be clear from the
			// source code calling Hash what the bad argument was.
			panic("bisect.Hash: unexpected argument type")
		case string:
			h = fnvString(h, v)
		case byte:
			h = fnv(h, v)
		case int:
			h = fnvUint64(h, uint64(v))
		case uint:
			h = fnvUint64(h, uint64(v))
		case int32:
			h = fnvUint32(h, uint32(v))
		case uint32:
			h = fnvUint32(h, v)
		case int64:
			h = fnvUint64(h, uint64(v))
		case uint64:
			h = fnvUint64(h, v)
		case uintptr:
			h = fnvUint64(h, uint64(v))
		case []string:
			for _, x := range v {
				h = fnvString(h, x)
			}
		case []byte:
			for _, x := range v {
				h = fnv(h, x)
			}
		case []int:
			for _, x := range v {
				h = fnvUint64(h, uint64(x))
			}
		case []uint:
			for _, x := range v {
				h = fnvUint64(h, uint64(x))
			}
		case []int32:
			for _, x := range v {
				h = fnvUint32(h, uint32(x))
			}
		case []uint32:
			for _, x := range v {
				h = fnvUint32(h, x)
			}
		case []int64:
			for _, x := range v {
				h = fnvUint64(h, uint64(x))
			}
		case []uint64:
			for _, x := range v {
				h = fnvUint64(h, x)
			}
		case []uintptr:
			for _, x := range v {
				h = fnvUint64(h, uint64(x))
			}
		}
	}
	return h
}

// Trivial error implementation, here to avoid importing errors.

// parseError is a trivial error implementation,
// defined here to avoid importing errors.
type parseError struct{ text string }

func (e *parseError) Error() string { return e.text }

// FNV-1a implementation. See Go's hash/fnv/fnv.go.
// Copied here for simplicity (can handle integers more directly)
// and to avoid importing hash/fnv.

const (
	offset64 uint64 = 14695981039346656037
	prime64  uint64 = 1099511628211
)

func fnv(h uint64, x byte) uint64 {
	h ^= uint64(x)
	h *= prime64
	return h
}

func fnvString(h uint64, x string) uint64 {
	for i := 0; i < len(x); i++ {
		h ^= uint64(x[i])
		h *= prime64
	}
	return h
}

func fnvUint64(h uint64, x uint64) uint64 {
	for i := 0; i < 8; i++ {
		h ^= x & 0xFF
		x >>= 8
		h *= prime64
	}
	return h
}

func fnvUint32(h uint64, x uint32) uint64 {
	for i := 0; i < 4; i++ {
		h ^= uint64(x & 0xFF)
		x >>= 8
		h *= prime64
	}
	return h
}

// A dedup is a deduplicator for call stacks, so that we only print
// a report for new call stacks, not for call stacks we've already
// reported.
//
// It has two modes: an approximate but lock-free mode that
// may still emit some duplicates, and a precise mode that uses
// a lock and never emits duplicates.
type dedup struct {
	// 128-entry 4-way, lossy cache for seenLossy
	recent [128][4]uint64

	// complete history for seen
	mu sync.Mutex
	m  map[uint64]bool
}

// seen records that h has now been seen and reports whether it was seen before.
// When seen returns false, the caller is expected to print a report for h.
func (d *dedup) seen(h uint64) bool {
	d.mu.Lock()
	if d.m == nil {
		d.m = make(map[uint64]bool)
	}
	seen := d.m[h]
	d.m[h] = true
	d.mu.Unlock()
	return seen
}

// seenLossy is a variant of seen that avoids a lock by using a cache of recently seen hashes.
// Each cache entry is N-way set-associative: h can appear in any of the slots.
// If h does not appear in any of them, then it is inserted into a random slot,
// overwriting whatever was there before.
func (d *dedup) seenLossy(h uint64) bool {
	cache := &d.recent[uint(h)%uint(len(d.recent))]
	for i := 0; i < len(cache); i++ {
		if atomic.LoadUint64(&cache[i]) == h {
			return true
		}
	}

	// Compute index in set to evict as hash of current set.
	ch := offset64
	for _, x := range cache {
		ch = fnvUint64(ch, x)
	}
	atomic.StoreUint64(&cache[uint(ch)%uint(len(cache))], h)
	return false
}

"""



```