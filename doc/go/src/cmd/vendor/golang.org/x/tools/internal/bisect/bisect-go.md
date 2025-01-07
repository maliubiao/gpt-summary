Response:
The user wants to understand the functionality of the `bisect` package in Go. I need to explain:

1. **Purpose:** What problem does this package solve?
2. **Core Concepts:**  Explain the main types and functions like `Matcher`, `Hash`, `ShouldEnable`, `ShouldReport`, `Marker`, and the pattern syntax.
3. **Example Usage:** Provide a concrete Go code snippet demonstrating how to use the package.
4. **Command-line Argument Handling:** Describe how the package interacts with command-line arguments (specifically the bisect pattern).
5. **Common Pitfalls:** Identify potential errors users might make while using this package.

Let's break down each point and construct the explanation.
`go/src/cmd/vendor/golang.org/x/tools/internal/bisect/bisect.go`  这个 Go 语言包 `bisect` 的主要功能是为其他 Go 程序提供支持，以便与 `bisect` 调试工具协同工作。 `bisect` 工具用于自动化地查找导致程序行为变化的特定代码变更。

**核心功能：**

1. **定义变更模式 (Change Pattern):**  `bisect` 包允许程序接收一个描述需要启用或禁用的变更集合的模式字符串。这个模式通常通过命令行标志或环境变量传递给目标程序。`New(pattern string)` 函数负责解析这个模式字符串，并返回一个 `Matcher` 对象。

2. **变更的唯一标识 (Change ID):**  程序需要为每个潜在的代码变更分配一个唯一的 ID。`Hash(data ...any)` 函数提供了一种便捷的方式来基于变更的标识信息（例如文件名、行号等）生成这样的 ID。

3. **启用/禁用变更:**  `Matcher` 对象的 `ShouldEnable(id uint64)` 方法根据解析后的模式，判断具有给定 ID 的变更是否应该被启用。

4. **报告变更:**  `Matcher` 对象的 `ShouldReport(id uint64)` 方法根据解析后的模式，判断具有给定 ID 的变更是否应该被报告。报告通常是将包含特定 "匹配标记" 的信息输出到标准错误或标准输出。`Marker(id uint64)` 函数生成这个匹配标记。

**它是什么 Go 语言功能的实现：**

`bisect` 包实现了一种用于增量式调试的技术，特别适用于查找引入 bug 的代码变更。它允许程序根据外部提供的模式动态地启用或禁用特定的代码修改，配合 `bisect` 工具可以自动化地进行二分查找，从而快速定位问题变更。

**Go 代码示例：**

假设你的 Go 程序中存在一些可以通过开关控制是否生效的代码变更。你可以使用 `bisect` 包来动态控制这些变更。

```go
package main

import (
	"flag"
	"fmt"
	"log"
	"strconv"

	"golang.org/x/tools/internal/bisect"
)

var (
	bisectPattern = flag.String("bisect", "", "bisect pattern")
	enableChange1 = flag.Bool("enable_change1", false, "Enable change 1 manually")
	enableChange2 = flag.Bool("enable_change2", false, "Enable change 2 manually")
)

func main() {
	flag.Parse()

	m, err := bisect.New(*bisectPattern)
	if err != nil {
		log.Fatal(err)
	}

	// 模拟代码变更
	changes := map[string]bool{
		"change1": *enableChange1,
		"change2": *enableChange2,
	}

	for name := range changes {
		id := bisect.Hash(name) // 使用变更名称作为 ID

		shouldEnableManually := changes[name]

		// 使用 bisect 模式决定是否启用变更
		shouldEnableBisect := true
		if m != nil {
			shouldEnableBisect = m.ShouldEnable(id)
		}

		// 最终是否启用取决于手动控制和 bisect 模式
		enable := shouldEnableManually || shouldEnableBisect

		if enable {
			fmt.Printf("启用变更: %s\n", name)
			// ... 执行变更相关的代码 ...
		} else {
			fmt.Printf("禁用变更: %s\n", name)
		}

		// 报告变更信息
		if m != nil && m.ShouldReport(id) {
			log.Printf("%s 发现了变更: %s", bisect.Marker(id), name)
		}
	}
}

// 假设的输入和输出：
// 命令行运行：go run main.go -bisect="0"
// 假设 change1 的 Hash 值为 0x1， change2 的 Hash 值为 0x0

// 输入（命令行参数）：-bisect="0"
//  change1 的 Hash:  运行程序时计算得到，假设为 0x1
//  change2 的 Hash:  运行程序时计算得到，假设为 0x0

// 输出：
// 禁用变更: change1
// 启用变更: change2
// [bisect-match 0x0000000000000000] 发现了变更: change2

// 解释：
// -bisect="0" 表示启用 ID 以二进制 "0" 结尾的变更。
// 假设 change1 的 Hash 值二进制表示以 "1" 结尾，change2 的 Hash 值二进制表示以 "0" 结尾。
// 因此，change2 被启用，并且由于 ShouldReport 返回 true，相关的报告信息被输出。
```

**命令行参数的具体处理：**

`bisect` 包本身不直接处理命令行参数。目标程序需要自行定义接收 bisect 模式的机制，通常是通过 `flag` 包定义一个命令行标志（如上面的 `-bisect` 示例）或者读取环境变量。

`New(pattern string)` 函数接收这个模式字符串作为参数。

**模式语法解析：**

`New` 函数会解析 `pattern` 字符串，其语法规则如下：

*   **位串 (Bit Strings):**  模式由一系列二进制位串组成，用于匹配变更 ID 的后缀。
*   **运算符 (+, -):**  `+` 表示集合的并集，`-` 表示集合的差集。运算符按照从左到右的顺序计算。所有 `+` 运算符必须出现在所有 `-` 运算符之前。
*   **特殊字符:**
    *   `y`:  代表所有变更的集合（空位串的别名）。
    *   `!`:  前缀 `!` 表示反转 `ShouldEnable` 的结果，用于查找需要禁用的变更。`ShouldReport` 的行为不受影响。
    *   `n`:  是 `!y` 的别名，表示禁用并报告所有变更。
    *   `v`:  前缀 `v` 表示启用 verbose 模式，`Matcher.Verbose()` 将返回 `true`。这提示目标程序生成更详细的报告信息。
    *   `x`:  如果位串以 `x` 开头，则后面的位串被解析为十六进制。

**示例模式：**

*   `01+10`: 启用并报告 ID 以 `01` 或 `10` 结尾的变更。
*   `01+10-1001`: 启用并报告 ID 以 `01` 或 `10` 结尾，但不包括以 `1001` 结尾的变更。
*   `-01-1000`: 启用并报告 ID 不以 `01` 或 `1000` 结尾的所有变更。
*   `!01+10`: 禁用并报告 ID 以 `01` 结尾的变更，启用并报告 ID 以 `10` 结尾的变更。
*   `v01`: 启用 verbose 模式，并启用/报告 ID 以 `01` 结尾的变更。

**使用者易犯错的点：**

1. **忘记检查 `Matcher` 是否为 `nil`:** 当没有提供 bisect 模式时，`New` 函数会返回 `nil` 的 `Matcher`。如果没有检查 `nil`，直接调用 `m.ShouldEnable()` 或 `m.ShouldReport()` 会导致 panic。应该先检查 `m == nil`，如果为 `nil`，则表示没有启用 bisect，可以跳过相关的 bisect 逻辑或采取默认行为。

    ```go
    // 错误示例：
    m, _ := bisect.New(*bisectPattern)
    if m.ShouldEnable(bisect.Hash("some_change")) { // 如果 *bisectPattern 为空，这里会 panic
        // ...
    }

    // 正确示例：
    m, _ := bisect.New(*bisectPattern)
    if m != nil && m.ShouldEnable(bisect.Hash("some_change")) {
        // ...
    } else if m == nil {
        // 没有启用 bisect 的默认行为
    }
    ```

2. **`ShouldEnable` 和 `ShouldReport` 的区别理解不清晰:**  这两个方法在 bisect 工具搜索最小禁用集时返回不同的值。`ShouldEnable` 决定是否激活变更，而 `ShouldReport` 决定是否输出包含匹配标记的报告信息。需要根据具体的使用场景正确调用这两个方法。

3. **匹配标记格式错误:**  报告变更时，必须按照 `"[bisect-match 0x<hex_id>]"` 或 `"[bisect-match <binary_id>]"` 的格式输出匹配标记。错误的格式会导致 bisect 工具无法正确解析。

    ```go
    // 错误示例：
    // log.Printf("发现了变更 %s", name) // 缺少匹配标记

    // 正确示例：
    log.Printf("%s 发现了变更 %s", bisect.Marker(id), name)
    ```

4. **模式语法错误:**  提供的模式字符串不符合 `bisect` 包定义的语法规则，会导致 `New` 函数返回错误。例如，`+` 运算符在 `-` 运算符之后出现。

    ```go
    m, err := bisect.New("01-10+00") // 错误的模式，+ 出现在 - 之后
    if err != nil {
        log.Println("模式解析错误:", err)
    }
    ```

5. **`Hash` 函数参数类型错误:** `Hash` 函数只接受特定类型的参数。传递不支持的类型会导致 panic。

    ```go
    type MyType struct {
        Value int
    }

    func main() {
        myVar := MyType{Value: 10}
        bisect.Hash(myVar) // 这里会 panic
    }
    ```

理解这些功能和注意事项可以帮助开发者正确地在自己的 Go 程序中集成 `bisect` 包，从而有效地利用 `bisect` 工具进行调试。

Prompt: 
```
这是路径为go/src/cmd/vendor/golang.org/x/tools/internal/bisect/bisect.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

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
//     The [Matcher.Enable] method answers this question for a given change ID.
//
//  4. Report each change that the pattern says should be reported.
//     The [Matcher.Report] method answers this question for a given change ID.
//     The report consists of one more lines on standard error or standard output
//     that contain a “match marker”. [Marker] returns the match marker for a given ID.
//     When bisect reports a change as causing the failure, it identifies the change
//     by printing those report lines, with the match marker removed.
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
// and then calls m.ShouldEnable and m.ShouldReport to decide whether to
// enable and report the change, respectively:
//
//	for each change {
//		h := bisect.Hash(file, line)
//		if m.ShouldEnable(h) {
//			enableChange()
//		}
//		if m.ShouldReport(h) {
//			log.Printf("%v %s:%d", bisect.Marker(h), file, line)
//		}
//	}
//
// Note that the two return different values when bisect is searching for a
// minimal set of changes to disable to provoke a failure.
//
// Finally, note that New returns a nil Matcher when there is no pattern,
// meaning that the target is not running under bisect at all.
// In that common case, the computation of the hash can be avoided entirely
// by checking for m == nil first:
//
//	for each change {
//		if m == nil {
//			enableChange()
//		} else {
//			h := bisect.Hash(file, line)
//			if m.ShouldEnable(h) {
//				enableChange()
//			}
//			if m.ShouldReport(h) {
//				log.Printf("%v %s:%d", bisect.Marker(h), file, line)
//			}
//		}
//	}
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
// but does not invert the result from [Matcher.ShouldReport].
//
// As a convenience for manual debugging, “n” is an alias for “!y”,
// meaning to disable and report all changes.
//
// Finally, a leading “v” in the pattern indicates that the reports will be shown
// to the user of bisect to describe the changes involved in a failure.
// At the API level, the leading “v” causes [Matcher.Verbose] to return true.
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
// When [Matcher.Verbose] returns false, the match reports are only
// being processed by bisect to learn the set of enabled changes,
// not shown to the user, meaning that each report can be a match
// marker on a line by itself, eliding the usual textual description.
// When the textual description is expensive to compute,
// checking [Matcher.Verbose] can help the avoid that expense
// in most runs.
package bisect

// New creates and returns a new Matcher implementing the given pattern.
// The pattern syntax is defined in the package doc comment.
//
// In addition to the pattern syntax syntax, New("") returns nil, nil.
// The nil *Matcher is valid for use: it returns true from ShouldEnable
// and false from ShouldReport for all changes. Callers can avoid calling
// [Hash], [Matcher.ShouldEnable], and [Matcher.ShouldPrint] entirely
// when they recognize the nil Matcher.
func New(pattern string) (*Matcher, error) {
	if pattern == "" {
		return nil, nil
	}

	m := new(Matcher)

	// Allow multiple v, so that “bisect cmd vPATTERN” can force verbose all the time.
	p := pattern
	for len(p) > 0 && p[0] == 'v' {
		m.verbose = true
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
	verbose bool
	enable  bool   // when true, list is for “enable and report” (when false, “disable and report”)
	list    []cond // conditions; later ones win over earlier ones
}

// A cond is a single condition in the matcher.
// Given an input id, if id&mask == bits, return the result.
type cond struct {
	mask   uint64
	bits   uint64
	result bool
}

// Verbose reports whether the reports will be shown to users
// and need to include a human-readable change description.
// If not, the target can print just the Marker on a line by itself
// and perhaps save some computation.
func (m *Matcher) Verbose() bool {
	return m.verbose
}

// ShouldEnable reports whether the change with the given id should be enabled.
func (m *Matcher) ShouldEnable(id uint64) bool {
	if m == nil {
		return true
	}
	for i := len(m.list) - 1; i >= 0; i-- {
		c := &m.list[i]
		if id&c.mask == c.bits {
			return c.result == m.enable
		}
	}
	return false == m.enable
}

// ShouldReport reports whether the change with the given id should be reported.
func (m *Matcher) ShouldReport(id uint64) bool {
	if m == nil {
		return false
	}
	for i := len(m.list) - 1; i >= 0; i-- {
		c := &m.list[i]
		if id&c.mask == c.bits {
			return c.result
		}
	}
	return false
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

type parseError struct{ text string }

func (e *parseError) Error() string { return e.text }

// FNV-1a implementation. See Go's hash/fnv/fnv.go.
// Copied here for simplicity (can handle uints directly)
// and to avoid the dependency.

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
		h ^= uint64(x & 0xFF)
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

"""



```