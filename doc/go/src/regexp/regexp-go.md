Response:
The user wants a summary of the functionalities of the provided Go code snippet, which is part of the `regexp` package. I need to identify the core features and capabilities offered by this specific section of the code. I should also identify the Go language feature it implements and provide a usage example.

Here's a plan:

1. **Identify the main purpose of the code:** The package name and comments clearly indicate this is about regular expression matching.
2. **List the core functionalities described in the comments:** Pay close attention to the different matching methods (Find, FindAll, Submatch, Index, String), compilation options (Compile, CompilePOSIX), and related functions like Match, ReplaceAll, Expand, QuoteMeta.
3. **Determine the Go language feature implemented:** This is the `regexp` package for regular expression matching.
4. **Provide a Go code example:** Demonstrate the basic usage of compiling a regex and finding a match.
5. **Identify and explain any command-line arguments:** This specific code snippet doesn't seem to handle command-line arguments directly. The user likely refers to how regexes are used in command-line tools, but that's outside the scope of this code. I should clarify this.
6. **Pinpoint potential user errors:** Focus on common mistakes when working with regular expressions in Go, such as misunderstanding matching semantics (leftmost-first vs. leftmost-longest) or incorrect usage of submatches and capturing groups.
7. **Summarize the overall function:** Condense the identified functionalities into a concise summary.
这段代码是 Go 语言标准库 `regexp` 包的一部分，它实现了**正则表达式的搜索和匹配功能**。

**主要功能归纳：**

1. **正则表达式编译：**
    *   `Compile(expr string)`:  将一个字符串形式的正则表达式编译成一个 `Regexp` 对象，用于后续的匹配操作。它采用的是 **leftmost-first** 的匹配语义，类似于 Perl 和 Python。
    *   `CompilePOSIX(expr string)`: 类似于 `Compile`，但它使用 POSIX ERE 语法，并且匹配语义是 **leftmost-longest**。
    *   `MustCompile(str string)` 和 `MustCompilePOSIX(str string)`:  与 `Compile` 和 `CompilePOSIX` 功能相同，但在编译失败时会直接 `panic`。

2. **基本匹配判断：**
    *   `Match(b []byte)`: 判断字节切片 `b` 中是否包含任何与正则表达式匹配的子串。
    *   `MatchString(s string)`: 判断字符串 `s` 中是否包含任何与正则表达式匹配的子串。
    *   `MatchReader(r io.RuneReader)`: 判断从 `io.RuneReader` 读取的文本中是否包含任何与正则表达式匹配的子串。

3. **查找匹配项：**
    *   `Find(b []byte)`: 在字节切片 `b` 中查找**最左边**的匹配项，并返回匹配的字节切片。如果未找到匹配项，则返回 `nil`。
    *   `FindIndex(b []byte)`: 在字节切片 `b` 中查找**最左边**的匹配项，并返回一个包含两个元素的切片，表示匹配项在 `b` 中的起始和结束索引。如果未找到匹配项，则返回 `nil`。
    *   `FindString(s string)`: 在字符串 `s` 中查找**最左边**的匹配项，并返回匹配的字符串。如果未找到匹配项，则返回空字符串。
    *   `FindStringIndex(s string)`: 在字符串 `s` 中查找**最左边**的匹配项，并返回一个包含两个元素的切片，表示匹配项在 `s` 中的起始和结束索引。如果未找到匹配项，则返回 `nil`。
    *   `FindReaderIndex(r io.RuneReader)`: 在从 `io.RuneReader` 读取的文本中查找**最左边**的匹配项，并返回一个包含两个元素的切片，表示匹配项的字节偏移量。如果未找到匹配项，则返回 `nil`。

4. **查找子匹配项（捕获组）：**
    *   `FindSubmatch(b []byte)`:  在字节切片 `b` 中查找**最左边**的匹配项，并返回一个字节切片的切片，其中第一个元素是整个匹配项，后续元素是各个捕获组的匹配项。如果未找到匹配项，则返回 `nil`。
    *   `FindSubmatchIndex(b []byte)`: 在字节切片 `b` 中查找**最左边**的匹配项，并返回一个整数切片，其中每两个元素表示一个捕获组的起始和结束索引（第一个索引对是整个匹配项的）。如果未找到匹配项，则返回 `nil`。
    *   `FindStringSubmatch(s string)`: 在字符串 `s` 中查找**最左边**的匹配项，并返回一个字符串切片，其中第一个元素是整个匹配项，后续元素是各个捕获组的匹配项。如果未找到匹配项，则返回 `nil`。
    *   `FindStringSubmatchIndex(s string)`: 在字符串 `s` 中查找**最左边**的匹配项，并返回一个整数切片，其中每两个元素表示一个捕获组的起始和结束索引（第一个索引对是整个匹配项的）。如果未找到匹配项，则返回 `nil`。
    *   `FindReaderSubmatchIndex(r io.RuneReader)`: 在从 `io.RuneReader` 读取的文本中查找**最左边**的匹配项及其子匹配项的字节偏移量。如果未找到匹配项，则返回 `nil`。

5. **查找所有匹配项：**
    *   `allMatches` 函数（内部使用）：用于查找所有不重叠的匹配项，并调用提供的 `deliver` 函数处理每个匹配项。
    *   提供了以 `FindAll...` 开头的系列方法（未在此部分代码中完全展示），基于 `allMatches` 实现，用于查找所有匹配项及其子匹配项，可以返回匹配文本或索引。

6. **替换功能：**
    *   `ReplaceAllString(src, repl string)`: 将字符串 `src` 中所有匹配正则表达式的部分替换为字符串 `repl`。`repl` 中可以使用 `$1`, `$2` 等引用捕获组。
    *   `ReplaceAllLiteralString(src, repl string)`: 将字符串 `src` 中所有匹配正则表达式的部分替换为字符串 `repl`，`repl` 中的特殊字符不会被解释。
    *   `ReplaceAllStringFunc(src string, repl func(string) string)`: 将字符串 `src` 中所有匹配正则表达式的部分替换为调用 `repl` 函数处理匹配项后的返回值。
    *   `ReplaceAll(src, repl []byte)`，`ReplaceAllLiteral(src, repl []byte)`，`ReplaceAllFunc(src []byte, repl func([]byte) []byte)`:  针对字节切片的替换操作，功能与字符串版本的类似。

7. **模板扩展：**
    *   `Expand(dst []byte, template []byte, src []byte, match []int)`: 将模板字符串 `template` 中的变量（例如 `$1`，`${name}`）替换为 `src` 中对应捕获组的匹配内容，并将结果追加到 `dst` 中。
    *   `ExpandString(dst []byte, template string, src string, match []int)`:  `Expand` 的字符串版本。
    *   `expand` 函数（内部使用）：实际执行模板扩展的逻辑。

8. **元字符转义：**
    *   `QuoteMeta(s string)`:  返回一个将字符串 `s` 中所有正则表达式元字符转义后的字符串，用于匹配字面值。

9. **其他辅助功能：**
    *   `Longest()`: 修改 `Regexp` 对象的行为，使其在匹配时优先选择**最左边最长**的匹配。
    *   `Copy()`: 返回 `Regexp` 对象的一个副本。
    *   `String()`: 返回用于编译正则表达式的原始字符串。
    *   `NumSubexp()`: 返回正则表达式中捕获组的数量。
    *   `SubexpNames()`: 返回一个字符串切片，包含所有捕获组的名称。
    *   `SubexpIndex(name string)`: 返回指定名称的第一个捕获组的索引。
    *   `LiteralPrefix()`: 返回正则表达式匹配项必须包含的字面前缀。

**它是什么 Go 语言功能的实现：**

这段代码是 Go 语言中 **正则表达式** 功能的实现。它提供了创建、编译和使用正则表达式的各种方法。

**Go 代码示例：**

```go
package main

import (
	"fmt"
	"regexp"
)

func main() {
	// 编译一个正则表达式，匹配以 "go" 开头的单词
	re := regexp.MustCompile(`^go\w*`)

	// 要匹配的字符串
	text := "golang is a great language, gofmt is useful."

	// 判断字符串是否包含匹配项
	matched := re.MatchString(text)
	fmt.Println("Match:", matched) // Output: Match: true

	// 查找第一个匹配项
	match := re.FindString(text)
	fmt.Println("FindString:", match) // Output: FindString: golang

	// 查找第一个匹配项及其索引
	matchIndex := re.FindStringIndex(text)
	fmt.Println("FindStringIndex:", matchIndex) // Output: FindStringIndex: [0 6]

	// 查找所有匹配项
	allMatches := re.FindAllString(text, -1)
	fmt.Println("FindAllString:", allMatches) // Output: FindAllString: [golang gofmt]

	// 查找带子匹配项的匹配
	reWithSubmatch := regexp.MustCompile(`(go)(\w*)`)
	submatch := reWithSubmatch.FindStringSubmatch(text)
	fmt.Println("FindStringSubmatch:", submatch) // Output: FindStringSubmatch: [golang go lang]

	// 替换匹配项
	replacedText := re.ReplaceAllString(text, "GO")
	fmt.Println("ReplaceAllString:", replacedText) // Output: ReplaceAllString: GO is a great language, GO is useful.
}
```

**假设的输入与输出（基于示例）：**

**输入字符串:** `"golang is a great language, gofmt is useful."`
**正则表达式:** `^go\w*`

**输出:**
*   `Match: true`
*   `FindString: golang`
*   `FindStringIndex: [0 6]`
*   `FindAllString: [golang gofmt]`
*   `FindStringSubmatch: [golang go lang]`
*   `ReplaceAllString: GO is a great language, GO is useful.`

**命令行参数的具体处理：**

这段代码本身并没有直接处理命令行参数。`regexp` 包主要用于在 Go 程序内部进行正则表达式操作。如果你想在命令行工具中使用正则表达式，你可能需要结合 Go 的 `flag` 包或者其他命令行参数解析库，然后在你的程序中使用 `regexp` 包的功能。

**使用者易犯错的点：**

1. **混淆 leftmost-first 和 leftmost-longest 匹配语义：**
    *   `Compile` 默认使用 leftmost-first，找到第一个匹配项就停止。
    *   `CompilePOSIX` 和 `Longest()` 方法使用 leftmost-longest，会找到最左边且最长的匹配项。
    *   **示例：**
        ```go
        package main

        import (
            "fmt"
            "regexp"
        )

        func main() {
            text := "aaaaa"
            re1 := regexp.MustCompile(`a+`) // leftmost-first
            match1 := re1.FindString(text)
            fmt.Println("Leftmost-first:", match1) // Output: Leftmost-first: aaaaa

            re2 := regexp.MustCompilePOSIX(`a+`) // leftmost-longest
            match2 := re2.FindString(text)
            fmt.Println("Leftmost-longest:", match2) // Output: Leftmost-longest: aaaaa

            re3 := regexp.MustCompile(`a+`)
            re3.Longest() // 设置为 leftmost-longest
            match3 := re3.FindString(text)
            fmt.Println("Longest method:", match3) // Output: Longest method: aaaaa
        }
        ```
        在这个简单的例子中，结果相同。但是在更复杂的模式下，两种语义可能会产生不同的结果，尤其是在涉及到可选部分和重复部分时。

2. **错误理解子匹配索引：** `FindSubmatchIndex` 返回的索引是捕获组在**输入字符串**中的起始和结束位置，而不是相对于整个匹配项的位置。

    *   **示例：**
        ```go
        package main

        import (
            "fmt"
            "regexp"
        )

        func main() {
            text := "abcde"
            re := regexp.MustCompile(`(b)(c)`)
            submatchIndices := re.FindStringSubmatchIndex(text)
            fmt.Println(submatchIndices) // Output: [1 3 1 2 2 3]  (整个匹配项: bc [1, 3], 第一个捕获组: b [1, 2], 第二个捕获组: c [2, 3])
        }
        ```

3. **在 `ReplaceAllString` 中错误使用 `$n` 引用：** 确保 `$n` 中的 `n` 是有效的捕获组编号。如果引用的捕获组不存在或未匹配，则会被替换为空字符串。

    *   **示例：**
        ```go
        package main

        import (
            "fmt"
            "regexp"
        )

        func main() {
            text := "abc"
            re := regexp.MustCompile(`(a)(b)?(c)`) // 第二个捕获组是可选的
            replaced := re.ReplaceAllString(text, "$1-$2-$3")
            fmt.Println(replaced) // Output: a--c (因为 'b' 存在, 第二个捕获组匹配到, $2 为 'b')

            text2 := "ac"
            replaced2 := re.ReplaceAllString(text2, "$1-$2-$3")
            fmt.Println(replaced2) // Output: a--c (因为 'b' 不存在, 第二个捕获组未匹配, $2 为空字符串)
        }
        ```

总而言之，这段代码提供了一套强大且高效的正则表达式处理工具，涵盖了匹配、查找、替换和模板扩展等核心功能。理解其不同的匹配语义和子匹配的处理方式是正确使用它的关键。

Prompt: 
```
这是路径为go/src/regexp/regexp.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package regexp implements regular expression search.
//
// The syntax of the regular expressions accepted is the same
// general syntax used by Perl, Python, and other languages.
// More precisely, it is the syntax accepted by RE2 and described at
// https://golang.org/s/re2syntax, except for \C.
// For an overview of the syntax, see the [regexp/syntax] package.
//
// The regexp implementation provided by this package is
// guaranteed to run in time linear in the size of the input.
// (This is a property not guaranteed by most open source
// implementations of regular expressions.) For more information
// about this property, see https://swtch.com/~rsc/regexp/regexp1.html
// or any book about automata theory.
//
// All characters are UTF-8-encoded code points.
// Following [utf8.DecodeRune], each byte of an invalid UTF-8 sequence
// is treated as if it encoded utf8.RuneError (U+FFFD).
//
// There are 16 methods of [Regexp] that match a regular expression and identify
// the matched text. Their names are matched by this regular expression:
//
//	Find(All)?(String)?(Submatch)?(Index)?
//
// If 'All' is present, the routine matches successive non-overlapping
// matches of the entire expression. Empty matches abutting a preceding
// match are ignored. The return value is a slice containing the successive
// return values of the corresponding non-'All' routine. These routines take
// an extra integer argument, n. If n >= 0, the function returns at most n
// matches/submatches; otherwise, it returns all of them.
//
// If 'String' is present, the argument is a string; otherwise it is a slice
// of bytes; return values are adjusted as appropriate.
//
// If 'Submatch' is present, the return value is a slice identifying the
// successive submatches of the expression. Submatches are matches of
// parenthesized subexpressions (also known as capturing groups) within the
// regular expression, numbered from left to right in order of opening
// parenthesis. Submatch 0 is the match of the entire expression, submatch 1 is
// the match of the first parenthesized subexpression, and so on.
//
// If 'Index' is present, matches and submatches are identified by byte index
// pairs within the input string: result[2*n:2*n+2] identifies the indexes of
// the nth submatch. The pair for n==0 identifies the match of the entire
// expression. If 'Index' is not present, the match is identified by the text
// of the match/submatch. If an index is negative or text is nil, it means that
// subexpression did not match any string in the input. For 'String' versions
// an empty string means either no match or an empty match.
//
// There is also a subset of the methods that can be applied to text read from
// an [io.RuneReader]: [Regexp.MatchReader], [Regexp.FindReaderIndex],
// [Regexp.FindReaderSubmatchIndex].
//
// This set may grow. Note that regular expression matches may need to
// examine text beyond the text returned by a match, so the methods that
// match text from an [io.RuneReader] may read arbitrarily far into the input
// before returning.
//
// (There are a few other methods that do not match this pattern.)
package regexp

import (
	"bytes"
	"io"
	"regexp/syntax"
	"strconv"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

// Regexp is the representation of a compiled regular expression.
// A Regexp is safe for concurrent use by multiple goroutines,
// except for configuration methods, such as [Regexp.Longest].
type Regexp struct {
	expr           string       // as passed to Compile
	prog           *syntax.Prog // compiled program
	onepass        *onePassProg // onepass program or nil
	numSubexp      int
	maxBitStateLen int
	subexpNames    []string
	prefix         string         // required prefix in unanchored matches
	prefixBytes    []byte         // prefix, as a []byte
	prefixRune     rune           // first rune in prefix
	prefixEnd      uint32         // pc for last rune in prefix
	mpool          int            // pool for machines
	matchcap       int            // size of recorded match lengths
	prefixComplete bool           // prefix is the entire regexp
	cond           syntax.EmptyOp // empty-width conditions required at start of match
	minInputLen    int            // minimum length of the input in bytes

	// This field can be modified by the Longest method,
	// but it is otherwise read-only.
	longest bool // whether regexp prefers leftmost-longest match
}

// String returns the source text used to compile the regular expression.
func (re *Regexp) String() string {
	return re.expr
}

// Copy returns a new [Regexp] object copied from re.
// Calling [Regexp.Longest] on one copy does not affect another.
//
// Deprecated: In earlier releases, when using a [Regexp] in multiple goroutines,
// giving each goroutine its own copy helped to avoid lock contention.
// As of Go 1.12, using Copy is no longer necessary to avoid lock contention.
// Copy may still be appropriate if the reason for its use is to make
// two copies with different [Regexp.Longest] settings.
func (re *Regexp) Copy() *Regexp {
	re2 := *re
	return &re2
}

// Compile parses a regular expression and returns, if successful,
// a [Regexp] object that can be used to match against text.
//
// When matching against text, the regexp returns a match that
// begins as early as possible in the input (leftmost), and among those
// it chooses the one that a backtracking search would have found first.
// This so-called leftmost-first matching is the same semantics
// that Perl, Python, and other implementations use, although this
// package implements it without the expense of backtracking.
// For POSIX leftmost-longest matching, see [CompilePOSIX].
func Compile(expr string) (*Regexp, error) {
	return compile(expr, syntax.Perl, false)
}

// CompilePOSIX is like [Compile] but restricts the regular expression
// to POSIX ERE (egrep) syntax and changes the match semantics to
// leftmost-longest.
//
// That is, when matching against text, the regexp returns a match that
// begins as early as possible in the input (leftmost), and among those
// it chooses a match that is as long as possible.
// This so-called leftmost-longest matching is the same semantics
// that early regular expression implementations used and that POSIX
// specifies.
//
// However, there can be multiple leftmost-longest matches, with different
// submatch choices, and here this package diverges from POSIX.
// Among the possible leftmost-longest matches, this package chooses
// the one that a backtracking search would have found first, while POSIX
// specifies that the match be chosen to maximize the length of the first
// subexpression, then the second, and so on from left to right.
// The POSIX rule is computationally prohibitive and not even well-defined.
// See https://swtch.com/~rsc/regexp/regexp2.html#posix for details.
func CompilePOSIX(expr string) (*Regexp, error) {
	return compile(expr, syntax.POSIX, true)
}

// Longest makes future searches prefer the leftmost-longest match.
// That is, when matching against text, the regexp returns a match that
// begins as early as possible in the input (leftmost), and among those
// it chooses a match that is as long as possible.
// This method modifies the [Regexp] and may not be called concurrently
// with any other methods.
func (re *Regexp) Longest() {
	re.longest = true
}

func compile(expr string, mode syntax.Flags, longest bool) (*Regexp, error) {
	re, err := syntax.Parse(expr, mode)
	if err != nil {
		return nil, err
	}
	maxCap := re.MaxCap()
	capNames := re.CapNames()

	re = re.Simplify()
	prog, err := syntax.Compile(re)
	if err != nil {
		return nil, err
	}
	matchcap := prog.NumCap
	if matchcap < 2 {
		matchcap = 2
	}
	regexp := &Regexp{
		expr:        expr,
		prog:        prog,
		onepass:     compileOnePass(prog),
		numSubexp:   maxCap,
		subexpNames: capNames,
		cond:        prog.StartCond(),
		longest:     longest,
		matchcap:    matchcap,
		minInputLen: minInputLen(re),
	}
	if regexp.onepass == nil {
		regexp.prefix, regexp.prefixComplete = prog.Prefix()
		regexp.maxBitStateLen = maxBitStateLen(prog)
	} else {
		regexp.prefix, regexp.prefixComplete, regexp.prefixEnd = onePassPrefix(prog)
	}
	if regexp.prefix != "" {
		// TODO(rsc): Remove this allocation by adding
		// IndexString to package bytes.
		regexp.prefixBytes = []byte(regexp.prefix)
		regexp.prefixRune, _ = utf8.DecodeRuneInString(regexp.prefix)
	}

	n := len(prog.Inst)
	i := 0
	for matchSize[i] != 0 && matchSize[i] < n {
		i++
	}
	regexp.mpool = i

	return regexp, nil
}

// Pools of *machine for use during (*Regexp).doExecute,
// split up by the size of the execution queues.
// matchPool[i] machines have queue size matchSize[i].
// On a 64-bit system each queue entry is 16 bytes,
// so matchPool[0] has 16*2*128 = 4kB queues, etc.
// The final matchPool is a catch-all for very large queues.
var (
	matchSize = [...]int{128, 512, 2048, 16384, 0}
	matchPool [len(matchSize)]sync.Pool
)

// get returns a machine to use for matching re.
// It uses the re's machine cache if possible, to avoid
// unnecessary allocation.
func (re *Regexp) get() *machine {
	m, ok := matchPool[re.mpool].Get().(*machine)
	if !ok {
		m = new(machine)
	}
	m.re = re
	m.p = re.prog
	if cap(m.matchcap) < re.matchcap {
		m.matchcap = make([]int, re.matchcap)
		for _, t := range m.pool {
			t.cap = make([]int, re.matchcap)
		}
	}

	// Allocate queues if needed.
	// Or reallocate, for "large" match pool.
	n := matchSize[re.mpool]
	if n == 0 { // large pool
		n = len(re.prog.Inst)
	}
	if len(m.q0.sparse) < n {
		m.q0 = queue{make([]uint32, n), make([]entry, 0, n)}
		m.q1 = queue{make([]uint32, n), make([]entry, 0, n)}
	}
	return m
}

// put returns a machine to the correct machine pool.
func (re *Regexp) put(m *machine) {
	m.re = nil
	m.p = nil
	m.inputs.clear()
	matchPool[re.mpool].Put(m)
}

// minInputLen walks the regexp to find the minimum length of any matchable input.
func minInputLen(re *syntax.Regexp) int {
	switch re.Op {
	default:
		return 0
	case syntax.OpAnyChar, syntax.OpAnyCharNotNL, syntax.OpCharClass:
		return 1
	case syntax.OpLiteral:
		l := 0
		for _, r := range re.Rune {
			if r == utf8.RuneError {
				l++
			} else {
				l += utf8.RuneLen(r)
			}
		}
		return l
	case syntax.OpCapture, syntax.OpPlus:
		return minInputLen(re.Sub[0])
	case syntax.OpRepeat:
		return re.Min * minInputLen(re.Sub[0])
	case syntax.OpConcat:
		l := 0
		for _, sub := range re.Sub {
			l += minInputLen(sub)
		}
		return l
	case syntax.OpAlternate:
		l := minInputLen(re.Sub[0])
		var lnext int
		for _, sub := range re.Sub[1:] {
			lnext = minInputLen(sub)
			if lnext < l {
				l = lnext
			}
		}
		return l
	}
}

// MustCompile is like [Compile] but panics if the expression cannot be parsed.
// It simplifies safe initialization of global variables holding compiled regular
// expressions.
func MustCompile(str string) *Regexp {
	regexp, err := Compile(str)
	if err != nil {
		panic(`regexp: Compile(` + quote(str) + `): ` + err.Error())
	}
	return regexp
}

// MustCompilePOSIX is like [CompilePOSIX] but panics if the expression cannot be parsed.
// It simplifies safe initialization of global variables holding compiled regular
// expressions.
func MustCompilePOSIX(str string) *Regexp {
	regexp, err := CompilePOSIX(str)
	if err != nil {
		panic(`regexp: CompilePOSIX(` + quote(str) + `): ` + err.Error())
	}
	return regexp
}

func quote(s string) string {
	if strconv.CanBackquote(s) {
		return "`" + s + "`"
	}
	return strconv.Quote(s)
}

// NumSubexp returns the number of parenthesized subexpressions in this [Regexp].
func (re *Regexp) NumSubexp() int {
	return re.numSubexp
}

// SubexpNames returns the names of the parenthesized subexpressions
// in this [Regexp]. The name for the first sub-expression is names[1],
// so that if m is a match slice, the name for m[i] is SubexpNames()[i].
// Since the Regexp as a whole cannot be named, names[0] is always
// the empty string. The slice should not be modified.
func (re *Regexp) SubexpNames() []string {
	return re.subexpNames
}

// SubexpIndex returns the index of the first subexpression with the given name,
// or -1 if there is no subexpression with that name.
//
// Note that multiple subexpressions can be written using the same name, as in
// (?P<bob>a+)(?P<bob>b+), which declares two subexpressions named "bob".
// In this case, SubexpIndex returns the index of the leftmost such subexpression
// in the regular expression.
func (re *Regexp) SubexpIndex(name string) int {
	if name != "" {
		for i, s := range re.subexpNames {
			if name == s {
				return i
			}
		}
	}
	return -1
}

const endOfText rune = -1

// input abstracts different representations of the input text. It provides
// one-character lookahead.
type input interface {
	step(pos int) (r rune, width int) // advance one rune
	canCheckPrefix() bool             // can we look ahead without losing info?
	hasPrefix(re *Regexp) bool
	index(re *Regexp, pos int) int
	context(pos int) lazyFlag
}

// inputString scans a string.
type inputString struct {
	str string
}

func (i *inputString) step(pos int) (rune, int) {
	if pos < len(i.str) {
		c := i.str[pos]
		if c < utf8.RuneSelf {
			return rune(c), 1
		}
		return utf8.DecodeRuneInString(i.str[pos:])
	}
	return endOfText, 0
}

func (i *inputString) canCheckPrefix() bool {
	return true
}

func (i *inputString) hasPrefix(re *Regexp) bool {
	return strings.HasPrefix(i.str, re.prefix)
}

func (i *inputString) index(re *Regexp, pos int) int {
	return strings.Index(i.str[pos:], re.prefix)
}

func (i *inputString) context(pos int) lazyFlag {
	r1, r2 := endOfText, endOfText
	// 0 < pos && pos <= len(i.str)
	if uint(pos-1) < uint(len(i.str)) {
		r1 = rune(i.str[pos-1])
		if r1 >= utf8.RuneSelf {
			r1, _ = utf8.DecodeLastRuneInString(i.str[:pos])
		}
	}
	// 0 <= pos && pos < len(i.str)
	if uint(pos) < uint(len(i.str)) {
		r2 = rune(i.str[pos])
		if r2 >= utf8.RuneSelf {
			r2, _ = utf8.DecodeRuneInString(i.str[pos:])
		}
	}
	return newLazyFlag(r1, r2)
}

// inputBytes scans a byte slice.
type inputBytes struct {
	str []byte
}

func (i *inputBytes) step(pos int) (rune, int) {
	if pos < len(i.str) {
		c := i.str[pos]
		if c < utf8.RuneSelf {
			return rune(c), 1
		}
		return utf8.DecodeRune(i.str[pos:])
	}
	return endOfText, 0
}

func (i *inputBytes) canCheckPrefix() bool {
	return true
}

func (i *inputBytes) hasPrefix(re *Regexp) bool {
	return bytes.HasPrefix(i.str, re.prefixBytes)
}

func (i *inputBytes) index(re *Regexp, pos int) int {
	return bytes.Index(i.str[pos:], re.prefixBytes)
}

func (i *inputBytes) context(pos int) lazyFlag {
	r1, r2 := endOfText, endOfText
	// 0 < pos && pos <= len(i.str)
	if uint(pos-1) < uint(len(i.str)) {
		r1 = rune(i.str[pos-1])
		if r1 >= utf8.RuneSelf {
			r1, _ = utf8.DecodeLastRune(i.str[:pos])
		}
	}
	// 0 <= pos && pos < len(i.str)
	if uint(pos) < uint(len(i.str)) {
		r2 = rune(i.str[pos])
		if r2 >= utf8.RuneSelf {
			r2, _ = utf8.DecodeRune(i.str[pos:])
		}
	}
	return newLazyFlag(r1, r2)
}

// inputReader scans a RuneReader.
type inputReader struct {
	r     io.RuneReader
	atEOT bool
	pos   int
}

func (i *inputReader) step(pos int) (rune, int) {
	if !i.atEOT && pos != i.pos {
		return endOfText, 0

	}
	r, w, err := i.r.ReadRune()
	if err != nil {
		i.atEOT = true
		return endOfText, 0
	}
	i.pos += w
	return r, w
}

func (i *inputReader) canCheckPrefix() bool {
	return false
}

func (i *inputReader) hasPrefix(re *Regexp) bool {
	return false
}

func (i *inputReader) index(re *Regexp, pos int) int {
	return -1
}

func (i *inputReader) context(pos int) lazyFlag {
	return 0 // not used
}

// LiteralPrefix returns a literal string that must begin any match
// of the regular expression re. It returns the boolean true if the
// literal string comprises the entire regular expression.
func (re *Regexp) LiteralPrefix() (prefix string, complete bool) {
	return re.prefix, re.prefixComplete
}

// MatchReader reports whether the text returned by the [io.RuneReader]
// contains any match of the regular expression re.
func (re *Regexp) MatchReader(r io.RuneReader) bool {
	return re.doMatch(r, nil, "")
}

// MatchString reports whether the string s
// contains any match of the regular expression re.
func (re *Regexp) MatchString(s string) bool {
	return re.doMatch(nil, nil, s)
}

// Match reports whether the byte slice b
// contains any match of the regular expression re.
func (re *Regexp) Match(b []byte) bool {
	return re.doMatch(nil, b, "")
}

// MatchReader reports whether the text returned by the [io.RuneReader]
// contains any match of the regular expression pattern.
// More complicated queries need to use [Compile] and the full [Regexp] interface.
func MatchReader(pattern string, r io.RuneReader) (matched bool, err error) {
	re, err := Compile(pattern)
	if err != nil {
		return false, err
	}
	return re.MatchReader(r), nil
}

// MatchString reports whether the string s
// contains any match of the regular expression pattern.
// More complicated queries need to use [Compile] and the full [Regexp] interface.
func MatchString(pattern string, s string) (matched bool, err error) {
	re, err := Compile(pattern)
	if err != nil {
		return false, err
	}
	return re.MatchString(s), nil
}

// Match reports whether the byte slice b
// contains any match of the regular expression pattern.
// More complicated queries need to use [Compile] and the full [Regexp] interface.
func Match(pattern string, b []byte) (matched bool, err error) {
	re, err := Compile(pattern)
	if err != nil {
		return false, err
	}
	return re.Match(b), nil
}

// ReplaceAllString returns a copy of src, replacing matches of the [Regexp]
// with the replacement string repl.
// Inside repl, $ signs are interpreted as in [Regexp.Expand].
func (re *Regexp) ReplaceAllString(src, repl string) string {
	n := 2
	if strings.Contains(repl, "$") {
		n = 2 * (re.numSubexp + 1)
	}
	b := re.replaceAll(nil, src, n, func(dst []byte, match []int) []byte {
		return re.expand(dst, repl, nil, src, match)
	})
	return string(b)
}

// ReplaceAllLiteralString returns a copy of src, replacing matches of the [Regexp]
// with the replacement string repl. The replacement repl is substituted directly,
// without using [Regexp.Expand].
func (re *Regexp) ReplaceAllLiteralString(src, repl string) string {
	return string(re.replaceAll(nil, src, 2, func(dst []byte, match []int) []byte {
		return append(dst, repl...)
	}))
}

// ReplaceAllStringFunc returns a copy of src in which all matches of the
// [Regexp] have been replaced by the return value of function repl applied
// to the matched substring. The replacement returned by repl is substituted
// directly, without using [Regexp.Expand].
func (re *Regexp) ReplaceAllStringFunc(src string, repl func(string) string) string {
	b := re.replaceAll(nil, src, 2, func(dst []byte, match []int) []byte {
		return append(dst, repl(src[match[0]:match[1]])...)
	})
	return string(b)
}

func (re *Regexp) replaceAll(bsrc []byte, src string, nmatch int, repl func(dst []byte, m []int) []byte) []byte {
	lastMatchEnd := 0 // end position of the most recent match
	searchPos := 0    // position where we next look for a match
	var buf []byte
	var endPos int
	if bsrc != nil {
		endPos = len(bsrc)
	} else {
		endPos = len(src)
	}
	if nmatch > re.prog.NumCap {
		nmatch = re.prog.NumCap
	}

	var dstCap [2]int
	for searchPos <= endPos {
		a := re.doExecute(nil, bsrc, src, searchPos, nmatch, dstCap[:0])
		if len(a) == 0 {
			break // no more matches
		}

		// Copy the unmatched characters before this match.
		if bsrc != nil {
			buf = append(buf, bsrc[lastMatchEnd:a[0]]...)
		} else {
			buf = append(buf, src[lastMatchEnd:a[0]]...)
		}

		// Now insert a copy of the replacement string, but not for a
		// match of the empty string immediately after another match.
		// (Otherwise, we get double replacement for patterns that
		// match both empty and nonempty strings.)
		if a[1] > lastMatchEnd || a[0] == 0 {
			buf = repl(buf, a)
		}
		lastMatchEnd = a[1]

		// Advance past this match; always advance at least one character.
		var width int
		if bsrc != nil {
			_, width = utf8.DecodeRune(bsrc[searchPos:])
		} else {
			_, width = utf8.DecodeRuneInString(src[searchPos:])
		}
		if searchPos+width > a[1] {
			searchPos += width
		} else if searchPos+1 > a[1] {
			// This clause is only needed at the end of the input
			// string. In that case, DecodeRuneInString returns width=0.
			searchPos++
		} else {
			searchPos = a[1]
		}
	}

	// Copy the unmatched characters after the last match.
	if bsrc != nil {
		buf = append(buf, bsrc[lastMatchEnd:]...)
	} else {
		buf = append(buf, src[lastMatchEnd:]...)
	}

	return buf
}

// ReplaceAll returns a copy of src, replacing matches of the [Regexp]
// with the replacement text repl.
// Inside repl, $ signs are interpreted as in [Regexp.Expand].
func (re *Regexp) ReplaceAll(src, repl []byte) []byte {
	n := 2
	if bytes.IndexByte(repl, '$') >= 0 {
		n = 2 * (re.numSubexp + 1)
	}
	srepl := ""
	b := re.replaceAll(src, "", n, func(dst []byte, match []int) []byte {
		if len(srepl) != len(repl) {
			srepl = string(repl)
		}
		return re.expand(dst, srepl, src, "", match)
	})
	return b
}

// ReplaceAllLiteral returns a copy of src, replacing matches of the [Regexp]
// with the replacement bytes repl. The replacement repl is substituted directly,
// without using [Regexp.Expand].
func (re *Regexp) ReplaceAllLiteral(src, repl []byte) []byte {
	return re.replaceAll(src, "", 2, func(dst []byte, match []int) []byte {
		return append(dst, repl...)
	})
}

// ReplaceAllFunc returns a copy of src in which all matches of the
// [Regexp] have been replaced by the return value of function repl applied
// to the matched byte slice. The replacement returned by repl is substituted
// directly, without using [Regexp.Expand].
func (re *Regexp) ReplaceAllFunc(src []byte, repl func([]byte) []byte) []byte {
	return re.replaceAll(src, "", 2, func(dst []byte, match []int) []byte {
		return append(dst, repl(src[match[0]:match[1]])...)
	})
}

// Bitmap used by func special to check whether a character needs to be escaped.
var specialBytes [16]byte

// special reports whether byte b needs to be escaped by QuoteMeta.
func special(b byte) bool {
	return b < utf8.RuneSelf && specialBytes[b%16]&(1<<(b/16)) != 0
}

func init() {
	for _, b := range []byte(`\.+*?()|[]{}^$`) {
		specialBytes[b%16] |= 1 << (b / 16)
	}
}

// QuoteMeta returns a string that escapes all regular expression metacharacters
// inside the argument text; the returned string is a regular expression matching
// the literal text.
func QuoteMeta(s string) string {
	// A byte loop is correct because all metacharacters are ASCII.
	var i int
	for i = 0; i < len(s); i++ {
		if special(s[i]) {
			break
		}
	}
	// No meta characters found, so return original string.
	if i >= len(s) {
		return s
	}

	b := make([]byte, 2*len(s)-i)
	copy(b, s[:i])
	j := i
	for ; i < len(s); i++ {
		if special(s[i]) {
			b[j] = '\\'
			j++
		}
		b[j] = s[i]
		j++
	}
	return string(b[:j])
}

// The number of capture values in the program may correspond
// to fewer capturing expressions than are in the regexp.
// For example, "(a){0}" turns into an empty program, so the
// maximum capture in the program is 0 but we need to return
// an expression for \1.  Pad appends -1s to the slice a as needed.
func (re *Regexp) pad(a []int) []int {
	if a == nil {
		// No match.
		return nil
	}
	n := (1 + re.numSubexp) * 2
	for len(a) < n {
		a = append(a, -1)
	}
	return a
}

// allMatches calls deliver at most n times
// with the location of successive matches in the input text.
// The input text is b if non-nil, otherwise s.
func (re *Regexp) allMatches(s string, b []byte, n int, deliver func([]int)) {
	var end int
	if b == nil {
		end = len(s)
	} else {
		end = len(b)
	}

	for pos, i, prevMatchEnd := 0, 0, -1; i < n && pos <= end; {
		matches := re.doExecute(nil, b, s, pos, re.prog.NumCap, nil)
		if len(matches) == 0 {
			break
		}

		accept := true
		if matches[1] == pos {
			// We've found an empty match.
			if matches[0] == prevMatchEnd {
				// We don't allow an empty match right
				// after a previous match, so ignore it.
				accept = false
			}
			var width int
			if b == nil {
				is := inputString{str: s}
				_, width = is.step(pos)
			} else {
				ib := inputBytes{str: b}
				_, width = ib.step(pos)
			}
			if width > 0 {
				pos += width
			} else {
				pos = end + 1
			}
		} else {
			pos = matches[1]
		}
		prevMatchEnd = matches[1]

		if accept {
			deliver(re.pad(matches))
			i++
		}
	}
}

// Find returns a slice holding the text of the leftmost match in b of the regular expression.
// A return value of nil indicates no match.
func (re *Regexp) Find(b []byte) []byte {
	var dstCap [2]int
	a := re.doExecute(nil, b, "", 0, 2, dstCap[:0])
	if a == nil {
		return nil
	}
	return b[a[0]:a[1]:a[1]]
}

// FindIndex returns a two-element slice of integers defining the location of
// the leftmost match in b of the regular expression. The match itself is at
// b[loc[0]:loc[1]].
// A return value of nil indicates no match.
func (re *Regexp) FindIndex(b []byte) (loc []int) {
	a := re.doExecute(nil, b, "", 0, 2, nil)
	if a == nil {
		return nil
	}
	return a[0:2]
}

// FindString returns a string holding the text of the leftmost match in s of the regular
// expression. If there is no match, the return value is an empty string,
// but it will also be empty if the regular expression successfully matches
// an empty string. Use [Regexp.FindStringIndex] or [Regexp.FindStringSubmatch] if it is
// necessary to distinguish these cases.
func (re *Regexp) FindString(s string) string {
	var dstCap [2]int
	a := re.doExecute(nil, nil, s, 0, 2, dstCap[:0])
	if a == nil {
		return ""
	}
	return s[a[0]:a[1]]
}

// FindStringIndex returns a two-element slice of integers defining the
// location of the leftmost match in s of the regular expression. The match
// itself is at s[loc[0]:loc[1]].
// A return value of nil indicates no match.
func (re *Regexp) FindStringIndex(s string) (loc []int) {
	a := re.doExecute(nil, nil, s, 0, 2, nil)
	if a == nil {
		return nil
	}
	return a[0:2]
}

// FindReaderIndex returns a two-element slice of integers defining the
// location of the leftmost match of the regular expression in text read from
// the [io.RuneReader]. The match text was found in the input stream at
// byte offset loc[0] through loc[1]-1.
// A return value of nil indicates no match.
func (re *Regexp) FindReaderIndex(r io.RuneReader) (loc []int) {
	a := re.doExecute(r, nil, "", 0, 2, nil)
	if a == nil {
		return nil
	}
	return a[0:2]
}

// FindSubmatch returns a slice of slices holding the text of the leftmost
// match of the regular expression in b and the matches, if any, of its
// subexpressions, as defined by the 'Submatch' descriptions in the package
// comment.
// A return value of nil indicates no match.
func (re *Regexp) FindSubmatch(b []byte) [][]byte {
	var dstCap [4]int
	a := re.doExecute(nil, b, "", 0, re.prog.NumCap, dstCap[:0])
	if a == nil {
		return nil
	}
	ret := make([][]byte, 1+re.numSubexp)
	for i := range ret {
		if 2*i < len(a) && a[2*i] >= 0 {
			ret[i] = b[a[2*i]:a[2*i+1]:a[2*i+1]]
		}
	}
	return ret
}

// Expand appends template to dst and returns the result; during the
// append, Expand replaces variables in the template with corresponding
// matches drawn from src. The match slice should have been returned by
// [Regexp.FindSubmatchIndex].
//
// In the template, a variable is denoted by a substring of the form
// $name or ${name}, where name is a non-empty sequence of letters,
// digits, and underscores. A purely numeric name like $1 refers to
// the submatch with the corresponding index; other names refer to
// capturing parentheses named with the (?P<name>...) syntax. A
// reference to an out of range or unmatched index or a name that is not
// present in the regular expression is replaced with an empty slice.
//
// In the $name form, name is taken to be as long as possible: $1x is
// equivalent to ${1x}, not ${1}x, and, $10 is equivalent to ${10}, not ${1}0.
//
// To insert a literal $ in the output, use $$ in the template.
func (re *Regexp) Expand(dst []byte, template []byte, src []byte, match []int) []byte {
	return re.expand(dst, string(template), src, "", match)
}

// ExpandString is like [Regexp.Expand] but the template and source are strings.
// It appends to and returns a byte slice in order to give the calling
// code control over allocation.
func (re *Regexp) ExpandString(dst []byte, template string, src string, match []int) []byte {
	return re.expand(dst, template, nil, src, match)
}

func (re *Regexp) expand(dst []byte, template string, bsrc []byte, src string, match []int) []byte {
	for len(template) > 0 {
		before, after, ok := strings.Cut(template, "$")
		if !ok {
			break
		}
		dst = append(dst, before...)
		template = after
		if template != "" && template[0] == '$' {
			// Treat $$ as $.
			dst = append(dst, '$')
			template = template[1:]
			continue
		}
		name, num, rest, ok := extract(template)
		if !ok {
			// Malformed; treat $ as raw text.
			dst = append(dst, '$')
			continue
		}
		template = rest
		if num >= 0 {
			if 2*num+1 < len(match) && match[2*num] >= 0 {
				if bsrc != nil {
					dst = append(dst, bsrc[match[2*num]:match[2*num+1]]...)
				} else {
					dst = append(dst, src[match[2*num]:match[2*num+1]]...)
				}
			}
		} else {
			for i, namei := range re.subexpNames {
				if name == namei && 2*i+1 < len(match) && match[2*i] >= 0 {
					if bsrc != nil {
						dst = append(dst, bsrc[match[2*i]:match[2*i+1]]...)
					} else {
						dst = append(dst, src[match[2*i]:match[2*i+1]]...)
					}
					break
				}
			}
		}
	}
	dst = append(dst, template...)
	return dst
}

// extract returns the name from a leading "name" or "{name}" in str.
// (The $ has already been removed by the caller.)
// If it is a number, extract returns num set to that number; otherwise num = -1.
func extract(str string) (name string, num int, rest string, ok bool) {
	if str == "" {
		return
	}
	brace := false
	if str[0] == '{' {
		brace = true
		str = str[1:]
	}
	i := 0
	for i < len(str) {
		rune, size := utf8.DecodeRuneInString(str[i:])
		if !unicode.IsLetter(rune) && !unicode.IsDigit(rune) && rune != '_' {
			break
		}
		i += size
	}
	if i == 0 {
		// empty name is not okay
		return
	}
	name = str[:i]
	if brace {
		if i >= len(str) || str[i] != '}' {
			// missing closing brace
			return
		}
		i++
	}

	// Parse number.
	num = 0
	for i := 0; i < len(name); i++ {
		if name[i] < '0' || '9' < name[i] || num >= 1e8 {
			num = -1
			break
		}
		num = num*10 + int(name[i]) - '0'
	}
	// Disallow leading zeros.
	if name[0] == '0' && len(name) > 1 {
		num = -1
	}

	rest = str[i:]
	ok = true
	return
}

// FindSubmatchIndex returns a slice holding the index pairs identifying the
// leftmost match of the regular expression in b and the matches, if any, of
// its subexpressions, as defined by the 'Submatch' and 'Index' descriptions
// in the package comment.
// A return value of nil indicates no match.
func (re *Regexp) FindSubmatchIndex(b []byte) []int {
	return re.pad(re.doExecute(nil, b, "", 0, re.prog.NumCap, nil))
}

// FindStringSubmatch returns a slice of strings holding the text of the
// leftmost match of the regular expression in s and the matches, if any, of
// its subexpressions, as defined by the 'Submatch' description in the
// package comment.
// A return value of nil indicates no match.
func (re *Regexp) FindStringSubmatch(s string) []string {
	var dstCap [4]int
	a := re.doExecute(nil, nil, s, 0, re.prog.NumCap, dstCap[:0])
	if a == nil {
		return nil
	}
	ret := make([]string, 1+re.numSubexp)
	for i := range ret {
		if 2*i < len(a) && a[2*i] >= 0 {
			ret[i] = s[a[2*i]:a[2*i+1]]
		}
	}
	return ret
}

// FindStringSubmatchIndex returns a slice holding the index pairs
// identifying the leftmost match of the regular expression in s and the
// matches, if any, of its subexpressions, as defined by the 'Submatch' and
// 'Index' descriptions in the package comment.
// A return value of nil indicates no match.
func (re *Regexp) FindStringSubmatchIndex(s string) []int {
	return re.pad(re.doExecute(nil, nil, s, 0, re.prog.NumCap, nil))
}

// FindReaderSubmatchIndex returns a slice holding the index pairs
// identifying the leftmost match of the regular expression of text read by
// the [io.RuneReader], and the matches, if any, of its subexpressions, as defined
// by the 'Submatch' and 'Index' descriptions in the package comment. A
// return value of nil indicates no match.
fu
"""




```