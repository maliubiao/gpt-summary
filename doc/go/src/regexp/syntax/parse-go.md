Response:
My thinking process to answer the request goes like this:

1. **Understand the Goal:** The core request is to analyze a Go file (`parse.go`) related to regular expressions and explain its functionality, focusing on its role within the larger `regexp` package. The breakdown into sections (error handling, flags, parsing logic, etc.) hints at the major areas to cover. The request also asks for examples and potential pitfalls.

2. **Initial Skim and Identify Key Areas:** I quickly read through the code, noting the major structures and functions. Keywords like `Error`, `ErrorCode`, `Flags`, `parser`, `Parse`, `literal`, `op`, `repeat`, `concat`, `alternate`, `factor` stand out. This gives me a high-level understanding of what the code is doing.

3. **Focus on the Provided Part (Part 1):** The request specifically asks to summarize the functionality of the *first part* of the file. This is crucial. I need to be careful not to delve too deeply into functions that might be primarily defined in the *second part*.

4. **Categorize Functionality:** I mentally group the code into logical categories:
    * **Error Handling:**  The `Error` and `ErrorCode` types, the `Error()` method, and the various `Err...` constants clearly relate to reporting parsing failures.
    * **Flags:** The `Flags` type and the `const` declarations are for controlling the regex parsing behavior.
    * **Parser Structure:** The `parser` struct holds the state of the parsing process (stack, flags, etc.).
    * **Basic Parsing Operations:**  Functions like `newRegexp`, `reuse`, `push`, `literal`, `op` are fundamental building blocks for constructing the regex parse tree.
    * **Combining Expressions:** Functions like `concat` and `alternate` deal with how different parts of the regex are combined.
    * **Repetition:** The `repeat` function handles operators like `*`, `+`, `?`, and `{}`.
    * **Limits and Optimization:** `maxHeight`, `maxSize`, `maxRunes`, and the associated `checkLimits` functions suggest mechanisms for preventing overly complex or large regexes.
    * **Factoring:** The `factor` function seems related to optimizing alternations (the `|` operator).
    * **Leading String/Regexp Handling:** Functions like `leadingString`, `removeLeadingString`, `leadingRegexp`, and `removeLeadingRegexp` suggest optimizations for concatenations.
    * **Entry Point:** The `Parse` function is the main entry point for using this code.

5. **Describe Each Category Concisely:** I now go through each category and summarize its purpose in the context of regex parsing:

    * **Error Handling:** This part defines how parsing errors are represented and reported, including specific error codes.
    * **Flags:**  These control how the regex is interpreted (case-sensitivity, handling of newlines, etc.). I list some key flags and their meanings.
    * **Parser Structure:** I explain that the `parser` struct holds the temporary data and state needed during the parsing process, mentioning the stack, flags, and allocated regexps.
    * **Basic Parsing Operations:** I explain that these functions create and manage individual regex nodes (like literals or operators) and place them on the stack.
    * **Combining Expressions:** I describe how `concat` and `alternate` combine sub-expressions according to the regex syntax.
    * **Repetition:**  I summarize how the `repeat` function handles repetition operators, noting the parsing of min/max values.
    * **Limits and Optimization:** I explain that these limits and checks prevent resource exhaustion and overly complex regexes.
    * **Factoring:**  I summarize the optimization done by `factor` to simplify alternations.
    * **Leading String/Regexp Handling:** I explain these functions are for optimizing concatenations by identifying and removing common prefixes.
    * **Entry Point:** I clearly identify `Parse` as the function used to initiate the parsing process.

6. **Infer the Overall Functionality:** Based on the individual components, I deduce that this part of `parse.go` is responsible for taking a regex string as input and converting it into an internal representation (the `Regexp` tree). This involves lexical analysis, syntax analysis, and potentially some early optimization.

7. **Illustrate with Go Code (Simple Case):** To provide a concrete example, I choose a very simple case of parsing a literal string. This avoids getting bogged down in more complex regex syntax. I show how to import the `syntax` package and call the `Parse` function. I also provide the expected output (the `OpLiteral` node).

8. **Address Potential Pitfalls (Based on the Code):**  I scan the error codes and the logic related to limits and repetitions to identify common mistakes:
    * **Invalid Escape Sequences:** The `ErrInvalidEscape` code suggests this.
    * **Missing Parentheses/Brackets:** `ErrMissingParen` and `ErrMissingBracket` are clear indicators.
    * **Invalid Repeat Syntax:** `ErrInvalidRepeatOp`, `ErrMissingRepeatArgument`, and `ErrInvalidRepeatSize` point to issues with repetition operators.
    * **Exceeding Limits:** The `ErrLarge` and `ErrNestingDepth` errors highlight the limitations on regex size and complexity.

9. **Structure the Answer Clearly:** I organize the answer using headings and bullet points to make it easy to read and understand. I use clear and concise language.

10. **Review and Refine:** Finally, I reread my answer and the code to ensure accuracy, completeness (within the scope of "part 1"), and clarity. I double-check that my Go code example is correct and that my explanations align with the code's behavior. For instance, initially, I might have focused too much on the `Regexp` struct's full details, but since this is just "part 1", focusing on its *creation* rather than its full structure is more appropriate. I also made sure to explicitly mention that this is only part of the regex implementation.
这是 `go/src/regexp/syntax/parse.go` 文件的一部分，专门负责将**正则表达式字符串**解析成一个**抽象语法树 (AST)** 的过程。这个 AST 由 `Regexp` 结构体表示，它详细描述了正则表达式的结构和操作。

**以下是该部分代码的主要功能归纳：**

1. **定义了错误类型和错误码：**
   - `Error` 结构体用于表示解析正则表达式时发生的错误，包含了错误码 `ErrorCode` 和错误的表达式 `Expr`。
   - `ErrorCode` 类型定义了各种可能的解析错误，例如无效字符类、无效转义序列、缺少括号等等。

2. **定义了解析器的标志 (Flags)：**
   - `Flags` 类型是一个位掩码，用于控制解析器的行为，并记录关于正则表达式上下文的信息。
   - 它定义了诸如 `FoldCase`（忽略大小写）、`Literal`（将模式视为字面字符串）、`DotNL`（允许 `.` 匹配换行符）等标志，这些标志会影响正则表达式的解释方式。

3. **定义了内部使用的伪操作符 (Pseudo-ops)：**
   - 这些常量 (`opLeftParen`, `opVerticalBar`) 用于在解析堆栈中辅助处理括号和竖线（或）操作符。

4. **定义了解析树的限制：**
   - `maxHeight` 和 `maxSize` 定义了正则表达式解析树的最大高度和编译后的最大尺寸，以防止解析过于复杂或庞大的正则表达式导致资源耗尽。
   - `maxRunes` 定义了字符类中允许的最大 `rune` 数量。

5. **实现了 `parser` 结构体：**
   - `parser` 结构体是进行正则表达式解析的核心，它维护了解析过程中的状态，例如：
     - `flags`: 当前的解析标志。
     - `stack`: 用于存储已解析的正则表达式片段的堆栈。
     - `free`: 用于复用 `Regexp` 结构体的空闲列表，提高性能。
     - `numCap`: 已遇到的捕获组的数量。
     - `wholeRegexp`: 完整的正则表达式字符串。
     - `tmpClass`: 用于构建字符类的临时工作空间。
     - `numRegexp`: 已分配的 `Regexp` 结构体的数量。
     - `numRunes`: 字符类中 `rune` 的数量。
     - `repeats`: 所有重复操作的乘积，用于初步判断是否可能超出大小限制。
     - `height`, `size`: 用于存储已解析的 `Regexp` 结构体的高度和大小，用于检查是否超出限制。

6. **实现了用于创建和管理 `Regexp` 结构体的辅助方法：**
   - `newRegexp`: 创建一个新的 `Regexp` 结构体。
   - `reuse`: 将一个 `Regexp` 结构体放回空闲列表。
   - `checkLimits`, `checkSize`, `checkHeight`: 检查解析的正则表达式是否超出了预定义的限制。

7. **实现了解析堆栈的操作方法：**
   - `push`: 将一个 `Regexp` 结构体压入解析堆栈。
   - `maybeConcat`:  尝试将顶部的两个字面量 `Regexp` 结构体合并成一个，实现字面量的连接优化。
   - `literal`: 创建一个表示字面字符的 `Regexp` 结构体并压入堆栈。
   - `op`: 创建一个带有指定操作符的 `Regexp` 结构体并压入堆栈。
   - `repeat`: 处理重复操作符 (`*`, `+`, `?`, `{}`)，将堆栈顶部的元素包装成一个重复的 `Regexp` 结构体。
   - `concat`: 将堆栈顶部的一系列 `Regexp` 结构体合并成一个表示连接操作的 `Regexp` 结构体。
   - `alternate`: 将堆栈顶部的一系列 `Regexp` 结构体合并成一个表示或操作的 `Regexp` 结构体。
   - `collapse`: 用于辅助 `concat` 和 `alternate`，将子表达式中相同类型的操作符进行扁平化处理，避免嵌套。
   - `factor`: 用于优化或操作，提取公共前缀，例如将 `ABC|ABD` 优化为 `AB(C|D)`。
   - `leadingString`, `removeLeadingString`, `leadingRegexp`, `removeLeadingRegexp`: 用于在 `factor` 过程中处理前缀。

8. **实现了 `Parse` 函数：**
   - `Parse` 函数是该部分代码的入口点，它接收一个正则表达式字符串和一组标志作为输入。
   - 它创建一个 `parser` 实例，并逐步解析输入字符串，根据不同的字符和操作符执行相应的解析操作，最终构建出代表整个正则表达式的 `Regexp` 抽象语法树。
   - 在解析过程中，它会处理各种语法元素，例如字面字符、特殊字符、字符类、分组、重复等等。
   - 如果解析过程中出现错误，它会返回一个包含错误信息的 `Error` 结构体。

**可以推理出它是什么 go 语言功能的实现：正则表达式解析器。**

**Go 代码举例说明：**

```go
package main

import (
	"fmt"
	"regexp/syntax"
)

func main() {
	reStr := "a(b|c)*d"
	flags := syntax.Perl // 使用 Perl 风格的正则表达式语法

	regexpAST, err := syntax.Parse(reStr, flags)
	if err != nil {
		fmt.Println("解析错误:", err)
		return
	}

	fmt.Printf("正则表达式: %s\n", reStr)
	fmt.Printf("抽象语法树: %+v\n", regexpAST)
	// 输出的抽象语法树结构会很复杂，这里只是一个示意
}
```

**假设输入与输出：**

**输入:** `reStr = "a(b|c)*d"`, `flags = syntax.Perl`

**可能的输出 (简化版，实际输出会更详细):**

```
正则表达式: a(b|c)*d
抽象语法树: &{Op:OpConcat Sub:[0xc000010000 0xc000010040 0xc000010080] ...}
```

这个输出表明解析器成功将正则表达式字符串 `a(b|c)*d` 解析成了一个 `OpConcat` (连接) 操作，其子表达式包含了 `a` (字面量)、`(b|c)*` (重复的或操作) 和 `d` (字面量)。

**该部分代码主要负责语法分析，将文本形式的正则表达式转化为结构化的内部表示，为后续的编译和匹配过程做准备。**

Prompt: 
```
这是路径为go/src/regexp/syntax/parse.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package syntax

import (
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// An Error describes a failure to parse a regular expression
// and gives the offending expression.
type Error struct {
	Code ErrorCode
	Expr string
}

func (e *Error) Error() string {
	return "error parsing regexp: " + e.Code.String() + ": `" + e.Expr + "`"
}

// An ErrorCode describes a failure to parse a regular expression.
type ErrorCode string

const (
	// Unexpected error
	ErrInternalError ErrorCode = "regexp/syntax: internal error"

	// Parse errors
	ErrInvalidCharClass      ErrorCode = "invalid character class"
	ErrInvalidCharRange      ErrorCode = "invalid character class range"
	ErrInvalidEscape         ErrorCode = "invalid escape sequence"
	ErrInvalidNamedCapture   ErrorCode = "invalid named capture"
	ErrInvalidPerlOp         ErrorCode = "invalid or unsupported Perl syntax"
	ErrInvalidRepeatOp       ErrorCode = "invalid nested repetition operator"
	ErrInvalidRepeatSize     ErrorCode = "invalid repeat count"
	ErrInvalidUTF8           ErrorCode = "invalid UTF-8"
	ErrMissingBracket        ErrorCode = "missing closing ]"
	ErrMissingParen          ErrorCode = "missing closing )"
	ErrMissingRepeatArgument ErrorCode = "missing argument to repetition operator"
	ErrTrailingBackslash     ErrorCode = "trailing backslash at end of expression"
	ErrUnexpectedParen       ErrorCode = "unexpected )"
	ErrNestingDepth          ErrorCode = "expression nests too deeply"
	ErrLarge                 ErrorCode = "expression too large"
)

func (e ErrorCode) String() string {
	return string(e)
}

// Flags control the behavior of the parser and record information about regexp context.
type Flags uint16

const (
	FoldCase      Flags = 1 << iota // case-insensitive match
	Literal                         // treat pattern as literal string
	ClassNL                         // allow character classes like [^a-z] and [[:space:]] to match newline
	DotNL                           // allow . to match newline
	OneLine                         // treat ^ and $ as only matching at beginning and end of text
	NonGreedy                       // make repetition operators default to non-greedy
	PerlX                           // allow Perl extensions
	UnicodeGroups                   // allow \p{Han}, \P{Han} for Unicode group and negation
	WasDollar                       // regexp OpEndText was $, not \z
	Simple                          // regexp contains no counted repetition

	MatchNL = ClassNL | DotNL

	Perl        = ClassNL | OneLine | PerlX | UnicodeGroups // as close to Perl as possible
	POSIX Flags = 0                                         // POSIX syntax
)

// Pseudo-ops for parsing stack.
const (
	opLeftParen = opPseudo + iota
	opVerticalBar
)

// maxHeight is the maximum height of a regexp parse tree.
// It is somewhat arbitrarily chosen, but the idea is to be large enough
// that no one will actually hit in real use but at the same time small enough
// that recursion on the Regexp tree will not hit the 1GB Go stack limit.
// The maximum amount of stack for a single recursive frame is probably
// closer to 1kB, so this could potentially be raised, but it seems unlikely
// that people have regexps nested even this deeply.
// We ran a test on Google's C++ code base and turned up only
// a single use case with depth > 100; it had depth 128.
// Using depth 1000 should be plenty of margin.
// As an optimization, we don't even bother calculating heights
// until we've allocated at least maxHeight Regexp structures.
const maxHeight = 1000

// maxSize is the maximum size of a compiled regexp in Insts.
// It too is somewhat arbitrarily chosen, but the idea is to be large enough
// to allow significant regexps while at the same time small enough that
// the compiled form will not take up too much memory.
// 128 MB is enough for a 3.3 million Inst structures, which roughly
// corresponds to a 3.3 MB regexp.
const (
	maxSize  = 128 << 20 / instSize
	instSize = 5 * 8 // byte, 2 uint32, slice is 5 64-bit words
)

// maxRunes is the maximum number of runes allowed in a regexp tree
// counting the runes in all the nodes.
// Ignoring character classes p.numRunes is always less than the length of the regexp.
// Character classes can make it much larger: each \pL adds 1292 runes.
// 128 MB is enough for 32M runes, which is over 26k \pL instances.
// Note that repetitions do not make copies of the rune slices,
// so \pL{1000} is only one rune slice, not 1000.
// We could keep a cache of character classes we've seen,
// so that all the \pL we see use the same rune list,
// but that doesn't remove the problem entirely:
// consider something like [\pL01234][\pL01235][\pL01236]...[\pL^&*()].
// And because the Rune slice is exposed directly in the Regexp,
// there is not an opportunity to change the representation to allow
// partial sharing between different character classes.
// So the limit is the best we can do.
const (
	maxRunes = 128 << 20 / runeSize
	runeSize = 4 // rune is int32
)

type parser struct {
	flags       Flags     // parse mode flags
	stack       []*Regexp // stack of parsed expressions
	free        *Regexp
	numCap      int // number of capturing groups seen
	wholeRegexp string
	tmpClass    []rune            // temporary char class work space
	numRegexp   int               // number of regexps allocated
	numRunes    int               // number of runes in char classes
	repeats     int64             // product of all repetitions seen
	height      map[*Regexp]int   // regexp height, for height limit check
	size        map[*Regexp]int64 // regexp compiled size, for size limit check
}

func (p *parser) newRegexp(op Op) *Regexp {
	re := p.free
	if re != nil {
		p.free = re.Sub0[0]
		*re = Regexp{}
	} else {
		re = new(Regexp)
		p.numRegexp++
	}
	re.Op = op
	return re
}

func (p *parser) reuse(re *Regexp) {
	if p.height != nil {
		delete(p.height, re)
	}
	re.Sub0[0] = p.free
	p.free = re
}

func (p *parser) checkLimits(re *Regexp) {
	if p.numRunes > maxRunes {
		panic(ErrLarge)
	}
	p.checkSize(re)
	p.checkHeight(re)
}

func (p *parser) checkSize(re *Regexp) {
	if p.size == nil {
		// We haven't started tracking size yet.
		// Do a relatively cheap check to see if we need to start.
		// Maintain the product of all the repeats we've seen
		// and don't track if the total number of regexp nodes
		// we've seen times the repeat product is in budget.
		if p.repeats == 0 {
			p.repeats = 1
		}
		if re.Op == OpRepeat {
			n := re.Max
			if n == -1 {
				n = re.Min
			}
			if n <= 0 {
				n = 1
			}
			if int64(n) > maxSize/p.repeats {
				p.repeats = maxSize
			} else {
				p.repeats *= int64(n)
			}
		}
		if int64(p.numRegexp) < maxSize/p.repeats {
			return
		}

		// We need to start tracking size.
		// Make the map and belatedly populate it
		// with info about everything we've constructed so far.
		p.size = make(map[*Regexp]int64)
		for _, re := range p.stack {
			p.checkSize(re)
		}
	}

	if p.calcSize(re, true) > maxSize {
		panic(ErrLarge)
	}
}

func (p *parser) calcSize(re *Regexp, force bool) int64 {
	if !force {
		if size, ok := p.size[re]; ok {
			return size
		}
	}

	var size int64
	switch re.Op {
	case OpLiteral:
		size = int64(len(re.Rune))
	case OpCapture, OpStar:
		// star can be 1+ or 2+; assume 2 pessimistically
		size = 2 + p.calcSize(re.Sub[0], false)
	case OpPlus, OpQuest:
		size = 1 + p.calcSize(re.Sub[0], false)
	case OpConcat:
		for _, sub := range re.Sub {
			size += p.calcSize(sub, false)
		}
	case OpAlternate:
		for _, sub := range re.Sub {
			size += p.calcSize(sub, false)
		}
		if len(re.Sub) > 1 {
			size += int64(len(re.Sub)) - 1
		}
	case OpRepeat:
		sub := p.calcSize(re.Sub[0], false)
		if re.Max == -1 {
			if re.Min == 0 {
				size = 2 + sub // x*
			} else {
				size = 1 + int64(re.Min)*sub // xxx+
			}
			break
		}
		// x{2,5} = xx(x(x(x)?)?)?
		size = int64(re.Max)*sub + int64(re.Max-re.Min)
	}

	size = max(1, size)
	p.size[re] = size
	return size
}

func (p *parser) checkHeight(re *Regexp) {
	if p.numRegexp < maxHeight {
		return
	}
	if p.height == nil {
		p.height = make(map[*Regexp]int)
		for _, re := range p.stack {
			p.checkHeight(re)
		}
	}
	if p.calcHeight(re, true) > maxHeight {
		panic(ErrNestingDepth)
	}
}

func (p *parser) calcHeight(re *Regexp, force bool) int {
	if !force {
		if h, ok := p.height[re]; ok {
			return h
		}
	}
	h := 1
	for _, sub := range re.Sub {
		hsub := p.calcHeight(sub, false)
		if h < 1+hsub {
			h = 1 + hsub
		}
	}
	p.height[re] = h
	return h
}

// Parse stack manipulation.

// push pushes the regexp re onto the parse stack and returns the regexp.
func (p *parser) push(re *Regexp) *Regexp {
	p.numRunes += len(re.Rune)
	if re.Op == OpCharClass && len(re.Rune) == 2 && re.Rune[0] == re.Rune[1] {
		// Single rune.
		if p.maybeConcat(re.Rune[0], p.flags&^FoldCase) {
			return nil
		}
		re.Op = OpLiteral
		re.Rune = re.Rune[:1]
		re.Flags = p.flags &^ FoldCase
	} else if re.Op == OpCharClass && len(re.Rune) == 4 &&
		re.Rune[0] == re.Rune[1] && re.Rune[2] == re.Rune[3] &&
		unicode.SimpleFold(re.Rune[0]) == re.Rune[2] &&
		unicode.SimpleFold(re.Rune[2]) == re.Rune[0] ||
		re.Op == OpCharClass && len(re.Rune) == 2 &&
			re.Rune[0]+1 == re.Rune[1] &&
			unicode.SimpleFold(re.Rune[0]) == re.Rune[1] &&
			unicode.SimpleFold(re.Rune[1]) == re.Rune[0] {
		// Case-insensitive rune like [Aa] or [Δδ].
		if p.maybeConcat(re.Rune[0], p.flags|FoldCase) {
			return nil
		}

		// Rewrite as (case-insensitive) literal.
		re.Op = OpLiteral
		re.Rune = re.Rune[:1]
		re.Flags = p.flags | FoldCase
	} else {
		// Incremental concatenation.
		p.maybeConcat(-1, 0)
	}

	p.stack = append(p.stack, re)
	p.checkLimits(re)
	return re
}

// maybeConcat implements incremental concatenation
// of literal runes into string nodes. The parser calls this
// before each push, so only the top fragment of the stack
// might need processing. Since this is called before a push,
// the topmost literal is no longer subject to operators like *
// (Otherwise ab* would turn into (ab)*.)
// If r >= 0 and there's a node left over, maybeConcat uses it
// to push r with the given flags.
// maybeConcat reports whether r was pushed.
func (p *parser) maybeConcat(r rune, flags Flags) bool {
	n := len(p.stack)
	if n < 2 {
		return false
	}

	re1 := p.stack[n-1]
	re2 := p.stack[n-2]
	if re1.Op != OpLiteral || re2.Op != OpLiteral || re1.Flags&FoldCase != re2.Flags&FoldCase {
		return false
	}

	// Push re1 into re2.
	re2.Rune = append(re2.Rune, re1.Rune...)

	// Reuse re1 if possible.
	if r >= 0 {
		re1.Rune = re1.Rune0[:1]
		re1.Rune[0] = r
		re1.Flags = flags
		return true
	}

	p.stack = p.stack[:n-1]
	p.reuse(re1)
	return false // did not push r
}

// literal pushes a literal regexp for the rune r on the stack.
func (p *parser) literal(r rune) {
	re := p.newRegexp(OpLiteral)
	re.Flags = p.flags
	if p.flags&FoldCase != 0 {
		r = minFoldRune(r)
	}
	re.Rune0[0] = r
	re.Rune = re.Rune0[:1]
	p.push(re)
}

// minFoldRune returns the minimum rune fold-equivalent to r.
func minFoldRune(r rune) rune {
	if r < minFold || r > maxFold {
		return r
	}
	m := r
	r0 := r
	for r = unicode.SimpleFold(r); r != r0; r = unicode.SimpleFold(r) {
		m = min(m, r)
	}
	return m
}

// op pushes a regexp with the given op onto the stack
// and returns that regexp.
func (p *parser) op(op Op) *Regexp {
	re := p.newRegexp(op)
	re.Flags = p.flags
	return p.push(re)
}

// repeat replaces the top stack element with itself repeated according to op, min, max.
// before is the regexp suffix starting at the repetition operator.
// after is the regexp suffix following after the repetition operator.
// repeat returns an updated 'after' and an error, if any.
func (p *parser) repeat(op Op, min, max int, before, after, lastRepeat string) (string, error) {
	flags := p.flags
	if p.flags&PerlX != 0 {
		if len(after) > 0 && after[0] == '?' {
			after = after[1:]
			flags ^= NonGreedy
		}
		if lastRepeat != "" {
			// In Perl it is not allowed to stack repetition operators:
			// a** is a syntax error, not a doubled star, and a++ means
			// something else entirely, which we don't support!
			return "", &Error{ErrInvalidRepeatOp, lastRepeat[:len(lastRepeat)-len(after)]}
		}
	}
	n := len(p.stack)
	if n == 0 {
		return "", &Error{ErrMissingRepeatArgument, before[:len(before)-len(after)]}
	}
	sub := p.stack[n-1]
	if sub.Op >= opPseudo {
		return "", &Error{ErrMissingRepeatArgument, before[:len(before)-len(after)]}
	}

	re := p.newRegexp(op)
	re.Min = min
	re.Max = max
	re.Flags = flags
	re.Sub = re.Sub0[:1]
	re.Sub[0] = sub
	p.stack[n-1] = re
	p.checkLimits(re)

	if op == OpRepeat && (min >= 2 || max >= 2) && !repeatIsValid(re, 1000) {
		return "", &Error{ErrInvalidRepeatSize, before[:len(before)-len(after)]}
	}

	return after, nil
}

// repeatIsValid reports whether the repetition re is valid.
// Valid means that the combination of the top-level repetition
// and any inner repetitions does not exceed n copies of the
// innermost thing.
// This function rewalks the regexp tree and is called for every repetition,
// so we have to worry about inducing quadratic behavior in the parser.
// We avoid this by only calling repeatIsValid when min or max >= 2.
// In that case the depth of any >= 2 nesting can only get to 9 without
// triggering a parse error, so each subtree can only be rewalked 9 times.
func repeatIsValid(re *Regexp, n int) bool {
	if re.Op == OpRepeat {
		m := re.Max
		if m == 0 {
			return true
		}
		if m < 0 {
			m = re.Min
		}
		if m > n {
			return false
		}
		if m > 0 {
			n /= m
		}
	}
	for _, sub := range re.Sub {
		if !repeatIsValid(sub, n) {
			return false
		}
	}
	return true
}

// concat replaces the top of the stack (above the topmost '|' or '(') with its concatenation.
func (p *parser) concat() *Regexp {
	p.maybeConcat(-1, 0)

	// Scan down to find pseudo-operator | or (.
	i := len(p.stack)
	for i > 0 && p.stack[i-1].Op < opPseudo {
		i--
	}
	subs := p.stack[i:]
	p.stack = p.stack[:i]

	// Empty concatenation is special case.
	if len(subs) == 0 {
		return p.push(p.newRegexp(OpEmptyMatch))
	}

	return p.push(p.collapse(subs, OpConcat))
}

// alternate replaces the top of the stack (above the topmost '(') with its alternation.
func (p *parser) alternate() *Regexp {
	// Scan down to find pseudo-operator (.
	// There are no | above (.
	i := len(p.stack)
	for i > 0 && p.stack[i-1].Op < opPseudo {
		i--
	}
	subs := p.stack[i:]
	p.stack = p.stack[:i]

	// Make sure top class is clean.
	// All the others already are (see swapVerticalBar).
	if len(subs) > 0 {
		cleanAlt(subs[len(subs)-1])
	}

	// Empty alternate is special case
	// (shouldn't happen but easy to handle).
	if len(subs) == 0 {
		return p.push(p.newRegexp(OpNoMatch))
	}

	return p.push(p.collapse(subs, OpAlternate))
}

// cleanAlt cleans re for eventual inclusion in an alternation.
func cleanAlt(re *Regexp) {
	switch re.Op {
	case OpCharClass:
		re.Rune = cleanClass(&re.Rune)
		if len(re.Rune) == 2 && re.Rune[0] == 0 && re.Rune[1] == unicode.MaxRune {
			re.Rune = nil
			re.Op = OpAnyChar
			return
		}
		if len(re.Rune) == 4 && re.Rune[0] == 0 && re.Rune[1] == '\n'-1 && re.Rune[2] == '\n'+1 && re.Rune[3] == unicode.MaxRune {
			re.Rune = nil
			re.Op = OpAnyCharNotNL
			return
		}
		if cap(re.Rune)-len(re.Rune) > 100 {
			// re.Rune will not grow any more.
			// Make a copy or inline to reclaim storage.
			re.Rune = append(re.Rune0[:0], re.Rune...)
		}
	}
}

// collapse returns the result of applying op to sub.
// If sub contains op nodes, they all get hoisted up
// so that there is never a concat of a concat or an
// alternate of an alternate.
func (p *parser) collapse(subs []*Regexp, op Op) *Regexp {
	if len(subs) == 1 {
		return subs[0]
	}
	re := p.newRegexp(op)
	re.Sub = re.Sub0[:0]
	for _, sub := range subs {
		if sub.Op == op {
			re.Sub = append(re.Sub, sub.Sub...)
			p.reuse(sub)
		} else {
			re.Sub = append(re.Sub, sub)
		}
	}
	if op == OpAlternate {
		re.Sub = p.factor(re.Sub)
		if len(re.Sub) == 1 {
			old := re
			re = re.Sub[0]
			p.reuse(old)
		}
	}
	return re
}

// factor factors common prefixes from the alternation list sub.
// It returns a replacement list that reuses the same storage and
// frees (passes to p.reuse) any removed *Regexps.
//
// For example,
//
//	ABC|ABD|AEF|BCX|BCY
//
// simplifies by literal prefix extraction to
//
//	A(B(C|D)|EF)|BC(X|Y)
//
// which simplifies by character class introduction to
//
//	A(B[CD]|EF)|BC[XY]
func (p *parser) factor(sub []*Regexp) []*Regexp {
	if len(sub) < 2 {
		return sub
	}

	// Round 1: Factor out common literal prefixes.
	var str []rune
	var strflags Flags
	start := 0
	out := sub[:0]
	for i := 0; i <= len(sub); i++ {
		// Invariant: the Regexps that were in sub[0:start] have been
		// used or marked for reuse, and the slice space has been reused
		// for out (len(out) <= start).
		//
		// Invariant: sub[start:i] consists of regexps that all begin
		// with str as modified by strflags.
		var istr []rune
		var iflags Flags
		if i < len(sub) {
			istr, iflags = p.leadingString(sub[i])
			if iflags == strflags {
				same := 0
				for same < len(str) && same < len(istr) && str[same] == istr[same] {
					same++
				}
				if same > 0 {
					// Matches at least one rune in current range.
					// Keep going around.
					str = str[:same]
					continue
				}
			}
		}

		// Found end of a run with common leading literal string:
		// sub[start:i] all begin with str[:len(str)], but sub[i]
		// does not even begin with str[0].
		//
		// Factor out common string and append factored expression to out.
		if i == start {
			// Nothing to do - run of length 0.
		} else if i == start+1 {
			// Just one: don't bother factoring.
			out = append(out, sub[start])
		} else {
			// Construct factored form: prefix(suffix1|suffix2|...)
			prefix := p.newRegexp(OpLiteral)
			prefix.Flags = strflags
			prefix.Rune = append(prefix.Rune[:0], str...)

			for j := start; j < i; j++ {
				sub[j] = p.removeLeadingString(sub[j], len(str))
				p.checkLimits(sub[j])
			}
			suffix := p.collapse(sub[start:i], OpAlternate) // recurse

			re := p.newRegexp(OpConcat)
			re.Sub = append(re.Sub[:0], prefix, suffix)
			out = append(out, re)
		}

		// Prepare for next iteration.
		start = i
		str = istr
		strflags = iflags
	}
	sub = out

	// Round 2: Factor out common simple prefixes,
	// just the first piece of each concatenation.
	// This will be good enough a lot of the time.
	//
	// Complex subexpressions (e.g. involving quantifiers)
	// are not safe to factor because that collapses their
	// distinct paths through the automaton, which affects
	// correctness in some cases.
	start = 0
	out = sub[:0]
	var first *Regexp
	for i := 0; i <= len(sub); i++ {
		// Invariant: the Regexps that were in sub[0:start] have been
		// used or marked for reuse, and the slice space has been reused
		// for out (len(out) <= start).
		//
		// Invariant: sub[start:i] consists of regexps that all begin with ifirst.
		var ifirst *Regexp
		if i < len(sub) {
			ifirst = p.leadingRegexp(sub[i])
			if first != nil && first.Equal(ifirst) &&
				// first must be a character class OR a fixed repeat of a character class.
				(isCharClass(first) || (first.Op == OpRepeat && first.Min == first.Max && isCharClass(first.Sub[0]))) {
				continue
			}
		}

		// Found end of a run with common leading regexp:
		// sub[start:i] all begin with first but sub[i] does not.
		//
		// Factor out common regexp and append factored expression to out.
		if i == start {
			// Nothing to do - run of length 0.
		} else if i == start+1 {
			// Just one: don't bother factoring.
			out = append(out, sub[start])
		} else {
			// Construct factored form: prefix(suffix1|suffix2|...)
			prefix := first
			for j := start; j < i; j++ {
				reuse := j != start // prefix came from sub[start]
				sub[j] = p.removeLeadingRegexp(sub[j], reuse)
				p.checkLimits(sub[j])
			}
			suffix := p.collapse(sub[start:i], OpAlternate) // recurse

			re := p.newRegexp(OpConcat)
			re.Sub = append(re.Sub[:0], prefix, suffix)
			out = append(out, re)
		}

		// Prepare for next iteration.
		start = i
		first = ifirst
	}
	sub = out

	// Round 3: Collapse runs of single literals into character classes.
	start = 0
	out = sub[:0]
	for i := 0; i <= len(sub); i++ {
		// Invariant: the Regexps that were in sub[0:start] have been
		// used or marked for reuse, and the slice space has been reused
		// for out (len(out) <= start).
		//
		// Invariant: sub[start:i] consists of regexps that are either
		// literal runes or character classes.
		if i < len(sub) && isCharClass(sub[i]) {
			continue
		}

		// sub[i] is not a char or char class;
		// emit char class for sub[start:i]...
		if i == start {
			// Nothing to do - run of length 0.
		} else if i == start+1 {
			out = append(out, sub[start])
		} else {
			// Make new char class.
			// Start with most complex regexp in sub[start].
			max := start
			for j := start + 1; j < i; j++ {
				if sub[max].Op < sub[j].Op || sub[max].Op == sub[j].Op && len(sub[max].Rune) < len(sub[j].Rune) {
					max = j
				}
			}
			sub[start], sub[max] = sub[max], sub[start]

			for j := start + 1; j < i; j++ {
				mergeCharClass(sub[start], sub[j])
				p.reuse(sub[j])
			}
			cleanAlt(sub[start])
			out = append(out, sub[start])
		}

		// ... and then emit sub[i].
		if i < len(sub) {
			out = append(out, sub[i])
		}
		start = i + 1
	}
	sub = out

	// Round 4: Collapse runs of empty matches into a single empty match.
	start = 0
	out = sub[:0]
	for i := range sub {
		if i+1 < len(sub) && sub[i].Op == OpEmptyMatch && sub[i+1].Op == OpEmptyMatch {
			continue
		}
		out = append(out, sub[i])
	}
	sub = out

	return sub
}

// leadingString returns the leading literal string that re begins with.
// The string refers to storage in re or its children.
func (p *parser) leadingString(re *Regexp) ([]rune, Flags) {
	if re.Op == OpConcat && len(re.Sub) > 0 {
		re = re.Sub[0]
	}
	if re.Op != OpLiteral {
		return nil, 0
	}
	return re.Rune, re.Flags & FoldCase
}

// removeLeadingString removes the first n leading runes
// from the beginning of re. It returns the replacement for re.
func (p *parser) removeLeadingString(re *Regexp, n int) *Regexp {
	if re.Op == OpConcat && len(re.Sub) > 0 {
		// Removing a leading string in a concatenation
		// might simplify the concatenation.
		sub := re.Sub[0]
		sub = p.removeLeadingString(sub, n)
		re.Sub[0] = sub
		if sub.Op == OpEmptyMatch {
			p.reuse(sub)
			switch len(re.Sub) {
			case 0, 1:
				// Impossible but handle.
				re.Op = OpEmptyMatch
				re.Sub = nil
			case 2:
				old := re
				re = re.Sub[1]
				p.reuse(old)
			default:
				copy(re.Sub, re.Sub[1:])
				re.Sub = re.Sub[:len(re.Sub)-1]
			}
		}
		return re
	}

	if re.Op == OpLiteral {
		re.Rune = re.Rune[:copy(re.Rune, re.Rune[n:])]
		if len(re.Rune) == 0 {
			re.Op = OpEmptyMatch
		}
	}
	return re
}

// leadingRegexp returns the leading regexp that re begins with.
// The regexp refers to storage in re or its children.
func (p *parser) leadingRegexp(re *Regexp) *Regexp {
	if re.Op == OpEmptyMatch {
		return nil
	}
	if re.Op == OpConcat && len(re.Sub) > 0 {
		sub := re.Sub[0]
		if sub.Op == OpEmptyMatch {
			return nil
		}
		return sub
	}
	return re
}

// removeLeadingRegexp removes the leading regexp in re.
// It returns the replacement for re.
// If reuse is true, it passes the removed regexp (if no longer needed) to p.reuse.
func (p *parser) removeLeadingRegexp(re *Regexp, reuse bool) *Regexp {
	if re.Op == OpConcat && len(re.Sub) > 0 {
		if reuse {
			p.reuse(re.Sub[0])
		}
		re.Sub = re.Sub[:copy(re.Sub, re.Sub[1:])]
		switch len(re.Sub) {
		case 0:
			re.Op = OpEmptyMatch
			re.Sub = nil
		case 1:
			old := re
			re = re.Sub[0]
			p.reuse(old)
		}
		return re
	}
	if reuse {
		p.reuse(re)
	}
	return p.newRegexp(OpEmptyMatch)
}

func literalRegexp(s string, flags Flags) *Regexp {
	re := &Regexp{Op: OpLiteral}
	re.Flags = flags
	re.Rune = re.Rune0[:0] // use local storage for small strings
	for _, c := range s {
		if len(re.Rune) >= cap(re.Rune) {
			// string is too long to fit in Rune0.  let Go handle it
			re.Rune = []rune(s)
			break
		}
		re.Rune = append(re.Rune, c)
	}
	return re
}

// Parsing.

// Parse parses a regular expression string s, controlled by the specified
// Flags, and returns a regular expression parse tree. The syntax is
// described in the top-level comment.
func Parse(s string, flags Flags) (*Regexp, error) {
	return parse(s, flags)
}

func parse(s string, flags Flags) (_ *Regexp, err error) {
	defer func() {
		switch r := recover(); r {
		default:
			panic(r)
		case nil:
			// ok
		case ErrLarge: // too big
			err = &Error{Code: ErrLarge, Expr: s}
		case ErrNestingDepth:
			err = &Error{Code: ErrNestingDepth, Expr: s}
		}
	}()

	if flags&Literal != 0 {
		// Trivial parser for literal string.
		if err := checkUTF8(s); err != nil {
			return nil, err
		}
		return literalRegexp(s, flags), nil
	}

	// Otherwise, must do real work.
	var (
		p          parser
		c          rune
		op         Op
		lastRepeat string
	)
	p.flags = flags
	p.wholeRegexp = s
	t := s
	for t != "" {
		repeat := ""
	BigSwitch:
		switch t[0] {
		default:
			if c, t, err = nextRune(t); err != nil {
				return nil, err
			}
			p.literal(c)

		case '(':
			if p.flags&PerlX != 0 && len(t) >= 2 && t[1] == '?' {
				// Flag changes and non-capturing groups.
				if t, err = p.parsePerlFlags(t); err != nil {
					return nil, err
				}
				break
			}
			p.numCap++
			p.op(opLeftParen).Cap = p.numCap
			t = t[1:]
		case '|':
			p.parseVerticalBar()
			t = t[1:]
		case ')':
			if err = p.parseRightParen(); err != nil {
				return nil, err
			}
			t = t[1:]
		case '^':
			if p.flags&OneLine != 0 {
				p.op(OpBeginText)
			} else {
				p.op(OpBeginLine)
			}
			t = t[1:]
		case '$':
			if p.flags&OneLine != 0 {
				p.op(OpEndText).Flags |= WasDollar
			} else {
				p.op(OpEndLine)
			}
			t = t[1:]
		case '.':
			if p.flags&DotNL != 0 {
				p.op(OpAnyChar)
			} else {
				p.op(OpAnyCharNotNL)
			}
			t = t[1:]
		case '[':
			if t, err = p.parseClass(t); err != nil {
				return nil, err
			}
		case '*', '+', '?':
			before := t
			switch t[0] {
			case '*':
				op = OpStar
			case '+':
				op = OpPlus
			case '?':
				op = OpQuest
			}
			after := t[1:]
			if after, err = p.repeat(op, 0, 0, before, after, lastRepeat); err != nil {
				return nil, err
			}
			repeat = before
			t = after
		case '{':
			op = OpRepeat
			before := t
			min, max, after, ok := p.parseRepeat(t)
			if !ok {
				// If the repeat cannot be parsed, { is a literal.
				p.literal('{')
				t = t[1:]
				break
			}
			if min < 0 || min > 1000 || max > 1000 || max >= 0 && min > max {
				// Numbers were too big, or max is present and min > max.
				return nil, &Error{ErrInvalidRepeatSize, before[:len(before)-len(after)]}
			}
			if after, err = p.repeat(op, min, max, before, after, lastRepeat); err != nil {
				return nil, err
			}
			repeat = before
			t = after
		case '\\':
			if p.flags&PerlX != 0 && len(t) >= 2 {
				switch t[1] {
				case 'A':
					p.op(OpBeginText)
					t = t[2:]
					break BigSwitch
				case 'b':
					p.op(OpWordBoundary)
					t = t[2:]
					break BigSwitch
				case 'B':
					p.op(OpNoWordBoundary)
					t = t[2:]
					break BigSwitch
				case 'C':
					// any byte; not supported
					return nil, &Error{ErrInvalidEscape, t[:2]}
				case 'Q':
					// \Q ... \E: the ... is always literals
					var lit string
					lit, t, _ = strings.Cut(t[2:], `\E`)
					for lit != "" {
						c, rest, err := nextRune(lit)
						if err != nil {
							return nil, err
						}
						p.literal(c)
						lit = rest
					}
					break BigSwitch
				case 'z':
					p.op(OpEndText)
					t = t[2:]
					break BigSwitch
				}
			}

			re := p.newRegexp(OpCharClass)
			re.Flags = p.flags

			// Look for Unicode character group like \p{Han}
			if len(t) >= 2 && (t[1] == 'p' || t[1] == 'P') {
				r, rest, err := p.parseUnicodeClass(t, re.Rune0[:0])
				if err != nil {
					return nil, err
				}
				if r != nil {
					re.Rune = r
					t = rest
					p.push(re)
					break BigSwitch
				}
			}

			// Perl character class escape.
			if r, rest := p.parsePerlClassEscape(t, re.Rune0[:0]); r != nil {
				re.Rune = r
				t = rest
				p.push(re)
				break BigSwitch
			}
			p.reuse(re)

			// Ordinary single-character escape.
			if c, t, err = p.parseEscape(t); err != nil {
				return nil, err
			}
			p.literal(c)
		}
		lastRepeat = repeat
	}

	p.concat()
	if p.swapVerticalBar() {
		// pop vertical bar
		p.stack = p.stack[:len(p.stack)-1]
	}
	p.alternate()

	n := len(p.stack)
	if n != 1 {
		return nil, &Error{ErrMissingParen, s}
	}
	return p.stack[0], nil
}

// parseRepeat parses {min} (max=min) or {min,} (max=-1) or {min,max}.
// If s is not of that form, it returns ok == false.
// If s has the right form but the values are too big, it returns min == -1, ok == true.
func (p *parser) parseRepeat(s string) (min, max int, rest string, ok bool) {
	if s == "" || s[0] != '{' {
		return
	}
	s = s[1:]
	var ok1 bool
	if min, s, ok1 = p.parseInt(s); !ok1 {
		return
	}
	if s == "" {
		return
	}
	if s[0] != ',' {
		max = min
	} else {
		s = s[1:]
		if s == "" {
			return
		}
		if s[0] == '}' {
			max = -1
		} else if max, s, ok1 = p.parseInt(s); !ok1 {
			return
		} else if max < 0 {
			// parseInt found too big a number
			min = -1
		}
	}
	if s == "" || s[0] != '}' {
		return
	}
	rest = s[1:]
	ok = true
	return
}

// parsePerlFlags parses a Perl flag setting or non-capturing group or both,
// like (?i) or (?: or (?i:.  It removes the prefix from s and updates the parse state.
// The caller must have ensured that s begins with "(?".
func (p *parser) parsePerlFlags(s string) (rest string, err error) {
	t := s

	// Check for named captures, first introduced in Python's regexp library.
	// As usual, there are three slightly different syntaxes:
	//
	//   (?P<name>expr)   the original, introduced by Python
	//   (?<name>expr)    the .NET alteration, adopted by Perl 5.10
	//   (?'name'expr)    another .NET alteration, adopted by Perl 5.10
	//
	// Perl 5.10 gave in and implemented the Python version too,
	// but they claim that the last two are the preferred forms.
	// PCRE and languages based on it (specifically, PHP and Ruby)
	// support all three as well. EcmaScript 4 uses only the Python form.
	//
	// In both the open source world (via Code Search) and the
	// Google source tree, (?P<expr>name) and (?<expr>name) are the
	// dominant forms of named captures and both are supported.
	startsWithP := len(t) > 4 && t[2] == 'P' && t[3] == '<'
	startsWithName := len(t) > 3 && t[2] == '<'

	if startsWithP || startsWithName {
		// position of expr start
		exprStartPos := 4
		if startsWithName {
			exprStartPos = 3
		}

		// Pull out name.
		end := strings.IndexRune(t, '>')
		if end < 0 {
			if err = checkUTF8(t); err != nil {
				return "", err
			}
			return "", &Error{ErrInvalidNamedCapture, s}
		}

		capture := t[:end+1]        // "(?P<name>" or "(?<name>"
		name := t[exprStartPos:end] // "name"
		if err = checkUTF8(name); err != nil {
			return "", err
		}
		if !isValidCaptureName(name) {
			return "", &Error{ErrInvalidNamedCapture, capture}
		}

		// Like ordinary capture, but named.
		p.numCap++
		re := p.op(opLeftParen)
		re.Cap = p.numCap
		re.Name = name
		return t[end+1:], nil
	}

	// Non-capturing group. Might also twiddle Perl flags.
	var c rune
	t = t[2:] // skip (?
	flags := p.flags
	sign := +1
	sawFlag := false
Loop:
	for t != "" {
		if c, t, err = nextRune(t); err != nil {
			return "", err
		}
		switch c {
		default:
			break Loop

		// Flags.
		case 'i':
			flags |= FoldCase
			sawFlag = true
		case 'm':
			flags &^= OneLine
			sawFlag = true
		case 's':
			flags |= DotNL
			sawFlag = true
		case 'U':
			flags |= NonGreedy
			sawFlag = true

		// Switch to negation.
		case '-':
			if sign < 0 {
				break Loop
			}
			sign = -1
			// Invert flags so that | above turn into &^ and vice versa.
			// We'll invert flags again before using it below.
			flags = ^flags
			sawFlag = false

		// End of flags, starting group or not.
		case ':', ')':
			if sign < 0 {
				if !sawFlag {
					break Loop
				}
				flags = ^flags
			}
			if c == ':' {
				// Open new group
				p.op(opLeftParen)
			}
			p.flags = flags
			return t, nil
		}
	}

	return "", &Error{ErrInvalidPerlOp, s[:len(s)-len(t)]}
}

// isValidCaptureName reports whether name
// is a valid capture name: [A-Za-z0-9_]+.
// PCRE limits names to 32 bytes.
// Python rejects names starting with digits.
// We don't enforce either of those.
func isValidCaptureName(name string) bool {
	if name == "" 
"""




```