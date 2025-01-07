Response:
The user wants to understand the functionality of the provided Go code snippet, which is part of the `go/src/regexp/syntax/parse.go` file. This is the second part of a two-part request. I need to summarize the functionalities present in *this* specific snippet.

Here's a breakdown of the functions and their roles:

1. **`isValidCaptureName(name string) bool`**: Checks if a given string is a valid capture group name.
2. **`parseInt(s string) (n int, rest string, ok bool)`**: Parses a decimal integer from the beginning of a string.
3. **`isCharClass(re *Regexp) bool`**: Checks if a `Regexp` represents a character class (literal, char class, `.`, or `.|\n`).
4. **`matchRune(re *Regexp, r rune) bool`**: Checks if a `Regexp` (representing a character class) matches a given rune.
5. **`parseVerticalBar()`**: Handles the '|' (OR) operator in the regex parsing process.
6. **`mergeCharClass(dst, src *Regexp)`**: Merges two character classes into one.
7. **`swapVerticalBar() bool`**:  Optimizes alternation of character classes by merging them.
8. **`parseRightParen() error`**: Handles the ')' (closing parenthesis) in the regex parsing.
9. **`parseEscape(s string) (r rune, rest string, err error)`**: Parses escape sequences (like `\n`, `\t`, `\xNN`, etc.).
10. **`parseClassChar(s, wholeClass string) (r rune, rest string, err error)`**: Parses a single character within a character class.
11. **`parsePerlClassEscape(s string, r []rune) (out []rune, rest string)`**: Parses Perl-style character class escapes (like `\d`, `\w`).
12. **`parseNamedClass(s string, r []rune) (out []rune, rest string, err error)`**: Parses POSIX named character classes (like `[:alnum:]`).
13. **`appendGroup(r []rune, g charGroup)`**: Appends a character group to a rune slice, considering case folding.
14. **`unicodeTable(name string) (*unicode.RangeTable, *unicode.RangeTable)`**: Retrieves Unicode character tables by name.
15. **`parseUnicodeClass(s string, r []rune) (out []rune, rest string, err error)`**: Parses Unicode character classes (like `\p{Han}`).
16. **`parseClass(s string) (rest string, err error)`**: Parses a complete character class (e.g., `[a-z]`, `[^0-9]`).
17. **`cleanClass(rp *[]rune) []rune`**: Sorts, merges, and removes duplicates from a character class.
18. **`inCharClass(r rune, class []rune) bool`**: Checks if a rune is within a cleaned character class.
19. **`appendLiteral(r []rune, x rune, flags Flags) []rune`**: Appends a literal rune to a character class.
20. **`appendRange(r []rune, lo, hi rune) []rune`**: Appends a rune range to a character class.
21. **`appendFoldedRange(r []rune, lo, hi rune) []rune`**: Appends a rune range and its case-folded equivalents.
22. **`appendClass(r []rune, x []rune)`**: Appends one cleaned character class to another.
23. **`appendFoldedClass(r []rune, x []rune)`**: Appends the case-folded version of a character class.
24. **`appendNegatedClass(r []rune, x []rune)`**: Appends the negation of a character class.
25. **`appendTable(r []rune, x *unicode.RangeTable)`**: Appends a Unicode character table to a character class.
26. **`appendNegatedTable(r []rune, x *unicode.RangeTable)`**: Appends the negation of a Unicode character table.
27. **`negateClass(r []rune) []rune`**:  Calculates the negation of a cleaned character class.
28. **`ranges` struct and its methods (`Less`, `Len`, `Swap`)**: Used for sorting rune ranges within a character class.
29. **`checkUTF8(s string) error`**: Checks if a string contains valid UTF-8 encoding.
30. **`nextRune(s string) (c rune, t string, err error)`**: Decodes the next rune from a string, handling UTF-8 errors.
31. **`isalnum(c rune) bool`**: Checks if a rune is alphanumeric.
32. **`unhex(c rune) rune`**: Converts a hexadecimal character to its integer value.

The overall theme of this part of the code is parsing different elements of a regular expression syntax, specifically focusing on character classes, escape sequences, and alternation. It builds upon the parsing state maintained in the `parser` struct (although not shown in the snippet).
这是 `go/src/regexp/syntax/parse.go` 文件的一部分，它专注于 **正则表达式语法的解析**，特别是以下功能：

**归纳一下它的功能:**

这部分代码主要负责解析正则表达式中关于 **字符和字符组** 的各种表示方式，以及处理 **或（`|`）操作符** 和 **括号分组**。 它将输入的正则表达式字符串逐步解析成内部的 `Regexp` 结构，为后续的编译和匹配做准备。

**具体功能包括：**

1. **解析基本字符和转义字符:**
    *   解析普通字符。
    *   解析各种转义序列，例如 `\n`, `\t`, `\xNN` (十六进制字符), `\0NNN` (八进制字符) 等。

2. **解析字符组（Character Classes）:**
    *   解析用 `[]` 包围的字符组，包括否定字符组 (例如 `[^abc]`)。
    *   处理字符组内的字符范围 (例如 `a-z`)。
    *   解析 POSIX 命名的字符组 (例如 `[:alnum:]`)。
    *   解析 Perl 风格的字符类转义 (例如 `\d`, `\w`)。
    *   解析 Unicode 字符类 (例如 `\p{Han}`, `\P{Latin}`)。
    *   支持字符组内的 case-insensitive 匹配。

3. **处理或操作符 (`|`)：**
    *   解析并构建表示或关系的 `Regexp` 结构。
    *   优化连续的字符类之间的或关系，将其合并成一个更大的字符类。

4. **处理括号分组 `()`：**
    *   解析捕获分组和非捕获分组。
    *   为捕获分组分配捕获编号。
    *   处理括号内的子表达式。

5. **辅助功能：**
    *   验证捕获组名称的合法性。
    *   解析十进制整数。
    *   判断一个 `Regexp` 结构是否可以表示为字符类。
    *   判断一个 `Regexp` 结构（代表字符类）是否匹配给定的 `rune`。
    *   合并两个字符类。
    *   清理和优化字符类表示，例如排序、合并重叠范围、去除重复项。
    *   计算字符类的补集（取反）。

**Go 代码示例说明 (基于代码推理):**

这段代码的核心目标是将正则表达式字符串转换成 `Regexp` 类型的抽象语法树。 虽然没有直接展示如何使用这个 `parse.go` 文件，但可以推断出它被 `regexp` 包的 `Compile` 或类似的函数内部调用。

假设我们有以下正则表达式： `a[bc]|d\w`

这段代码（`parse.go` 的一部分）会参与将其解析为以下 `Regexp` 结构（简化表示）：

```go
&syntax.Regexp{
    Op: syntax.OpAlt, // 表示或关系
    Sub: []*syntax.Regexp{
        &syntax.Regexp{
            Op: syntax.OpConcat, // 表示连接
            Sub: []*syntax.Regexp{
                &syntax.Regexp{Op: syntax.OpLiteral, Rune: []rune{'a'}},
                &syntax.Regexp{Op: syntax.OpCharClass, Rune: []rune{'b', 'b', 'c', 'c'}}, // 字符组 [bc]
            },
        },
        &syntax.Regexp{
            Op: syntax.OpConcat,
            Sub: []*syntax.Regexp{
                &syntax.Regexp{Op: syntax.OpLiteral, Rune: []rune{'d'}},
                &syntax.Regexp{Op: syntax.OpCharClass, Rune: /* \w 对应的字符范围 */},
            },
        },
    },
}
```

**假设的输入与输出：**

*   **输入 (字符串):**  `[a-z0-9]`
*   **输出 (解析后的 `Regexp` 结构，简化表示):**
    ```go
    &syntax.Regexp{
        Op: syntax.OpCharClass,
        Rune: []rune{'0', '9', 'a', 'z'}, // 假设 cleanClass 排序后是这样的
    }
    ```

*   **输入 (字符串):** `\p{Lu}`
*   **输出 (解析后的 `Regexp` 结构，简化表示):**
    ```go
    &syntax.Regexp{
        Op: syntax.OpCharClass,
        Rune: /* 所有大写字母对应的 rune 范围 */,
    }
    ```

**使用者易犯错的点举例说明：**

1. **字符组中 `-` 的使用:**  在字符组中，`-` 只有在表示范围时才具有特殊含义。如果想要匹配字面上的 `-`，需要将其放在字符组的首尾，或者进行转义。

    *   **错误示例:** `[a-z-]`  （可能被误解为 `a` 到 `z` 的范围，然后匹配 `-`，但实际行为取决于具体实现）
    *   **正确示例:** `[-az]` 或 `[az-]` 或 `[a\-z]`

2. **忘记转义特殊字符:**  某些字符在正则表达式中具有特殊含义（例如 `.`、`*`、`+`、`?`、`(`、`)`、`[`、`]`、`\`、`|`、`^`、`$`）。 如果想要匹配这些字符本身，需要使用反斜杠进行转义。

    *   **错误示例:** `a.b` （`.` 匹配任意字符）
    *   **正确示例:** `a\.b` （`.` 匹配字面上的点号）

3. **对 Unicode 字符类的误解:** 错误地使用或拼写 Unicode 字符类的名称会导致解析错误。

    *   **错误示例:** `\p{Lower}` （正确的应该是 `\p{Ll}` 或 `\p{Lowercase}`)
    *   **正确示例:** `\p{Lu}`

总而言之，这部分代码是 Go 语言 `regexp` 包中至关重要的组成部分，负责将人类可读的正则表达式字符串转换为机器可以理解和执行的内部表示形式。它处理了正则表达式语法中关于字符和字符组的各种复杂细节。

Prompt: 
```
这是路径为go/src/regexp/syntax/parse.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

"""
{
		return false
	}
	for _, c := range name {
		if c != '_' && !isalnum(c) {
			return false
		}
	}
	return true
}

// parseInt parses a decimal integer.
func (p *parser) parseInt(s string) (n int, rest string, ok bool) {
	if s == "" || s[0] < '0' || '9' < s[0] {
		return
	}
	// Disallow leading zeros.
	if len(s) >= 2 && s[0] == '0' && '0' <= s[1] && s[1] <= '9' {
		return
	}
	t := s
	for s != "" && '0' <= s[0] && s[0] <= '9' {
		s = s[1:]
	}
	rest = s
	ok = true
	// Have digits, compute value.
	t = t[:len(t)-len(s)]
	for i := 0; i < len(t); i++ {
		// Avoid overflow.
		if n >= 1e8 {
			n = -1
			break
		}
		n = n*10 + int(t[i]) - '0'
	}
	return
}

// can this be represented as a character class?
// single-rune literal string, char class, ., and .|\n.
func isCharClass(re *Regexp) bool {
	return re.Op == OpLiteral && len(re.Rune) == 1 ||
		re.Op == OpCharClass ||
		re.Op == OpAnyCharNotNL ||
		re.Op == OpAnyChar
}

// does re match r?
func matchRune(re *Regexp, r rune) bool {
	switch re.Op {
	case OpLiteral:
		return len(re.Rune) == 1 && re.Rune[0] == r
	case OpCharClass:
		for i := 0; i < len(re.Rune); i += 2 {
			if re.Rune[i] <= r && r <= re.Rune[i+1] {
				return true
			}
		}
		return false
	case OpAnyCharNotNL:
		return r != '\n'
	case OpAnyChar:
		return true
	}
	return false
}

// parseVerticalBar handles a | in the input.
func (p *parser) parseVerticalBar() {
	p.concat()

	// The concatenation we just parsed is on top of the stack.
	// If it sits above an opVerticalBar, swap it below
	// (things below an opVerticalBar become an alternation).
	// Otherwise, push a new vertical bar.
	if !p.swapVerticalBar() {
		p.op(opVerticalBar)
	}
}

// mergeCharClass makes dst = dst|src.
// The caller must ensure that dst.Op >= src.Op,
// to reduce the amount of copying.
func mergeCharClass(dst, src *Regexp) {
	switch dst.Op {
	case OpAnyChar:
		// src doesn't add anything.
	case OpAnyCharNotNL:
		// src might add \n
		if matchRune(src, '\n') {
			dst.Op = OpAnyChar
		}
	case OpCharClass:
		// src is simpler, so either literal or char class
		if src.Op == OpLiteral {
			dst.Rune = appendLiteral(dst.Rune, src.Rune[0], src.Flags)
		} else {
			dst.Rune = appendClass(dst.Rune, src.Rune)
		}
	case OpLiteral:
		// both literal
		if src.Rune[0] == dst.Rune[0] && src.Flags == dst.Flags {
			break
		}
		dst.Op = OpCharClass
		dst.Rune = appendLiteral(dst.Rune[:0], dst.Rune[0], dst.Flags)
		dst.Rune = appendLiteral(dst.Rune, src.Rune[0], src.Flags)
	}
}

// If the top of the stack is an element followed by an opVerticalBar
// swapVerticalBar swaps the two and returns true.
// Otherwise it returns false.
func (p *parser) swapVerticalBar() bool {
	// If above and below vertical bar are literal or char class,
	// can merge into a single char class.
	n := len(p.stack)
	if n >= 3 && p.stack[n-2].Op == opVerticalBar && isCharClass(p.stack[n-1]) && isCharClass(p.stack[n-3]) {
		re1 := p.stack[n-1]
		re3 := p.stack[n-3]
		// Make re3 the more complex of the two.
		if re1.Op > re3.Op {
			re1, re3 = re3, re1
			p.stack[n-3] = re3
		}
		mergeCharClass(re3, re1)
		p.reuse(re1)
		p.stack = p.stack[:n-1]
		return true
	}

	if n >= 2 {
		re1 := p.stack[n-1]
		re2 := p.stack[n-2]
		if re2.Op == opVerticalBar {
			if n >= 3 {
				// Now out of reach.
				// Clean opportunistically.
				cleanAlt(p.stack[n-3])
			}
			p.stack[n-2] = re1
			p.stack[n-1] = re2
			return true
		}
	}
	return false
}

// parseRightParen handles a ) in the input.
func (p *parser) parseRightParen() error {
	p.concat()
	if p.swapVerticalBar() {
		// pop vertical bar
		p.stack = p.stack[:len(p.stack)-1]
	}
	p.alternate()

	n := len(p.stack)
	if n < 2 {
		return &Error{ErrUnexpectedParen, p.wholeRegexp}
	}
	re1 := p.stack[n-1]
	re2 := p.stack[n-2]
	p.stack = p.stack[:n-2]
	if re2.Op != opLeftParen {
		return &Error{ErrUnexpectedParen, p.wholeRegexp}
	}
	// Restore flags at time of paren.
	p.flags = re2.Flags
	if re2.Cap == 0 {
		// Just for grouping.
		p.push(re1)
	} else {
		re2.Op = OpCapture
		re2.Sub = re2.Sub0[:1]
		re2.Sub[0] = re1
		p.push(re2)
	}
	return nil
}

// parseEscape parses an escape sequence at the beginning of s
// and returns the rune.
func (p *parser) parseEscape(s string) (r rune, rest string, err error) {
	t := s[1:]
	if t == "" {
		return 0, "", &Error{ErrTrailingBackslash, ""}
	}
	c, t, err := nextRune(t)
	if err != nil {
		return 0, "", err
	}

Switch:
	switch c {
	default:
		if c < utf8.RuneSelf && !isalnum(c) {
			// Escaped non-word characters are always themselves.
			// PCRE is not quite so rigorous: it accepts things like
			// \q, but we don't. We once rejected \_, but too many
			// programs and people insist on using it, so allow \_.
			return c, t, nil
		}

	// Octal escapes.
	case '1', '2', '3', '4', '5', '6', '7':
		// Single non-zero digit is a backreference; not supported
		if t == "" || t[0] < '0' || t[0] > '7' {
			break
		}
		fallthrough
	case '0':
		// Consume up to three octal digits; already have one.
		r = c - '0'
		for i := 1; i < 3; i++ {
			if t == "" || t[0] < '0' || t[0] > '7' {
				break
			}
			r = r*8 + rune(t[0]) - '0'
			t = t[1:]
		}
		return r, t, nil

	// Hexadecimal escapes.
	case 'x':
		if t == "" {
			break
		}
		if c, t, err = nextRune(t); err != nil {
			return 0, "", err
		}
		if c == '{' {
			// Any number of digits in braces.
			// Perl accepts any text at all; it ignores all text
			// after the first non-hex digit. We require only hex digits,
			// and at least one.
			nhex := 0
			r = 0
			for {
				if t == "" {
					break Switch
				}
				if c, t, err = nextRune(t); err != nil {
					return 0, "", err
				}
				if c == '}' {
					break
				}
				v := unhex(c)
				if v < 0 {
					break Switch
				}
				r = r*16 + v
				if r > unicode.MaxRune {
					break Switch
				}
				nhex++
			}
			if nhex == 0 {
				break Switch
			}
			return r, t, nil
		}

		// Easy case: two hex digits.
		x := unhex(c)
		if c, t, err = nextRune(t); err != nil {
			return 0, "", err
		}
		y := unhex(c)
		if x < 0 || y < 0 {
			break
		}
		return x*16 + y, t, nil

	// C escapes. There is no case 'b', to avoid misparsing
	// the Perl word-boundary \b as the C backspace \b
	// when in POSIX mode. In Perl, /\b/ means word-boundary
	// but /[\b]/ means backspace. We don't support that.
	// If you want a backspace, embed a literal backspace
	// character or use \x08.
	case 'a':
		return '\a', t, err
	case 'f':
		return '\f', t, err
	case 'n':
		return '\n', t, err
	case 'r':
		return '\r', t, err
	case 't':
		return '\t', t, err
	case 'v':
		return '\v', t, err
	}
	return 0, "", &Error{ErrInvalidEscape, s[:len(s)-len(t)]}
}

// parseClassChar parses a character class character at the beginning of s
// and returns it.
func (p *parser) parseClassChar(s, wholeClass string) (r rune, rest string, err error) {
	if s == "" {
		return 0, "", &Error{Code: ErrMissingBracket, Expr: wholeClass}
	}

	// Allow regular escape sequences even though
	// many need not be escaped in this context.
	if s[0] == '\\' {
		return p.parseEscape(s)
	}

	return nextRune(s)
}

type charGroup struct {
	sign  int
	class []rune
}

//go:generate perl make_perl_groups.pl perl_groups.go

// parsePerlClassEscape parses a leading Perl character class escape like \d
// from the beginning of s. If one is present, it appends the characters to r
// and returns the new slice r and the remainder of the string.
func (p *parser) parsePerlClassEscape(s string, r []rune) (out []rune, rest string) {
	if p.flags&PerlX == 0 || len(s) < 2 || s[0] != '\\' {
		return
	}
	g := perlGroup[s[0:2]]
	if g.sign == 0 {
		return
	}
	return p.appendGroup(r, g), s[2:]
}

// parseNamedClass parses a leading POSIX named character class like [:alnum:]
// from the beginning of s. If one is present, it appends the characters to r
// and returns the new slice r and the remainder of the string.
func (p *parser) parseNamedClass(s string, r []rune) (out []rune, rest string, err error) {
	if len(s) < 2 || s[0] != '[' || s[1] != ':' {
		return
	}

	i := strings.Index(s[2:], ":]")
	if i < 0 {
		return
	}
	i += 2
	name, s := s[0:i+2], s[i+2:]
	g := posixGroup[name]
	if g.sign == 0 {
		return nil, "", &Error{ErrInvalidCharRange, name}
	}
	return p.appendGroup(r, g), s, nil
}

func (p *parser) appendGroup(r []rune, g charGroup) []rune {
	if p.flags&FoldCase == 0 {
		if g.sign < 0 {
			r = appendNegatedClass(r, g.class)
		} else {
			r = appendClass(r, g.class)
		}
	} else {
		tmp := p.tmpClass[:0]
		tmp = appendFoldedClass(tmp, g.class)
		p.tmpClass = tmp
		tmp = cleanClass(&p.tmpClass)
		if g.sign < 0 {
			r = appendNegatedClass(r, tmp)
		} else {
			r = appendClass(r, tmp)
		}
	}
	return r
}

var anyTable = &unicode.RangeTable{
	R16: []unicode.Range16{{Lo: 0, Hi: 1<<16 - 1, Stride: 1}},
	R32: []unicode.Range32{{Lo: 1 << 16, Hi: unicode.MaxRune, Stride: 1}},
}

// unicodeTable returns the unicode.RangeTable identified by name
// and the table of additional fold-equivalent code points.
func unicodeTable(name string) (*unicode.RangeTable, *unicode.RangeTable) {
	// Special case: "Any" means any.
	if name == "Any" {
		return anyTable, anyTable
	}
	if t := unicode.Categories[name]; t != nil {
		return t, unicode.FoldCategory[name]
	}
	if t := unicode.Scripts[name]; t != nil {
		return t, unicode.FoldScript[name]
	}
	return nil, nil
}

// parseUnicodeClass parses a leading Unicode character class like \p{Han}
// from the beginning of s. If one is present, it appends the characters to r
// and returns the new slice r and the remainder of the string.
func (p *parser) parseUnicodeClass(s string, r []rune) (out []rune, rest string, err error) {
	if p.flags&UnicodeGroups == 0 || len(s) < 2 || s[0] != '\\' || s[1] != 'p' && s[1] != 'P' {
		return
	}

	// Committed to parse or return error.
	sign := +1
	if s[1] == 'P' {
		sign = -1
	}
	t := s[2:]
	c, t, err := nextRune(t)
	if err != nil {
		return
	}
	var seq, name string
	if c != '{' {
		// Single-letter name.
		seq = s[:len(s)-len(t)]
		name = seq[2:]
	} else {
		// Name is in braces.
		end := strings.IndexRune(s, '}')
		if end < 0 {
			if err = checkUTF8(s); err != nil {
				return
			}
			return nil, "", &Error{ErrInvalidCharRange, s}
		}
		seq, t = s[:end+1], s[end+1:]
		name = s[3:end]
		if err = checkUTF8(name); err != nil {
			return
		}
	}

	// Group can have leading negation too.  \p{^Han} == \P{Han}, \P{^Han} == \p{Han}.
	if name != "" && name[0] == '^' {
		sign = -sign
		name = name[1:]
	}

	tab, fold := unicodeTable(name)
	if tab == nil {
		return nil, "", &Error{ErrInvalidCharRange, seq}
	}

	if p.flags&FoldCase == 0 || fold == nil {
		if sign > 0 {
			r = appendTable(r, tab)
		} else {
			r = appendNegatedTable(r, tab)
		}
	} else {
		// Merge and clean tab and fold in a temporary buffer.
		// This is necessary for the negative case and just tidy
		// for the positive case.
		tmp := p.tmpClass[:0]
		tmp = appendTable(tmp, tab)
		tmp = appendTable(tmp, fold)
		p.tmpClass = tmp
		tmp = cleanClass(&p.tmpClass)
		if sign > 0 {
			r = appendClass(r, tmp)
		} else {
			r = appendNegatedClass(r, tmp)
		}
	}
	return r, t, nil
}

// parseClass parses a character class at the beginning of s
// and pushes it onto the parse stack.
func (p *parser) parseClass(s string) (rest string, err error) {
	t := s[1:] // chop [
	re := p.newRegexp(OpCharClass)
	re.Flags = p.flags
	re.Rune = re.Rune0[:0]

	sign := +1
	if t != "" && t[0] == '^' {
		sign = -1
		t = t[1:]

		// If character class does not match \n, add it here,
		// so that negation later will do the right thing.
		if p.flags&ClassNL == 0 {
			re.Rune = append(re.Rune, '\n', '\n')
		}
	}

	class := re.Rune
	first := true // ] and - are okay as first char in class
	for t == "" || t[0] != ']' || first {
		// POSIX: - is only okay unescaped as first or last in class.
		// Perl: - is okay anywhere.
		if t != "" && t[0] == '-' && p.flags&PerlX == 0 && !first && (len(t) == 1 || t[1] != ']') {
			_, size := utf8.DecodeRuneInString(t[1:])
			return "", &Error{Code: ErrInvalidCharRange, Expr: t[:1+size]}
		}
		first = false

		// Look for POSIX [:alnum:] etc.
		if len(t) > 2 && t[0] == '[' && t[1] == ':' {
			nclass, nt, err := p.parseNamedClass(t, class)
			if err != nil {
				return "", err
			}
			if nclass != nil {
				class, t = nclass, nt
				continue
			}
		}

		// Look for Unicode character group like \p{Han}.
		nclass, nt, err := p.parseUnicodeClass(t, class)
		if err != nil {
			return "", err
		}
		if nclass != nil {
			class, t = nclass, nt
			continue
		}

		// Look for Perl character class symbols (extension).
		if nclass, nt := p.parsePerlClassEscape(t, class); nclass != nil {
			class, t = nclass, nt
			continue
		}

		// Single character or simple range.
		rng := t
		var lo, hi rune
		if lo, t, err = p.parseClassChar(t, s); err != nil {
			return "", err
		}
		hi = lo
		// [a-] means (a|-) so check for final ].
		if len(t) >= 2 && t[0] == '-' && t[1] != ']' {
			t = t[1:]
			if hi, t, err = p.parseClassChar(t, s); err != nil {
				return "", err
			}
			if hi < lo {
				rng = rng[:len(rng)-len(t)]
				return "", &Error{Code: ErrInvalidCharRange, Expr: rng}
			}
		}
		if p.flags&FoldCase == 0 {
			class = appendRange(class, lo, hi)
		} else {
			class = appendFoldedRange(class, lo, hi)
		}
	}
	t = t[1:] // chop ]

	// Use &re.Rune instead of &class to avoid allocation.
	re.Rune = class
	class = cleanClass(&re.Rune)
	if sign < 0 {
		class = negateClass(class)
	}
	re.Rune = class
	p.push(re)
	return t, nil
}

// cleanClass sorts the ranges (pairs of elements of r),
// merges them, and eliminates duplicates.
func cleanClass(rp *[]rune) []rune {

	// Sort by lo increasing, hi decreasing to break ties.
	sort.Sort(ranges{rp})

	r := *rp
	if len(r) < 2 {
		return r
	}

	// Merge abutting, overlapping.
	w := 2 // write index
	for i := 2; i < len(r); i += 2 {
		lo, hi := r[i], r[i+1]
		if lo <= r[w-1]+1 {
			// merge with previous range
			if hi > r[w-1] {
				r[w-1] = hi
			}
			continue
		}
		// new disjoint range
		r[w] = lo
		r[w+1] = hi
		w += 2
	}

	return r[:w]
}

// inCharClass reports whether r is in the class.
// It assumes the class has been cleaned by cleanClass.
func inCharClass(r rune, class []rune) bool {
	_, ok := sort.Find(len(class)/2, func(i int) int {
		lo, hi := class[2*i], class[2*i+1]
		if r > hi {
			return +1
		}
		if r < lo {
			return -1
		}
		return 0
	})
	return ok
}

// appendLiteral returns the result of appending the literal x to the class r.
func appendLiteral(r []rune, x rune, flags Flags) []rune {
	if flags&FoldCase != 0 {
		return appendFoldedRange(r, x, x)
	}
	return appendRange(r, x, x)
}

// appendRange returns the result of appending the range lo-hi to the class r.
func appendRange(r []rune, lo, hi rune) []rune {
	// Expand last range or next to last range if it overlaps or abuts.
	// Checking two ranges helps when appending case-folded
	// alphabets, so that one range can be expanding A-Z and the
	// other expanding a-z.
	n := len(r)
	for i := 2; i <= 4; i += 2 { // twice, using i=2, i=4
		if n >= i {
			rlo, rhi := r[n-i], r[n-i+1]
			if lo <= rhi+1 && rlo <= hi+1 {
				if lo < rlo {
					r[n-i] = lo
				}
				if hi > rhi {
					r[n-i+1] = hi
				}
				return r
			}
		}
	}

	return append(r, lo, hi)
}

const (
	// minimum and maximum runes involved in folding.
	// checked during test.
	minFold = 0x0041
	maxFold = 0x1e943
)

// appendFoldedRange returns the result of appending the range lo-hi
// and its case folding-equivalent runes to the class r.
func appendFoldedRange(r []rune, lo, hi rune) []rune {
	// Optimizations.
	if lo <= minFold && hi >= maxFold {
		// Range is full: folding can't add more.
		return appendRange(r, lo, hi)
	}
	if hi < minFold || lo > maxFold {
		// Range is outside folding possibilities.
		return appendRange(r, lo, hi)
	}
	if lo < minFold {
		// [lo, minFold-1] needs no folding.
		r = appendRange(r, lo, minFold-1)
		lo = minFold
	}
	if hi > maxFold {
		// [maxFold+1, hi] needs no folding.
		r = appendRange(r, maxFold+1, hi)
		hi = maxFold
	}

	// Brute force. Depend on appendRange to coalesce ranges on the fly.
	for c := lo; c <= hi; c++ {
		r = appendRange(r, c, c)
		f := unicode.SimpleFold(c)
		for f != c {
			r = appendRange(r, f, f)
			f = unicode.SimpleFold(f)
		}
	}
	return r
}

// appendClass returns the result of appending the class x to the class r.
// It assume x is clean.
func appendClass(r []rune, x []rune) []rune {
	for i := 0; i < len(x); i += 2 {
		r = appendRange(r, x[i], x[i+1])
	}
	return r
}

// appendFoldedClass returns the result of appending the case folding of the class x to the class r.
func appendFoldedClass(r []rune, x []rune) []rune {
	for i := 0; i < len(x); i += 2 {
		r = appendFoldedRange(r, x[i], x[i+1])
	}
	return r
}

// appendNegatedClass returns the result of appending the negation of the class x to the class r.
// It assumes x is clean.
func appendNegatedClass(r []rune, x []rune) []rune {
	nextLo := '\u0000'
	for i := 0; i < len(x); i += 2 {
		lo, hi := x[i], x[i+1]
		if nextLo <= lo-1 {
			r = appendRange(r, nextLo, lo-1)
		}
		nextLo = hi + 1
	}
	if nextLo <= unicode.MaxRune {
		r = appendRange(r, nextLo, unicode.MaxRune)
	}
	return r
}

// appendTable returns the result of appending x to the class r.
func appendTable(r []rune, x *unicode.RangeTable) []rune {
	for _, xr := range x.R16 {
		lo, hi, stride := rune(xr.Lo), rune(xr.Hi), rune(xr.Stride)
		if stride == 1 {
			r = appendRange(r, lo, hi)
			continue
		}
		for c := lo; c <= hi; c += stride {
			r = appendRange(r, c, c)
		}
	}
	for _, xr := range x.R32 {
		lo, hi, stride := rune(xr.Lo), rune(xr.Hi), rune(xr.Stride)
		if stride == 1 {
			r = appendRange(r, lo, hi)
			continue
		}
		for c := lo; c <= hi; c += stride {
			r = appendRange(r, c, c)
		}
	}
	return r
}

// appendNegatedTable returns the result of appending the negation of x to the class r.
func appendNegatedTable(r []rune, x *unicode.RangeTable) []rune {
	nextLo := '\u0000' // lo end of next class to add
	for _, xr := range x.R16 {
		lo, hi, stride := rune(xr.Lo), rune(xr.Hi), rune(xr.Stride)
		if stride == 1 {
			if nextLo <= lo-1 {
				r = appendRange(r, nextLo, lo-1)
			}
			nextLo = hi + 1
			continue
		}
		for c := lo; c <= hi; c += stride {
			if nextLo <= c-1 {
				r = appendRange(r, nextLo, c-1)
			}
			nextLo = c + 1
		}
	}
	for _, xr := range x.R32 {
		lo, hi, stride := rune(xr.Lo), rune(xr.Hi), rune(xr.Stride)
		if stride == 1 {
			if nextLo <= lo-1 {
				r = appendRange(r, nextLo, lo-1)
			}
			nextLo = hi + 1
			continue
		}
		for c := lo; c <= hi; c += stride {
			if nextLo <= c-1 {
				r = appendRange(r, nextLo, c-1)
			}
			nextLo = c + 1
		}
	}
	if nextLo <= unicode.MaxRune {
		r = appendRange(r, nextLo, unicode.MaxRune)
	}
	return r
}

// negateClass overwrites r and returns r's negation.
// It assumes the class r is already clean.
func negateClass(r []rune) []rune {
	nextLo := '\u0000' // lo end of next class to add
	w := 0             // write index
	for i := 0; i < len(r); i += 2 {
		lo, hi := r[i], r[i+1]
		if nextLo <= lo-1 {
			r[w] = nextLo
			r[w+1] = lo - 1
			w += 2
		}
		nextLo = hi + 1
	}
	r = r[:w]
	if nextLo <= unicode.MaxRune {
		// It's possible for the negation to have one more
		// range - this one - than the original class, so use append.
		r = append(r, nextLo, unicode.MaxRune)
	}
	return r
}

// ranges implements sort.Interface on a []rune.
// The choice of receiver type definition is strange
// but avoids an allocation since we already have
// a *[]rune.
type ranges struct {
	p *[]rune
}

func (ra ranges) Less(i, j int) bool {
	p := *ra.p
	i *= 2
	j *= 2
	return p[i] < p[j] || p[i] == p[j] && p[i+1] > p[j+1]
}

func (ra ranges) Len() int {
	return len(*ra.p) / 2
}

func (ra ranges) Swap(i, j int) {
	p := *ra.p
	i *= 2
	j *= 2
	p[i], p[i+1], p[j], p[j+1] = p[j], p[j+1], p[i], p[i+1]
}

func checkUTF8(s string) error {
	for s != "" {
		rune, size := utf8.DecodeRuneInString(s)
		if rune == utf8.RuneError && size == 1 {
			return &Error{Code: ErrInvalidUTF8, Expr: s}
		}
		s = s[size:]
	}
	return nil
}

func nextRune(s string) (c rune, t string, err error) {
	c, size := utf8.DecodeRuneInString(s)
	if c == utf8.RuneError && size == 1 {
		return 0, "", &Error{Code: ErrInvalidUTF8, Expr: s}
	}
	return c, s[size:], nil
}

func isalnum(c rune) bool {
	return '0' <= c && c <= '9' || 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z'
}

func unhex(c rune) rune {
	if '0' <= c && c <= '9' {
		return c - '0'
	}
	if 'a' <= c && c <= 'f' {
		return c - 'a' + 10
	}
	if 'A' <= c && c <= 'F' {
		return c - 'A' + 10
	}
	return -1
}

"""




```