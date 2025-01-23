Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Understanding and Context:**

The first step is to recognize the file path: `go/src/regexp/syntax/parse_test.go`. This immediately tells us a few crucial things:

* **Language:** Go.
* **Location:** Part of the standard Go library (`regexp` package).
* **Purpose:**  Testing the `syntax` sub-package, specifically its `parse` functionality related to regular expressions. The `_test.go` suffix confirms this is a testing file.

**2. Examining the Core Data Structure (`parseTest`):**

The code defines a struct `parseTest` with two fields: `Regexp` (string) and `Dump` (string). This suggests a pattern: the tests likely involve feeding a regular expression string to a parsing function and comparing the resulting internal representation (or a string representation of it) with an expected `Dump` value.

**3. Analyzing the Test Cases (`parseTests`):**

The `parseTests` variable is a slice of `parseTest` structs. Going through the examples reveals the expected behavior of the parser for various regular expression constructs:

* **Basic Literals:** `a`, `ab`, `abc`.
* **Special Characters:** `.`, `^`, `$`, `|`, `(`, `)`, `*`, `+`, `?`, `{}`.
* **Character Classes:** `[ace]`, `[a-z]`, `[^a]`.
* **Escaped Characters:** `\.`, `\\`, `\|`.
* **POSIX and Perl Extensions:** `[[:lower:]]`, `\d`, `\w`, `\p{Braille}`.
* **Quantifiers:** `a*`, `a+`, `a?`, `a{2}`, `a{2,3}`, `a{2,}`.
* **Non-Greedy Quantifiers:** `a*?`, `a+?`, `a??`, `a{2}?`.
* **Grouping and Capturing:** `(a)`, `(?:ab)*`, `(?P<name>a)`.
* **Case-Insensitive Matching:** `(?i)[[:lower:]]`, `(?i)\w`.
* **Anchors:** `^`, `$`, `\A`, `\z`.
* **Quoted Literals:** `\Q+|*?{[\E`.
* **Folding:** `[Aa]`, `[\x{100}\x{101}]`.
* **String Optimization:** Examples showing how consecutive literals are combined into `str` nodes.
* **Factoring:** Examples demonstrating how the parser groups common prefixes in alternations.

The `Dump` strings appear to be a simplified, internal representation of the parsed regular expression tree. Terms like `lit`, `str`, `cc`, `cat`, `alt`, `star`, `plus`, `que`, `rep`, `cap` clearly represent different nodes in the parse tree.

**4. Identifying the Core Testing Function (`testParseDump`):**

The `TestParseSimple` function calls `testParseDump`. This function takes a slice of `parseTest` and `flags` as input. It iterates through the tests, calls `Parse` (the function under test), and compares the output of the `dump` function (applied to the parsed result) with the expected `Dump` string. This confirms the initial hypothesis about the testing mechanism.

**5. Deducing the Functionality of `Parse`:**

Based on the test cases and the `testParseDump` function, we can infer that the `Parse` function (likely from the `regexp/syntax` package) takes a regular expression string and a set of flags as input. It returns a parsed representation of the regular expression (presumably a `Regexp` struct) and potentially an error if the input is invalid.

**6. Reconstructing a Go Code Example:**

Now, we can create a concrete Go example to illustrate the usage of the `Parse` function and how to interpret its output. We choose a simple example from the test cases: `"a|b"`. We anticipate that `Parse` will return a `Regexp` object representing the alternation of "a" and "b", and `dump` will output `cc{0x61-0x62}`.

**7. Analyzing Flags:**

The `testFlags` constant (`MatchNL | PerlX | UnicodeGroups`) and the flags passed to other test functions (`FoldCase`, `Literal`, `MatchNL`, `0` (meaning no flags)) highlight that the `Parse` function accepts flags to control its behavior (e.g., whether to treat newline specially, enable Perl extensions, perform case-insensitive matching).

**8. Identifying Potential Pitfalls:**

By examining the `invalidRegexps`, `onlyPerl`, and `onlyPOSIX` variables, we can identify common errors users might make:

* **Unmatched parentheses or brackets.**
* **Invalid repetition counts (too large, incorrect order).**
* **Invalid UTF-8 sequences.**
* **Using Perl-specific features when the POSIX flag is set (and vice-versa).**
* **Nesting too deeply or creating excessively long regular expressions.**

**9. Review and Refinement:**

Finally, review the entire analysis to ensure it's coherent, accurate, and addresses all aspects of the prompt. Organize the information logically, using clear headings and examples. Ensure the Go code example is compilable and demonstrates the key functionality.
这段代码是 Go 语言 `regexp/syntax` 包中的 `parse_test.go` 文件的一部分，它主要用于**测试正则表达式的解析器 (`Parse` 函数)**。

**功能列表:**

1. **定义测试用例:**  `parseTest` 结构体用于定义单个测试用例，包含一个正则表达式字符串 (`Regexp`) 和其期望的解析结果的字符串表示 (`Dump`)。
2. **基础测试用例:**  `parseTests` 变量包含了一系列 `parseTest` 结构体，覆盖了正则表达式语法的各种基本情况，例如：
    * 字面量匹配 (`a`, `ab`, `abc`)
    * 特殊字符 (`.`, `^`, `$`, `|`, `(`, `)`, `*`, `+`, `?`, `{}`)
    * 字符类 (`[ace]`, `[a-z]`, `[^a]`)
    * 转义字符 (`\.`, `\\`, `\|`)
    * 重复次数 (`a*`, `a+`, `a?`, `a{2}`, `a{2,3}`, `a{2,}`)
    * 非贪婪匹配 (`a*?`, `a+?`, `a??`, `a{2}?`)
    * 分组和捕获 (`(a)`, `(?:ab)*`, `(?P<name>a)`)
    * Unicode 属性 (`\p{Braille}`, `\pZ`)
    * 十六进制和八进制表示 (`\012`, `\x{41}`)
3. **扩展功能测试用例:**  还包括对 POSIX 和 Perl 扩展语法的测试，例如：
    * POSIX 字符类 (`[[:lower:]]`)
    * Perl 字符类 (`\d`, `\w`, `\s`)
    * 命名捕获 (`(?P<name>a)`, `(?<name>a)`)
    * `\A` 和 `\z` 锚点
    * `\Q...\E` 字面量引用
4. **不同 Flag 的测试:**  定义了不同的测试用例集 (`foldcaseTests`, `literalTests`, `matchnlTests`, `nomatchnlTests`)，用于测试在不同 `Flags` 设置下解析器的行为，例如：
    * `FoldCase`: 大小写折叠
    * `Literal`: 将所有字符视为字面量
    * `MatchNL`: `.` 匹配换行符
5. **无效正则表达式测试:**  `invalidRegexps` 包含了各种无效的正则表达式，用于测试解析器是否能正确地报告错误。
6. **特定语法测试:** `onlyPerl` 和 `onlyPOSIX` 分别测试仅在 Perl 或 POSIX 模式下有效的语法。
7. **解析结果的 Dump:** `dump` 函数将解析后的 `Regexp` 结构体转换成一个易于比较的字符串表示形式，用于断言测试结果的正确性。
8. **测试辅助函数:** `testParseDump` 是一个核心的测试辅助函数，它接收一组测试用例和标志位，遍历每个测试用例，调用 `Parse` 函数解析正则表达式，然后将解析结果 `dump` 成字符串，并与期望的 `Dump` 值进行比较。
9. **测试解析结果的 String 方法:** `TestToStringEquivalentParse` 测试解析后的 `Regexp` 结构体的 `String` 方法是否能够生成与原始正则表达式等价（或者更简洁）的字符串，并确保重新解析该字符串能得到相同的内部结构。
10. **测试 String 方法的输出:** `TestString` 测试 `Regexp` 结构体的 `String` 方法在不同情况下的输出格式，特别是针对 `(?i)` 大小写不敏感标志的处理。

**推理 `Parse` 函数的功能实现:**

从这些测试用例可以看出，`Parse` 函数的主要功能是**将一个正则表达式字符串解析成一个内部的语法树结构**，该结构表示了正则表达式的组成部分及其关系。  `Regexp` 结构体就是这个语法树的根节点，它的 `Op` 字段表示当前节点的类型（例如 `OpLiteral` 表示字面量，`OpCharClass` 表示字符类，`OpStar` 表示 `*` 重复）。`Sub` 字段通常包含子表达式。

**Go 代码举例说明:**

假设我们要解析正则表达式 `"a|b"`，预期的输出是 `cc{0x61-0x62}`。

```go
package main

import (
	"fmt"
	"regexp/syntax"
)

func main() {
	re, err := syntax.Parse("a|b", syntax.Perl) // 使用 Perl 标志
	if err != nil {
		fmt.Println("解析出错:", err)
		return
	}

	dumped := dumpRegexpToString(re)
	fmt.Println("解析结果:", dumped) // 输出: 解析结果: cc{0x61-0x62}
}

// 简化的 dump 函数，只输出核心信息
func dumpRegexpToString(re *syntax.Regexp) string {
	switch re.Op {
	case syntax.OpCharClass:
		if len(re.Rune) == 2 && re.Rune[0]+1 == re.Rune[1] {
			return fmt.Sprintf("cc{0x%x-0x%x}", re.Rune[0], re.Rune[1])
		} else if len(re.Rune) > 0 {
			res := "cc{"
			for i := 0; i < len(re.Rune); i++ {
				res += fmt.Sprintf("0x%x", re.Rune[i])
				if i < len(re.Rune)-1 {
					res += " "
				}
			}
			res += "}"
			return res
		}
	// ... 可以添加其他 Op 类型的处理
	default:
		return fmt.Sprintf("%v", re.Op) // 简化输出
	}
	return ""
}
```

**假设的输入与输出:**

* **输入:**  正则表达式字符串 `"a|b"`
* **输出:**  字符串 `"cc{0x61-0x62}"` (通过 `dump` 函数转换后的表示)

**使用者易犯错的点:**

1. **不理解不同的 Flag 含义:**  例如，在 POSIX 模式下使用 Perl 特有的语法，或者在没有设置 `MatchNL` 的情况下期望 `.` 匹配换行符。

   ```go
   package main

   import (
       "fmt"
       "regexp/syntax"
   )

   func main() {
       // 错误示例：在 POSIX 模式下使用 \d
       _, err := syntax.Parse("\\d", syntax.POSIX)
       if err != nil {
           fmt.Println("错误:", err) // 输出类似：错误: error parsing regexp: invalid character class range
       }

       // 正确示例：在 Perl 模式下使用 \d
       re, err := syntax.Parse("\\d", syntax.Perl)
       if err != nil {
           fmt.Println("错误:", err)
           return
       }
       fmt.Println("解析成功:", dumpRegexpToString(re)) // 输出类似：解析成功: cc{0x30-0x39}
   }

   // ... (dumpRegexpToString 函数同上)
   ```

2. **误解特殊字符的含义:**  忘记某些字符在正则表达式中具有特殊意义，需要进行转义才能匹配字面量。

   ```go
   package main

   import (
       "fmt"
       "regexp/syntax"
   )

   func main() {
       // 错误示例：期望匹配字符串 "."，但 . 是匹配任意字符
       re1, _ := syntax.Parse(".", syntax.Perl)
       fmt.Println("解析 '.' :", dumpRegexpToString(re1)) // 输出类似：解析 '.' : dot{}

       // 正确示例：使用转义字符匹配字面量 "."
       re2, _ := syntax.Parse("\\.", syntax.Perl)
       fmt.Println("解析 '\\.' :", dumpRegexpToString(re2)) // 输出类似：解析 '\.' : lit{.}
   }

   // ... (dumpRegexpToString 函数同上)
   ```

3. **括号不匹配:**  正则表达式中的括号必须成对出现，否则会导致解析错误。

   ```go
   package main

   import (
       "fmt"
       "regexp/syntax"
   )

   func main() {
       // 错误示例：缺少右括号
       _, err := syntax.Parse("(ab", syntax.Perl)
       if err != nil {
           fmt.Println("错误:", err) // 输出类似：错误: error parsing regexp: missing closing )
       }
   }
   ```

这段测试代码是理解 Go 语言正则表达式解析器工作原理的重要参考。通过分析这些测试用例，可以深入了解正则表达式语法的细节以及 `regexp/syntax` 包是如何解析和表示它们的。

### 提示词
```
这是路径为go/src/regexp/syntax/parse_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package syntax

import (
	"fmt"
	"strings"
	"testing"
	"unicode"
)

type parseTest struct {
	Regexp string
	Dump   string
}

var parseTests = []parseTest{
	// Base cases
	{`a`, `lit{a}`},
	{`a.`, `cat{lit{a}dot{}}`},
	{`a.b`, `cat{lit{a}dot{}lit{b}}`},
	{`ab`, `str{ab}`},
	{`a.b.c`, `cat{lit{a}dot{}lit{b}dot{}lit{c}}`},
	{`abc`, `str{abc}`},
	{`a|^`, `alt{lit{a}bol{}}`},
	{`a|b`, `cc{0x61-0x62}`},
	{`(a)`, `cap{lit{a}}`},
	{`(a)|b`, `alt{cap{lit{a}}lit{b}}`},
	{`a*`, `star{lit{a}}`},
	{`a+`, `plus{lit{a}}`},
	{`a?`, `que{lit{a}}`},
	{`a{2}`, `rep{2,2 lit{a}}`},
	{`a{2,3}`, `rep{2,3 lit{a}}`},
	{`a{2,}`, `rep{2,-1 lit{a}}`},
	{`a*?`, `nstar{lit{a}}`},
	{`a+?`, `nplus{lit{a}}`},
	{`a??`, `nque{lit{a}}`},
	{`a{2}?`, `nrep{2,2 lit{a}}`},
	{`a{2,3}?`, `nrep{2,3 lit{a}}`},
	{`a{2,}?`, `nrep{2,-1 lit{a}}`},
	// Malformed { } are treated as literals.
	{`x{1001`, `str{x{1001}`},
	{`x{9876543210`, `str{x{9876543210}`},
	{`x{9876543210,`, `str{x{9876543210,}`},
	{`x{2,1`, `str{x{2,1}`},
	{`x{1,9876543210`, `str{x{1,9876543210}`},
	{``, `emp{}`},
	{`|`, `emp{}`}, // alt{emp{}emp{}} but got factored
	{`|x|`, `alt{emp{}lit{x}emp{}}`},
	{`.`, `dot{}`},
	{`^`, `bol{}`},
	{`$`, `eol{}`},
	{`\|`, `lit{|}`},
	{`\(`, `lit{(}`},
	{`\)`, `lit{)}`},
	{`\*`, `lit{*}`},
	{`\+`, `lit{+}`},
	{`\?`, `lit{?}`},
	{`{`, `lit{{}`},
	{`}`, `lit{}}`},
	{`\.`, `lit{.}`},
	{`\^`, `lit{^}`},
	{`\$`, `lit{$}`},
	{`\\`, `lit{\}`},
	{`[ace]`, `cc{0x61 0x63 0x65}`},
	{`[abc]`, `cc{0x61-0x63}`},
	{`[a-z]`, `cc{0x61-0x7a}`},
	{`[a]`, `lit{a}`},
	{`\-`, `lit{-}`},
	{`-`, `lit{-}`},
	{`\_`, `lit{_}`},
	{`abc`, `str{abc}`},
	{`abc|def`, `alt{str{abc}str{def}}`},
	{`abc|def|ghi`, `alt{str{abc}str{def}str{ghi}}`},

	// Posix and Perl extensions
	{`[[:lower:]]`, `cc{0x61-0x7a}`},
	{`[a-z]`, `cc{0x61-0x7a}`},
	{`[^[:lower:]]`, `cc{0x0-0x60 0x7b-0x10ffff}`},
	{`[[:^lower:]]`, `cc{0x0-0x60 0x7b-0x10ffff}`},
	{`(?i)[[:lower:]]`, `cc{0x41-0x5a 0x61-0x7a 0x17f 0x212a}`},
	{`(?i)[a-z]`, `cc{0x41-0x5a 0x61-0x7a 0x17f 0x212a}`},
	{`(?i)[^[:lower:]]`, `cc{0x0-0x40 0x5b-0x60 0x7b-0x17e 0x180-0x2129 0x212b-0x10ffff}`},
	{`(?i)[[:^lower:]]`, `cc{0x0-0x40 0x5b-0x60 0x7b-0x17e 0x180-0x2129 0x212b-0x10ffff}`},
	{`\d`, `cc{0x30-0x39}`},
	{`\D`, `cc{0x0-0x2f 0x3a-0x10ffff}`},
	{`\s`, `cc{0x9-0xa 0xc-0xd 0x20}`},
	{`\S`, `cc{0x0-0x8 0xb 0xe-0x1f 0x21-0x10ffff}`},
	{`\w`, `cc{0x30-0x39 0x41-0x5a 0x5f 0x61-0x7a}`},
	{`\W`, `cc{0x0-0x2f 0x3a-0x40 0x5b-0x5e 0x60 0x7b-0x10ffff}`},
	{`(?i)\w`, `cc{0x30-0x39 0x41-0x5a 0x5f 0x61-0x7a 0x17f 0x212a}`},
	{`(?i)\W`, `cc{0x0-0x2f 0x3a-0x40 0x5b-0x5e 0x60 0x7b-0x17e 0x180-0x2129 0x212b-0x10ffff}`},
	{`[^\\]`, `cc{0x0-0x5b 0x5d-0x10ffff}`},
	//	{ `\C`, `byte{}` },  // probably never

	// Unicode, negatives, and a double negative.
	{`\p{Braille}`, `cc{0x2800-0x28ff}`},
	{`\P{Braille}`, `cc{0x0-0x27ff 0x2900-0x10ffff}`},
	{`\p{^Braille}`, `cc{0x0-0x27ff 0x2900-0x10ffff}`},
	{`\P{^Braille}`, `cc{0x2800-0x28ff}`},
	{`\pZ`, `cc{0x20 0xa0 0x1680 0x2000-0x200a 0x2028-0x2029 0x202f 0x205f 0x3000}`},
	{`[\p{Braille}]`, `cc{0x2800-0x28ff}`},
	{`[\P{Braille}]`, `cc{0x0-0x27ff 0x2900-0x10ffff}`},
	{`[\p{^Braille}]`, `cc{0x0-0x27ff 0x2900-0x10ffff}`},
	{`[\P{^Braille}]`, `cc{0x2800-0x28ff}`},
	{`[\pZ]`, `cc{0x20 0xa0 0x1680 0x2000-0x200a 0x2028-0x2029 0x202f 0x205f 0x3000}`},
	{`\p{Lu}`, mkCharClass(unicode.IsUpper)},
	{`[\p{Lu}]`, mkCharClass(unicode.IsUpper)},
	{`(?i)[\p{Lu}]`, mkCharClass(isUpperFold)},
	{`\p{Any}`, `dot{}`},
	{`\p{^Any}`, `cc{}`},

	// Hex, octal.
	{`[\012-\234]\141`, `cat{cc{0xa-0x9c}lit{a}}`},
	{`[\x{41}-\x7a]\x61`, `cat{cc{0x41-0x7a}lit{a}}`},

	// More interesting regular expressions.
	{`a{,2}`, `str{a{,2}}`},
	{`\.\^\$\\`, `str{.^$\}`},
	{`[a-zABC]`, `cc{0x41-0x43 0x61-0x7a}`},
	{`[^a]`, `cc{0x0-0x60 0x62-0x10ffff}`},
	{`[α-ε☺]`, `cc{0x3b1-0x3b5 0x263a}`}, // utf-8
	{`a*{`, `cat{star{lit{a}}lit{{}}`},

	// Test precedences
	{`(?:ab)*`, `star{str{ab}}`},
	{`(ab)*`, `star{cap{str{ab}}}`},
	{`ab|cd`, `alt{str{ab}str{cd}}`},
	{`a(b|c)d`, `cat{lit{a}cap{cc{0x62-0x63}}lit{d}}`},

	// Test flattening.
	{`(?:a)`, `lit{a}`},
	{`(?:ab)(?:cd)`, `str{abcd}`},
	{`(?:a+b+)(?:c+d+)`, `cat{plus{lit{a}}plus{lit{b}}plus{lit{c}}plus{lit{d}}}`},
	{`(?:a+|b+)|(?:c+|d+)`, `alt{plus{lit{a}}plus{lit{b}}plus{lit{c}}plus{lit{d}}}`},
	{`(?:a|b)|(?:c|d)`, `cc{0x61-0x64}`},
	{`a|.`, `dot{}`},
	{`.|a`, `dot{}`},
	{`(?:[abc]|A|Z|hello|world)`, `alt{cc{0x41 0x5a 0x61-0x63}str{hello}str{world}}`},
	{`(?:[abc]|A|Z)`, `cc{0x41 0x5a 0x61-0x63}`},

	// Test Perl quoted literals
	{`\Q+|*?{[\E`, `str{+|*?{[}`},
	{`\Q+\E+`, `plus{lit{+}}`},
	{`\Qab\E+`, `cat{lit{a}plus{lit{b}}}`},
	{`\Q\\E`, `lit{\}`},
	{`\Q\\\E`, `str{\\}`},

	// Test Perl \A and \z
	{`(?m)^`, `bol{}`},
	{`(?m)$`, `eol{}`},
	{`(?-m)^`, `bot{}`},
	{`(?-m)$`, `eot{}`},
	{`(?m)\A`, `bot{}`},
	{`(?m)\z`, `eot{\z}`},
	{`(?-m)\A`, `bot{}`},
	{`(?-m)\z`, `eot{\z}`},

	// Test named captures
	{`(?P<name>a)`, `cap{name:lit{a}}`},
	{`(?<name>a)`, `cap{name:lit{a}}`},

	// Case-folded literals
	{`[Aa]`, `litfold{A}`},
	{`[\x{100}\x{101}]`, `litfold{Ā}`},
	{`[Δδ]`, `litfold{Δ}`},

	// Strings
	{`abcde`, `str{abcde}`},
	{`[Aa][Bb]cd`, `cat{strfold{AB}str{cd}}`},

	// Factoring.
	{`abc|abd|aef|bcx|bcy`, `alt{cat{lit{a}alt{cat{lit{b}cc{0x63-0x64}}str{ef}}}cat{str{bc}cc{0x78-0x79}}}`},
	{`ax+y|ax+z|ay+w`, `cat{lit{a}alt{cat{plus{lit{x}}lit{y}}cat{plus{lit{x}}lit{z}}cat{plus{lit{y}}lit{w}}}}`},

	// Bug fixes.
	{`(?:.)`, `dot{}`},
	{`(?:x|(?:xa))`, `cat{lit{x}alt{emp{}lit{a}}}`},
	{`(?:.|(?:.a))`, `cat{dot{}alt{emp{}lit{a}}}`},
	{`(?:A(?:A|a))`, `cat{lit{A}litfold{A}}`},
	{`(?:A|a)`, `litfold{A}`},
	{`A|(?:A|a)`, `litfold{A}`},
	{`(?s).`, `dot{}`},
	{`(?-s).`, `dnl{}`},
	{`(?:(?:^).)`, `cat{bol{}dot{}}`},
	{`(?-s)(?:(?:^).)`, `cat{bol{}dnl{}}`},
	{`[\s\S]a`, `cat{cc{0x0-0x10ffff}lit{a}}`},

	// RE2 prefix_tests
	{`abc|abd`, `cat{str{ab}cc{0x63-0x64}}`},
	{`a(?:b)c|abd`, `cat{str{ab}cc{0x63-0x64}}`},
	{`abc|abd|aef|bcx|bcy`,
		`alt{cat{lit{a}alt{cat{lit{b}cc{0x63-0x64}}str{ef}}}` +
			`cat{str{bc}cc{0x78-0x79}}}`},
	{`abc|x|abd`, `alt{str{abc}lit{x}str{abd}}`},
	{`(?i)abc|ABD`, `cat{strfold{AB}cc{0x43-0x44 0x63-0x64}}`},
	{`[ab]c|[ab]d`, `cat{cc{0x61-0x62}cc{0x63-0x64}}`},
	{`.c|.d`, `cat{dot{}cc{0x63-0x64}}`},
	{`x{2}|x{2}[0-9]`,
		`cat{rep{2,2 lit{x}}alt{emp{}cc{0x30-0x39}}}`},
	{`x{2}y|x{2}[0-9]y`,
		`cat{rep{2,2 lit{x}}alt{lit{y}cat{cc{0x30-0x39}lit{y}}}}`},
	{`a.*?c|a.*?b`,
		`cat{lit{a}alt{cat{nstar{dot{}}lit{c}}cat{nstar{dot{}}lit{b}}}}`},

	// Valid repetitions.
	{`((((((((((x{2}){2}){2}){2}){2}){2}){2}){2}){2}))`, ``},
	{`((((((((((x{1}){2}){2}){2}){2}){2}){2}){2}){2}){2})`, ``},

	// Valid nesting.
	{strings.Repeat("(", 999) + strings.Repeat(")", 999), ``},
	{strings.Repeat("(?:", 999) + strings.Repeat(")*", 999), ``},
	{"(" + strings.Repeat("|", 12345) + ")", ``}, // not nested at all
}

const testFlags = MatchNL | PerlX | UnicodeGroups

func TestParseSimple(t *testing.T) {
	testParseDump(t, parseTests, testFlags)
}

var foldcaseTests = []parseTest{
	{`AbCdE`, `strfold{ABCDE}`},
	{`[Aa]`, `litfold{A}`},
	{`a`, `litfold{A}`},

	// 0x17F is an old English long s (looks like an f) and folds to s.
	// 0x212A is the Kelvin symbol and folds to k.
	{`A[F-g]`, `cat{litfold{A}cc{0x41-0x7a 0x17f 0x212a}}`}, // [Aa][A-z...]
	{`[[:upper:]]`, `cc{0x41-0x5a 0x61-0x7a 0x17f 0x212a}`},
	{`[[:lower:]]`, `cc{0x41-0x5a 0x61-0x7a 0x17f 0x212a}`},
}

func TestParseFoldCase(t *testing.T) {
	testParseDump(t, foldcaseTests, FoldCase)
}

var literalTests = []parseTest{
	{"(|)^$.[*+?]{5,10},\\", "str{(|)^$.[*+?]{5,10},\\}"},
}

func TestParseLiteral(t *testing.T) {
	testParseDump(t, literalTests, Literal)
}

var matchnlTests = []parseTest{
	{`.`, `dot{}`},
	{"\n", "lit{\n}"},
	{`[^a]`, `cc{0x0-0x60 0x62-0x10ffff}`},
	{`[a\n]`, `cc{0xa 0x61}`},
}

func TestParseMatchNL(t *testing.T) {
	testParseDump(t, matchnlTests, MatchNL)
}

var nomatchnlTests = []parseTest{
	{`.`, `dnl{}`},
	{"\n", "lit{\n}"},
	{`[^a]`, `cc{0x0-0x9 0xb-0x60 0x62-0x10ffff}`},
	{`[a\n]`, `cc{0xa 0x61}`},
}

func TestParseNoMatchNL(t *testing.T) {
	testParseDump(t, nomatchnlTests, 0)
}

// Test Parse -> Dump.
func testParseDump(t *testing.T, tests []parseTest, flags Flags) {
	for _, tt := range tests {
		re, err := Parse(tt.Regexp, flags)
		if err != nil {
			t.Errorf("Parse(%#q): %v", tt.Regexp, err)
			continue
		}
		if tt.Dump == "" {
			// It parsed. That's all we care about.
			continue
		}
		d := dump(re)
		if d != tt.Dump {
			t.Errorf("Parse(%#q).Dump() = %#q want %#q", tt.Regexp, d, tt.Dump)
		}
	}
}

// dump prints a string representation of the regexp showing
// the structure explicitly.
func dump(re *Regexp) string {
	var b strings.Builder
	dumpRegexp(&b, re)
	return b.String()
}

var opNames = []string{
	OpNoMatch:        "no",
	OpEmptyMatch:     "emp",
	OpLiteral:        "lit",
	OpCharClass:      "cc",
	OpAnyCharNotNL:   "dnl",
	OpAnyChar:        "dot",
	OpBeginLine:      "bol",
	OpEndLine:        "eol",
	OpBeginText:      "bot",
	OpEndText:        "eot",
	OpWordBoundary:   "wb",
	OpNoWordBoundary: "nwb",
	OpCapture:        "cap",
	OpStar:           "star",
	OpPlus:           "plus",
	OpQuest:          "que",
	OpRepeat:         "rep",
	OpConcat:         "cat",
	OpAlternate:      "alt",
}

// dumpRegexp writes an encoding of the syntax tree for the regexp re to b.
// It is used during testing to distinguish between parses that might print
// the same using re's String method.
func dumpRegexp(b *strings.Builder, re *Regexp) {
	if int(re.Op) >= len(opNames) || opNames[re.Op] == "" {
		fmt.Fprintf(b, "op%d", re.Op)
	} else {
		switch re.Op {
		default:
			b.WriteString(opNames[re.Op])
		case OpStar, OpPlus, OpQuest, OpRepeat:
			if re.Flags&NonGreedy != 0 {
				b.WriteByte('n')
			}
			b.WriteString(opNames[re.Op])
		case OpLiteral:
			if len(re.Rune) > 1 {
				b.WriteString("str")
			} else {
				b.WriteString("lit")
			}
			if re.Flags&FoldCase != 0 {
				for _, r := range re.Rune {
					if unicode.SimpleFold(r) != r {
						b.WriteString("fold")
						break
					}
				}
			}
		}
	}
	b.WriteByte('{')
	switch re.Op {
	case OpEndText:
		if re.Flags&WasDollar == 0 {
			b.WriteString(`\z`)
		}
	case OpLiteral:
		for _, r := range re.Rune {
			b.WriteRune(r)
		}
	case OpConcat, OpAlternate:
		for _, sub := range re.Sub {
			dumpRegexp(b, sub)
		}
	case OpStar, OpPlus, OpQuest:
		dumpRegexp(b, re.Sub[0])
	case OpRepeat:
		fmt.Fprintf(b, "%d,%d ", re.Min, re.Max)
		dumpRegexp(b, re.Sub[0])
	case OpCapture:
		if re.Name != "" {
			b.WriteString(re.Name)
			b.WriteByte(':')
		}
		dumpRegexp(b, re.Sub[0])
	case OpCharClass:
		sep := ""
		for i := 0; i < len(re.Rune); i += 2 {
			b.WriteString(sep)
			sep = " "
			lo, hi := re.Rune[i], re.Rune[i+1]
			if lo == hi {
				fmt.Fprintf(b, "%#x", lo)
			} else {
				fmt.Fprintf(b, "%#x-%#x", lo, hi)
			}
		}
	}
	b.WriteByte('}')
}

func mkCharClass(f func(rune) bool) string {
	re := &Regexp{Op: OpCharClass}
	lo := rune(-1)
	for i := rune(0); i <= unicode.MaxRune; i++ {
		if f(i) {
			if lo < 0 {
				lo = i
			}
		} else {
			if lo >= 0 {
				re.Rune = append(re.Rune, lo, i-1)
				lo = -1
			}
		}
	}
	if lo >= 0 {
		re.Rune = append(re.Rune, lo, unicode.MaxRune)
	}
	return dump(re)
}

func isUpperFold(r rune) bool {
	if unicode.IsUpper(r) {
		return true
	}
	c := unicode.SimpleFold(r)
	for c != r {
		if unicode.IsUpper(c) {
			return true
		}
		c = unicode.SimpleFold(c)
	}
	return false
}

func TestFoldConstants(t *testing.T) {
	last := rune(-1)
	for i := rune(0); i <= unicode.MaxRune; i++ {
		if unicode.SimpleFold(i) == i {
			continue
		}
		if last == -1 && minFold != i {
			t.Errorf("minFold=%#U should be %#U", minFold, i)
		}
		last = i
	}
	if maxFold != last {
		t.Errorf("maxFold=%#U should be %#U", maxFold, last)
	}
}

func TestAppendRangeCollapse(t *testing.T) {
	// AppendRange should collapse each of the new ranges
	// into the earlier ones (it looks back two ranges), so that
	// the slice never grows very large.
	// Note that we are not calling cleanClass.
	var r []rune
	for i := rune('A'); i <= 'Z'; i++ {
		r = appendRange(r, i, i)
		r = appendRange(r, i+'a'-'A', i+'a'-'A')
	}
	if string(r) != "AZaz" {
		t.Errorf("appendRange interlaced A-Z a-z = %s, want AZaz", string(r))
	}
}

var invalidRegexps = []string{
	`(`,
	`)`,
	`(a`,
	`a)`,
	`(a))`,
	`(a|b|`,
	`a|b|)`,
	`(a|b|))`,
	`(a|b`,
	`a|b)`,
	`(a|b))`,
	`[a-z`,
	`([a-z)`,
	`[a-z)`,
	`([a-z]))`,
	`x{1001}`,
	`x{9876543210}`,
	`x{2,1}`,
	`x{1,9876543210}`,
	"\xff", // Invalid UTF-8
	"[\xff]",
	"[\\\xff]",
	"\\\xff",
	`(?P<name>a`,
	`(?P<name>`,
	`(?P<name`,
	`(?P<x y>a)`,
	`(?P<>a)`,
	`(?<name>a`,
	`(?<name>`,
	`(?<name`,
	`(?<x y>a)`,
	`(?<>a)`,
	`[a-Z]`,
	`(?i)[a-Z]`,
	`\Q\E*`,
	`a{100000}`,  // too much repetition
	`a{100000,}`, // too much repetition
	"((((((((((x{2}){2}){2}){2}){2}){2}){2}){2}){2}){2})",    // too much repetition
	strings.Repeat("(", 1000) + strings.Repeat(")", 1000),    // too deep
	strings.Repeat("(?:", 1000) + strings.Repeat(")*", 1000), // too deep
	"(" + strings.Repeat("(xx?)", 1000) + "){1000}",          // too long
	strings.Repeat("(xx?){1000}", 1000),                      // too long
	strings.Repeat(`\pL`, 27000),                             // too many runes
}

var onlyPerl = []string{
	`[a-b-c]`,
	`\Qabc\E`,
	`\Q*+?{[\E`,
	`\Q\\E`,
	`\Q\\\E`,
	`\Q\\\\E`,
	`\Q\\\\\E`,
	`(?:a)`,
	`(?P<name>a)`,
}

var onlyPOSIX = []string{
	"a++",
	"a**",
	"a?*",
	"a+*",
	"a{1}*",
	".{1}{2}.{3}",
}

func TestParseInvalidRegexps(t *testing.T) {
	for _, regexp := range invalidRegexps {
		if re, err := Parse(regexp, Perl); err == nil {
			t.Errorf("Parse(%#q, Perl) = %s, should have failed", regexp, dump(re))
		}
		if re, err := Parse(regexp, POSIX); err == nil {
			t.Errorf("Parse(%#q, POSIX) = %s, should have failed", regexp, dump(re))
		}
	}
	for _, regexp := range onlyPerl {
		if _, err := Parse(regexp, Perl); err != nil {
			t.Errorf("Parse(%#q, Perl): %v", regexp, err)
		}
		if re, err := Parse(regexp, POSIX); err == nil {
			t.Errorf("Parse(%#q, POSIX) = %s, should have failed", regexp, dump(re))
		}
	}
	for _, regexp := range onlyPOSIX {
		if re, err := Parse(regexp, Perl); err == nil {
			t.Errorf("Parse(%#q, Perl) = %s, should have failed", regexp, dump(re))
		}
		if _, err := Parse(regexp, POSIX); err != nil {
			t.Errorf("Parse(%#q, POSIX): %v", regexp, err)
		}
	}
}

func TestToStringEquivalentParse(t *testing.T) {
	for _, tt := range parseTests {
		re, err := Parse(tt.Regexp, testFlags)
		if err != nil {
			t.Errorf("Parse(%#q): %v", tt.Regexp, err)
			continue
		}
		if tt.Dump == "" {
			// It parsed. That's all we care about.
			continue
		}
		d := dump(re)
		if d != tt.Dump {
			t.Errorf("Parse(%#q).Dump() = %#q want %#q", tt.Regexp, d, tt.Dump)
			continue
		}

		s := re.String()
		if s != tt.Regexp {
			// If ToString didn't return the original regexp,
			// it must have found one with fewer parens.
			// Unfortunately we can't check the length here, because
			// ToString produces "\\{" for a literal brace,
			// but "{" is a shorter equivalent in some contexts.
			nre, err := Parse(s, testFlags)
			if err != nil {
				t.Errorf("Parse(%#q.String() = %#q): %v", tt.Regexp, s, err)
				continue
			}
			nd := dump(nre)
			if d != nd {
				t.Errorf("Parse(%#q) -> %#q; %#q vs %#q", tt.Regexp, s, d, nd)
			}

			ns := nre.String()
			if s != ns {
				t.Errorf("Parse(%#q) -> %#q -> %#q", tt.Regexp, s, ns)
			}
		}
	}
}

var stringTests = []struct {
	re  string
	out string
}{
	{`x(?i:ab*c|d?e)1`, `x(?i:AB*C|D?E)1`},
	{`x(?i:ab*cd?e)1`, `x(?i:AB*CD?E)1`},
	{`0(?i:ab*c|d?e)1`, `(?i:0(?:AB*C|D?E)1)`},
	{`0(?i:ab*cd?e)1`, `(?i:0AB*CD?E1)`},
	{`x(?i:ab*c|d?e)`, `x(?i:AB*C|D?E)`},
	{`x(?i:ab*cd?e)`, `x(?i:AB*CD?E)`},
	{`0(?i:ab*c|d?e)`, `(?i:0(?:AB*C|D?E))`},
	{`0(?i:ab*cd?e)`, `(?i:0AB*CD?E)`},
	{`(?i:ab*c|d?e)1`, `(?i:(?:AB*C|D?E)1)`},
	{`(?i:ab*cd?e)1`, `(?i:AB*CD?E1)`},
	{`(?i:ab)[123](?i:cd)`, `(?i:AB[1-3]CD)`},
	{`(?i:ab*c|d?e)`, `(?i:AB*C|D?E)`},
	{`[Aa][Bb]`, `(?i:AB)`},
	{`[Aa][Bb]*[Cc]`, `(?i:AB*C)`},
	{`A(?:[Bb][Cc]|[Dd])[Zz]`, `A(?i:(?:BC|D)Z)`},
	{`[Aa](?:[Bb][Cc]|[Dd])Z`, `(?i:A(?:BC|D))Z`},
}

func TestString(t *testing.T) {
	for _, tt := range stringTests {
		re, err := Parse(tt.re, Perl)
		if err != nil {
			t.Errorf("Parse(%#q): %v", tt.re, err)
			continue
		}
		out := re.String()
		if out != tt.out {
			t.Errorf("Parse(%#q).String() = %#q, want %#q", tt.re, out, tt.out)
		}
	}
}
```