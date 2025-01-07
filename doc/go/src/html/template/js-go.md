Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Understanding the Goal:**

The core request is to understand the functionality of the `js.go` file within the `html/template` package in Go. This immediately suggests it's related to safely embedding data within JavaScript contexts in HTML templates.

**2. Initial Scan and Keyword Identification:**

I'd start by quickly skimming the code, looking for prominent keywords and data structures. Some initial observations:

* **Package `template`:**  Confirms its role in HTML templating.
* **Constants (`jsWhitespace`):**  Indicates handling of whitespace in JavaScript.
* **Functions with "js" prefix (`nextJSCtx`, `jsValEscaper`, `jsStrEscaper`, etc.):**  Strongly suggests functions for JavaScript-specific escaping.
* **Data structures like `regexpPrecederKeywords` and various `ReplacementTable` variables:** Points to pre-defined rules and mappings for escaping.
* **Regular expressions (`scriptTagRe`):** Hints at sanitization or specific pattern matching.
* **`json` package usage (`json.Marshal`, `json.Marshaler`):** Implies handling of JSON data within JavaScript.
* **`reflect` package usage (`reflect.ValueOf`, `reflect.TypeFor`):** Suggests runtime type inspection and handling.

**3. Analyzing Key Functions and Data Structures:**

Now, I'd delve deeper into the most important functions and data structures.

* **`nextJSCtx(s []byte, preceding jsCtx) jsCtx`:** The comment is quite descriptive. It's about determining the context to differentiate between division operators and regular expressions. This is a nuanced aspect of JavaScript parsing. I'd note its role in preventing potential interpretation errors.

* **`regexpPrecederKeywords`:**  A simple map, but crucial for `nextJSCtx`. I'd understand its purpose in the lookbehind logic.

* **`jsValEscaper(args ...any) string`:** This looks like the core function for safely embedding Go values into JavaScript. The steps involved are key:
    * Handling `JS` and `JSStr` types directly (assuming they represent pre-escaped or specifically intended JavaScript strings).
    * Using `json.Marshal` as the primary mechanism.
    * Error handling with sanitization to prevent script injection within error messages.
    * Padding with spaces to avoid accidental comment creation.
    * Escaping Unicode line separators (`\u2028`, `\u2029`).

* **`jsStrEscaper(args ...any) string`:** Clearly for escaping strings to be placed *within* JavaScript string literals (single or double quotes). The different `replacementTable` variables (`jsStrReplacementTable`, `jsBqStrReplacementTable`, `jsStrNormReplacementTable`) indicate variations depending on the context (normal strings, template literals, etc.).

* **`jsRegexpEscaper(args ...any) string`:** Specifically for escaping strings that need to be treated literally within JavaScript regular expressions.

* **`replace(s string, replacementTable []string) string`:** A utility function used by the escapers. I'd note its purpose in applying the pre-defined replacements.

* **`isJSIdentPart(r rune) bool`:**  A helper function for `nextJSCtx` to identify parts of JavaScript identifiers.

* **`isJSType(mimeType string) bool`:** Determines if a given MIME type corresponds to JavaScript. This is relevant for `<script>` tag handling.

**4. Inferring the Overall Goal:**

By examining the individual components, the overall goal becomes clear:  **to provide functions that safely embed Go data into various JavaScript contexts within HTML templates, preventing script injection vulnerabilities and ensuring correct JavaScript parsing.**

**5. Generating Examples and Explanations:**

Based on the understanding of the functions, I would then construct examples. For instance, for `jsValEscaper`, showing how different Go types are marshaled to JSON and the error handling would be important. For `jsStrEscaper`, demonstrating the escaping of special characters within strings would be key.

**6. Identifying Potential Pitfalls:**

Thinking about how developers might misuse these functions leads to identifying common errors. For example, not understanding the different escaper functions and using the wrong one for a given context, or relying on manual string concatenation instead of using the provided escapers.

**7. Structuring the Answer:**

Finally, I would organize the information logically, starting with a summary of the file's purpose, then detailing each function's functionality with examples, and concluding with potential pitfalls. Using clear and concise language is essential. I would also make sure to explicitly address each point in the original request (functionality, Go feature implementation, code examples, command-line arguments (if applicable - in this case, not really), and common mistakes).

This iterative process of scanning, analyzing, inferring, and illustrating allows for a comprehensive understanding of the code and the generation of a helpful explanation. The key is to connect the individual pieces of code to the larger purpose of the file within the `html/template` package.
这段代码是 Go 语言 `html/template` 标准库中 `js.go` 文件的一部分。它的主要功能是提供一系列函数，用于**安全地将 Go 语言的数据嵌入到 HTML 模板中的 JavaScript 代码片段中**。 这些函数的主要目的是**防止跨站脚本攻击 (XSS)**。

更具体地说，它实现了以下功能：

1. **`nextJSCtx(s []byte, preceding jsCtx) jsCtx`**:  这是一个用于确定 JavaScript 代码上下文中下一个 token 是除法运算符还是正则表达式的辅助函数。它通过分析前一个 token 来做出判断，这对于某些边缘情况下的 JavaScript 语法解析非常重要。

2. **`jsValEscaper(args ...any) string`**:  这是最核心的函数之一，用于将 Go 的任意值（`any`）安全地转义为可以作为 JavaScript 表达式使用的字符串。它会处理各种 Go 数据类型，包括字符串、数字、布尔值、切片、映射等。它使用 `encoding/json` 包进行序列化，并对结果进行额外的转义，以确保生成的 JavaScript 代码不会引起语法错误或安全问题。

3. **`jsStrEscaper(args ...any) string`**:  此函数用于将 Go 的值转义为可以安全地放置在 JavaScript 字符串字面量（单引号或双引号）中的字符串。它会转义 JavaScript 字符串中的特殊字符，例如引号、反斜杠等。

4. **`jsTmplLitEscaper(args ...any) string`**: 此函数类似于 `jsStrEscaper`，但专门用于转义 JavaScript 模板字面量（用反引号 `` 包裹的字符串）中的特殊字符，包括 `${}` 等。

5. **`jsRegexpEscaper(args ...any) string`**:  此函数用于将 Go 的值转义为可以安全地放置在 JavaScript 正则表达式字面量 `/.../` 中的字符串。它会转义正则表达式中的特殊字符，确保插入的文本被视为字面值而不是正则表达式元字符。

6. **`replace(s string, replacementTable []string) string`**:  这是一个通用的字符串替换辅助函数，被其他转义函数使用。它根据提供的替换表，将字符串中的特定字符替换为指定的字符串。

7. **`isJSIdentPart(r rune) bool`**:  判断给定的 Unicode 字符是否可以作为 JavaScript 标识符的一部分。

8. **`isJSType(mimeType string) bool`**: 判断给定的 MIME 类型是否被认为是 JavaScript 的 MIME 类型。这主要用于判断 `<script>` 标签的 `type` 属性是否指定了 JavaScript。

**它是什么 Go 语言功能的实现？**

这段代码主要实现了 Go 语言 `html/template` 包中**针对 JavaScript 上下文的安全输出功能**。  `html/template` 允许开发者创建动态的 HTML 内容，而将数据安全地嵌入到 JavaScript 代码中是防止 XSS 攻击的关键部分。

**Go 代码举例说明：**

假设我们有一个 HTML 模板文件 `index.html`：

```html
<!DOCTYPE html>
<html>
<head>
    <title>模板示例</title>
</head>
<body>
    <script>
        var name = {{ .Name | js }};
        var items = {{ .Items | js }};
        console.log("Name:", name);
        console.log("Items:", items);
        var message = 'Hello, {{ .Message | jsstring }}!';
        console.log(message);
        var regex = /{{ .RegexPattern | jsregexp }}/;
        console.log(regex.test("abcdef"));
    </script>
</body>
</html>
```

以及以下 Go 代码：

```go
package main

import (
	"html/template"
	"net/http"
)

type Data struct {
	Name         string
	Items        []string
	Message      string
	RegexPattern string
}

func handler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("index.html"))
	data := Data{
		Name:         `O'Reilly`,
		Items:        []string{"apple", "banana", "orange"},
		Message:      `World <script>alert('XSS')</script>`,
		RegexPattern: `[a-z]+`,
	}
	tmpl.Execute(w, data)
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8080", nil)
}
```

**假设的输入与输出：**

当访问 `http://localhost:8080` 时，Go 代码会将 `data` 传递给模板进行渲染。

* **`.Name | js`**:  `jsValEscaper` 会将字符串 `O'Reilly` 转义为有效的 JavaScript 字符串字面量。 输出： `"O'Reilly"`
* **`.Items | js`**: `jsValEscaper` 会将字符串切片转义为 JavaScript 数组。 输出： `["apple","banana","orange"]`
* **`.Message | jsstring`**: `jsStrEscaper` 会将包含潜在 XSS 攻击的字符串转义为安全的 JavaScript字符串。 输出： `'World \u003cscript\u003ealert(\'XSS\')\u003c/script\u003e'`
* **`.RegexPattern | jsregexp`**: `jsRegexpEscaper` 会将正则表达式模式转义为可以在 JavaScript 正则表达式中安全使用的字符串。 输出： `[a-z]+`

最终生成的 HTML 中的 `<script>` 标签内容将类似于：

```html
<script>
    var name = "O'Reilly";
    var items = ["apple","banana","orange"];
    console.log("Name:", name);
    console.log("Items:", items);
    var message = 'World \u003cscript\u003ealert(\'XSS\')\u003c/script\u003e!';
    console.log(message);
    var regex = /[a-z]+/;
    console.log(regex.test("abcdef"));
</script>
```

**代码推理：**

* `jsValEscaper` 首先检查输入是否已经是 `JS` 或 `JSStr` 类型，如果是则直接使用（假设这些类型已经经过安全处理）。
* 否则，它尝试将输入作为 `json.Marshaler` 或 `fmt.Stringer` 处理。
* 最终，它使用 `json.Marshal` 将数据序列化为 JSON 字符串。
* 序列化后的 JSON 字符串会经过进一步处理，例如替换特定的 Unicode 行分隔符 (`\u2028`, `\u2029`)，并添加空格以避免与 JavaScript 运算符意外结合。
* 如果 `json.Marshal` 发生错误，它会生成一个包含错误信息的 JavaScript 注释，并返回 `null`，同时对错误信息进行转义以防止破坏脚本。
* `jsStrEscaper` 和其他专门的转义函数使用预定义的替换表来替换 JavaScript 中的特殊字符。例如，`jsStrReplacementTable` 会将 `<`, `>` 等 HTML 特殊字符转义为 Unicode 编码，以防止它们被浏览器解析为 HTML 标签。

**命令行参数的具体处理：**

这段代码本身并不直接处理命令行参数。它属于 `html/template` 库的一部分，主要用于在 Go 程序中进行 HTML 模板的渲染。命令行参数的处理通常发生在调用此库的 Go 应用程序中。

**使用者易犯错的点：**

使用者在使用 `html/template` 时，最容易犯的错误是**不理解不同转义函数的用途，并在错误的上下文中使用它们**，或者**忘记进行转义**。

**例子：**

1. **在 JavaScript 字符串字面量中使用 `js` 而不是 `jsstring`：**

   ```html
   <script>
       var message = "{{ .UntrustedInput | js }}"; // 错误！
   </script>
   ```

   如果 `.UntrustedInput` 包含引号或其他 JavaScript 特殊字符，这可能会导致语法错误或安全漏洞。应该使用 `jsstring`：

   ```html
   <script>
       var message = "{{ .UntrustedInput | jsstring }}"; // 正确
   </script>
   ```

2. **在 JavaScript 正则表达式中使用 `js` 而不是 `jsregexp`：**

   ```html
   <script>
       var pattern = /{{ .Regex }}/; // 错误！
   </script>
   ```

   如果 `.Regex` 包含正则表达式的元字符（如 `.`、`*` 等），这会导致正则表达式的行为与预期不符。应该使用 `jsregexp`：

   ```html
   <script>
       var pattern = /{{ .Regex | jsregexp }}/; // 正确
   </script>
   ```

3. **忘记对用户输入进行转义：**

   ```html
   <script>
       var userInput = '{{ .UserInput }}'; // 危险！
   </script>
   ```

   如果 `.UserInput` 来自用户输入，并且没有经过任何转义，那么恶意用户可以注入 JavaScript 代码，导致 XSS 攻击。应该使用适当的转义函数，例如 `jsstring`：

   ```html
   <script>
       var userInput = '{{ .UserInput | jsstring }}'; // 相对安全
   </script>
   ```

总而言之，`go/src/html/template/js.go` 的核心功能是提供必要的工具，以确保在 Go 语言的 HTML 模板中嵌入 JavaScript 代码时，能够有效地防止安全漏洞，特别是 XSS 攻击。理解每个转义函数的用途并正确使用它们是至关重要的。

Prompt: 
```
这是路径为go/src/html/template/js.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package template

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"unicode/utf8"
)

// jsWhitespace contains all of the JS whitespace characters, as defined
// by the \s character class.
// See https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Regular_expressions/Character_classes.
const jsWhitespace = "\f\n\r\t\v\u0020\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"

// nextJSCtx returns the context that determines whether a slash after the
// given run of tokens starts a regular expression instead of a division
// operator: / or /=.
//
// This assumes that the token run does not include any string tokens, comment
// tokens, regular expression literal tokens, or division operators.
//
// This fails on some valid but nonsensical JavaScript programs like
// "x = ++/foo/i" which is quite different than "x++/foo/i", but is not known to
// fail on any known useful programs. It is based on the draft
// JavaScript 2.0 lexical grammar and requires one token of lookbehind:
// https://www.mozilla.org/js/language/js20-2000-07/rationale/syntax.html
func nextJSCtx(s []byte, preceding jsCtx) jsCtx {
	// Trim all JS whitespace characters
	s = bytes.TrimRight(s, jsWhitespace)
	if len(s) == 0 {
		return preceding
	}

	// All cases below are in the single-byte UTF-8 group.
	switch c, n := s[len(s)-1], len(s); c {
	case '+', '-':
		// ++ and -- are not regexp preceders, but + and - are whether
		// they are used as infix or prefix operators.
		start := n - 1
		// Count the number of adjacent dashes or pluses.
		for start > 0 && s[start-1] == c {
			start--
		}
		if (n-start)&1 == 1 {
			// Reached for trailing minus signs since "---" is the
			// same as "-- -".
			return jsCtxRegexp
		}
		return jsCtxDivOp
	case '.':
		// Handle "42."
		if n != 1 && '0' <= s[n-2] && s[n-2] <= '9' {
			return jsCtxDivOp
		}
		return jsCtxRegexp
	// Suffixes for all punctuators from section 7.7 of the language spec
	// that only end binary operators not handled above.
	case ',', '<', '>', '=', '*', '%', '&', '|', '^', '?':
		return jsCtxRegexp
	// Suffixes for all punctuators from section 7.7 of the language spec
	// that are prefix operators not handled above.
	case '!', '~':
		return jsCtxRegexp
	// Matches all the punctuators from section 7.7 of the language spec
	// that are open brackets not handled above.
	case '(', '[':
		return jsCtxRegexp
	// Matches all the punctuators from section 7.7 of the language spec
	// that precede expression starts.
	case ':', ';', '{':
		return jsCtxRegexp
	// CAVEAT: the close punctuators ('}', ']', ')') precede div ops and
	// are handled in the default except for '}' which can precede a
	// division op as in
	//    ({ valueOf: function () { return 42 } } / 2
	// which is valid, but, in practice, developers don't divide object
	// literals, so our heuristic works well for code like
	//    function () { ... }  /foo/.test(x) && sideEffect();
	// The ')' punctuator can precede a regular expression as in
	//     if (b) /foo/.test(x) && ...
	// but this is much less likely than
	//     (a + b) / c
	case '}':
		return jsCtxRegexp
	default:
		// Look for an IdentifierName and see if it is a keyword that
		// can precede a regular expression.
		j := n
		for j > 0 && isJSIdentPart(rune(s[j-1])) {
			j--
		}
		if regexpPrecederKeywords[string(s[j:])] {
			return jsCtxRegexp
		}
	}
	// Otherwise is a punctuator not listed above, or
	// a string which precedes a div op, or an identifier
	// which precedes a div op.
	return jsCtxDivOp
}

// regexpPrecederKeywords is a set of reserved JS keywords that can precede a
// regular expression in JS source.
var regexpPrecederKeywords = map[string]bool{
	"break":      true,
	"case":       true,
	"continue":   true,
	"delete":     true,
	"do":         true,
	"else":       true,
	"finally":    true,
	"in":         true,
	"instanceof": true,
	"return":     true,
	"throw":      true,
	"try":        true,
	"typeof":     true,
	"void":       true,
}

var jsonMarshalType = reflect.TypeFor[json.Marshaler]()

// indirectToJSONMarshaler returns the value, after dereferencing as many times
// as necessary to reach the base type (or nil) or an implementation of json.Marshal.
func indirectToJSONMarshaler(a any) any {
	// text/template now supports passing untyped nil as a func call
	// argument, so we must support it. Otherwise we'd panic below, as one
	// cannot call the Type or Interface methods on an invalid
	// reflect.Value. See golang.org/issue/18716.
	if a == nil {
		return nil
	}

	v := reflect.ValueOf(a)
	for !v.Type().Implements(jsonMarshalType) && v.Kind() == reflect.Pointer && !v.IsNil() {
		v = v.Elem()
	}
	return v.Interface()
}

var scriptTagRe = regexp.MustCompile("(?i)<(/?)script")

// jsValEscaper escapes its inputs to a JS Expression (section 11.14) that has
// neither side-effects nor free variables outside (NaN, Infinity).
func jsValEscaper(args ...any) string {
	var a any
	if len(args) == 1 {
		a = indirectToJSONMarshaler(args[0])
		switch t := a.(type) {
		case JS:
			return string(t)
		case JSStr:
			// TODO: normalize quotes.
			return `"` + string(t) + `"`
		case json.Marshaler:
			// Do not treat as a Stringer.
		case fmt.Stringer:
			a = t.String()
		}
	} else {
		for i, arg := range args {
			args[i] = indirectToJSONMarshaler(arg)
		}
		a = fmt.Sprint(args...)
	}
	// TODO: detect cycles before calling Marshal which loops infinitely on
	// cyclic data. This may be an unacceptable DoS risk.
	b, err := json.Marshal(a)
	if err != nil {
		// While the standard JSON marshaler does not include user controlled
		// information in the error message, if a type has a MarshalJSON method,
		// the content of the error message is not guaranteed. Since we insert
		// the error into the template, as part of a comment, we attempt to
		// prevent the error from either terminating the comment, or the script
		// block itself.
		//
		// In particular we:
		//   * replace "*/" comment end tokens with "* /", which does not
		//     terminate the comment
		//   * replace "<script" and "</script" with "\x3Cscript" and "\x3C/script"
		//     (case insensitively), and "<!--" with "\x3C!--", which prevents
		//     confusing script block termination semantics
		//
		// We also put a space before the comment so that if it is flush against
		// a division operator it is not turned into a line comment:
		//     x/{{y}}
		// turning into
		//     x//* error marshaling y:
		//          second line of error message */null
		errStr := err.Error()
		errStr = string(scriptTagRe.ReplaceAll([]byte(errStr), []byte(`\x3C${1}script`)))
		errStr = strings.ReplaceAll(errStr, "*/", "* /")
		errStr = strings.ReplaceAll(errStr, "<!--", `\x3C!--`)
		return fmt.Sprintf(" /* %s */null ", errStr)
	}

	// TODO: maybe post-process output to prevent it from containing
	// "<!--", "-->", "<![CDATA[", "]]>", or "</script"
	// in case custom marshalers produce output containing those.
	// Note: Do not use \x escaping to save bytes because it is not JSON compatible and this escaper
	// supports ld+json content-type.
	if len(b) == 0 {
		// In, `x=y/{{.}}*z` a json.Marshaler that produces "" should
		// not cause the output `x=y/*z`.
		return " null "
	}
	first, _ := utf8.DecodeRune(b)
	last, _ := utf8.DecodeLastRune(b)
	var buf strings.Builder
	// Prevent IdentifierNames and NumericLiterals from running into
	// keywords: in, instanceof, typeof, void
	pad := isJSIdentPart(first) || isJSIdentPart(last)
	if pad {
		buf.WriteByte(' ')
	}
	written := 0
	// Make sure that json.Marshal escapes codepoints U+2028 & U+2029
	// so it falls within the subset of JSON which is valid JS.
	for i := 0; i < len(b); {
		rune, n := utf8.DecodeRune(b[i:])
		repl := ""
		if rune == 0x2028 {
			repl = `\u2028`
		} else if rune == 0x2029 {
			repl = `\u2029`
		}
		if repl != "" {
			buf.Write(b[written:i])
			buf.WriteString(repl)
			written = i + n
		}
		i += n
	}
	if buf.Len() != 0 {
		buf.Write(b[written:])
		if pad {
			buf.WriteByte(' ')
		}
		return buf.String()
	}
	return string(b)
}

// jsStrEscaper produces a string that can be included between quotes in
// JavaScript source, in JavaScript embedded in an HTML5 <script> element,
// or in an HTML5 event handler attribute such as onclick.
func jsStrEscaper(args ...any) string {
	s, t := stringify(args...)
	if t == contentTypeJSStr {
		return replace(s, jsStrNormReplacementTable)
	}
	return replace(s, jsStrReplacementTable)
}

func jsTmplLitEscaper(args ...any) string {
	s, _ := stringify(args...)
	return replace(s, jsBqStrReplacementTable)
}

// jsRegexpEscaper behaves like jsStrEscaper but escapes regular expression
// specials so the result is treated literally when included in a regular
// expression literal. /foo{{.X}}bar/ matches the string "foo" followed by
// the literal text of {{.X}} followed by the string "bar".
func jsRegexpEscaper(args ...any) string {
	s, _ := stringify(args...)
	s = replace(s, jsRegexpReplacementTable)
	if s == "" {
		// /{{.X}}/ should not produce a line comment when .X == "".
		return "(?:)"
	}
	return s
}

// replace replaces each rune r of s with replacementTable[r], provided that
// r < len(replacementTable). If replacementTable[r] is the empty string then
// no replacement is made.
// It also replaces runes U+2028 and U+2029 with the raw strings `\u2028` and
// `\u2029`.
func replace(s string, replacementTable []string) string {
	var b strings.Builder
	r, w, written := rune(0), 0, 0
	for i := 0; i < len(s); i += w {
		// See comment in htmlEscaper.
		r, w = utf8.DecodeRuneInString(s[i:])
		var repl string
		switch {
		case int(r) < len(lowUnicodeReplacementTable):
			repl = lowUnicodeReplacementTable[r]
		case int(r) < len(replacementTable) && replacementTable[r] != "":
			repl = replacementTable[r]
		case r == '\u2028':
			repl = `\u2028`
		case r == '\u2029':
			repl = `\u2029`
		default:
			continue
		}
		if written == 0 {
			b.Grow(len(s))
		}
		b.WriteString(s[written:i])
		b.WriteString(repl)
		written = i + w
	}
	if written == 0 {
		return s
	}
	b.WriteString(s[written:])
	return b.String()
}

var lowUnicodeReplacementTable = []string{
	0: `\u0000`, 1: `\u0001`, 2: `\u0002`, 3: `\u0003`, 4: `\u0004`, 5: `\u0005`, 6: `\u0006`,
	'\a': `\u0007`,
	'\b': `\u0008`,
	'\t': `\t`,
	'\n': `\n`,
	'\v': `\u000b`, // "\v" == "v" on IE 6.
	'\f': `\f`,
	'\r': `\r`,
	0xe:  `\u000e`, 0xf: `\u000f`, 0x10: `\u0010`, 0x11: `\u0011`, 0x12: `\u0012`, 0x13: `\u0013`,
	0x14: `\u0014`, 0x15: `\u0015`, 0x16: `\u0016`, 0x17: `\u0017`, 0x18: `\u0018`, 0x19: `\u0019`,
	0x1a: `\u001a`, 0x1b: `\u001b`, 0x1c: `\u001c`, 0x1d: `\u001d`, 0x1e: `\u001e`, 0x1f: `\u001f`,
}

var jsStrReplacementTable = []string{
	0:    `\u0000`,
	'\t': `\t`,
	'\n': `\n`,
	'\v': `\u000b`, // "\v" == "v" on IE 6.
	'\f': `\f`,
	'\r': `\r`,
	// Encode HTML specials as hex so the output can be embedded
	// in HTML attributes without further encoding.
	'"':  `\u0022`,
	'`':  `\u0060`,
	'&':  `\u0026`,
	'\'': `\u0027`,
	'+':  `\u002b`,
	'/':  `\/`,
	'<':  `\u003c`,
	'>':  `\u003e`,
	'\\': `\\`,
}

// jsBqStrReplacementTable is like jsStrReplacementTable except it also contains
// the special characters for JS template literals: $, {, and }.
var jsBqStrReplacementTable = []string{
	0:    `\u0000`,
	'\t': `\t`,
	'\n': `\n`,
	'\v': `\u000b`, // "\v" == "v" on IE 6.
	'\f': `\f`,
	'\r': `\r`,
	// Encode HTML specials as hex so the output can be embedded
	// in HTML attributes without further encoding.
	'"':  `\u0022`,
	'`':  `\u0060`,
	'&':  `\u0026`,
	'\'': `\u0027`,
	'+':  `\u002b`,
	'/':  `\/`,
	'<':  `\u003c`,
	'>':  `\u003e`,
	'\\': `\\`,
	'$':  `\u0024`,
	'{':  `\u007b`,
	'}':  `\u007d`,
}

// jsStrNormReplacementTable is like jsStrReplacementTable but does not
// overencode existing escapes since this table has no entry for `\`.
var jsStrNormReplacementTable = []string{
	0:    `\u0000`,
	'\t': `\t`,
	'\n': `\n`,
	'\v': `\u000b`, // "\v" == "v" on IE 6.
	'\f': `\f`,
	'\r': `\r`,
	// Encode HTML specials as hex so the output can be embedded
	// in HTML attributes without further encoding.
	'"':  `\u0022`,
	'&':  `\u0026`,
	'\'': `\u0027`,
	'`':  `\u0060`,
	'+':  `\u002b`,
	'/':  `\/`,
	'<':  `\u003c`,
	'>':  `\u003e`,
}
var jsRegexpReplacementTable = []string{
	0:    `\u0000`,
	'\t': `\t`,
	'\n': `\n`,
	'\v': `\u000b`, // "\v" == "v" on IE 6.
	'\f': `\f`,
	'\r': `\r`,
	// Encode HTML specials as hex so the output can be embedded
	// in HTML attributes without further encoding.
	'"':  `\u0022`,
	'$':  `\$`,
	'&':  `\u0026`,
	'\'': `\u0027`,
	'(':  `\(`,
	')':  `\)`,
	'*':  `\*`,
	'+':  `\u002b`,
	'-':  `\-`,
	'.':  `\.`,
	'/':  `\/`,
	'<':  `\u003c`,
	'>':  `\u003e`,
	'?':  `\?`,
	'[':  `\[`,
	'\\': `\\`,
	']':  `\]`,
	'^':  `\^`,
	'{':  `\{`,
	'|':  `\|`,
	'}':  `\}`,
}

// isJSIdentPart reports whether the given rune is a JS identifier part.
// It does not handle all the non-Latin letters, joiners, and combining marks,
// but it does handle every codepoint that can occur in a numeric literal or
// a keyword.
func isJSIdentPart(r rune) bool {
	switch {
	case r == '$':
		return true
	case '0' <= r && r <= '9':
		return true
	case 'A' <= r && r <= 'Z':
		return true
	case r == '_':
		return true
	case 'a' <= r && r <= 'z':
		return true
	}
	return false
}

// isJSType reports whether the given MIME type should be considered JavaScript.
//
// It is used to determine whether a script tag with a type attribute is a javascript container.
func isJSType(mimeType string) bool {
	// per
	//   https://www.w3.org/TR/html5/scripting-1.html#attr-script-type
	//   https://tools.ietf.org/html/rfc7231#section-3.1.1
	//   https://tools.ietf.org/html/rfc4329#section-3
	//   https://www.ietf.org/rfc/rfc4627.txt
	// discard parameters
	mimeType, _, _ = strings.Cut(mimeType, ";")
	mimeType = strings.ToLower(mimeType)
	mimeType = strings.TrimSpace(mimeType)
	switch mimeType {
	case
		"application/ecmascript",
		"application/javascript",
		"application/json",
		"application/ld+json",
		"application/x-ecmascript",
		"application/x-javascript",
		"module",
		"text/ecmascript",
		"text/javascript",
		"text/javascript1.0",
		"text/javascript1.1",
		"text/javascript1.2",
		"text/javascript1.3",
		"text/javascript1.4",
		"text/javascript1.5",
		"text/jscript",
		"text/livescript",
		"text/x-ecmascript",
		"text/x-javascript":
		return true
	default:
		return false
	}
}

"""



```