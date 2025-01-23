Response:
Let's break down the thought process for analyzing the Go code snippet.

**1. Understanding the Request:**

The core request is to understand the functionality of the provided Go code, specifically the `transition.go` file from the `html/template` package. The request asks for:

* Listing the functions performed by the code.
* Inferring the broader Go functionality it supports.
* Providing Go code examples (with input/output assumptions) if code inference is involved.
* Explaining command-line parameter handling (if applicable).
* Identifying common mistakes users might make.
* Answering in Chinese.

**2. Initial Code Scan and Identification of Key Elements:**

The first step is a quick scan of the code to identify its major components. I noticed:

* **Package Declaration:** `package template` immediately tells me this code belongs to the Go template engine.
* **Imports:** `bytes` and `strings` suggest the code manipulates byte slices and strings.
* **`transitionFunc`:** This is a crucial variable. It's an array of functions. The function signature `func(context, []byte) (context, int)` strongly hints at a state machine or a process that consumes input and updates its internal state. The keys of the array (`stateText`, `stateTag`, etc.) appear to be different states.
* **State Constants:**  The presence of constants like `stateText`, `stateTag` (used as array indices in `transitionFunc`) reinforces the state machine idea.
* **Individual `tXxx` Functions:** Functions like `tText`, `tTag`, `tAttrName` etc., correspond directly to the states in `transitionFunc`. This confirms the state machine pattern.
* **`context` struct:** Although not shown in the provided snippet, the parameter `context` in the transition functions implies a structure holding the current parsing state.
* **Helper Functions:** Functions like `eatTagName`, `eatWhiteSpace`, `eatAttrName` suggest lexical analysis or parsing of HTML-like structures.
* **Special Tag Handling:** Variables like `commentStart`, `commentEnd`, `specialTagEndMarkers`, and the `tSpecialTagEnd` function point to specific handling for HTML comments and special tags (`<script>`, `<style>`, etc.).

**3. Deducing the Core Functionality:**

Based on the identified elements, the central functionality becomes clear:

* **HTML Parsing/Lexing:** The code is responsible for processing HTML text. It needs to identify different parts of the HTML structure: tags, attributes, content, comments, etc.
* **Contextual Awareness:** The state machine approach, particularly the `context` parameter, indicates that the parsing is context-sensitive. The interpretation of certain sequences (like `<script>`) depends on the current parsing state.
* **Security Considerations (Implicit):** The existence of distinct states for `<script>` and `<style>` and the handling of URLs and JavaScript suggest that this code is likely related to preventing cross-site scripting (XSS) vulnerabilities. Template engines often need to escape or sanitize output based on the context to ensure security.

**4. Constructing the Explanation:**

Now, the task is to organize the findings into a coherent explanation in Chinese, following the prompt's requirements.

* **Listing Functions:**  I systematically listed the roles of `transitionFunc` and the individual `tXxx` functions.
* **Inferring Go Functionality:** I connected the code to the `html/template` package and explained its purpose in parsing HTML templates, highlighting the state machine and context-sensitive nature.
* **Providing Go Code Examples:**  This requires choosing relevant states and demonstrating how the transition functions might work. I selected `tText` and `tTag` as they represent fundamental HTML parsing. I crafted simple HTML input strings and explained the expected state transitions and consumed byte counts. I had to make assumptions about the internal structure of the `context` struct, focusing on the `state` and `element` fields as they were used in the provided code.
* **Command-Line Parameters:** I correctly identified that this specific code snippet does *not* directly handle command-line parameters. This is important to state explicitly.
* **Common Mistakes:** I focused on potential errors related to unclosed tags or incorrect attribute syntax, as these are common issues when working with HTML and are directly relevant to the parsing logic.
* **Language:** I ensured the explanation was in clear and concise Chinese.

**5. Refinement and Double-Checking:**

Finally, I reread the explanation to ensure accuracy, clarity, and completeness, making sure it addressed all aspects of the original request. I double-checked the Go code examples for correctness and that the assumed inputs and outputs made sense in the context of HTML parsing.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** Maybe this is just about syntax highlighting?  **Correction:** The state machine and the focus on different content types (JS, CSS) suggest a deeper purpose than simple syntax highlighting. It's likely related to security and correct rendering of dynamic content.
* **Uncertainty about `context`:** I didn't have the full definition of the `context` struct. **Solution:**  I focused on the fields explicitly used in the provided code (`state`, `element`, etc.) and made reasonable assumptions about their purpose. I acknowledged this limitation in my explanation by saying "假设 context 结构体包含..." (assuming the context struct contains...).
* **Over-complicating examples:** I initially thought about more complex HTML structures for the examples. **Correction:** I realized that simpler examples would be more effective in illustrating the basic functionality of the transition functions.

This iterative process of scanning, deducing, constructing, and refining allows for a comprehensive understanding and explanation of the code snippet.
这段代码是 Go 语言 `html/template` 包中用于处理 HTML 模板状态转换逻辑的一部分。它定义了一系列函数，用于在解析 HTML 模板时，根据当前的解析状态和读取到的字符，来确定下一个解析状态。这对于正确地理解和转义模板中的内容至关重要，特别是当模板中包含 JavaScript、CSS 或 URL 等需要特殊处理的内容时。

**主要功能：**

1. **定义状态转换函数：** `transitionFunc` 是一个函数数组，每个函数对应一个解析状态（例如，`stateText` 表示在纯文本中，`stateTag` 表示在标签内）。这些函数接收当前的状态和输入的字节切片，并返回新的状态和消耗的字节数。
2. **文本状态处理 (`tText`)：**  负责处理纯文本状态。它会查找 `<` 字符，并判断是否为 HTML 注释 `<!--` 或标签的开始。如果是标签开始，则会进一步解析标签名，并转换到 `stateTag` 状态。
3. **标签状态处理 (`tTag`)：**  负责处理标签内的内容。它会查找属性名，并根据属性名（例如 `type` 为 `script`）和标签名来决定后续的状态。例如，如果发现 `type="text/javascript"`，可能会转换到 `stateJS` 状态。
4. **属性名状态处理 (`tAttrName`)：**  处理属性名的读取。
5. **属性名后状态处理 (`tAfterName`)：**  处理属性名后的空格或等号。
6. **属性值前状态处理 (`tBeforeValue`)：**  处理属性值前的空格和引号。
7. **HTML 注释状态处理 (`tHTMLCmt`)：**  跳过 HTML 注释的内容直到 `-->`。
8. **特殊标签内容结束处理 (`tSpecialTagEnd`)：**  用于处理 `script`、`style`、`textarea` 和 `title` 等特殊标签的内容结束标记，例如 `</script>`。它会忽略脚本字面量或注释内的结束标签。
9. **属性值状态处理 (`tAttr`)：**  处理普通的属性值。
10. **URL 状态处理 (`tURL`)：**  处理 URL 类型的属性值，例如 `href` 或 `src`。它会识别 URL 的不同部分（例如查询参数或片段）。
11. **JavaScript 状态处理 (`tJS`)：**  处理 `<script>` 标签内的 JavaScript 代码。它会识别字符串、注释、正则表达式等，并相应地转换状态。
12. **JavaScript 字符串和正则表达式状态处理 (`tJSDelimited`)：**  处理 JavaScript 的单引号字符串、双引号字符串和正则表达式。
13. **JavaScript 模板字面量状态处理 (`tJSTmpl`)：** 处理 JavaScript 的模板字面量 (backtick string)。
14. **块注释状态处理 (`tBlockCmt`)：**  处理 `/* ... */` 形式的块注释。
15. **行注释状态处理 (`tLineCmt`)：**  处理 `// ...` 形式的行注释，以及 JavaScript 中的 HTML 风格注释 `<!-- ...` 和 `-->`。
16. **CSS 状态处理 (`tCSS`)：**  处理 `<style>` 标签内的 CSS 代码。它会识别字符串、URL、注释等。
17. **CSS 字符串和 URL 状态处理 (`tCSSStr`)：**  处理 CSS 的单引号字符串、双引号字符串和 `url()` 中的内容。
18. **错误状态处理 (`tError`)：**  当遇到解析错误时，会进入这个状态。
19. **辅助函数：**  `eatAttrName` 用于提取属性名，`eatTagName` 用于提取标签名，`eatWhiteSpace` 用于跳过空白字符。

**推断 Go 语言功能实现：HTML 模板解析器的状态机**

这段代码是 HTML 模板解析器实现的核心部分，它使用**状态机**模式来解析 HTML 结构。  解析器在不同的状态之间转换，每个状态定义了如何处理当前的输入。 这种方法使得解析器能够理解 HTML 的嵌套结构和不同类型的上下文（例如，在 `<script>` 标签内和在属性值内有不同的解析规则）。

**Go 代码举例：**

假设我们有以下简单的 HTML 片段：

```html
<div id="myId">Hello, <script>var name = "World";</script></div>
```

解析器会按照以下步骤进行（简化）：

1. **初始状态：`stateText`**
   - 输入："<div id="myId">Hello, <script>var name = "World";</script></div>"
   - `tText` 函数会被调用。
   - `tText` 识别到 `<`，判断是标签开始。
   - 输出：状态 `stateTag`，消耗字节数（直到 `<script` 的 `<`）。
   - 假设输入为 "<div>"，输出可能是：状态 `{state: stateTag, element: elementNone}`，消耗字节数 5。

2. **状态：`stateTag`**
   - 输入："div id=\"myId\">Hello, <script>var name = \"World\";</script></div>" (从 "id" 开始)
   - `tTag` 函数会被调用。
   - `tTag` 识别到属性名 "id"。
   - 输出：状态 `stateAfterName`，消耗字节数（直到 "id" 结束）。
   - 假设输入为 "id"，输出可能是：状态 `{state: stateAfterName, element: elementNone, attr: attrNone}`，消耗字节数 2。

3. **状态：`stateAfterName`**
   - 输入："=\"myId\">Hello, <script>var name = \"World\";</script></div>" (从 "=" 开始)
   - `tAfterName` 函数会被调用。
   - `tAfterName` 识别到 `=`。
   - 输出：状态 `stateBeforeValue`，消耗字节数 1。

4. **状态：`stateBeforeValue`**
   - 输入："\"myId\">Hello, <script>var name = \"World\";</script></div>" (从 `"` 开始)
   - `tBeforeValue` 函数会被调用。
   - `tBeforeValue` 识别到双引号。
   - 输出：状态 `stateAttr`，消耗字节数 1。

5. **状态：`stateAttr`**
   - 输入："myId\">Hello, <script>var name = \"World\";</script></div>" (从 "m" 开始)
   - `tAttr` 函数会被调用。
   - `tAttr` 处理属性值 "myId"。
   - 输出：状态 `stateTag` (假设遇到 `>` )，消耗字节数 (直到 `>` )。

6. **状态：`stateTag`**
   - 输入：">Hello, <script>var name = \"World\";</script></div>" (从 `>` 开始)
   - `tTag` 函数会被调用。
   - `tTag` 识别到 `>`，表示标签结束。
   - 输出：状态 `stateText`，消耗字节数 1。

7. **状态：`stateText`**
   - 输入："Hello, <script>var name = \"World\";</script></div>" (从 "H" 开始)
   - `tText` 函数会被调用。
   - `tText` 处理文本 "Hello, "，直到遇到 `<`。
   - 输出：状态 `stateTag`，消耗字节数（直到 `<script` 的 `<`）。

8. **状态：`stateTag`**
   - 输入："script>var name = \"World\";</script></div>" (从 "script" 开始)
   - `tTag` 函数会被调用。
   - `tTag` 识别到标签名 "script"。
   - 输出：状态 `stateJS`，消耗字节数（直到 `>`）。

9. **状态：`stateJS`**
   - 输入："var name = \"World\";</script></div>"
   - `tJS` 函数会被调用。
   - `tJS` 处理 JavaScript 代码，直到遇到 `</script>`。
   - 输出：状态 `stateText` (遇到 `</script>`)，消耗字节数（直到 `</script>` 的 `<`）。

10. **后续状态：**  继续类似的过程处理剩余的 HTML。

**假设的输入与输出：**

```go
package main

import (
	"fmt"
	"html/template"
)

func main() {
	input := []byte("<p>Hello</p>")
	c := template.Context{State: template.StateText} // 假设初始状态为文本

	nextC, consumed := template.TransitionFunc[c.State](c, input)
	fmt.Printf("初始状态: %s, 输入: %q\n", c.State, string(input))
	fmt.Printf("下一个状态: %s, 消耗字节数: %d\n", nextC.State, consumed)

	// 假设 context 结构体包含 State 字段
	c.State = nextC.State
	input = input[consumed:]
	if len(input) > 0 {
		nextC, consumed = template.TransitionFunc[c.State](c, input)
		fmt.Printf("当前状态: %s, 输入: %q\n", c.State, string(input))
		fmt.Printf("下一个状态: %s, 消耗字节数: %d\n", nextC.State, consumed)
	}
}
```

**假设的输出：**

```
初始状态: text, 输入: "<p>Hello</p>"
下一个状态: tag, 消耗字节数: 1
当前状态: tag, 输入: "p>Hello</p>"
下一个状态: text, 消耗字节数: 2
```

**命令行参数的具体处理：**

这段代码本身不直接处理命令行参数。`html/template` 包通常在 Go 代码中被调用，模板内容可以从字符串、文件或其他数据源加载。命令行参数的处理通常发生在调用 `html/template` 包的应用程序代码中，而不是在 `transition.go` 这样的底层实现中。

**使用者易犯错的点：**

虽然这段代码是模板引擎的内部实现，普通使用者不会直接操作它，但理解其背后的原理有助于避免在使用模板时犯错：

1. **未正确闭合标签：**  如果 HTML 标签未正确闭合，解析器可能会进入错误的状态，导致渲染结果不符合预期。例如，`<script>var x = 1;` 没有 `</script>` 结束标签，会导致后续内容被当作 JavaScript 处理。

2. **在 `<script>` 或 `<style>` 标签中直接插入未转义的 HTML：**  例如，在 `<script>` 标签中插入包含 `<` 或 `>` 的字符串，如果没有进行适当的 JavaScript 字符串转义，可能会导致解析错误。模板引擎通常会根据上下文自动转义，但开发者需要理解这种机制，避免手动插入可能破坏上下文的代码。

3. **URL 属性值未正确处理：**  在 URL 属性中直接拼接用户输入，而没有进行 URL 编码，可能会导致安全漏洞（例如，XSS）。模板引擎在处理 URL 上下文时会进行一些转义，但开发者仍然需要注意。

**举例说明未正确闭合标签可能导致的问题：**

假设模板内容为：

```html
<div>
  <p>这是一个段落
  <script>
    console.log("Hello");
```

由于 `<p>` 标签没有正确闭合，解析器在遇到 `<script>` 时可能仍然认为它在 `div` 标签的内部，而 `<script>` 标签的内容会被错误地嵌套处理。这可能会导致 JavaScript 代码无法执行或产生意外的渲染结果。

总结来说，`transition.go` 文件是 Go 语言 `html/template` 包实现 HTML 模板安全且正确解析的关键部分。它通过状态机的方式，根据不同的上下文状态应用不同的解析规则，确保模板中的各种内容（文本、标签、属性、JavaScript、CSS 等）得到正确的处理和转义。理解其工作原理可以帮助开发者更好地使用模板引擎，并避免一些常见的错误。

### 提示词
```
这是路径为go/src/html/template/transition.go的go语言实现的一部分， 请列举一下它的功能, 　
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

package template

import (
	"bytes"
	"strings"
)

// transitionFunc is the array of context transition functions for text nodes.
// A transition function takes a context and template text input, and returns
// the updated context and the number of bytes consumed from the front of the
// input.
var transitionFunc = [...]func(context, []byte) (context, int){
	stateText:           tText,
	stateTag:            tTag,
	stateAttrName:       tAttrName,
	stateAfterName:      tAfterName,
	stateBeforeValue:    tBeforeValue,
	stateHTMLCmt:        tHTMLCmt,
	stateRCDATA:         tSpecialTagEnd,
	stateAttr:           tAttr,
	stateURL:            tURL,
	stateSrcset:         tURL,
	stateJS:             tJS,
	stateJSDqStr:        tJSDelimited,
	stateJSSqStr:        tJSDelimited,
	stateJSRegexp:       tJSDelimited,
	stateJSTmplLit:      tJSTmpl,
	stateJSBlockCmt:     tBlockCmt,
	stateJSLineCmt:      tLineCmt,
	stateJSHTMLOpenCmt:  tLineCmt,
	stateJSHTMLCloseCmt: tLineCmt,
	stateCSS:            tCSS,
	stateCSSDqStr:       tCSSStr,
	stateCSSSqStr:       tCSSStr,
	stateCSSDqURL:       tCSSStr,
	stateCSSSqURL:       tCSSStr,
	stateCSSURL:         tCSSStr,
	stateCSSBlockCmt:    tBlockCmt,
	stateCSSLineCmt:     tLineCmt,
	stateError:          tError,
}

var commentStart = []byte("<!--")
var commentEnd = []byte("-->")

// tText is the context transition function for the text state.
func tText(c context, s []byte) (context, int) {
	k := 0
	for {
		i := k + bytes.IndexByte(s[k:], '<')
		if i < k || i+1 == len(s) {
			return c, len(s)
		} else if i+4 <= len(s) && bytes.Equal(commentStart, s[i:i+4]) {
			return context{state: stateHTMLCmt}, i + 4
		}
		i++
		end := false
		if s[i] == '/' {
			if i+1 == len(s) {
				return c, len(s)
			}
			end, i = true, i+1
		}
		j, e := eatTagName(s, i)
		if j != i {
			if end {
				e = elementNone
			}
			// We've found an HTML tag.
			return context{state: stateTag, element: e}, j
		}
		k = j
	}
}

var elementContentType = [...]state{
	elementNone:     stateText,
	elementScript:   stateJS,
	elementStyle:    stateCSS,
	elementTextarea: stateRCDATA,
	elementTitle:    stateRCDATA,
}

// tTag is the context transition function for the tag state.
func tTag(c context, s []byte) (context, int) {
	// Find the attribute name.
	i := eatWhiteSpace(s, 0)
	if i == len(s) {
		return c, len(s)
	}
	if s[i] == '>' {
		return context{
			state:   elementContentType[c.element],
			element: c.element,
		}, i + 1
	}
	j, err := eatAttrName(s, i)
	if err != nil {
		return context{state: stateError, err: err}, len(s)
	}
	state, attr := stateTag, attrNone
	if i == j {
		return context{
			state: stateError,
			err:   errorf(ErrBadHTML, nil, 0, "expected space, attr name, or end of tag, but got %q", s[i:]),
		}, len(s)
	}

	attrName := strings.ToLower(string(s[i:j]))
	if c.element == elementScript && attrName == "type" {
		attr = attrScriptType
	} else {
		switch attrType(attrName) {
		case contentTypeURL:
			attr = attrURL
		case contentTypeCSS:
			attr = attrStyle
		case contentTypeJS:
			attr = attrScript
		case contentTypeSrcset:
			attr = attrSrcset
		}
	}

	if j == len(s) {
		state = stateAttrName
	} else {
		state = stateAfterName
	}
	return context{state: state, element: c.element, attr: attr}, j
}

// tAttrName is the context transition function for stateAttrName.
func tAttrName(c context, s []byte) (context, int) {
	i, err := eatAttrName(s, 0)
	if err != nil {
		return context{state: stateError, err: err}, len(s)
	} else if i != len(s) {
		c.state = stateAfterName
	}
	return c, i
}

// tAfterName is the context transition function for stateAfterName.
func tAfterName(c context, s []byte) (context, int) {
	// Look for the start of the value.
	i := eatWhiteSpace(s, 0)
	if i == len(s) {
		return c, len(s)
	} else if s[i] != '=' {
		// Occurs due to tag ending '>', and valueless attribute.
		c.state = stateTag
		return c, i
	}
	c.state = stateBeforeValue
	// Consume the "=".
	return c, i + 1
}

var attrStartStates = [...]state{
	attrNone:       stateAttr,
	attrScript:     stateJS,
	attrScriptType: stateAttr,
	attrStyle:      stateCSS,
	attrURL:        stateURL,
	attrSrcset:     stateSrcset,
}

// tBeforeValue is the context transition function for stateBeforeValue.
func tBeforeValue(c context, s []byte) (context, int) {
	i := eatWhiteSpace(s, 0)
	if i == len(s) {
		return c, len(s)
	}
	// Find the attribute delimiter.
	delim := delimSpaceOrTagEnd
	switch s[i] {
	case '\'':
		delim, i = delimSingleQuote, i+1
	case '"':
		delim, i = delimDoubleQuote, i+1
	}
	c.state, c.delim = attrStartStates[c.attr], delim
	return c, i
}

// tHTMLCmt is the context transition function for stateHTMLCmt.
func tHTMLCmt(c context, s []byte) (context, int) {
	if i := bytes.Index(s, commentEnd); i != -1 {
		return context{}, i + 3
	}
	return c, len(s)
}

// specialTagEndMarkers maps element types to the character sequence that
// case-insensitively signals the end of the special tag body.
var specialTagEndMarkers = [...][]byte{
	elementScript:   []byte("script"),
	elementStyle:    []byte("style"),
	elementTextarea: []byte("textarea"),
	elementTitle:    []byte("title"),
}

var (
	specialTagEndPrefix = []byte("</")
	tagEndSeparators    = []byte("> \t\n\f/")
)

// tSpecialTagEnd is the context transition function for raw text and RCDATA
// element states.
func tSpecialTagEnd(c context, s []byte) (context, int) {
	if c.element != elementNone {
		// script end tags ("</script") within script literals are ignored, so that
		// we can properly escape them.
		if c.element == elementScript && (isInScriptLiteral(c.state) || isComment(c.state)) {
			return c, len(s)
		}
		if i := indexTagEnd(s, specialTagEndMarkers[c.element]); i != -1 {
			return context{}, i
		}
	}
	return c, len(s)
}

// indexTagEnd finds the index of a special tag end in a case insensitive way, or returns -1
func indexTagEnd(s []byte, tag []byte) int {
	res := 0
	plen := len(specialTagEndPrefix)
	for len(s) > 0 {
		// Try to find the tag end prefix first
		i := bytes.Index(s, specialTagEndPrefix)
		if i == -1 {
			return i
		}
		s = s[i+plen:]
		// Try to match the actual tag if there is still space for it
		if len(tag) <= len(s) && bytes.EqualFold(tag, s[:len(tag)]) {
			s = s[len(tag):]
			// Check the tag is followed by a proper separator
			if len(s) > 0 && bytes.IndexByte(tagEndSeparators, s[0]) != -1 {
				return res + i
			}
			res += len(tag)
		}
		res += i + plen
	}
	return -1
}

// tAttr is the context transition function for the attribute state.
func tAttr(c context, s []byte) (context, int) {
	return c, len(s)
}

// tURL is the context transition function for the URL state.
func tURL(c context, s []byte) (context, int) {
	if bytes.ContainsAny(s, "#?") {
		c.urlPart = urlPartQueryOrFrag
	} else if len(s) != eatWhiteSpace(s, 0) && c.urlPart == urlPartNone {
		// HTML5 uses "Valid URL potentially surrounded by spaces" for
		// attrs: https://www.w3.org/TR/html5/index.html#attributes-1
		c.urlPart = urlPartPreQuery
	}
	return c, len(s)
}

// tJS is the context transition function for the JS state.
func tJS(c context, s []byte) (context, int) {
	i := bytes.IndexAny(s, "\"`'/{}<-#")
	if i == -1 {
		// Entire input is non string, comment, regexp tokens.
		c.jsCtx = nextJSCtx(s, c.jsCtx)
		return c, len(s)
	}
	c.jsCtx = nextJSCtx(s[:i], c.jsCtx)
	switch s[i] {
	case '"':
		c.state, c.jsCtx = stateJSDqStr, jsCtxRegexp
	case '\'':
		c.state, c.jsCtx = stateJSSqStr, jsCtxRegexp
	case '`':
		c.state, c.jsCtx = stateJSTmplLit, jsCtxRegexp
	case '/':
		switch {
		case i+1 < len(s) && s[i+1] == '/':
			c.state, i = stateJSLineCmt, i+1
		case i+1 < len(s) && s[i+1] == '*':
			c.state, i = stateJSBlockCmt, i+1
		case c.jsCtx == jsCtxRegexp:
			c.state = stateJSRegexp
		case c.jsCtx == jsCtxDivOp:
			c.jsCtx = jsCtxRegexp
		default:
			return context{
				state: stateError,
				err:   errorf(ErrSlashAmbig, nil, 0, "'/' could start a division or regexp: %.32q", s[i:]),
			}, len(s)
		}
	// ECMAScript supports HTML style comments for legacy reasons, see Appendix
	// B.1.1 "HTML-like Comments". The handling of these comments is somewhat
	// confusing. Multi-line comments are not supported, i.e. anything on lines
	// between the opening and closing tokens is not considered a comment, but
	// anything following the opening or closing token, on the same line, is
	// ignored. As such we simply treat any line prefixed with "<!--" or "-->"
	// as if it were actually prefixed with "//" and move on.
	case '<':
		if i+3 < len(s) && bytes.Equal(commentStart, s[i:i+4]) {
			c.state, i = stateJSHTMLOpenCmt, i+3
		}
	case '-':
		if i+2 < len(s) && bytes.Equal(commentEnd, s[i:i+3]) {
			c.state, i = stateJSHTMLCloseCmt, i+2
		}
	// ECMAScript also supports "hashbang" comment lines, see Section 12.5.
	case '#':
		if i+1 < len(s) && s[i+1] == '!' {
			c.state, i = stateJSLineCmt, i+1
		}
	case '{':
		// We only care about tracking brace depth if we are inside of a
		// template literal.
		if len(c.jsBraceDepth) == 0 {
			return c, i + 1
		}
		c.jsBraceDepth[len(c.jsBraceDepth)-1]++
	case '}':
		if len(c.jsBraceDepth) == 0 {
			return c, i + 1
		}
		// There are no cases where a brace can be escaped in the JS context
		// that are not syntax errors, it seems. Because of this we can just
		// count "\}" as "}" and move on, the script is already broken as
		// fully fledged parsers will just fail anyway.
		c.jsBraceDepth[len(c.jsBraceDepth)-1]--
		if c.jsBraceDepth[len(c.jsBraceDepth)-1] >= 0 {
			return c, i + 1
		}
		c.jsBraceDepth = c.jsBraceDepth[:len(c.jsBraceDepth)-1]
		c.state = stateJSTmplLit
	default:
		panic("unreachable")
	}
	return c, i + 1
}

func tJSTmpl(c context, s []byte) (context, int) {
	var k int
	for {
		i := k + bytes.IndexAny(s[k:], "`\\$")
		if i < k {
			break
		}
		switch s[i] {
		case '\\':
			i++
			if i == len(s) {
				return context{
					state: stateError,
					err:   errorf(ErrPartialEscape, nil, 0, "unfinished escape sequence in JS string: %q", s),
				}, len(s)
			}
		case '$':
			if len(s) >= i+2 && s[i+1] == '{' {
				c.jsBraceDepth = append(c.jsBraceDepth, 0)
				c.state = stateJS
				return c, i + 2
			}
		case '`':
			// end
			c.state = stateJS
			return c, i + 1
		}
		k = i + 1
	}

	return c, len(s)
}

// tJSDelimited is the context transition function for the JS string and regexp
// states.
func tJSDelimited(c context, s []byte) (context, int) {
	specials := `\"`
	switch c.state {
	case stateJSSqStr:
		specials = `\'`
	case stateJSRegexp:
		specials = `\/[]`
	}

	k, inCharset := 0, false
	for {
		i := k + bytes.IndexAny(s[k:], specials)
		if i < k {
			break
		}
		switch s[i] {
		case '\\':
			i++
			if i == len(s) {
				return context{
					state: stateError,
					err:   errorf(ErrPartialEscape, nil, 0, "unfinished escape sequence in JS string: %q", s),
				}, len(s)
			}
		case '[':
			inCharset = true
		case ']':
			inCharset = false
		case '/':
			// If "</script" appears in a regex literal, the '/' should not
			// close the regex literal, and it will later be escaped to
			// "\x3C/script" in escapeText.
			if i > 0 && i+7 <= len(s) && bytes.Equal(bytes.ToLower(s[i-1:i+7]), []byte("</script")) {
				i++
			} else if !inCharset {
				c.state, c.jsCtx = stateJS, jsCtxDivOp
				return c, i + 1
			}
		default:
			// end delimiter
			if !inCharset {
				c.state, c.jsCtx = stateJS, jsCtxDivOp
				return c, i + 1
			}
		}
		k = i + 1
	}

	if inCharset {
		// This can be fixed by making context richer if interpolation
		// into charsets is desired.
		return context{
			state: stateError,
			err:   errorf(ErrPartialCharset, nil, 0, "unfinished JS regexp charset: %q", s),
		}, len(s)
	}

	return c, len(s)
}

var blockCommentEnd = []byte("*/")

// tBlockCmt is the context transition function for /*comment*/ states.
func tBlockCmt(c context, s []byte) (context, int) {
	i := bytes.Index(s, blockCommentEnd)
	if i == -1 {
		return c, len(s)
	}
	switch c.state {
	case stateJSBlockCmt:
		c.state = stateJS
	case stateCSSBlockCmt:
		c.state = stateCSS
	default:
		panic(c.state.String())
	}
	return c, i + 2
}

// tLineCmt is the context transition function for //comment states, and the JS HTML-like comment state.
func tLineCmt(c context, s []byte) (context, int) {
	var lineTerminators string
	var endState state
	switch c.state {
	case stateJSLineCmt, stateJSHTMLOpenCmt, stateJSHTMLCloseCmt:
		lineTerminators, endState = "\n\r\u2028\u2029", stateJS
	case stateCSSLineCmt:
		lineTerminators, endState = "\n\f\r", stateCSS
		// Line comments are not part of any published CSS standard but
		// are supported by the 4 major browsers.
		// This defines line comments as
		//     LINECOMMENT ::= "//" [^\n\f\d]*
		// since https://www.w3.org/TR/css3-syntax/#SUBTOK-nl defines
		// newlines:
		//     nl ::= #xA | #xD #xA | #xD | #xC
	default:
		panic(c.state.String())
	}

	i := bytes.IndexAny(s, lineTerminators)
	if i == -1 {
		return c, len(s)
	}
	c.state = endState
	// Per section 7.4 of EcmaScript 5 : https://es5.github.io/#x7.4
	// "However, the LineTerminator at the end of the line is not
	// considered to be part of the single-line comment; it is
	// recognized separately by the lexical grammar and becomes part
	// of the stream of input elements for the syntactic grammar."
	return c, i
}

// tCSS is the context transition function for the CSS state.
func tCSS(c context, s []byte) (context, int) {
	// CSS quoted strings are almost never used except for:
	// (1) URLs as in background: "/foo.png"
	// (2) Multiword font-names as in font-family: "Times New Roman"
	// (3) List separators in content values as in inline-lists:
	//    <style>
	//    ul.inlineList { list-style: none; padding:0 }
	//    ul.inlineList > li { display: inline }
	//    ul.inlineList > li:before { content: ", " }
	//    ul.inlineList > li:first-child:before { content: "" }
	//    </style>
	//    <ul class=inlineList><li>One<li>Two<li>Three</ul>
	// (4) Attribute value selectors as in a[href="http://example.com/"]
	//
	// We conservatively treat all strings as URLs, but make some
	// allowances to avoid confusion.
	//
	// In (1), our conservative assumption is justified.
	// In (2), valid font names do not contain ':', '?', or '#', so our
	// conservative assumption is fine since we will never transition past
	// urlPartPreQuery.
	// In (3), our protocol heuristic should not be tripped, and there
	// should not be non-space content after a '?' or '#', so as long as
	// we only %-encode RFC 3986 reserved characters we are ok.
	// In (4), we should URL escape for URL attributes, and for others we
	// have the attribute name available if our conservative assumption
	// proves problematic for real code.

	k := 0
	for {
		i := k + bytes.IndexAny(s[k:], `("'/`)
		if i < k {
			return c, len(s)
		}
		switch s[i] {
		case '(':
			// Look for url to the left.
			p := bytes.TrimRight(s[:i], "\t\n\f\r ")
			if endsWithCSSKeyword(p, "url") {
				j := len(s) - len(bytes.TrimLeft(s[i+1:], "\t\n\f\r "))
				switch {
				case j != len(s) && s[j] == '"':
					c.state, j = stateCSSDqURL, j+1
				case j != len(s) && s[j] == '\'':
					c.state, j = stateCSSSqURL, j+1
				default:
					c.state = stateCSSURL
				}
				return c, j
			}
		case '/':
			if i+1 < len(s) {
				switch s[i+1] {
				case '/':
					c.state = stateCSSLineCmt
					return c, i + 2
				case '*':
					c.state = stateCSSBlockCmt
					return c, i + 2
				}
			}
		case '"':
			c.state = stateCSSDqStr
			return c, i + 1
		case '\'':
			c.state = stateCSSSqStr
			return c, i + 1
		}
		k = i + 1
	}
}

// tCSSStr is the context transition function for the CSS string and URL states.
func tCSSStr(c context, s []byte) (context, int) {
	var endAndEsc string
	switch c.state {
	case stateCSSDqStr, stateCSSDqURL:
		endAndEsc = `\"`
	case stateCSSSqStr, stateCSSSqURL:
		endAndEsc = `\'`
	case stateCSSURL:
		// Unquoted URLs end with a newline or close parenthesis.
		// The below includes the wc (whitespace character) and nl.
		endAndEsc = "\\\t\n\f\r )"
	default:
		panic(c.state.String())
	}

	k := 0
	for {
		i := k + bytes.IndexAny(s[k:], endAndEsc)
		if i < k {
			c, nread := tURL(c, decodeCSS(s[k:]))
			return c, k + nread
		}
		if s[i] == '\\' {
			i++
			if i == len(s) {
				return context{
					state: stateError,
					err:   errorf(ErrPartialEscape, nil, 0, "unfinished escape sequence in CSS string: %q", s),
				}, len(s)
			}
		} else {
			c.state = stateCSS
			return c, i + 1
		}
		c, _ = tURL(c, decodeCSS(s[:i+1]))
		k = i + 1
	}
}

// tError is the context transition function for the error state.
func tError(c context, s []byte) (context, int) {
	return c, len(s)
}

// eatAttrName returns the largest j such that s[i:j] is an attribute name.
// It returns an error if s[i:] does not look like it begins with an
// attribute name, such as encountering a quote mark without a preceding
// equals sign.
func eatAttrName(s []byte, i int) (int, *Error) {
	for j := i; j < len(s); j++ {
		switch s[j] {
		case ' ', '\t', '\n', '\f', '\r', '=', '>':
			return j, nil
		case '\'', '"', '<':
			// These result in a parse warning in HTML5 and are
			// indicative of serious problems if seen in an attr
			// name in a template.
			return -1, errorf(ErrBadHTML, nil, 0, "%q in attribute name: %.32q", s[j:j+1], s)
		default:
			// No-op.
		}
	}
	return len(s), nil
}

var elementNameMap = map[string]element{
	"script":   elementScript,
	"style":    elementStyle,
	"textarea": elementTextarea,
	"title":    elementTitle,
}

// asciiAlpha reports whether c is an ASCII letter.
func asciiAlpha(c byte) bool {
	return 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z'
}

// asciiAlphaNum reports whether c is an ASCII letter or digit.
func asciiAlphaNum(c byte) bool {
	return asciiAlpha(c) || '0' <= c && c <= '9'
}

// eatTagName returns the largest j such that s[i:j] is a tag name and the tag type.
func eatTagName(s []byte, i int) (int, element) {
	if i == len(s) || !asciiAlpha(s[i]) {
		return i, elementNone
	}
	j := i + 1
	for j < len(s) {
		x := s[j]
		if asciiAlphaNum(x) {
			j++
			continue
		}
		// Allow "x-y" or "x:y" but not "x-", "-y", or "x--y".
		if (x == ':' || x == '-') && j+1 < len(s) && asciiAlphaNum(s[j+1]) {
			j += 2
			continue
		}
		break
	}
	return j, elementNameMap[strings.ToLower(string(s[i:j]))]
}

// eatWhiteSpace returns the largest j such that s[i:j] is white space.
func eatWhiteSpace(s []byte, i int) int {
	for j := i; j < len(s); j++ {
		switch s[j] {
		case ' ', '\t', '\n', '\f', '\r':
			// No-op.
		default:
			return j
		}
	}
	return len(s)
}
```