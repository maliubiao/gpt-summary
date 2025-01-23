Response:
这是对一个Go语言测试文件的第二部分内容的分析。这个文件名为 `escape_test.go`，位于 `go/src/html/template` 目录下。 从文件名和路径来看，这个文件是 `html/template` 包的一部分，专门用于测试 HTML 模板的转义功能。

**第二部分的功能归纳:**

这部分测试文件主要关注以下几个方面的功能：

1. **上下文切换的正确性**: 通过一系列的输入 HTML 片段和期望的上下文状态，测试模板引擎在解析 HTML 过程中，能否正确地识别当前所处的上下文（例如：在标签内，属性名后，属性值中，JavaScript 代码中，CSS 代码中等等）。 这对于后续的转义处理至关重要，因为不同上下文需要不同的转义策略。

2. **管道操作的转义处理**: 测试模板语法中的管道操作符 `|`  与转义函数的结合使用。 主要验证 `ensurePipelineContains` 函数的功能，该函数用于确保特定的转义函数（例如 `html`、`urlquery`）被正确地添加到管道中，以保证输出的安全性。

3. **处理错误的管道**: 测试模板引擎对于格式错误的管道操作的处理能力，确保在遇到错误时能够正确返回错误，而不是panic。

4. **转义错误不应被忽略**: 测试当转义过程中发生错误时，模板引擎是否会停止执行并返回错误，而不是继续执行并产生不安全的输出。

5. **冗余转义函数的测试**:  测试某些转义函数是否是冗余的，即多次应用相同的转义函数不会导致多次转义。

6. **间接打印的测试**: 测试模板引擎对于间接引用（例如指针）的变量的打印和转义处理是否正确。

7. **空模板的处理**:  测试对于未定义内容的模板的处理机制，预期会返回错误。

8. **方法调用的转义**: 测试在模板中通过管道调用对象方法时，其返回值的转义是否正确。

9. **未定义模板的错误处理**: 测试执行未定义的模板时是否会产生预期的错误。

10. **多次执行相同模板的幂等性**: 测试多次执行同一个模板是否会产生相同的结果，特别是涉及到自动添加转义函数的情况。

11. **性能测试**: 提供了一个基准测试 `BenchmarkEscapedExecute` 来衡量转义执行的性能。

12. **孤立模板的测试**: 测试在创建新的模板时，如果基于的模板是空的或不完整的，是否会产生预期的错误。

13. **共享解析树的模板**: 测试多个模板共享同一个解析树时，转义功能是否正常工作，不会发生过度转义的情况。

总而言之，这部分测试代码专注于验证 `html/template` 包在解析和执行 HTML 模板时，其核心的转义功能是否正确、健壮和高效，并且能够正确处理各种边界情况和错误情况，以防止跨站脚本攻击 (XSS) 等安全问题。

这是 `go/src/html/template/escape_test.go` 文件的第二部分，主要功能是进一步测试 HTML 模板的转义逻辑，涵盖了更广泛的场景和边缘情况。

**1. 功能列举:**

* **测试上下文（Context）状态转换的准确性:** 这部分延续了上一部分，通过更多的 HTML 片段输入，验证模板引擎在解析 HTML 标签、属性名、属性值、JavaScript 和 CSS 代码时，能否正确地跟踪和切换上下文状态。这对于后续的转义处理至关重要。
* **测试 `ensurePipelineContains` 函数:**  该函数用于确保在模板的管道操作中，特定的转义函数（如 `html`，`urlquery`）被正确地添加到管道中。这是为了保证输出的安全性，防止 XSS 攻击。
* **测试处理格式错误的管道:**  验证模板引擎对于语法错误的管道操作的处理能力，预期会产生错误而不是 panic。
* **测试转义错误不会被忽略:** 确保当转义过程中发生错误时，模板执行会停止并返回错误，而不是继续执行并输出可能存在安全风险的内容。
* **测试冗余转义函数:** 验证多次应用相同的转义函数不会导致过度转义。例如，对已经 HTML 转义过的字符串再次进行 HTML 转义，结果应该保持不变。
* **测试间接打印:** 测试模板引擎能否正确处理和转义通过指针间接引用的变量。
* **测试空模板的错误处理:** 验证当执行一个没有定义内容的模板时，是否会产生预期的错误。
* **测试通过管道调用方法的转义:** 确保通过管道操作符 `|` 调用结构体方法时，返回的字符串也会被正确转义。
* **测试未定义模板的错误处理:**  验证执行一个尚未定义的模板时会产生错误。
* **测试模板执行的幂等性:** 验证多次执行同一个模板是否产生相同的结果，特别是在涉及到自动添加转义函数的情况下。
* **性能基准测试:** 提供了一个 `BenchmarkEscapedExecute` 函数来衡量模板转义执行的性能。
* **测试孤立模板:** 验证基于一个空的或不完整的模板创建新模板时，会产生预期的错误。
* **测试共享解析树的模板:**  验证多个模板共享同一个解析树时，转义功能是否仍然正常，不会发生过度转义。

**2. Go 语言功能实现推理与代码示例:**

这部分代码主要测试了 `html/template` 包的核心转义功能，特别是其根据上下文进行不同转义的能力。

**示例：上下文切换测试**

以下是一个简化的例子，展示了如何测试上下文切换：

```go
package main

import (
	"fmt"
	"html/template"
	"strings"
)

func main() {
	testCases := []struct {
		input    string
		expected string // 期望的转义输出 (简化，实际测试会更复杂)
	}{
		{`<a href=">`, `<a href="></a>`},
		{`<script>alert("hello")</script>`, `<script>alert("hello")</script>`},
		{`<div title=">`, `<div title="></div>`},
	}

	for _, tc := range testCases {
		tmpl, err := template.New("test").Parse(tc.input)
		if err != nil {
			fmt.Println("解析错误:", err)
			continue
		}
		var buf strings.Builder
		err = tmpl.Execute(&buf, nil)
		if err != nil {
			fmt.Println("执行错误:", err)
			continue
		}
		if buf.String() != tc.expected {
			fmt.Printf("输入: %q, 期望: %q, 实际: %q\n", tc.input, tc.expected, buf.String())
		} else {
			fmt.Printf("输入: %q, 测试通过\n", tc.input)
		}
	}
}
```

**假设的输入与输出:**

* **输入:** `<a href=">`
* **期望的输出:** `<a href="></a>` (实际测试中，会更关注内部状态的转变)

* **输入:** `<script>alert("hello")</script>`
* **期望的输出:** `<script>alert("hello")</script>` (script 标签内的内容不会被 HTML 转义)

* **输入:** `<div title=">`
* **期望的输出:** `<div title="></div>`

**示例：`ensurePipelineContains` 功能测试**

```go
package main

import (
	"fmt"
	"html/template/parse"
	"strings"
	"testing"
)

// 简化的 ensurePipelineContains 实现用于演示
func ensurePipelineContains(pipe *parse.PipeNode, funcs []string) {
	// 实际实现会更复杂，这里只是演示概念
	for _, fn := range funcs {
		found := false
		for _, cmd := range pipe.Cmds {
			if len(cmd.Args) > 0 {
				if id, ok := cmd.Args[0].(*parse.IdentifierNode); ok && id.Ident == fn {
					found = true
					break
				}
			}
		}
		if !found {
			// 模拟添加转义函数
			newNode := &parse.CommandNode{Args: []parse.Node{&parse.IdentifierNode{Ident: fn}}}
			pipe.Cmds = append(pipe.Cmds, newNode)
		}
	}
}

func main() {
	testCases := []struct {
		input    string
		funcs    []string
		expected string // 期望的管道字符串表示
	}{
		{"{{.X}}", []string{"html"}, ".X | html"},
		{"{{.X | urlquery}}", []string{"html"}, ".X | urlquery | html"},
	}

	for _, tc := range testCases {
		tmpl, err := template.New("test").Parse(tc.input)
		if err != nil {
			fmt.Println("解析错误:", err)
			continue
		}
		action := tmpl.Tree.Root.Nodes[0].(*parse.ActionNode)
		pipe := action.Pipe
		ensurePipelineContains(pipe, tc.funcs)
		if pipe.String() != tc.expected {
			fmt.Printf("输入: %q, 函数: %v, 期望: %q, 实际: %q\n", tc.input, tc.funcs, tc.expected, pipe.String())
		} else {
			fmt.Printf("输入: %q, 函数: %v, 测试通过\n", tc.input, tc.funcs)
		}
	}
}
```

**假设的输入与输出:**

* **输入:** `{{.X}}`, `funcs`: `["html"]`
* **期望的输出:** `.X | html`

* **输入:** `{{.X | urlquery}}`, `funcs`: `["html"]`
* **期望的输出:** `.X | urlquery | html`

**3. 命令行参数的具体处理:**

这段代码本身是测试代码，并不直接处理命令行参数。`html/template` 包在实际使用中，可以通过 `template.ParseFiles` 或 `template.ParseGlob` 函数加载模板文件，这些函数会接收文件路径作为参数。

**4. 使用者易犯错的点 (基于代码推理):**

* **不理解上下文的重要性:**  开发者可能会错误地认为所有输出都会进行统一的 HTML 转义。但是，在 `<script>` 标签内或 CSS 样式中，需要不同的转义策略。例如，在 JavaScript 中，HTML 转义是不够的，需要进行 JavaScript 字符串转义。
    * **错误示例:**  在 JavaScript 代码中直接插入 HTML 内容，而没有进行 JavaScript 字符串转义。
    ```html
    <script>
        var message = '{{.Message}}'; // 如果 .Message 包含单引号，会导致 JavaScript 错误
        alert(message);
    </script>
    ```
    * **正确做法:** 使用 `js` 管道函数进行 JavaScript 字符串转义。
    ```html
    <script>
        var message = '{{.Message | js}}';
        alert(message);
    </script>
    ```

* **错误地使用管道函数:**  开发者可能不清楚何时应该使用 `html`，`urlquery`，`js`，`css` 等管道函数。
    * **错误示例:** 在 URL 属性中使用 `html` 转义。
    ```html
    <a href="/search?q={{.Query | html}}">Search</a>
    ```
    * **正确做法:** 应该使用 `urlquery` 进行 URL 查询参数的转义。
    ```html
    <a href="/search?q={{.Query | urlquery}}">Search</a>
    ```

* **忘记对用户输入进行适当的转义:**  即使使用了 `html/template`，如果直接将未经处理的用户输入插入到模板中，仍然可能存在安全风险。应该始终对来自不可信来源的数据进行适当的转义。

这部分测试代码通过大量的测试用例，旨在覆盖各种可能的上下文和使用场景，确保 `html/template` 包能够安全可靠地处理 HTML 模板。

### 提示词
```
这是路径为go/src/html/template/escape_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
stateAttrName, attr: attrURL},
		},
		{
			`<a on`,
			context{state: stateAttrName, attr: attrScript},
		},
		{
			`<a href `,
			context{state: stateAfterName, attr: attrURL},
		},
		{
			`<a style  =  `,
			context{state: stateBeforeValue, attr: attrStyle},
		},
		{
			`<a href=`,
			context{state: stateBeforeValue, attr: attrURL},
		},
		{
			`<a href=x`,
			context{state: stateURL, delim: delimSpaceOrTagEnd, urlPart: urlPartPreQuery, attr: attrURL},
		},
		{
			`<a href=x `,
			context{state: stateTag},
		},
		{
			`<a href=>`,
			context{state: stateText},
		},
		{
			`<a href=x>`,
			context{state: stateText},
		},
		{
			`<a href ='`,
			context{state: stateURL, delim: delimSingleQuote, attr: attrURL},
		},
		{
			`<a href=''`,
			context{state: stateTag},
		},
		{
			`<a href= "`,
			context{state: stateURL, delim: delimDoubleQuote, attr: attrURL},
		},
		{
			`<a href=""`,
			context{state: stateTag},
		},
		{
			`<a title="`,
			context{state: stateAttr, delim: delimDoubleQuote},
		},
		{
			`<a HREF='http:`,
			context{state: stateURL, delim: delimSingleQuote, urlPart: urlPartPreQuery, attr: attrURL},
		},
		{
			`<a Href='/`,
			context{state: stateURL, delim: delimSingleQuote, urlPart: urlPartPreQuery, attr: attrURL},
		},
		{
			`<a href='"`,
			context{state: stateURL, delim: delimSingleQuote, urlPart: urlPartPreQuery, attr: attrURL},
		},
		{
			`<a href="'`,
			context{state: stateURL, delim: delimDoubleQuote, urlPart: urlPartPreQuery, attr: attrURL},
		},
		{
			`<a href='&apos;`,
			context{state: stateURL, delim: delimSingleQuote, urlPart: urlPartPreQuery, attr: attrURL},
		},
		{
			`<a href="&quot;`,
			context{state: stateURL, delim: delimDoubleQuote, urlPart: urlPartPreQuery, attr: attrURL},
		},
		{
			`<a href="&#34;`,
			context{state: stateURL, delim: delimDoubleQuote, urlPart: urlPartPreQuery, attr: attrURL},
		},
		{
			`<a href=&quot;`,
			context{state: stateURL, delim: delimSpaceOrTagEnd, urlPart: urlPartPreQuery, attr: attrURL},
		},
		{
			`<img alt="1">`,
			context{state: stateText},
		},
		{
			`<img alt="1>"`,
			context{state: stateTag},
		},
		{
			`<img alt="1>">`,
			context{state: stateText},
		},
		{
			`<input checked type="checkbox"`,
			context{state: stateTag},
		},
		{
			`<a onclick="`,
			context{state: stateJS, delim: delimDoubleQuote, attr: attrScript},
		},
		{
			`<a onclick="//foo`,
			context{state: stateJSLineCmt, delim: delimDoubleQuote, attr: attrScript},
		},
		{
			"<a onclick='//\n",
			context{state: stateJS, delim: delimSingleQuote, attr: attrScript},
		},
		{
			"<a onclick='//\r\n",
			context{state: stateJS, delim: delimSingleQuote, attr: attrScript},
		},
		{
			"<a onclick='//\u2028",
			context{state: stateJS, delim: delimSingleQuote, attr: attrScript},
		},
		{
			`<a onclick="/*`,
			context{state: stateJSBlockCmt, delim: delimDoubleQuote, attr: attrScript},
		},
		{
			`<a onclick="/*/`,
			context{state: stateJSBlockCmt, delim: delimDoubleQuote, attr: attrScript},
		},
		{
			`<a onclick="/**/`,
			context{state: stateJS, delim: delimDoubleQuote, attr: attrScript},
		},
		{
			`<a onkeypress="&quot;`,
			context{state: stateJSDqStr, delim: delimDoubleQuote, attr: attrScript},
		},
		{
			`<a onclick='&quot;foo&quot;`,
			context{state: stateJS, delim: delimSingleQuote, jsCtx: jsCtxDivOp, attr: attrScript},
		},
		{
			`<a onclick=&#39;foo&#39;`,
			context{state: stateJS, delim: delimSpaceOrTagEnd, jsCtx: jsCtxDivOp, attr: attrScript},
		},
		{
			`<a onclick=&#39;foo`,
			context{state: stateJSSqStr, delim: delimSpaceOrTagEnd, attr: attrScript},
		},
		{
			`<a onclick="&quot;foo'`,
			context{state: stateJSDqStr, delim: delimDoubleQuote, attr: attrScript},
		},
		{
			`<a onclick="'foo&quot;`,
			context{state: stateJSSqStr, delim: delimDoubleQuote, attr: attrScript},
		},
		{
			"<a onclick=\"`foo",
			context{state: stateJSTmplLit, delim: delimDoubleQuote, attr: attrScript},
		},
		{
			`<A ONCLICK="'`,
			context{state: stateJSSqStr, delim: delimDoubleQuote, attr: attrScript},
		},
		{
			`<a onclick="/`,
			context{state: stateJSRegexp, delim: delimDoubleQuote, attr: attrScript},
		},
		{
			`<a onclick="'foo'`,
			context{state: stateJS, delim: delimDoubleQuote, jsCtx: jsCtxDivOp, attr: attrScript},
		},
		{
			`<a onclick="'foo\'`,
			context{state: stateJSSqStr, delim: delimDoubleQuote, attr: attrScript},
		},
		{
			`<a onclick="'foo\'`,
			context{state: stateJSSqStr, delim: delimDoubleQuote, attr: attrScript},
		},
		{
			`<a onclick="/foo/`,
			context{state: stateJS, delim: delimDoubleQuote, jsCtx: jsCtxDivOp, attr: attrScript},
		},
		{
			`<script>/foo/ /=`,
			context{state: stateJS, element: elementScript},
		},
		{
			`<a onclick="1 /foo`,
			context{state: stateJS, delim: delimDoubleQuote, jsCtx: jsCtxDivOp, attr: attrScript},
		},
		{
			`<a onclick="1 /*c*/ /foo`,
			context{state: stateJS, delim: delimDoubleQuote, jsCtx: jsCtxDivOp, attr: attrScript},
		},
		{
			`<a onclick="/foo[/]`,
			context{state: stateJSRegexp, delim: delimDoubleQuote, attr: attrScript},
		},
		{
			`<a onclick="/foo\/`,
			context{state: stateJSRegexp, delim: delimDoubleQuote, attr: attrScript},
		},
		{
			`<a onclick="/foo/`,
			context{state: stateJS, delim: delimDoubleQuote, jsCtx: jsCtxDivOp, attr: attrScript},
		},
		{
			`<input checked style="`,
			context{state: stateCSS, delim: delimDoubleQuote, attr: attrStyle},
		},
		{
			`<a style="//`,
			context{state: stateCSSLineCmt, delim: delimDoubleQuote, attr: attrStyle},
		},
		{
			`<a style="//</script>`,
			context{state: stateCSSLineCmt, delim: delimDoubleQuote, attr: attrStyle},
		},
		{
			"<a style='//\n",
			context{state: stateCSS, delim: delimSingleQuote, attr: attrStyle},
		},
		{
			"<a style='//\r",
			context{state: stateCSS, delim: delimSingleQuote, attr: attrStyle},
		},
		{
			`<a style="/*`,
			context{state: stateCSSBlockCmt, delim: delimDoubleQuote, attr: attrStyle},
		},
		{
			`<a style="/*/`,
			context{state: stateCSSBlockCmt, delim: delimDoubleQuote, attr: attrStyle},
		},
		{
			`<a style="/**/`,
			context{state: stateCSS, delim: delimDoubleQuote, attr: attrStyle},
		},
		{
			`<a style="background: '`,
			context{state: stateCSSSqStr, delim: delimDoubleQuote, attr: attrStyle},
		},
		{
			`<a style="background: &quot;`,
			context{state: stateCSSDqStr, delim: delimDoubleQuote, attr: attrStyle},
		},
		{
			`<a style="background: '/foo?img=`,
			context{state: stateCSSSqStr, delim: delimDoubleQuote, urlPart: urlPartQueryOrFrag, attr: attrStyle},
		},
		{
			`<a style="background: '/`,
			context{state: stateCSSSqStr, delim: delimDoubleQuote, urlPart: urlPartPreQuery, attr: attrStyle},
		},
		{
			`<a style="background: url(&#x22;/`,
			context{state: stateCSSDqURL, delim: delimDoubleQuote, urlPart: urlPartPreQuery, attr: attrStyle},
		},
		{
			`<a style="background: url('/`,
			context{state: stateCSSSqURL, delim: delimDoubleQuote, urlPart: urlPartPreQuery, attr: attrStyle},
		},
		{
			`<a style="background: url('/)`,
			context{state: stateCSSSqURL, delim: delimDoubleQuote, urlPart: urlPartPreQuery, attr: attrStyle},
		},
		{
			`<a style="background: url('/ `,
			context{state: stateCSSSqURL, delim: delimDoubleQuote, urlPart: urlPartPreQuery, attr: attrStyle},
		},
		{
			`<a style="background: url(/`,
			context{state: stateCSSURL, delim: delimDoubleQuote, urlPart: urlPartPreQuery, attr: attrStyle},
		},
		{
			`<a style="background: url( `,
			context{state: stateCSSURL, delim: delimDoubleQuote, attr: attrStyle},
		},
		{
			`<a style="background: url( /image?name=`,
			context{state: stateCSSURL, delim: delimDoubleQuote, urlPart: urlPartQueryOrFrag, attr: attrStyle},
		},
		{
			`<a style="background: url(x)`,
			context{state: stateCSS, delim: delimDoubleQuote, attr: attrStyle},
		},
		{
			`<a style="background: url('x'`,
			context{state: stateCSS, delim: delimDoubleQuote, attr: attrStyle},
		},
		{
			`<a style="background: url( x `,
			context{state: stateCSS, delim: delimDoubleQuote, attr: attrStyle},
		},
		{
			`<!-- foo`,
			context{state: stateHTMLCmt},
		},
		{
			`<!-->`,
			context{state: stateHTMLCmt},
		},
		{
			`<!--->`,
			context{state: stateHTMLCmt},
		},
		{
			`<!-- foo -->`,
			context{state: stateText},
		},
		{
			`<script`,
			context{state: stateTag, element: elementScript},
		},
		{
			`<script `,
			context{state: stateTag, element: elementScript},
		},
		{
			`<script src="foo.js" `,
			context{state: stateTag, element: elementScript},
		},
		{
			`<script src='foo.js' `,
			context{state: stateTag, element: elementScript},
		},
		{
			`<script type=text/javascript `,
			context{state: stateTag, element: elementScript},
		},
		{
			`<script>`,
			context{state: stateJS, jsCtx: jsCtxRegexp, element: elementScript},
		},
		{
			`<script>foo`,
			context{state: stateJS, jsCtx: jsCtxDivOp, element: elementScript},
		},
		{
			`<script>foo</script>`,
			context{state: stateText},
		},
		{
			`<script>foo</script><!--`,
			context{state: stateHTMLCmt},
		},
		{
			`<script>document.write("<p>foo</p>");`,
			context{state: stateJS, element: elementScript},
		},
		{
			`<script>document.write("<p>foo<\/script>");`,
			context{state: stateJS, element: elementScript},
		},
		{
			// <script and </script tags are escaped, so </script> should not
			// cause us to exit the JS state.
			`<script>document.write("<script>alert(1)</script>");`,
			context{state: stateJS, element: elementScript},
		},
		{
			`<script>document.write("<script>`,
			context{state: stateJSDqStr, element: elementScript},
		},
		{
			`<script>document.write("<script>alert(1)</script>`,
			context{state: stateJSDqStr, element: elementScript},
		},
		{
			`<script>document.write("<script>alert(1)<!--`,
			context{state: stateJSDqStr, element: elementScript},
		},
		{
			`<script>document.write("<script>alert(1)</Script>");`,
			context{state: stateJS, element: elementScript},
		},
		{
			`<script>document.write("<!--");`,
			context{state: stateJS, element: elementScript},
		},
		{
			`<script>let a = /</script`,
			context{state: stateJSRegexp, element: elementScript},
		},
		{
			`<script>let a = /</script/`,
			context{state: stateJS, element: elementScript, jsCtx: jsCtxDivOp},
		},
		{
			`<script type="text/template">`,
			context{state: stateText},
		},
		// covering issue 19968
		{
			`<script type="TEXT/JAVASCRIPT">`,
			context{state: stateJS, element: elementScript},
		},
		// covering issue 19965
		{
			`<script TYPE="text/template">`,
			context{state: stateText},
		},
		{
			`<script type="notjs">`,
			context{state: stateText},
		},
		{
			`<Script>`,
			context{state: stateJS, element: elementScript},
		},
		{
			`<SCRIPT>foo`,
			context{state: stateJS, jsCtx: jsCtxDivOp, element: elementScript},
		},
		{
			`<textarea>value`,
			context{state: stateRCDATA, element: elementTextarea},
		},
		{
			`<textarea>value</TEXTAREA>`,
			context{state: stateText},
		},
		{
			`<textarea name=html><b`,
			context{state: stateRCDATA, element: elementTextarea},
		},
		{
			`<title>value`,
			context{state: stateRCDATA, element: elementTitle},
		},
		{
			`<style>value`,
			context{state: stateCSS, element: elementStyle},
		},
		{
			`<a xlink:href`,
			context{state: stateAttrName, attr: attrURL},
		},
		{
			`<a xmlns`,
			context{state: stateAttrName, attr: attrURL},
		},
		{
			`<a xmlns:foo`,
			context{state: stateAttrName, attr: attrURL},
		},
		{
			`<a xmlnsxyz`,
			context{state: stateAttrName},
		},
		{
			`<a data-url`,
			context{state: stateAttrName, attr: attrURL},
		},
		{
			`<a data-iconUri`,
			context{state: stateAttrName, attr: attrURL},
		},
		{
			`<a data-urlItem`,
			context{state: stateAttrName, attr: attrURL},
		},
		{
			`<a g:`,
			context{state: stateAttrName},
		},
		{
			`<a g:url`,
			context{state: stateAttrName, attr: attrURL},
		},
		{
			`<a g:iconUri`,
			context{state: stateAttrName, attr: attrURL},
		},
		{
			`<a g:urlItem`,
			context{state: stateAttrName, attr: attrURL},
		},
		{
			`<a g:value`,
			context{state: stateAttrName},
		},
		{
			`<a svg:style='`,
			context{state: stateCSS, delim: delimSingleQuote, attr: attrStyle},
		},
		{
			`<svg:font-face`,
			context{state: stateTag},
		},
		{
			`<svg:a svg:onclick="`,
			context{state: stateJS, delim: delimDoubleQuote, attr: attrScript},
		},
		{
			`<svg:a svg:onclick="x()">`,
			context{},
		},
		{
			"<script>var a = `",
			context{state: stateJSTmplLit, element: elementScript},
		},
		{
			"<script>var a = `${",
			context{state: stateJS, element: elementScript},
		},
		{
			"<script>var a = `${}",
			context{state: stateJSTmplLit, element: elementScript},
		},
		{
			"<script>var a = `${`",
			context{state: stateJSTmplLit, element: elementScript},
		},
		{
			"<script>var a = `${var a = \"",
			context{state: stateJSDqStr, element: elementScript},
		},
		{
			"<script>var a = `${var a = \"`",
			context{state: stateJSDqStr, element: elementScript},
		},
		{
			"<script>var a = `${var a = \"}",
			context{state: stateJSDqStr, element: elementScript},
		},
		{
			"<script>var a = `${``",
			context{state: stateJS, element: elementScript},
		},
		{
			"<script>var a = `${`}",
			context{state: stateJSTmplLit, element: elementScript},
		},
		{
			"<script>`${ {} } asd`</script><script>`${ {} }",
			context{state: stateJSTmplLit, element: elementScript},
		},
		{
			"<script>var foo = `${ (_ => { return \"x\" })() + \"${",
			context{state: stateJSDqStr, element: elementScript},
		},
		{
			"<script>var a = `${ {</script><script>var b = `${ x }",
			context{state: stateJSTmplLit, element: elementScript, jsCtx: jsCtxDivOp},
		},
		{
			"<script>var foo = `x` + \"${",
			context{state: stateJSDqStr, element: elementScript},
		},
		{
			"<script>function f() { var a = `${}`; }",
			context{state: stateJS, element: elementScript},
		},
		{
			"<script>{`${}`}",
			context{state: stateJS, element: elementScript},
		},
		{
			"<script>`${ function f() { return `${1}` }() }`",
			context{state: stateJS, element: elementScript, jsCtx: jsCtxDivOp},
		},
		{
			"<script>function f() {`${ function f() { `${1}` } }`}",
			context{state: stateJS, element: elementScript, jsCtx: jsCtxDivOp},
		},
		{
			"<script>`${ { `` }",
			context{state: stateJS, element: elementScript},
		},
		{
			"<script>`${ { }`",
			context{state: stateJSTmplLit, element: elementScript},
		},
		{
			"<script>var foo = `${ foo({ a: { c: `${",
			context{state: stateJS, element: elementScript},
		},
		{
			"<script>var foo = `${ foo({ a: { c: `${ {{.}} }` }, b: ",
			context{state: stateJS, element: elementScript},
		},
		{
			"<script>`${ `}",
			context{state: stateJSTmplLit, element: elementScript},
		},
	}

	for _, test := range tests {
		b, e := []byte(test.input), makeEscaper(nil)
		c := e.escapeText(context{}, &parse.TextNode{NodeType: parse.NodeText, Text: b})
		if !test.output.eq(c) {
			t.Errorf("input %q: want context\n\t%v\ngot\n\t%v", test.input, test.output, c)
			continue
		}
		if test.input != string(b) {
			t.Errorf("input %q: text node was modified: want %q got %q", test.input, test.input, b)
			continue
		}
	}
}

func TestEnsurePipelineContains(t *testing.T) {
	tests := []struct {
		input, output string
		ids           []string
	}{
		{
			"{{.X}}",
			".X",
			[]string{},
		},
		{
			"{{.X | html}}",
			".X | html",
			[]string{},
		},
		{
			"{{.X}}",
			".X | html",
			[]string{"html"},
		},
		{
			"{{html .X}}",
			"_eval_args_ .X | html | urlquery",
			[]string{"html", "urlquery"},
		},
		{
			"{{html .X .Y .Z}}",
			"_eval_args_ .X .Y .Z | html | urlquery",
			[]string{"html", "urlquery"},
		},
		{
			"{{.X | print}}",
			".X | print | urlquery",
			[]string{"urlquery"},
		},
		{
			"{{.X | print | urlquery}}",
			".X | print | urlquery",
			[]string{"urlquery"},
		},
		{
			"{{.X | urlquery}}",
			".X | html | urlquery",
			[]string{"html", "urlquery"},
		},
		{
			"{{.X | print 2 | .f 3}}",
			".X | print 2 | .f 3 | urlquery | html",
			[]string{"urlquery", "html"},
		},
		{
			// covering issue 10801
			"{{.X | println.x }}",
			".X | println.x | urlquery | html",
			[]string{"urlquery", "html"},
		},
		{
			// covering issue 10801
			"{{.X | (print 12 | println).x }}",
			".X | (print 12 | println).x | urlquery | html",
			[]string{"urlquery", "html"},
		},
		// The following test cases ensure that the merging of internal escapers
		// with the predefined "html" and "urlquery" escapers is correct.
		{
			"{{.X | urlquery}}",
			".X | _html_template_urlfilter | urlquery",
			[]string{"_html_template_urlfilter", "_html_template_urlnormalizer"},
		},
		{
			"{{.X | urlquery}}",
			".X | urlquery | _html_template_urlfilter | _html_template_cssescaper",
			[]string{"_html_template_urlfilter", "_html_template_cssescaper"},
		},
		{
			"{{.X | urlquery}}",
			".X | urlquery",
			[]string{"_html_template_urlnormalizer"},
		},
		{
			"{{.X | urlquery}}",
			".X | urlquery",
			[]string{"_html_template_urlescaper"},
		},
		{
			"{{.X | html}}",
			".X | html",
			[]string{"_html_template_htmlescaper"},
		},
		{
			"{{.X | html}}",
			".X | html",
			[]string{"_html_template_rcdataescaper"},
		},
	}
	for i, test := range tests {
		tmpl := template.Must(template.New("test").Parse(test.input))
		action, ok := (tmpl.Tree.Root.Nodes[0].(*parse.ActionNode))
		if !ok {
			t.Errorf("First node is not an action: %s", test.input)
			continue
		}
		pipe := action.Pipe
		originalIDs := make([]string, len(test.ids))
		copy(originalIDs, test.ids)
		ensurePipelineContains(pipe, test.ids)
		got := pipe.String()
		if got != test.output {
			t.Errorf("#%d: %s, %v: want\n\t%s\ngot\n\t%s", i, test.input, originalIDs, test.output, got)
		}
	}
}

func TestEscapeMalformedPipelines(t *testing.T) {
	tests := []string{
		"{{ 0 | $ }}",
		"{{ 0 | $ | urlquery }}",
		"{{ 0 | (nil) }}",
		"{{ 0 | (nil) | html }}",
	}
	for _, test := range tests {
		var b bytes.Buffer
		tmpl, err := New("test").Parse(test)
		if err != nil {
			t.Errorf("failed to parse set: %q", err)
		}
		err = tmpl.Execute(&b, nil)
		if err == nil {
			t.Errorf("Expected error for %q", test)
		}
	}
}

func TestEscapeErrorsNotIgnorable(t *testing.T) {
	var b bytes.Buffer
	tmpl, _ := New("dangerous").Parse("<a")
	err := tmpl.Execute(&b, nil)
	if err == nil {
		t.Errorf("Expected error")
	} else if b.Len() != 0 {
		t.Errorf("Emitted output despite escaping failure")
	}
}

func TestEscapeSetErrorsNotIgnorable(t *testing.T) {
	var b bytes.Buffer
	tmpl, err := New("root").Parse(`{{define "t"}}<a{{end}}`)
	if err != nil {
		t.Errorf("failed to parse set: %q", err)
	}
	err = tmpl.ExecuteTemplate(&b, "t", nil)
	if err == nil {
		t.Errorf("Expected error")
	} else if b.Len() != 0 {
		t.Errorf("Emitted output despite escaping failure")
	}
}

func TestRedundantFuncs(t *testing.T) {
	inputs := []any{
		"\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f" +
			"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f" +
			` !"#$%&'()*+,-./` +
			`0123456789:;<=>?` +
			`@ABCDEFGHIJKLMNO` +
			`PQRSTUVWXYZ[\]^_` +
			"`abcdefghijklmno" +
			"pqrstuvwxyz{|}~\x7f" +
			"\u00A0\u0100\u2028\u2029\ufeff\ufdec\ufffd\uffff\U0001D11E" +
			"&amp;%22\\",
		CSS(`a[href =~ "//example.com"]#foo`),
		HTML(`Hello, <b>World</b> &amp;tc!`),
		HTMLAttr(` dir="ltr"`),
		JS(`c && alert("Hello, World!");`),
		JSStr(`Hello, World & O'Reilly\x21`),
		URL(`greeting=H%69&addressee=(World)`),
	}

	for n0, m := range redundantFuncs {
		f0 := funcMap[n0].(func(...any) string)
		for n1 := range m {
			f1 := funcMap[n1].(func(...any) string)
			for _, input := range inputs {
				want := f0(input)
				if got := f1(want); want != got {
					t.Errorf("%s %s with %T %q: want\n\t%q,\ngot\n\t%q", n0, n1, input, input, want, got)
				}
			}
		}
	}
}

func TestIndirectPrint(t *testing.T) {
	a := 3
	ap := &a
	b := "hello"
	bp := &b
	bpp := &bp
	tmpl := Must(New("t").Parse(`{{.}}`))
	var buf strings.Builder
	err := tmpl.Execute(&buf, ap)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	} else if buf.String() != "3" {
		t.Errorf(`Expected "3"; got %q`, buf.String())
	}
	buf.Reset()
	err = tmpl.Execute(&buf, bpp)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	} else if buf.String() != "hello" {
		t.Errorf(`Expected "hello"; got %q`, buf.String())
	}
}

// This is a test for issue 3272.
func TestEmptyTemplateHTML(t *testing.T) {
	page := Must(New("page").ParseFiles(os.DevNull))
	if err := page.ExecuteTemplate(os.Stdout, "page", "nothing"); err == nil {
		t.Fatal("expected error")
	}
}

type Issue7379 int

func (Issue7379) SomeMethod(x int) string {
	return fmt.Sprintf("<%d>", x)
}

// This is a test for issue 7379: type assertion error caused panic, and then
// the code to handle the panic breaks escaping. It's hard to see the second
// problem once the first is fixed, but its fix is trivial so we let that go. See
// the discussion for issue 7379.
func TestPipeToMethodIsEscaped(t *testing.T) {
	tmpl := Must(New("x").Parse("<html>{{0 | .SomeMethod}}</html>\n"))
	tryExec := func() string {
		defer func() {
			panicValue := recover()
			if panicValue != nil {
				t.Errorf("panicked: %v\n", panicValue)
			}
		}()
		var b strings.Builder
		tmpl.Execute(&b, Issue7379(0))
		return b.String()
	}
	for i := 0; i < 3; i++ {
		str := tryExec()
		const expect = "<html>&lt;0&gt;</html>\n"
		if str != expect {
			t.Errorf("expected %q got %q", expect, str)
		}
	}
}

// Unlike text/template, html/template crashed if given an incomplete
// template, that is, a template that had been named but not given any content.
// This is issue #10204.
func TestErrorOnUndefined(t *testing.T) {
	tmpl := New("undefined")

	err := tmpl.Execute(nil, nil)
	if err == nil {
		t.Error("expected error")
	} else if !strings.Contains(err.Error(), "incomplete") {
		t.Errorf("expected error about incomplete template; got %s", err)
	}
}

// This covers issue #20842.
func TestIdempotentExecute(t *testing.T) {
	tmpl := Must(New("").
		Parse(`{{define "main"}}<body>{{template "hello"}}</body>{{end}}`))
	Must(tmpl.
		Parse(`{{define "hello"}}Hello, {{"Ladies & Gentlemen!"}}{{end}}`))
	got := new(strings.Builder)
	var err error
	// Ensure that "hello" produces the same output when executed twice.
	want := "Hello, Ladies &amp; Gentlemen!"
	for i := 0; i < 2; i++ {
		err = tmpl.ExecuteTemplate(got, "hello", nil)
		if err != nil {
			t.Errorf("unexpected error: %s", err)
		}
		if got.String() != want {
			t.Errorf("after executing template \"hello\", got:\n\t%q\nwant:\n\t%q\n", got.String(), want)
		}
		got.Reset()
	}
	// Ensure that the implicit re-execution of "hello" during the execution of
	// "main" does not cause the output of "hello" to change.
	err = tmpl.ExecuteTemplate(got, "main", nil)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	// If the HTML escaper is added again to the action {{"Ladies & Gentlemen!"}},
	// we would expected to see the ampersand overescaped to "&amp;amp;".
	want = "<body>Hello, Ladies &amp; Gentlemen!</body>"
	if got.String() != want {
		t.Errorf("after executing template \"main\", got:\n\t%q\nwant:\n\t%q\n", got.String(), want)
	}
}

func BenchmarkEscapedExecute(b *testing.B) {
	tmpl := Must(New("t").Parse(`<a onclick="alert('{{.}}')">{{.}}</a>`))
	var buf bytes.Buffer
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tmpl.Execute(&buf, "foo & 'bar' & baz")
		buf.Reset()
	}
}

// Covers issue 22780.
func TestOrphanedTemplate(t *testing.T) {
	t1 := Must(New("foo").Parse(`<a href="{{.}}">link1</a>`))
	t2 := Must(t1.New("foo").Parse(`bar`))

	var b strings.Builder
	const wantError = `template: "foo" is an incomplete or empty template`
	if err := t1.Execute(&b, "javascript:alert(1)"); err == nil {
		t.Fatal("expected error executing t1")
	} else if gotError := err.Error(); gotError != wantError {
		t.Fatalf("got t1 execution error:\n\t%s\nwant:\n\t%s", gotError, wantError)
	}
	b.Reset()
	if err := t2.Execute(&b, nil); err != nil {
		t.Fatalf("error executing t2: %s", err)
	}
	const want = "bar"
	if got := b.String(); got != want {
		t.Fatalf("t2 rendered %q, want %q", got, want)
	}
}

// Covers issue 21844.
func TestAliasedParseTreeDoesNotOverescape(t *testing.T) {
	const (
		tmplText = `{{.}}`
		data     = `<baz>`
		want     = `&lt;baz&gt;`
	)
	// Templates "foo" and "bar" both alias the same underlying parse tree.
	tpl := Must(New("foo").Parse(tmplText))
	if _, err := tpl.AddParseTree("bar", tpl.Tree); err != nil {
		t.Fatalf("AddParseTree error: %v", err)
	}
	var b1, b2 strings.Builder
	if err := tpl.ExecuteTemplate(&b1, "foo", data); err != nil {
		t.Fatalf(`ExecuteTemplate failed for "foo": %v`, err)
	}
	if err := tpl.ExecuteTemplate(&b2, "bar", data); err != nil {
		t.Fatalf(`ExecuteTemplate failed for "foo": %v`, err)
	}
	got1, got2 := b1.String(), b2.String()
	if got1 != want {
		t.Fatalf(`Template "foo" rendered %q, want %q`, got1, want)
	}
	if got1 != got2 {
		t.Fatalf(`Template "foo" and "bar" rendered %q and %q respectively, expected equal values`, got1, got2)
	}
}
```