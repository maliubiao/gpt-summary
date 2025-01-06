Response: Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Understanding and Goal:**

The first step is to recognize that this code is part of the Go compiler, specifically within the SSA (Static Single Assignment) intermediate representation. The file name `html.go` strongly suggests its purpose: generating HTML reports about the SSA form of a function. The request asks for the functionality, potential Go feature implementation, code examples, command-line arguments, and common mistakes.

**2. Core Functionality Identification (Top-Down Approach):**

* **`HTMLWriter` struct:** This is the central data structure. It holds an `io.WriteCloser` for writing to the HTML file, the `Func` being analyzed, the output file path, a `dotWriter` for generating graph visualizations, and some state for handling phases. This immediately tells us the code is about *outputting* something related to a `Func`.
* **`NewHTMLWriter` function:**  This is the constructor. It takes a file path and a `Func` as input, opens the output file, and initializes the `HTMLWriter`. This confirms the output is an HTML file. The `cfgMask` parameter hints at some filtering or configuration related to graph generation.
* **`WritePhase` and `flushPhases` functions:** These suggest a structured way of organizing the HTML output, likely by compiler optimization passes or stages. The hashing mechanism hints at detecting changes in the SSA representation between phases.
* **`WriteSources` and `WriteAST` functions:** These clearly point to the ability to include source code and Abstract Syntax Tree information in the report.
* **`WriteColumn` and `WriteMultiTitleColumn` functions:** These are lower-level functions for adding arbitrary HTML content into columns.
* **`Close` function:** This closes the output file and prints a confirmation message.

**3. Inferring the Go Feature (Connecting the Dots):**

Based on the functionality, the most likely Go feature being implemented is the **SSA dump/visualization**. Go compilers often have flags to dump their internal representations for debugging and analysis. This `html.go` file seems to be responsible for creating a user-friendly HTML version of the SSA graph and related information.

**4. Generating a Code Example (Illustrative Usage):**

To demonstrate the usage, we need a plausible scenario. The core idea is that the `HTMLWriter` would be used within the compiler when a specific flag (related to SSA dumping) is enabled. Therefore, the example needs:

* A simplified representation of how a `Func` might be obtained (even if it's a placeholder).
* The creation of an `HTMLWriter` instance with a file path and the `Func`.
* Calling `WritePhase` multiple times to simulate different compiler passes.
* Calling `Close` to finalize the output.

This leads to the example provided in the prompt, showing the basic structure of how the `HTMLWriter` might be used. The `// Imagine...` comments are crucial for acknowledging that this is a simplified representation and not the actual compiler code.

**5. Analyzing Command-Line Arguments (Focusing on `cfgMask`):**

The constructor `NewHTMLWriter` takes a `cfgMask`. Looking at the `newDotWriter` function, which uses this mask, reveals its purpose: to control which compiler phases will have their Control Flow Graphs (CFGs) included in the HTML report as SVG images. The parsing logic within `newDotWriter` (handling `*`, ranges like `x-y`, and comma-separated values like `x,y`) confirms this. This leads to the explanation of the `cfgMask` and examples of its usage.

**6. Identifying Potential User Mistakes (Considering the Interface):**

The key to identifying potential mistakes is to think about how a user (in this case, a compiler developer or someone debugging the compiler) would interact with this code. The most obvious point of error lies in the `WritePhase` mechanism and the requirement for a consistent hashing of the `Func`.

* **Forgetting to call `WritePhase`:** If a phase isn't explicitly written, its information won't appear in the report.
* **Incorrect phase ordering:** The order of `WritePhase` calls dictates the column order.
* **Modifying `Func` without calling `WritePhase`:** If the `Func` changes, but `WritePhase` isn't called, the HTML report might not reflect the latest state. This is where the hashing mechanism becomes important, but even with hashing, relying on the developer to call `WritePhase` at appropriate times is crucial.

**7. Review and Refinement:**

After drafting the initial answer, it's essential to review it for clarity, accuracy, and completeness. This involves:

* **Double-checking the code:** Ensure the interpretations of the functions are correct.
* **Verifying the code example:** Does it logically illustrate the functionality?
* **Ensuring the command-line argument explanation is clear and accurate.**
* **Making sure the common mistake section is relevant and provides practical advice.**
* **Checking for any missing aspects of the prompt.**

This iterative process of understanding, inferring, generating examples, and refining the answer helps create a comprehensive and helpful explanation of the code snippet's functionality. The "imagine" comments in the code example are crucial for setting the right context and acknowledging the simplification.
这段Go语言代码实现了将SSA（Static Single Assignment）形式的中间代码以HTML格式输出的功能。它主要用于Go语言编译器的内部，帮助开发者理解和调试编译过程中的SSA转换和优化阶段。

下面详细列举其功能：

**核心功能:**

1. **生成HTML报告:**  `HTMLWriter` 结构体及其相关方法负责创建和写入HTML文件，该文件包含了函数的SSA表示。
2. **按阶段组织输出:**  `WritePhase` 方法允许按照编译器的不同阶段（例如，死代码消除、优化、寄存器分配等）来组织SSA输出，每个阶段的SSA会被放在HTML表格的不同列中。
3. **展示SSA代码:**  `HTML` 方法将 `Func` 的SSA表示转换为HTML格式的代码，包括指令、操作数、类型等信息。
4. **可视化控制流图 (CFG):**  通过调用外部 `dot` 工具，可以将函数的控制流图以SVG图片的形式嵌入到HTML报告中。`newDotWriter` 和 `writeFuncSVG` 方法负责与 `dot` 工具交互。
5. **展示源代码:**  `WriteSources` 方法可以将函数的源代码以及内联函数的源代码以带行号的形式显示在HTML中。
6. **展示抽象语法树 (AST):** `WriteAST` 方法可以将函数的抽象语法树信息显示在HTML中。
7. **代码高亮和交互:**  生成的HTML包含JavaScript代码，允许用户点击SSA值或基本块来高亮显示它们在整个函数中的出现，方便追踪数据流和控制流。
8. **暗黑模式支持:**  HTML和JavaScript代码支持切换到暗黑模式。
9. **折叠/展开列:**  用户可以根据需要折叠或展开不同阶段的SSA表示列，以减少页面上的信息量。
10. **拖拽缩放CFG:**  生成的SVG控制流图可以通过JavaScript进行拖拽和平移，方便查看大型图。

**推理出的 Go 语言功能实现:**

这段代码是 Go 编译器中 **SSA 中间表示的可视化** 功能的一部分。Go 编译器在编译过程中会将源代码转换为 SSA 形式，方便进行各种优化。开发者可以通过特定的编译器标志来生成 SSA 的 HTML 报告，从而了解编译器的优化过程。

**Go 代码举例说明:**

虽然这段代码本身不是一个可以直接运行的 Go 程序，但它会被 Go 编译器内部调用。  假设你在编译一个 Go 源文件 `example.go`，你可以使用 `-d=ssa/all=path/to/output.html` 这样的编译器标志来生成 SSA 的 HTML 报告。

```bash
go build -gcflags="-d=ssa/all=ssa.html" example.go
```

这将会在当前目录下生成一个名为 `ssa.html` 的文件，其中包含了编译 `example.go` 过程中生成的 SSA 信息。

**假设的输入与输出 (针对 `HTML` 方法):**

**假设输入 (一个简单的 `Func` 结构体):**

```go
package main

import "fmt"

func add(a, b int) int {
	return a + b
}

// Imagine this Func structure is created by the Go compiler for the 'add' function.
var exampleFunc = &Func{
	Name: "main.add",
	Blocks: []*Block{
		{
			ID:   0,
			Kind: BlockPlain,
			Values: []*Value{
				{ID: 1, Op: OpArg, Args: nil, Type: &Type{Name: "int"}},
				{ID: 2, Op: OpArg, Args: nil, Type: &Type{Name: "int"}},
				{ID: 3, Op: OpAdd64, Args: []*Value{{ID: 1}, {ID: 2}}, Type: &Type{Name: "int"}},
				{ID: 4, Op: OpRet, Args: []*Value{{ID: 3}}},
			},
			Succs: nil,
		},
	},
}
```

**假设输出 (部分 HTML 输出):**

```html
<code><ul class="0 ssa-print-func ">
<li class="ssa-start-block">B0:</li>
<li class="ssa-value-list"><ul>
<li class="ssa-long-value "><span class="v1 ssa-value">v1</span> <span class="no-line-number">(?)</span> v1 = Arg &lt;int&gt;</li>
<li class="ssa-long-value "><span class="v2 ssa-value">v2</span> <span class="no-line-number">(?)</span> v2 = Arg &lt;int&gt;</li>
<li class="ssa-long-value "><span class="v3 ssa-value">v3</span> <span class="no-line-number">(?)</span> v3 = Add64 &lt;int&gt; v1 v2</li>
<li class="ssa-long-value "><span class="v4 ssa-value">v4</span> <span class="no-line-number">(?)</span> v4 = Ret &lt;void&gt; v3</li>
</ul></li>
<li class="ssa-end-block">Plain</li>
</ul></code>
```

**命令行参数的具体处理:**

`NewHTMLWriter` 函数接受一个 `path` 字符串和一个 `cfgMask` 字符串作为参数。

* **`path`:**  指定生成的 HTML 报告文件的路径。如果路径不是绝对路径，则会相对于当前工作目录。
* **`cfgMask`:**  用于控制是否为特定的编译阶段生成控制流图 (CFG) 的 SVG 图片。`newDotWriter` 函数会解析这个 `cfgMask`。
    * **`"*"`:**  为所有阶段生成 CFG。
    * **`"x-y"`:**  为从阶段 `x` 到阶段 `y` (包含 `x` 和 `y`) 的所有阶段生成 CFG。这里的 `x` 和 `y` 是编译阶段的名称。
    * **`"x,y,z"`:**  仅为阶段 `x`、`y` 和 `z` 生成 CFG。
    * **`"x"`:** 仅为阶段 `x` 生成 CFG。

   例如，如果 `cfgMask` 是 `"opt-lower"`, 则会为 "opt" 和 "lower" 阶段生成 CFG。如果 `cfgMask` 是 `"start,opt,regalloc"`, 则只会为 "start"、"opt" 和 "regalloc" 阶段生成 CFG。

**使用者易犯错的点:**

1. **忘记调用 `WritePhase`:** 如果在某个编译阶段修改了 SSA，但忘记调用 `WritePhase` 来输出该阶段的 SSA，那么生成的报告将不会包含该阶段的信息，或者信息不完整。这会导致对编译过程的理解出现偏差。

   ```go
   // 假设 w 是一个 *HTMLWriter 实例
   // ... 进行一些 SSA 修改 ...

   // 错误：忘记调用 WritePhase
   // w.WritePhase("my_custom_phase", "My Custom Phase")
   ```

2. **`cfgMask` 配置错误:**  如果 `cfgMask` 配置不正确，可能导致期望的 CFG 没有生成，或者生成了不必要的 CFG，影响报告的可读性。例如，拼写错误的阶段名称或者错误的范围。

   ```bash
   # 错误的 cfgMask，阶段名称拼写错误
   go build -gcflags="-d=ssa/myphase=ssa.html" example.go

   # 错误的 cfgMask，范围不合法
   go build -gcflags="-d=ssa/opt-start=ssa.html" example.go
   ```

3. **依赖外部 `dot` 工具:**  生成 CFG 图片需要系统安装 `graphviz` 包及其 `dot` 工具。如果 `dot` 工具不存在或者不在系统的 PATH 环境变量中，则 CFG 图片将无法生成，虽然不会导致程序崩溃，但会缺失一部分重要的可视化信息。

4. **混淆阶段名称:**  不同的 Go 版本或者不同的编译选项可能会导致编译阶段的名称略有不同。开发者需要查阅当前 Go 版本的编译阶段名称，以确保 `cfgMask` 中的名称是正确的。

总而言之，这段代码是 Go 编译器中一个强大的调试和分析工具，它通过将复杂的 SSA 中间表示以易于理解的 HTML 形式呈现出来，极大地帮助了开发者深入了解 Go 编译器的内部工作机制。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/html.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssa

import (
	"bytes"
	"cmd/internal/src"
	"cmp"
	"fmt"
	"html"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

type HTMLWriter struct {
	w             io.WriteCloser
	Func          *Func
	path          string
	dot           *dotWriter
	prevHash      []byte
	pendingPhases []string
	pendingTitles []string
}

func NewHTMLWriter(path string, f *Func, cfgMask string) *HTMLWriter {
	path = strings.Replace(path, "/", string(filepath.Separator), -1)
	out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		f.Fatalf("%v", err)
	}
	reportPath := path
	if !filepath.IsAbs(reportPath) {
		pwd, err := os.Getwd()
		if err != nil {
			f.Fatalf("%v", err)
		}
		reportPath = filepath.Join(pwd, path)
	}
	html := HTMLWriter{
		w:    out,
		Func: f,
		path: reportPath,
		dot:  newDotWriter(cfgMask),
	}
	html.start()
	return &html
}

// Fatalf reports an error and exits.
func (w *HTMLWriter) Fatalf(msg string, args ...interface{}) {
	fe := w.Func.Frontend()
	fe.Fatalf(src.NoXPos, msg, args...)
}

// Logf calls the (w *HTMLWriter).Func's Logf method passing along a msg and args.
func (w *HTMLWriter) Logf(msg string, args ...interface{}) {
	w.Func.Logf(msg, args...)
}

func (w *HTMLWriter) start() {
	if w == nil {
		return
	}
	w.WriteString("<html>")
	w.WriteString(`<head>
<meta http-equiv="Content-Type" content="text/html;charset=UTF-8">
<style>

body {
    font-size: 14px;
    font-family: Arial, sans-serif;
}

h1 {
    font-size: 18px;
    display: inline-block;
    margin: 0 1em .5em 0;
}

#helplink {
    display: inline-block;
}

#help {
    display: none;
}

.stats {
    font-size: 60%;
}

table {
    border: 1px solid black;
    table-layout: fixed;
    width: 300px;
}

th, td {
    border: 1px solid black;
    overflow: hidden;
    width: 400px;
    vertical-align: top;
    padding: 5px;
}

td > h2 {
    cursor: pointer;
    font-size: 120%;
    margin: 5px 0px 5px 0px;
}

td.collapsed {
    font-size: 12px;
    width: 12px;
    border: 1px solid white;
    padding: 2px;
    cursor: pointer;
    background: #fafafa;
}

td.collapsed div {
    text-align: right;
    transform: rotate(180deg);
    writing-mode: vertical-lr;
    white-space: pre;
}

code, pre, .lines, .ast {
    font-family: Menlo, monospace;
    font-size: 12px;
}

pre {
    -moz-tab-size: 4;
    -o-tab-size:   4;
    tab-size:      4;
}

.allow-x-scroll {
    overflow-x: scroll;
}

.lines {
    float: left;
    overflow: hidden;
    text-align: right;
    margin-top: 7px;
}

.lines div {
    padding-right: 10px;
    color: gray;
}

div.line-number {
    font-size: 12px;
}

.ast {
    white-space: nowrap;
}

td.ssa-prog {
    width: 600px;
    word-wrap: break-word;
}

li {
    list-style-type: none;
}

li.ssa-long-value {
    text-indent: -2em;  /* indent wrapped lines */
}

li.ssa-value-list {
    display: inline;
}

li.ssa-start-block {
    padding: 0;
    margin: 0;
}

li.ssa-end-block {
    padding: 0;
    margin: 0;
}

ul.ssa-print-func {
    padding-left: 0;
}

li.ssa-start-block button {
    padding: 0 1em;
    margin: 0;
    border: none;
    display: inline;
    font-size: 14px;
    float: right;
}

button:hover {
    background-color: #eee;
    cursor: pointer;
}

dl.ssa-gen {
    padding-left: 0;
}

dt.ssa-prog-src {
    padding: 0;
    margin: 0;
    float: left;
    width: 4em;
}

dd.ssa-prog {
    padding: 0;
    margin-right: 0;
    margin-left: 4em;
}

.dead-value {
    color: gray;
}

.dead-block {
    opacity: 0.5;
}

.depcycle {
    font-style: italic;
}

.line-number {
    font-size: 11px;
}

.no-line-number {
    font-size: 11px;
    color: gray;
}

.zoom {
	position: absolute;
	float: left;
	white-space: nowrap;
	background-color: #eee;
}

.zoom a:link, .zoom a:visited  {
    text-decoration: none;
    color: blue;
    font-size: 16px;
    padding: 4px 2px;
}

svg {
    cursor: default;
    outline: 1px solid #eee;
    width: 100%;
}

body.darkmode {
    background-color: rgb(21, 21, 21);
    color: rgb(230, 255, 255);
    opacity: 100%;
}

td.darkmode {
    background-color: rgb(21, 21, 21);
    border: 1px solid gray;
}

body.darkmode table, th {
    border: 1px solid gray;
}

body.darkmode text {
    fill: white;
}

body.darkmode svg polygon:first-child {
    fill: rgb(21, 21, 21);
}

.highlight-aquamarine     { background-color: aquamarine; color: black; }
.highlight-coral          { background-color: coral; color: black; }
.highlight-lightpink      { background-color: lightpink; color: black; }
.highlight-lightsteelblue { background-color: lightsteelblue; color: black; }
.highlight-palegreen      { background-color: palegreen; color: black; }
.highlight-skyblue        { background-color: skyblue; color: black; }
.highlight-lightgray      { background-color: lightgray; color: black; }
.highlight-yellow         { background-color: yellow; color: black; }
.highlight-lime           { background-color: lime; color: black; }
.highlight-khaki          { background-color: khaki; color: black; }
.highlight-aqua           { background-color: aqua; color: black; }
.highlight-salmon         { background-color: salmon; color: black; }

/* Ensure all dead values/blocks continue to have gray font color in dark mode with highlights */
.dead-value span.highlight-aquamarine,
.dead-block.highlight-aquamarine,
.dead-value span.highlight-coral,
.dead-block.highlight-coral,
.dead-value span.highlight-lightpink,
.dead-block.highlight-lightpink,
.dead-value span.highlight-lightsteelblue,
.dead-block.highlight-lightsteelblue,
.dead-value span.highlight-palegreen,
.dead-block.highlight-palegreen,
.dead-value span.highlight-skyblue,
.dead-block.highlight-skyblue,
.dead-value span.highlight-lightgray,
.dead-block.highlight-lightgray,
.dead-value span.highlight-yellow,
.dead-block.highlight-yellow,
.dead-value span.highlight-lime,
.dead-block.highlight-lime,
.dead-value span.highlight-khaki,
.dead-block.highlight-khaki,
.dead-value span.highlight-aqua,
.dead-block.highlight-aqua,
.dead-value span.highlight-salmon,
.dead-block.highlight-salmon {
    color: gray;
}

.outline-blue           { outline: #2893ff solid 2px; }
.outline-red            { outline: red solid 2px; }
.outline-blueviolet     { outline: blueviolet solid 2px; }
.outline-darkolivegreen { outline: darkolivegreen solid 2px; }
.outline-fuchsia        { outline: fuchsia solid 2px; }
.outline-sienna         { outline: sienna solid 2px; }
.outline-gold           { outline: gold solid 2px; }
.outline-orangered      { outline: orangered solid 2px; }
.outline-teal           { outline: teal solid 2px; }
.outline-maroon         { outline: maroon solid 2px; }
.outline-black          { outline: black solid 2px; }

ellipse.outline-blue           { stroke-width: 2px; stroke: #2893ff; }
ellipse.outline-red            { stroke-width: 2px; stroke: red; }
ellipse.outline-blueviolet     { stroke-width: 2px; stroke: blueviolet; }
ellipse.outline-darkolivegreen { stroke-width: 2px; stroke: darkolivegreen; }
ellipse.outline-fuchsia        { stroke-width: 2px; stroke: fuchsia; }
ellipse.outline-sienna         { stroke-width: 2px; stroke: sienna; }
ellipse.outline-gold           { stroke-width: 2px; stroke: gold; }
ellipse.outline-orangered      { stroke-width: 2px; stroke: orangered; }
ellipse.outline-teal           { stroke-width: 2px; stroke: teal; }
ellipse.outline-maroon         { stroke-width: 2px; stroke: maroon; }
ellipse.outline-black          { stroke-width: 2px; stroke: black; }

/* Capture alternative for outline-black and ellipse.outline-black when in dark mode */
body.darkmode .outline-black        { outline: gray solid 2px; }
body.darkmode ellipse.outline-black { outline: gray solid 2px; }

</style>

<script type="text/javascript">

// Contains phase names which are expanded by default. Other columns are collapsed.
let expandedDefault = [
    "start",
    "deadcode",
    "opt",
    "lower",
    "late-deadcode",
    "regalloc",
    "genssa",
];
if (history.state === null) {
    history.pushState({expandedDefault}, "", location.href);
}

// ordered list of all available highlight colors
var highlights = [
    "highlight-aquamarine",
    "highlight-coral",
    "highlight-lightpink",
    "highlight-lightsteelblue",
    "highlight-palegreen",
    "highlight-skyblue",
    "highlight-lightgray",
    "highlight-yellow",
    "highlight-lime",
    "highlight-khaki",
    "highlight-aqua",
    "highlight-salmon"
];

// state: which value is highlighted this color?
var highlighted = {};
for (var i = 0; i < highlights.length; i++) {
    highlighted[highlights[i]] = "";
}

// ordered list of all available outline colors
var outlines = [
    "outline-blue",
    "outline-red",
    "outline-blueviolet",
    "outline-darkolivegreen",
    "outline-fuchsia",
    "outline-sienna",
    "outline-gold",
    "outline-orangered",
    "outline-teal",
    "outline-maroon",
    "outline-black"
];

// state: which value is outlined this color?
var outlined = {};
for (var i = 0; i < outlines.length; i++) {
    outlined[outlines[i]] = "";
}

window.onload = function() {
    if (history.state !== null) {
        expandedDefault = history.state.expandedDefault;
    }
    if (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches) {
        toggleDarkMode();
        document.getElementById("dark-mode-button").checked = true;
    }

    var ssaElemClicked = function(elem, event, selections, selected) {
        event.stopPropagation();

        // find all values with the same name
        var c = elem.classList.item(0);
        var x = document.getElementsByClassName(c);

        // if selected, remove selections from all of them
        // otherwise, attempt to add

        var remove = "";
        for (var i = 0; i < selections.length; i++) {
            var color = selections[i];
            if (selected[color] == c) {
                remove = color;
                break;
            }
        }

        if (remove != "") {
            for (var i = 0; i < x.length; i++) {
                x[i].classList.remove(remove);
            }
            selected[remove] = "";
            return;
        }

        // we're adding a selection
        // find first available color
        var avail = "";
        for (var i = 0; i < selections.length; i++) {
            var color = selections[i];
            if (selected[color] == "") {
                avail = color;
                break;
            }
        }
        if (avail == "") {
            alert("out of selection colors; go add more");
            return;
        }

        // set that as the selection
        for (var i = 0; i < x.length; i++) {
            x[i].classList.add(avail);
        }
        selected[avail] = c;
    };

    var ssaValueClicked = function(event) {
        ssaElemClicked(this, event, highlights, highlighted);
    };

    var ssaBlockClicked = function(event) {
        ssaElemClicked(this, event, outlines, outlined);
    };

    var ssavalues = document.getElementsByClassName("ssa-value");
    for (var i = 0; i < ssavalues.length; i++) {
        ssavalues[i].addEventListener('click', ssaValueClicked);
    }

    var ssalongvalues = document.getElementsByClassName("ssa-long-value");
    for (var i = 0; i < ssalongvalues.length; i++) {
        // don't attach listeners to li nodes, just the spans they contain
        if (ssalongvalues[i].nodeName == "SPAN") {
            ssalongvalues[i].addEventListener('click', ssaValueClicked);
        }
    }

    var ssablocks = document.getElementsByClassName("ssa-block");
    for (var i = 0; i < ssablocks.length; i++) {
        ssablocks[i].addEventListener('click', ssaBlockClicked);
    }

    var lines = document.getElementsByClassName("line-number");
    for (var i = 0; i < lines.length; i++) {
        lines[i].addEventListener('click', ssaValueClicked);
    }


    function toggler(phase) {
        return function() {
            toggle_cell(phase+'-col');
            toggle_cell(phase+'-exp');
            const i = expandedDefault.indexOf(phase);
            if (i !== -1) {
                expandedDefault.splice(i, 1);
            } else {
                expandedDefault.push(phase);
            }
            history.pushState({expandedDefault}, "", location.href);
        };
    }

    function toggle_cell(id) {
        var e = document.getElementById(id);
        if (e.style.display == 'table-cell') {
            e.style.display = 'none';
        } else {
            e.style.display = 'table-cell';
        }
    }

    // Go through all columns and collapse needed phases.
    const td = document.getElementsByTagName("td");
    for (let i = 0; i < td.length; i++) {
        const id = td[i].id;
        const phase = id.substr(0, id.length-4);
        let show = expandedDefault.indexOf(phase) !== -1

        // If show == false, check to see if this is a combined column (multiple phases).
        // If combined, check each of the phases to see if they are in our expandedDefaults.
        // If any are found, that entire combined column gets shown.
        if (!show) {
            const combined = phase.split('--+--');
            const len = combined.length;
            if (len > 1) {
                for (let i = 0; i < len; i++) {
                    const num = expandedDefault.indexOf(combined[i]);
                    if (num !== -1) {
                        expandedDefault.splice(num, 1);
                        if (expandedDefault.indexOf(phase) === -1) {
                            expandedDefault.push(phase);
                            show = true;
                        }
                    }
                }
            }
        }
        if (id.endsWith("-exp")) {
            const h2Els = td[i].getElementsByTagName("h2");
            const len = h2Els.length;
            if (len > 0) {
                for (let i = 0; i < len; i++) {
                    h2Els[i].addEventListener('click', toggler(phase));
                }
            }
        } else {
            td[i].addEventListener('click', toggler(phase));
        }
        if (id.endsWith("-col") && show || id.endsWith("-exp") && !show) {
            td[i].style.display = 'none';
            continue;
        }
        td[i].style.display = 'table-cell';
    }

    // find all svg block nodes, add their block classes
    var nodes = document.querySelectorAll('*[id^="graph_node_"]');
    for (var i = 0; i < nodes.length; i++) {
    	var node = nodes[i];
    	var name = node.id.toString();
    	var block = name.substring(name.lastIndexOf("_")+1);
    	node.classList.remove("node");
    	node.classList.add(block);
        node.addEventListener('click', ssaBlockClicked);
        var ellipse = node.getElementsByTagName('ellipse')[0];
        ellipse.classList.add(block);
        ellipse.addEventListener('click', ssaBlockClicked);
    }

    // make big graphs smaller
    var targetScale = 0.5;
    var nodes = document.querySelectorAll('*[id^="svg_graph_"]');
    // TODO: Implement smarter auto-zoom using the viewBox attribute
    // and in case of big graphs set the width and height of the svg graph to
    // maximum allowed.
    for (var i = 0; i < nodes.length; i++) {
    	var node = nodes[i];
    	var name = node.id.toString();
    	var phase = name.substring(name.lastIndexOf("_")+1);
    	var gNode = document.getElementById("g_graph_"+phase);
    	var scale = gNode.transform.baseVal.getItem(0).matrix.a;
    	if (scale > targetScale) {
    		node.width.baseVal.value *= targetScale / scale;
    		node.height.baseVal.value *= targetScale / scale;
    	}
    }
};

function toggle_visibility(id) {
    var e = document.getElementById(id);
    if (e.style.display == 'block') {
        e.style.display = 'none';
    } else {
        e.style.display = 'block';
    }
}

function hideBlock(el) {
    var es = el.parentNode.parentNode.getElementsByClassName("ssa-value-list");
    if (es.length===0)
        return;
    var e = es[0];
    if (e.style.display === 'block' || e.style.display === '') {
        e.style.display = 'none';
        el.innerHTML = '+';
    } else {
        e.style.display = 'block';
        el.innerHTML = '-';
    }
}

// TODO: scale the graph with the viewBox attribute.
function graphReduce(id) {
    var node = document.getElementById(id);
    if (node) {
    		node.width.baseVal.value *= 0.9;
    		node.height.baseVal.value *= 0.9;
    }
    return false;
}

function graphEnlarge(id) {
    var node = document.getElementById(id);
    if (node) {
    		node.width.baseVal.value *= 1.1;
    		node.height.baseVal.value *= 1.1;
    }
    return false;
}

function makeDraggable(event) {
    var svg = event.target;
    if (window.PointerEvent) {
        svg.addEventListener('pointerdown', startDrag);
        svg.addEventListener('pointermove', drag);
        svg.addEventListener('pointerup', endDrag);
        svg.addEventListener('pointerleave', endDrag);
    } else {
        svg.addEventListener('mousedown', startDrag);
        svg.addEventListener('mousemove', drag);
        svg.addEventListener('mouseup', endDrag);
        svg.addEventListener('mouseleave', endDrag);
    }

    var point = svg.createSVGPoint();
    var isPointerDown = false;
    var pointerOrigin;
    var viewBox = svg.viewBox.baseVal;

    function getPointFromEvent (event) {
        point.x = event.clientX;
        point.y = event.clientY;

        // We get the current transformation matrix of the SVG and we inverse it
        var invertedSVGMatrix = svg.getScreenCTM().inverse();
        return point.matrixTransform(invertedSVGMatrix);
    }

    function startDrag(event) {
        isPointerDown = true;
        pointerOrigin = getPointFromEvent(event);
    }

    function drag(event) {
        if (!isPointerDown) {
            return;
        }
        event.preventDefault();

        var pointerPosition = getPointFromEvent(event);
        viewBox.x -= (pointerPosition.x - pointerOrigin.x);
        viewBox.y -= (pointerPosition.y - pointerOrigin.y);
    }

    function endDrag(event) {
        isPointerDown = false;
    }
}

function toggleDarkMode() {
    document.body.classList.toggle('darkmode');

    // Collect all of the "collapsed" elements and apply dark mode on each collapsed column
    const collapsedEls = document.getElementsByClassName('collapsed');
    const len = collapsedEls.length;

    for (let i = 0; i < len; i++) {
        collapsedEls[i].classList.toggle('darkmode');
    }

    // Collect and spread the appropriate elements from all of the svgs on the page into one array
    const svgParts = [
        ...document.querySelectorAll('path'),
        ...document.querySelectorAll('ellipse'),
        ...document.querySelectorAll('polygon'),
    ];

    // Iterate over the svgParts specifically looking for white and black fill/stroke to be toggled.
    // The verbose conditional is intentional here so that we do not mutate any svg path, ellipse, or polygon that is of any color other than white or black.
    svgParts.forEach(el => {
        if (el.attributes.stroke.value === 'white') {
            el.attributes.stroke.value = 'black';
        } else if (el.attributes.stroke.value === 'black') {
            el.attributes.stroke.value = 'white';
        }
        if (el.attributes.fill.value === 'white') {
            el.attributes.fill.value = 'black';
        } else if (el.attributes.fill.value === 'black') {
            el.attributes.fill.value = 'white';
        }
    });
}

</script>

</head>`)
	w.WriteString("<body>")
	w.WriteString("<h1>")
	w.WriteString(html.EscapeString(w.Func.NameABI()))
	w.WriteString("</h1>")
	w.WriteString(`
<a href="#" onclick="toggle_visibility('help');return false;" id="helplink">help</a>
<div id="help">

<p>
Click on a value or block to toggle highlighting of that value/block
and its uses.  (Values and blocks are highlighted by ID, and IDs of
dead items may be reused, so not all highlights necessarily correspond
to the clicked item.)
</p>

<p>
Faded out values and blocks are dead code that has not been eliminated.
</p>

<p>
Values printed in italics have a dependency cycle.
</p>

<p>
<b>CFG</b>: Dashed edge is for unlikely branches. Blue color is for backward edges.
Edge with a dot means that this edge follows the order in which blocks were laidout.
</p>

</div>
<label for="dark-mode-button" style="margin-left: 15px; cursor: pointer;">darkmode</label>
<input type="checkbox" onclick="toggleDarkMode();" id="dark-mode-button" style="cursor: pointer" />
`)
	w.WriteString("<table>")
	w.WriteString("<tr>")
}

func (w *HTMLWriter) Close() {
	if w == nil {
		return
	}
	io.WriteString(w.w, "</tr>")
	io.WriteString(w.w, "</table>")
	io.WriteString(w.w, "</body>")
	io.WriteString(w.w, "</html>")
	w.w.Close()
	fmt.Printf("dumped SSA for %s to %v\n", w.Func.NameABI(), w.path)
}

// WritePhase writes f in a column headed by title.
// phase is used for collapsing columns and should be unique across the table.
func (w *HTMLWriter) WritePhase(phase, title string) {
	if w == nil {
		return // avoid generating HTML just to discard it
	}
	hash := hashFunc(w.Func)
	w.pendingPhases = append(w.pendingPhases, phase)
	w.pendingTitles = append(w.pendingTitles, title)
	if !bytes.Equal(hash, w.prevHash) {
		w.flushPhases()
	}
	w.prevHash = hash
}

// flushPhases collects any pending phases and titles, writes them to the html, and resets the pending slices.
func (w *HTMLWriter) flushPhases() {
	phaseLen := len(w.pendingPhases)
	if phaseLen == 0 {
		return
	}
	phases := strings.Join(w.pendingPhases, "  +  ")
	w.WriteMultiTitleColumn(
		phases,
		w.pendingTitles,
		fmt.Sprintf("hash-%x", w.prevHash),
		w.Func.HTML(w.pendingPhases[phaseLen-1], w.dot),
	)
	w.pendingPhases = w.pendingPhases[:0]
	w.pendingTitles = w.pendingTitles[:0]
}

// FuncLines contains source code for a function to be displayed
// in sources column.
type FuncLines struct {
	Filename    string
	StartLineno uint
	Lines       []string
}

// ByTopoCmp sorts topologically: target function is on top,
// followed by inlined functions sorted by filename and line numbers.
func ByTopoCmp(a, b *FuncLines) int {
	if r := strings.Compare(a.Filename, b.Filename); r != 0 {
		return r
	}
	return cmp.Compare(a.StartLineno, b.StartLineno)
}

// WriteSources writes lines as source code in a column headed by title.
// phase is used for collapsing columns and should be unique across the table.
func (w *HTMLWriter) WriteSources(phase string, all []*FuncLines) {
	if w == nil {
		return // avoid generating HTML just to discard it
	}
	var buf strings.Builder
	fmt.Fprint(&buf, "<div class=\"lines\" style=\"width: 8%\">")
	filename := ""
	for _, fl := range all {
		fmt.Fprint(&buf, "<div>&nbsp;</div>")
		if filename != fl.Filename {
			fmt.Fprint(&buf, "<div>&nbsp;</div>")
			filename = fl.Filename
		}
		for i := range fl.Lines {
			ln := int(fl.StartLineno) + i
			fmt.Fprintf(&buf, "<div class=\"l%v line-number\">%v</div>", ln, ln)
		}
	}
	fmt.Fprint(&buf, "</div><div style=\"width: 92%\"><pre>")
	filename = ""
	for _, fl := range all {
		fmt.Fprint(&buf, "<div>&nbsp;</div>")
		if filename != fl.Filename {
			fmt.Fprintf(&buf, "<div><strong>%v</strong></div>", fl.Filename)
			filename = fl.Filename
		}
		for i, line := range fl.Lines {
			ln := int(fl.StartLineno) + i
			var escaped string
			if strings.TrimSpace(line) == "" {
				escaped = "&nbsp;"
			} else {
				escaped = html.EscapeString(line)
			}
			fmt.Fprintf(&buf, "<div class=\"l%v line-number\">%v</div>", ln, escaped)
		}
	}
	fmt.Fprint(&buf, "</pre></div>")
	w.WriteColumn(phase, phase, "allow-x-scroll", buf.String())
}

func (w *HTMLWriter) WriteAST(phase string, buf *bytes.Buffer) {
	if w == nil {
		return // avoid generating HTML just to discard it
	}
	lines := strings.Split(buf.String(), "\n")
	var out strings.Builder

	fmt.Fprint(&out, "<div>")
	for _, l := range lines {
		l = strings.TrimSpace(l)
		var escaped string
		var lineNo string
		if l == "" {
			escaped = "&nbsp;"
		} else {
			if strings.HasPrefix(l, "buildssa") {
				escaped = fmt.Sprintf("<b>%v</b>", l)
			} else {
				// Parse the line number from the format file:line:col.
				// See the implementation in ir/fmt.go:dumpNodeHeader.
				sl := strings.Split(l, ":")
				if len(sl) >= 3 {
					if _, err := strconv.Atoi(sl[len(sl)-2]); err == nil {
						lineNo = sl[len(sl)-2]
					}
				}
				escaped = html.EscapeString(l)
			}
		}
		if lineNo != "" {
			fmt.Fprintf(&out, "<div class=\"l%v line-number ast\">%v</div>", lineNo, escaped)
		} else {
			fmt.Fprintf(&out, "<div class=\"ast\">%v</div>", escaped)
		}
	}
	fmt.Fprint(&out, "</div>")
	w.WriteColumn(phase, phase, "allow-x-scroll", out.String())
}

// WriteColumn writes raw HTML in a column headed by title.
// It is intended for pre- and post-compilation log output.
func (w *HTMLWriter) WriteColumn(phase, title, class, html string) {
	w.WriteMultiTitleColumn(phase, []string{title}, class, html)
}

func (w *HTMLWriter) WriteMultiTitleColumn(phase string, titles []string, class, html string) {
	if w == nil {
		return
	}
	id := strings.Replace(phase, " ", "-", -1)
	// collapsed column
	w.Printf("<td id=\"%v-col\" class=\"collapsed\"><div>%v</div></td>", id, phase)

	if class == "" {
		w.Printf("<td id=\"%v-exp\">", id)
	} else {
		w.Printf("<td id=\"%v-exp\" class=\"%v\">", id, class)
	}
	for _, title := range titles {
		w.WriteString("<h2>" + title + "</h2>")
	}
	w.WriteString(html)
	w.WriteString("</td>\n")
}

func (w *HTMLWriter) Printf(msg string, v ...interface{}) {
	if _, err := fmt.Fprintf(w.w, msg, v...); err != nil {
		w.Fatalf("%v", err)
	}
}

func (w *HTMLWriter) WriteString(s string) {
	if _, err := io.WriteString(w.w, s); err != nil {
		w.Fatalf("%v", err)
	}
}

func (v *Value) HTML() string {
	// TODO: Using the value ID as the class ignores the fact
	// that value IDs get recycled and that some values
	// are transmuted into other values.
	s := v.String()
	return fmt.Sprintf("<span class=\"%s ssa-value\">%s</span>", s, s)
}

func (v *Value) LongHTML() string {
	// TODO: Any intra-value formatting?
	// I'm wary of adding too much visual noise,
	// but a little bit might be valuable.
	// We already have visual noise in the form of punctuation
	// maybe we could replace some of that with formatting.
	s := fmt.Sprintf("<span class=\"%s ssa-long-value\">", v.String())

	linenumber := "<span class=\"no-line-number\">(?)</span>"
	if v.Pos.IsKnown() {
		linenumber = fmt.Sprintf("<span class=\"l%v line-number\">(%s)</span>", v.Pos.LineNumber(), v.Pos.LineNumberHTML())
	}

	s += fmt.Sprintf("%s %s = %s", v.HTML(), linenumber, v.Op.String())

	s += " &lt;" + html.EscapeString(v.Type.String()) + "&gt;"
	s += html.EscapeString(v.auxString())
	for _, a := range v.Args {
		s += fmt.Sprintf(" %s", a.HTML())
	}
	r := v.Block.Func.RegAlloc
	if int(v.ID) < len(r) && r[v.ID] != nil {
		s += " : " + html.EscapeString(r[v.ID].String())
	}
	if reg := v.Block.Func.tempRegs[v.ID]; reg != nil {
		s += " tmp=" + reg.String()
	}
	var names []string
	for name, values := range v.Block.Func.NamedValues {
		for _, value := range values {
			if value == v {
				names = append(names, name.String())
				break // drop duplicates.
			}
		}
	}
	if len(names) != 0 {
		s += " (" + strings.Join(names, ", ") + ")"
	}

	s += "</span>"
	return s
}

func (b *Block) HTML() string {
	// TODO: Using the value ID as the class ignores the fact
	// that value IDs get recycled and that some values
	// are transmuted into other values.
	s := html.EscapeString(b.String())
	return fmt.Sprintf("<span class=\"%s ssa-block\">%s</span>", s, s)
}

func (b *Block) LongHTML() string {
	// TODO: improve this for HTML?
	s := fmt.Sprintf("<span class=\"%s ssa-block\">%s</span>", html.EscapeString(b.String()), html.EscapeString(b.Kind.String()))
	if b.Aux != nil {
		s += html.EscapeString(fmt.Sprintf(" {%v}", b.Aux))
	}
	if t := b.AuxIntString(); t != "" {
		s += html.EscapeString(fmt.Sprintf(" [%v]", t))
	}
	for _, c := range b.ControlValues() {
		s += fmt.Sprintf(" %s", c.HTML())
	}
	if len(b.Succs) > 0 {
		s += " &#8594;" // right arrow
		for _, e := range b.Succs {
			c := e.b
			s += " " + c.HTML()
		}
	}
	switch b.Likely {
	case BranchUnlikely:
		s += " (unlikely)"
	case BranchLikely:
		s += " (likely)"
	}
	if b.Pos.IsKnown() {
		// TODO does not begin to deal with the full complexity of line numbers.
		// Maybe we want a string/slice instead, of outer-inner when inlining.
		s += fmt.Sprintf(" <span class=\"l%v line-number\">(%s)</span>", b.Pos.LineNumber(), b.Pos.LineNumberHTML())
	}
	return s
}

func (f *Func) HTML(phase string, dot *dotWriter) string {
	buf := new(strings.Builder)
	if dot != nil {
		dot.writeFuncSVG(buf, phase, f)
	}
	fmt.Fprint(buf, "<code>")
	p := htmlFuncPrinter{w: buf}
	fprintFunc(p, f)

	// fprintFunc(&buf, f) // TODO: HTML, not text, <br> for line breaks, etc.
	fmt.Fprint(buf, "</code>")
	return buf.String()
}

func (d *dotWriter) writeFuncSVG(w io.Writer, phase string, f *Func) {
	if d.broken {
		return
	}
	if _, ok := d.phases[phase]; !ok {
		return
	}
	cmd := exec.Command(d.path, "-Tsvg")
	pipe, err := cmd.StdinPipe()
	if err != nil {
		d.broken = true
		fmt.Println(err)
		return
	}
	buf := new(bytes.Buffer)
	cmd.Stdout = buf
	bufErr := new(strings.Builder)
	cmd.Stderr = bufErr
	err = cmd.Start()
	if err != nil {
		d.broken = true
		fmt.Println(err)
		return
	}
	fmt.Fprint(pipe, `digraph "" { margin=0; ranksep=.2; `)
	id := strings.Replace(phase, " ", "-", -1)
	fmt.Fprintf(pipe, `id="g_graph_%s";`, id)
	fmt.Fprintf(pipe, `node [style=filled,fillcolor=white,fontsize=16,fontname="Menlo,Times,serif",margin="0.01,0.03"];`)
	fmt.Fprintf(pipe, `edge [fontsize=16,fontname="Menlo,Times,serif"];`)
	for i, b := range f.Blocks {
		if b.Kind == BlockInvalid {
			continue
		}
		layout := ""
		if f.laidout {
			layout = fmt.Sprintf(" #%d", i)
		}
		fmt.Fprintf(pipe, `%v [label="%v%s\n%v",id="graph_node_%v_%v",tooltip="%v"];`, b, b, layout, b.Kind.String(), id, b, b.LongString())
	}
	indexOf := make([]int, f.NumBlocks())
	for i, b := range f.Blocks {
		indexOf[b.ID] = i
	}
	layoutDrawn := make([]bool, f.NumBlocks())

	ponums := make([]int32, f.NumBlocks())
	_ = postorderWithNumbering(f, ponums)
	isBackEdge := func(from, to ID) bool {
		return ponums[from] <= ponums[to]
	}

	for _, b := range f.Blocks {
		for i, s := range b.Succs {
			style := "solid"
			color := "black"
			arrow := "vee"
			if b.unlikelyIndex() == i {
				style = "dashed"
			}
			if f.laidout && indexOf[s.b.ID] == indexOf[b.ID]+1 {
				// Red color means ordered edge. It overrides other colors.
				arrow = "dotvee"
				layoutDrawn[s.b.ID] = true
			} else if isBackEdge(b.ID, s.b.ID) {
				color = "#2893ff"
			}
			fmt.Fprintf(pipe, `%v -> %v [label=" %d ",style="%s",color="%s",arrowhead="%s"];`, b, s.b, i, style, color, arrow)
		}
	}
	if f.laidout {
		fmt.Fprintln(pipe, `edge[constraint=false,color=gray,style=solid,arrowhead=dot];`)
		colors := [...]string{"#eea24f", "#f38385", "#f4d164", "#ca89fc", "gray"}
		ci := 0
		for i := 1; i < len(f.Blocks); i++ {
			if layoutDrawn[f.Blocks[i].ID] {
				continue
			}
			fmt.Fprintf(pipe, `%s -> %s [color="%s"];`, f.Blocks[i-1], f.Blocks[i], colors[ci])
			ci = (ci + 1) % len(colors)
		}
	}
	fmt.Fprint(pipe, "}")
	pipe.Close()
	err = cmd.Wait()
	if err != nil {
		d.broken = true
		fmt.Printf("dot: %v\n%v\n", err, bufErr.String())
		return
	}

	svgID := "svg_graph_" + id
	fmt.Fprintf(w, `<div class="zoom"><button onclick="return graphReduce('%s');">-</button> <button onclick="return graphEnlarge('%s');">+</button></div>`, svgID, svgID)
	// For now, an awful hack: edit the html as it passes through
	// our fingers, finding '<svg ' and injecting needed attributes after it.
	err = d.copyUntil(w, buf, `<svg `)
	if err != nil {
		fmt.Printf("injecting attributes: %v\n", err)
		return
	}
	fmt.Fprintf(w, ` id="%s" onload="makeDraggable(evt)" `, svgID)
	io.Copy(w, buf)
}

func (b *Block) unlikelyIndex() int {
	switch b.Likely {
	case BranchLikely:
		return 1
	case BranchUnlikely:
		return 0
	}
	return -1
}

func (d *dotWriter) copyUntil(w io.Writer, buf *bytes.Buffer, sep string) error {
	i := bytes.Index(buf.Bytes(), []byte(sep))
	if i == -1 {
		return fmt.Errorf("couldn't find dot sep %q", sep)
	}
	_, err := io.CopyN(w, buf, int64(i+len(sep)))
	return err
}

type htmlFuncPrinter struct {
	w io.Writer
}

func (p htmlFuncPrinter) header(f *Func) {}

func (p htmlFuncPrinter) startBlock(b *Block, reachable bool) {
	var dead string
	if !reachable {
		dead = "dead-block"
	}
	fmt.Fprintf(p.w, "<ul class=\"%s ssa-print-func %s\">", b, dead)
	fmt.Fprintf(p.w, "<li class=\"ssa-start-block\">%s:", b.HTML())
	if len(b.Preds) > 0 {
		io.WriteString(p.w, " &#8592;") // left arrow
		for _, e := range b.Preds {
			pred := e.b
			fmt.Fprintf(p.w, " %s", pred.HTML())
		}
	}
	if len(b.Values) > 0 {
		io.WriteString(p.w, `<button onclick="hideBlock(this)">-</button>`)
	}
	io.WriteString(p.w, "</li>")
	if len(b.Values) > 0 { // start list of values
		io.WriteString(p.w, "<li class=\"ssa-value-list\">")
		io.WriteString(p.w, "<ul>")
	}
}

func (p htmlFuncPrinter) endBlock(b *Block, reachable bool) {
	if len(b.Values) > 0 { // end list of values
		io.WriteString(p.w, "</ul>")
		io.WriteString(p.w, "</li>")
	}
	io.WriteString(p.w, "<li class=\"ssa-end-block\">")
	fmt.Fprint(p.w, b.LongHTML())
	io.WriteString(p.w, "</li>")
	io.WriteString(p.w, "</ul>")
}

func (p htmlFuncPrinter) value(v *Value, live bool) {
	var dead string
	if !live {
		dead = "dead-value"
	}
	fmt.Fprintf(p.w, "<li class=\"ssa-long-value %s\">", dead)
	fmt.Fprint(p.w, v.LongHTML())
	io.WriteString(p.w, "</li>")
}

func (p htmlFuncPrinter) startDepCycle() {
	fmt.Fprintln(p.w, "<span class=\"depcycle\">")
}

func (p htmlFuncPrinter) endDepCycle() {
	fmt.Fprintln(p.w, "</span>")
}

func (p htmlFuncPrinter) named(n LocalSlot, vals []*Value) {
	fmt.Fprintf(p.w, "<li>name %s: ", n)
	for _, val := range vals {
		fmt.Fprintf(p.w, "%s ", val.HTML())
	}
	fmt.Fprintf(p.w, "</li>")
}

type dotWriter struct {
	path   string
	broken bool
	phases map[string]bool // keys specify phases with CFGs
}

// newDotWriter returns non-nil value when mask is valid.
// dotWriter will generate SVGs only for the phases specified in the mask.
// mask can contain following patterns and combinations of them:
// *   - all of them;
// x-y - x through y, inclusive;
// x,y - x and y, but not the passes between.
func newDotWriter(mask string) *dotWriter {
	if mask == "" {
		return nil
	}
	// User can specify phase name with _ instead of spaces.
	mask = strings.Replace(mask, "_", " ", -1)
	ph := make(map[string]bool)
	ranges := strings.Split(mask, ",")
	for _, r := range ranges {
		spl := strings.Split(r, "-")
		if len(spl) > 2 {
			fmt.Printf("range is not valid: %v\n", mask)
			return nil
		}
		var first, last int
		if mask == "*" {
			first = 0
			last = len(passes) - 1
		} else {
			first = passIdxByName(spl[0])
			last = passIdxByName(spl[len(spl)-1])
		}
		if first < 0 || last < 0 || first > last {
			fmt.Printf("range is not valid: %v\n", r)
			return nil
		}
		for p := first; p <= last; p++ {
			ph[passes[p].name] = true
		}
	}

	path, err := exec.LookPath("dot")
	if err != nil {
		fmt.Println(err)
		return nil
	}
	return &dotWriter{path: path, phases: ph}
}

func passIdxByName(name string) int {
	for i, p := range passes {
		if p.name == name {
			return i
		}
	}
	return -1
}

"""



```