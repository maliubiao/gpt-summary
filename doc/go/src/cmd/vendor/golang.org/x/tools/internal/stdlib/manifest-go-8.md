Response:
The user wants to understand the functionality of the Go code represented by the provided data. This data seems to be a manifest of symbols (functions, types, constants, etc.) defined within various standard library packages in Go. The task is to:

1. **List the functionality:** Based on the provided symbol manifest.
2. **Infer the Go feature and provide an example:**  Identify a general Go feature that this manifest supports and illustrate it with a Go code example, including assumed input and output.
3. **Explain command-line argument handling (if applicable):** Determine if this manifest relates to command-line argument processing.
4. **Highlight common mistakes (if applicable):** Identify potential pitfalls for users based on the manifest.
5. **Summarize the overall function:** Provide a concise description of the purpose of this `manifest.go` file.

**Breakdown of the Thought Process:**

1. **Understanding the Data Structure:** The data is a Go map where the keys are package paths (e.g., "archive/tar") and the values are lists of symbols defined within those packages. Each symbol has a name, a type (Func, Type, Const, Method, Field), and a line number (likely the line where it's defined).

2. **Inferring Functionality:**  The most obvious function of this data is to provide a structured inventory of the standard library's public interface. This information could be used for various purposes, including:
    * **Documentation generation:**  Knowing the available functions, types, etc., is essential for generating API documentation.
    * **Code analysis:** Tools could use this data to understand the structure of the standard library, identify dependencies, or perform static analysis.
    * **Code completion/IntelliSense:** IDEs could leverage this information to provide suggestions as developers write code.
    * **Testing and verification:** To ensure the stability and compatibility of the standard library, its interface can be compared against a known good state.
    * **Reflection and metaprogramming:** Though not directly used for runtime reflection, this data provides a compile-time representation of the library's structure.

3. **Inferring the Go Feature and Providing an Example:**  Considering the nature of the data, the most likely Go feature it relates to is **package management and the visibility of exported symbols**. Go uses capitalization to determine if a symbol is exported (public) or not (private). This manifest explicitly lists the *exported* symbols.

    * **Example Construction:** I need to create a simple Go program that demonstrates how exported symbols from a standard library package are used. The `fmt` package is a good choice because it's commonly used.

    * **Input/Output:** The example will simply print something to the console using `fmt.Println`. There's no complex input needed here. The output will be the string printed to the console.

4. **Command-Line Argument Handling:** Reviewing the symbols, I don't see anything directly related to `os.Args` or the `flag` package. Therefore, it's unlikely this manifest is directly involved in handling command-line arguments.

5. **Common Mistakes:**  The manifest itself isn't something users directly interact with. However, understanding the concept of exported symbols is crucial for Go developers. A common mistake is trying to access unexported (lowercase) symbols from other packages.

    * **Example Construction:**  I will create two simple Go files. One will define an exported function and an unexported function. The other file will try to access both, demonstrating the compiler error when attempting to use the unexported function.

6. **Summarizing the Overall Function:** The core purpose of this `manifest.go` file is to act as a static declaration of the exported interface of Go's standard library. It's a machine-readable representation of what's publicly available in each package.

**Self-Correction/Refinement:**

* Initially, I might have considered whether this relates to Go modules. While modules are the current way to manage dependencies, the *content* of the standard library itself isn't determined by modules in the same way as external packages. This manifest reflects the *internal structure* of the standard library at a particular Go version.
* I also considered if this could be related to Go's reflection capabilities. While the data *resembles* information obtained through reflection, it's a *static* representation generated at compile time or during the build process, not dynamically at runtime.
* I double-checked the symbols to ensure I wasn't missing any obvious connection to command-line arguments or other specific Go features. The symbols are primarily focused on package contents.

By following these steps, I can construct a comprehensive answer that addresses all aspects of the user's request.
看起来你提供的是一个Go语言程序的符号清单（symbol manifest）。这个清单列出了Go标准库中一些包（例如 `archive/tar`, `bufio`, `bytes` 等）及其包含的公开的（exported）标识符，包括函数（Func）、类型（Type）、常量（Const）、方法（Method）和字段（Field）。每个标识符后面还跟着一个数字，这个数字很可能是该标识符在对应源文件中的行号。

**这个 `manifest.go` 文件的功能是：**

1. **提供标准库中公开符号的静态元数据。** 它像一个索引，列出了哪些包暴露了哪些可供外部使用的函数、类型、常量等。
2. **作为构建或分析工具的输入。**  例如，Go的文档生成工具、代码分析工具或者IDE的代码补全功能可能使用这样的清单来了解标准库的结构和API。
3. **用于版本控制和兼容性检查。** 可以比较不同Go版本之间的 `manifest.go` 文件，以了解标准库API的变化。

**它是什么go语言功能的实现，用go代码举例说明:**

这个 `manifest.go` 文件本身并不是一个直接实现某个Go语言功能的代码。它更像是一个由构建过程生成的元数据文件，用于描述Go标准库的接口。

但是，这个清单反映了Go语言中**包的导出机制**（exporting）。在Go中，只有首字母大写的标识符（函数、类型、常量等）才能被其他包导入和使用。这个 `manifest.go` 文件列出的都是这些导出的标识符。

**Go代码示例：**

假设我们想使用 `fmt` 包中的 `Println` 函数。`manifest.go` 中会有类似 `{"Println", Func, ...}` 的条目。

```go
package main

import "fmt"

func main() {
	message := "Hello, world!"
	fmt.Println(message) // 使用了 fmt 包中导出的 Println 函数
}
```

**假设的输入与输出：**

在这个例子中，输入是字符串 `"Hello, world!"`，输出是该字符串被打印到标准输出。

**涉及命令行参数的具体处理：**

这个 `manifest.go` 文件本身不涉及命令行参数的处理。命令行参数的处理通常由 `os` 包和 `flag` 包完成。

**使用者易犯错的点：**

对于开发者来说，理解Go的导出规则是很重要的。新手容易犯的错误是尝试访问其他包中未导出的（首字母小写）的标识符。

**举例说明：**

假设 `fmt` 包内部有一个未导出的函数 `internalPrint`。

```go
package main

import "fmt"

func main() {
	// 尝试调用 fmt 包中未导出的函数，会导致编译错误
	// fmt.internalPrint("This will cause an error")
}
```

**编译错误信息可能类似：** `fmt.internalPrint undefined (cannot refer to unexported name fmt.internalPrint)`

**这是第9部分，共9部分，请归纳一下它的功能**

作为系列文章的最后一部分，`manifest.go` 文件的功能可以被归纳为：

**它提供了一个Go标准库中所有公开的函数、类型、常量、方法和字段的静态清单。这个清单是Go工具链（如编译器、文档生成器等）理解和操作标准库接口的基础数据。它反映了Go语言的包导出机制，确保了开发者只能访问标准库中明确公开的部分。**

总的来说，`manifest.go` 就像标准库的公开API蓝图，为Go生态系统中的各种工具提供了关于标准库结构的必要信息。

### 提示词
```
这是路径为go/src/cmd/vendor/golang.org/x/tools/internal/stdlib/manifest.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第9部分，共9部分，请归纳一下它的功能
```

### 源代码
```go
overMode", Func, 8},
		{"Coverage", Func, 4},
		{"F", Type, 18},
		{"Init", Func, 13},
		{"InternalBenchmark", Type, 0},
		{"InternalBenchmark.F", Field, 0},
		{"InternalBenchmark.Name", Field, 0},
		{"InternalExample", Type, 0},
		{"InternalExample.F", Field, 0},
		{"InternalExample.Name", Field, 0},
		{"InternalExample.Output", Field, 0},
		{"InternalExample.Unordered", Field, 7},
		{"InternalFuzzTarget", Type, 18},
		{"InternalFuzzTarget.Fn", Field, 18},
		{"InternalFuzzTarget.Name", Field, 18},
		{"InternalTest", Type, 0},
		{"InternalTest.F", Field, 0},
		{"InternalTest.Name", Field, 0},
		{"M", Type, 4},
		{"Main", Func, 0},
		{"MainStart", Func, 4},
		{"PB", Type, 3},
		{"RegisterCover", Func, 2},
		{"RunBenchmarks", Func, 0},
		{"RunExamples", Func, 0},
		{"RunTests", Func, 0},
		{"Short", Func, 0},
		{"T", Type, 0},
		{"TB", Type, 2},
		{"Testing", Func, 21},
		{"Verbose", Func, 1},
	},
	"testing/fstest": {
		{"(MapFS).Glob", Method, 16},
		{"(MapFS).Open", Method, 16},
		{"(MapFS).ReadDir", Method, 16},
		{"(MapFS).ReadFile", Method, 16},
		{"(MapFS).Stat", Method, 16},
		{"(MapFS).Sub", Method, 16},
		{"MapFS", Type, 16},
		{"MapFile", Type, 16},
		{"MapFile.Data", Field, 16},
		{"MapFile.ModTime", Field, 16},
		{"MapFile.Mode", Field, 16},
		{"MapFile.Sys", Field, 16},
		{"TestFS", Func, 16},
	},
	"testing/iotest": {
		{"DataErrReader", Func, 0},
		{"ErrReader", Func, 16},
		{"ErrTimeout", Var, 0},
		{"HalfReader", Func, 0},
		{"NewReadLogger", Func, 0},
		{"NewWriteLogger", Func, 0},
		{"OneByteReader", Func, 0},
		{"TestReader", Func, 16},
		{"TimeoutReader", Func, 0},
		{"TruncateWriter", Func, 0},
	},
	"testing/quick": {
		{"(*CheckEqualError).Error", Method, 0},
		{"(*CheckError).Error", Method, 0},
		{"(SetupError).Error", Method, 0},
		{"Check", Func, 0},
		{"CheckEqual", Func, 0},
		{"CheckEqualError", Type, 0},
		{"CheckEqualError.CheckError", Field, 0},
		{"CheckEqualError.Out1", Field, 0},
		{"CheckEqualError.Out2", Field, 0},
		{"CheckError", Type, 0},
		{"CheckError.Count", Field, 0},
		{"CheckError.In", Field, 0},
		{"Config", Type, 0},
		{"Config.MaxCount", Field, 0},
		{"Config.MaxCountScale", Field, 0},
		{"Config.Rand", Field, 0},
		{"Config.Values", Field, 0},
		{"Generator", Type, 0},
		{"SetupError", Type, 0},
		{"Value", Func, 0},
	},
	"testing/slogtest": {
		{"Run", Func, 22},
		{"TestHandler", Func, 21},
	},
	"text/scanner": {
		{"(*Position).IsValid", Method, 0},
		{"(*Scanner).Init", Method, 0},
		{"(*Scanner).IsValid", Method, 0},
		{"(*Scanner).Next", Method, 0},
		{"(*Scanner).Peek", Method, 0},
		{"(*Scanner).Pos", Method, 0},
		{"(*Scanner).Scan", Method, 0},
		{"(*Scanner).TokenText", Method, 0},
		{"(Position).String", Method, 0},
		{"(Scanner).String", Method, 0},
		{"Char", Const, 0},
		{"Comment", Const, 0},
		{"EOF", Const, 0},
		{"Float", Const, 0},
		{"GoTokens", Const, 0},
		{"GoWhitespace", Const, 0},
		{"Ident", Const, 0},
		{"Int", Const, 0},
		{"Position", Type, 0},
		{"Position.Column", Field, 0},
		{"Position.Filename", Field, 0},
		{"Position.Line", Field, 0},
		{"Position.Offset", Field, 0},
		{"RawString", Const, 0},
		{"ScanChars", Const, 0},
		{"ScanComments", Const, 0},
		{"ScanFloats", Const, 0},
		{"ScanIdents", Const, 0},
		{"ScanInts", Const, 0},
		{"ScanRawStrings", Const, 0},
		{"ScanStrings", Const, 0},
		{"Scanner", Type, 0},
		{"Scanner.Error", Field, 0},
		{"Scanner.ErrorCount", Field, 0},
		{"Scanner.IsIdentRune", Field, 4},
		{"Scanner.Mode", Field, 0},
		{"Scanner.Position", Field, 0},
		{"Scanner.Whitespace", Field, 0},
		{"SkipComments", Const, 0},
		{"String", Const, 0},
		{"TokenString", Func, 0},
	},
	"text/tabwriter": {
		{"(*Writer).Flush", Method, 0},
		{"(*Writer).Init", Method, 0},
		{"(*Writer).Write", Method, 0},
		{"AlignRight", Const, 0},
		{"Debug", Const, 0},
		{"DiscardEmptyColumns", Const, 0},
		{"Escape", Const, 0},
		{"FilterHTML", Const, 0},
		{"NewWriter", Func, 0},
		{"StripEscape", Const, 0},
		{"TabIndent", Const, 0},
		{"Writer", Type, 0},
	},
	"text/template": {
		{"(*Template).AddParseTree", Method, 0},
		{"(*Template).Clone", Method, 0},
		{"(*Template).DefinedTemplates", Method, 5},
		{"(*Template).Delims", Method, 0},
		{"(*Template).Execute", Method, 0},
		{"(*Template).ExecuteTemplate", Method, 0},
		{"(*Template).Funcs", Method, 0},
		{"(*Template).Lookup", Method, 0},
		{"(*Template).Name", Method, 0},
		{"(*Template).New", Method, 0},
		{"(*Template).Option", Method, 5},
		{"(*Template).Parse", Method, 0},
		{"(*Template).ParseFS", Method, 16},
		{"(*Template).ParseFiles", Method, 0},
		{"(*Template).ParseGlob", Method, 0},
		{"(*Template).Templates", Method, 0},
		{"(ExecError).Error", Method, 6},
		{"(ExecError).Unwrap", Method, 13},
		{"(Template).Copy", Method, 2},
		{"(Template).ErrorContext", Method, 1},
		{"ExecError", Type, 6},
		{"ExecError.Err", Field, 6},
		{"ExecError.Name", Field, 6},
		{"FuncMap", Type, 0},
		{"HTMLEscape", Func, 0},
		{"HTMLEscapeString", Func, 0},
		{"HTMLEscaper", Func, 0},
		{"IsTrue", Func, 6},
		{"JSEscape", Func, 0},
		{"JSEscapeString", Func, 0},
		{"JSEscaper", Func, 0},
		{"Must", Func, 0},
		{"New", Func, 0},
		{"ParseFS", Func, 16},
		{"ParseFiles", Func, 0},
		{"ParseGlob", Func, 0},
		{"Template", Type, 0},
		{"Template.Tree", Field, 0},
		{"URLQueryEscaper", Func, 0},
	},
	"text/template/parse": {
		{"(*ActionNode).Copy", Method, 0},
		{"(*ActionNode).String", Method, 0},
		{"(*BoolNode).Copy", Method, 0},
		{"(*BoolNode).String", Method, 0},
		{"(*BranchNode).Copy", Method, 4},
		{"(*BranchNode).String", Method, 0},
		{"(*BreakNode).Copy", Method, 18},
		{"(*BreakNode).String", Method, 18},
		{"(*ChainNode).Add", Method, 1},
		{"(*ChainNode).Copy", Method, 1},
		{"(*ChainNode).String", Method, 1},
		{"(*CommandNode).Copy", Method, 0},
		{"(*CommandNode).String", Method, 0},
		{"(*CommentNode).Copy", Method, 16},
		{"(*CommentNode).String", Method, 16},
		{"(*ContinueNode).Copy", Method, 18},
		{"(*ContinueNode).String", Method, 18},
		{"(*DotNode).Copy", Method, 0},
		{"(*DotNode).String", Method, 0},
		{"(*DotNode).Type", Method, 0},
		{"(*FieldNode).Copy", Method, 0},
		{"(*FieldNode).String", Method, 0},
		{"(*IdentifierNode).Copy", Method, 0},
		{"(*IdentifierNode).SetPos", Method, 1},
		{"(*IdentifierNode).SetTree", Method, 4},
		{"(*IdentifierNode).String", Method, 0},
		{"(*IfNode).Copy", Method, 0},
		{"(*IfNode).String", Method, 0},
		{"(*ListNode).Copy", Method, 0},
		{"(*ListNode).CopyList", Method, 0},
		{"(*ListNode).String", Method, 0},
		{"(*NilNode).Copy", Method, 1},
		{"(*NilNode).String", Method, 1},
		{"(*NilNode).Type", Method, 1},
		{"(*NumberNode).Copy", Method, 0},
		{"(*NumberNode).String", Method, 0},
		{"(*PipeNode).Copy", Method, 0},
		{"(*PipeNode).CopyPipe", Method, 0},
		{"(*PipeNode).String", Method, 0},
		{"(*RangeNode).Copy", Method, 0},
		{"(*RangeNode).String", Method, 0},
		{"(*StringNode).Copy", Method, 0},
		{"(*StringNode).String", Method, 0},
		{"(*TemplateNode).Copy", Method, 0},
		{"(*TemplateNode).String", Method, 0},
		{"(*TextNode).Copy", Method, 0},
		{"(*TextNode).String", Method, 0},
		{"(*Tree).Copy", Method, 2},
		{"(*Tree).ErrorContext", Method, 1},
		{"(*Tree).Parse", Method, 0},
		{"(*VariableNode).Copy", Method, 0},
		{"(*VariableNode).String", Method, 0},
		{"(*WithNode).Copy", Method, 0},
		{"(*WithNode).String", Method, 0},
		{"(ActionNode).Position", Method, 1},
		{"(ActionNode).Type", Method, 0},
		{"(BoolNode).Position", Method, 1},
		{"(BoolNode).Type", Method, 0},
		{"(BranchNode).Position", Method, 1},
		{"(BranchNode).Type", Method, 0},
		{"(BreakNode).Position", Method, 18},
		{"(BreakNode).Type", Method, 18},
		{"(ChainNode).Position", Method, 1},
		{"(ChainNode).Type", Method, 1},
		{"(CommandNode).Position", Method, 1},
		{"(CommandNode).Type", Method, 0},
		{"(CommentNode).Position", Method, 16},
		{"(CommentNode).Type", Method, 16},
		{"(ContinueNode).Position", Method, 18},
		{"(ContinueNode).Type", Method, 18},
		{"(DotNode).Position", Method, 1},
		{"(FieldNode).Position", Method, 1},
		{"(FieldNode).Type", Method, 0},
		{"(IdentifierNode).Position", Method, 1},
		{"(IdentifierNode).Type", Method, 0},
		{"(IfNode).Position", Method, 1},
		{"(IfNode).Type", Method, 0},
		{"(ListNode).Position", Method, 1},
		{"(ListNode).Type", Method, 0},
		{"(NilNode).Position", Method, 1},
		{"(NodeType).Type", Method, 0},
		{"(NumberNode).Position", Method, 1},
		{"(NumberNode).Type", Method, 0},
		{"(PipeNode).Position", Method, 1},
		{"(PipeNode).Type", Method, 0},
		{"(Pos).Position", Method, 1},
		{"(RangeNode).Position", Method, 1},
		{"(RangeNode).Type", Method, 0},
		{"(StringNode).Position", Method, 1},
		{"(StringNode).Type", Method, 0},
		{"(TemplateNode).Position", Method, 1},
		{"(TemplateNode).Type", Method, 0},
		{"(TextNode).Position", Method, 1},
		{"(TextNode).Type", Method, 0},
		{"(VariableNode).Position", Method, 1},
		{"(VariableNode).Type", Method, 0},
		{"(WithNode).Position", Method, 1},
		{"(WithNode).Type", Method, 0},
		{"ActionNode", Type, 0},
		{"ActionNode.Line", Field, 0},
		{"ActionNode.NodeType", Field, 0},
		{"ActionNode.Pipe", Field, 0},
		{"ActionNode.Pos", Field, 1},
		{"BoolNode", Type, 0},
		{"BoolNode.NodeType", Field, 0},
		{"BoolNode.Pos", Field, 1},
		{"BoolNode.True", Field, 0},
		{"BranchNode", Type, 0},
		{"BranchNode.ElseList", Field, 0},
		{"BranchNode.Line", Field, 0},
		{"BranchNode.List", Field, 0},
		{"BranchNode.NodeType", Field, 0},
		{"BranchNode.Pipe", Field, 0},
		{"BranchNode.Pos", Field, 1},
		{"BreakNode", Type, 18},
		{"BreakNode.Line", Field, 18},
		{"BreakNode.NodeType", Field, 18},
		{"BreakNode.Pos", Field, 18},
		{"ChainNode", Type, 1},
		{"ChainNode.Field", Field, 1},
		{"ChainNode.Node", Field, 1},
		{"ChainNode.NodeType", Field, 1},
		{"ChainNode.Pos", Field, 1},
		{"CommandNode", Type, 0},
		{"CommandNode.Args", Field, 0},
		{"CommandNode.NodeType", Field, 0},
		{"CommandNode.Pos", Field, 1},
		{"CommentNode", Type, 16},
		{"CommentNode.NodeType", Field, 16},
		{"CommentNode.Pos", Field, 16},
		{"CommentNode.Text", Field, 16},
		{"ContinueNode", Type, 18},
		{"ContinueNode.Line", Field, 18},
		{"ContinueNode.NodeType", Field, 18},
		{"ContinueNode.Pos", Field, 18},
		{"DotNode", Type, 0},
		{"DotNode.NodeType", Field, 4},
		{"DotNode.Pos", Field, 1},
		{"FieldNode", Type, 0},
		{"FieldNode.Ident", Field, 0},
		{"FieldNode.NodeType", Field, 0},
		{"FieldNode.Pos", Field, 1},
		{"IdentifierNode", Type, 0},
		{"IdentifierNode.Ident", Field, 0},
		{"IdentifierNode.NodeType", Field, 0},
		{"IdentifierNode.Pos", Field, 1},
		{"IfNode", Type, 0},
		{"IfNode.BranchNode", Field, 0},
		{"IsEmptyTree", Func, 0},
		{"ListNode", Type, 0},
		{"ListNode.NodeType", Field, 0},
		{"ListNode.Nodes", Field, 0},
		{"ListNode.Pos", Field, 1},
		{"Mode", Type, 16},
		{"New", Func, 0},
		{"NewIdentifier", Func, 0},
		{"NilNode", Type, 1},
		{"NilNode.NodeType", Field, 4},
		{"NilNode.Pos", Field, 1},
		{"Node", Type, 0},
		{"NodeAction", Const, 0},
		{"NodeBool", Const, 0},
		{"NodeBreak", Const, 18},
		{"NodeChain", Const, 1},
		{"NodeCommand", Const, 0},
		{"NodeComment", Const, 16},
		{"NodeContinue", Const, 18},
		{"NodeDot", Const, 0},
		{"NodeField", Const, 0},
		{"NodeIdentifier", Const, 0},
		{"NodeIf", Const, 0},
		{"NodeList", Const, 0},
		{"NodeNil", Const, 1},
		{"NodeNumber", Const, 0},
		{"NodePipe", Const, 0},
		{"NodeRange", Const, 0},
		{"NodeString", Const, 0},
		{"NodeTemplate", Const, 0},
		{"NodeText", Const, 0},
		{"NodeType", Type, 0},
		{"NodeVariable", Const, 0},
		{"NodeWith", Const, 0},
		{"NumberNode", Type, 0},
		{"NumberNode.Complex128", Field, 0},
		{"NumberNode.Float64", Field, 0},
		{"NumberNode.Int64", Field, 0},
		{"NumberNode.IsComplex", Field, 0},
		{"NumberNode.IsFloat", Field, 0},
		{"NumberNode.IsInt", Field, 0},
		{"NumberNode.IsUint", Field, 0},
		{"NumberNode.NodeType", Field, 0},
		{"NumberNode.Pos", Field, 1},
		{"NumberNode.Text", Field, 0},
		{"NumberNode.Uint64", Field, 0},
		{"Parse", Func, 0},
		{"ParseComments", Const, 16},
		{"PipeNode", Type, 0},
		{"PipeNode.Cmds", Field, 0},
		{"PipeNode.Decl", Field, 0},
		{"PipeNode.IsAssign", Field, 11},
		{"PipeNode.Line", Field, 0},
		{"PipeNode.NodeType", Field, 0},
		{"PipeNode.Pos", Field, 1},
		{"Pos", Type, 1},
		{"RangeNode", Type, 0},
		{"RangeNode.BranchNode", Field, 0},
		{"SkipFuncCheck", Const, 17},
		{"StringNode", Type, 0},
		{"StringNode.NodeType", Field, 0},
		{"StringNode.Pos", Field, 1},
		{"StringNode.Quoted", Field, 0},
		{"StringNode.Text", Field, 0},
		{"TemplateNode", Type, 0},
		{"TemplateNode.Line", Field, 0},
		{"TemplateNode.Name", Field, 0},
		{"TemplateNode.NodeType", Field, 0},
		{"TemplateNode.Pipe", Field, 0},
		{"TemplateNode.Pos", Field, 1},
		{"TextNode", Type, 0},
		{"TextNode.NodeType", Field, 0},
		{"TextNode.Pos", Field, 1},
		{"TextNode.Text", Field, 0},
		{"Tree", Type, 0},
		{"Tree.Mode", Field, 16},
		{"Tree.Name", Field, 0},
		{"Tree.ParseName", Field, 1},
		{"Tree.Root", Field, 0},
		{"VariableNode", Type, 0},
		{"VariableNode.Ident", Field, 0},
		{"VariableNode.NodeType", Field, 0},
		{"VariableNode.Pos", Field, 1},
		{"WithNode", Type, 0},
		{"WithNode.BranchNode", Field, 0},
	},
	"time": {
		{"(*Location).String", Method, 0},
		{"(*ParseError).Error", Method, 0},
		{"(*Ticker).Reset", Method, 15},
		{"(*Ticker).Stop", Method, 0},
		{"(*Time).GobDecode", Method, 0},
		{"(*Time).UnmarshalBinary", Method, 2},
		{"(*Time).UnmarshalJSON", Method, 0},
		{"(*Time).UnmarshalText", Method, 2},
		{"(*Timer).Reset", Method, 1},
		{"(*Timer).Stop", Method, 0},
		{"(Duration).Abs", Method, 19},
		{"(Duration).Hours", Method, 0},
		{"(Duration).Microseconds", Method, 13},
		{"(Duration).Milliseconds", Method, 13},
		{"(Duration).Minutes", Method, 0},
		{"(Duration).Nanoseconds", Method, 0},
		{"(Duration).Round", Method, 9},
		{"(Duration).Seconds", Method, 0},
		{"(Duration).String", Method, 0},
		{"(Duration).Truncate", Method, 9},
		{"(Month).String", Method, 0},
		{"(Time).Add", Method, 0},
		{"(Time).AddDate", Method, 0},
		{"(Time).After", Method, 0},
		{"(Time).AppendFormat", Method, 5},
		{"(Time).Before", Method, 0},
		{"(Time).Clock", Method, 0},
		{"(Time).Compare", Method, 20},
		{"(Time).Date", Method, 0},
		{"(Time).Day", Method, 0},
		{"(Time).Equal", Method, 0},
		{"(Time).Format", Method, 0},
		{"(Time).GoString", Method, 17},
		{"(Time).GobEncode", Method, 0},
		{"(Time).Hour", Method, 0},
		{"(Time).ISOWeek", Method, 0},
		{"(Time).In", Method, 0},
		{"(Time).IsDST", Method, 17},
		{"(Time).IsZero", Method, 0},
		{"(Time).Local", Method, 0},
		{"(Time).Location", Method, 0},
		{"(Time).MarshalBinary", Method, 2},
		{"(Time).MarshalJSON", Method, 0},
		{"(Time).MarshalText", Method, 2},
		{"(Time).Minute", Method, 0},
		{"(Time).Month", Method, 0},
		{"(Time).Nanosecond", Method, 0},
		{"(Time).Round", Method, 1},
		{"(Time).Second", Method, 0},
		{"(Time).String", Method, 0},
		{"(Time).Sub", Method, 0},
		{"(Time).Truncate", Method, 1},
		{"(Time).UTC", Method, 0},
		{"(Time).Unix", Method, 0},
		{"(Time).UnixMicro", Method, 17},
		{"(Time).UnixMilli", Method, 17},
		{"(Time).UnixNano", Method, 0},
		{"(Time).Weekday", Method, 0},
		{"(Time).Year", Method, 0},
		{"(Time).YearDay", Method, 1},
		{"(Time).Zone", Method, 0},
		{"(Time).ZoneBounds", Method, 19},
		{"(Weekday).String", Method, 0},
		{"ANSIC", Const, 0},
		{"After", Func, 0},
		{"AfterFunc", Func, 0},
		{"April", Const, 0},
		{"August", Const, 0},
		{"Date", Func, 0},
		{"DateOnly", Const, 20},
		{"DateTime", Const, 20},
		{"December", Const, 0},
		{"Duration", Type, 0},
		{"February", Const, 0},
		{"FixedZone", Func, 0},
		{"Friday", Const, 0},
		{"Hour", Const, 0},
		{"January", Const, 0},
		{"July", Const, 0},
		{"June", Const, 0},
		{"Kitchen", Const, 0},
		{"Layout", Const, 17},
		{"LoadLocation", Func, 0},
		{"LoadLocationFromTZData", Func, 10},
		{"Local", Var, 0},
		{"Location", Type, 0},
		{"March", Const, 0},
		{"May", Const, 0},
		{"Microsecond", Const, 0},
		{"Millisecond", Const, 0},
		{"Minute", Const, 0},
		{"Monday", Const, 0},
		{"Month", Type, 0},
		{"Nanosecond", Const, 0},
		{"NewTicker", Func, 0},
		{"NewTimer", Func, 0},
		{"November", Const, 0},
		{"Now", Func, 0},
		{"October", Const, 0},
		{"Parse", Func, 0},
		{"ParseDuration", Func, 0},
		{"ParseError", Type, 0},
		{"ParseError.Layout", Field, 0},
		{"ParseError.LayoutElem", Field, 0},
		{"ParseError.Message", Field, 0},
		{"ParseError.Value", Field, 0},
		{"ParseError.ValueElem", Field, 0},
		{"ParseInLocation", Func, 1},
		{"RFC1123", Const, 0},
		{"RFC1123Z", Const, 0},
		{"RFC3339", Const, 0},
		{"RFC3339Nano", Const, 0},
		{"RFC822", Const, 0},
		{"RFC822Z", Const, 0},
		{"RFC850", Const, 0},
		{"RubyDate", Const, 0},
		{"Saturday", Const, 0},
		{"Second", Const, 0},
		{"September", Const, 0},
		{"Since", Func, 0},
		{"Sleep", Func, 0},
		{"Stamp", Const, 0},
		{"StampMicro", Const, 0},
		{"StampMilli", Const, 0},
		{"StampNano", Const, 0},
		{"Sunday", Const, 0},
		{"Thursday", Const, 0},
		{"Tick", Func, 0},
		{"Ticker", Type, 0},
		{"Ticker.C", Field, 0},
		{"Time", Type, 0},
		{"TimeOnly", Const, 20},
		{"Timer", Type, 0},
		{"Timer.C", Field, 0},
		{"Tuesday", Const, 0},
		{"UTC", Var, 0},
		{"Unix", Func, 0},
		{"UnixDate", Const, 0},
		{"UnixMicro", Func, 17},
		{"UnixMilli", Func, 17},
		{"Until", Func, 8},
		{"Wednesday", Const, 0},
		{"Weekday", Type, 0},
	},
	"unicode": {
		{"(SpecialCase).ToLower", Method, 0},
		{"(SpecialCase).ToTitle", Method, 0},
		{"(SpecialCase).ToUpper", Method, 0},
		{"ASCII_Hex_Digit", Var, 0},
		{"Adlam", Var, 7},
		{"Ahom", Var, 5},
		{"Anatolian_Hieroglyphs", Var, 5},
		{"Arabic", Var, 0},
		{"Armenian", Var, 0},
		{"Avestan", Var, 0},
		{"AzeriCase", Var, 0},
		{"Balinese", Var, 0},
		{"Bamum", Var, 0},
		{"Bassa_Vah", Var, 4},
		{"Batak", Var, 0},
		{"Bengali", Var, 0},
		{"Bhaiksuki", Var, 7},
		{"Bidi_Control", Var, 0},
		{"Bopomofo", Var, 0},
		{"Brahmi", Var, 0},
		{"Braille", Var, 0},
		{"Buginese", Var, 0},
		{"Buhid", Var, 0},
		{"C", Var, 0},
		{"Canadian_Aboriginal", Var, 0},
		{"Carian", Var, 0},
		{"CaseRange", Type, 0},
		{"CaseRange.Delta", Field, 0},
		{"CaseRange.Hi", Field, 0},
		{"CaseRange.Lo", Field, 0},
		{"CaseRanges", Var, 0},
		{"Categories", Var, 0},
		{"Caucasian_Albanian", Var, 4},
		{"Cc", Var, 0},
		{"Cf", Var, 0},
		{"Chakma", Var, 1},
		{"Cham", Var, 0},
		{"Cherokee", Var, 0},
		{"Chorasmian", Var, 16},
		{"Co", Var, 0},
		{"Common", Var, 0},
		{"Coptic", Var, 0},
		{"Cs", Var, 0},
		{"Cuneiform", Var, 0},
		{"Cypriot", Var, 0},
		{"Cypro_Minoan", Var, 21},
		{"Cyrillic", Var, 0},
		{"Dash", Var, 0},
		{"Deprecated", Var, 0},
		{"Deseret", Var, 0},
		{"Devanagari", Var, 0},
		{"Diacritic", Var, 0},
		{"Digit", Var, 0},
		{"Dives_Akuru", Var, 16},
		{"Dogra", Var, 13},
		{"Duployan", Var, 4},
		{"Egyptian_Hieroglyphs", Var, 0},
		{"Elbasan", Var, 4},
		{"Elymaic", Var, 14},
		{"Ethiopic", Var, 0},
		{"Extender", Var, 0},
		{"FoldCategory", Var, 0},
		{"FoldScript", Var, 0},
		{"Georgian", Var, 0},
		{"Glagolitic", Var, 0},
		{"Gothic", Var, 0},
		{"Grantha", Var, 4},
		{"GraphicRanges", Var, 0},
		{"Greek", Var, 0},
		{"Gujarati", Var, 0},
		{"Gunjala_Gondi", Var, 13},
		{"Gurmukhi", Var, 0},
		{"Han", Var, 0},
		{"Hangul", Var, 0},
		{"Hanifi_Rohingya", Var, 13},
		{"Hanunoo", Var, 0},
		{"Hatran", Var, 5},
		{"Hebrew", Var, 0},
		{"Hex_Digit", Var, 0},
		{"Hiragana", Var, 0},
		{"Hyphen", Var, 0},
		{"IDS_Binary_Operator", Var, 0},
		{"IDS_Trinary_Operator", Var, 0},
		{"Ideographic", Var, 0},
		{"Imperial_Aramaic", Var, 0},
		{"In", Func, 2},
		{"Inherited", Var, 0},
		{"Inscriptional_Pahlavi", Var, 0},
		{"Inscriptional_Parthian", Var, 0},
		{"Is", Func, 0},
		{"IsControl", Func, 0},
		{"IsDigit", Func, 0},
		{"IsGraphic", Func, 0},
		{"IsLetter", Func, 0},
		{"IsLower", Func, 0},
		{"IsMark", Func, 0},
		{"IsNumber", Func, 0},
		{"IsOneOf", Func, 0},
		{"IsPrint", Func, 0},
		{"IsPunct", Func, 0},
		{"IsSpace", Func, 0},
		{"IsSymbol", Func, 0},
		{"IsTitle", Func, 0},
		{"IsUpper", Func, 0},
		{"Javanese", Var, 0},
		{"Join_Control", Var, 0},
		{"Kaithi", Var, 0},
		{"Kannada", Var, 0},
		{"Katakana", Var, 0},
		{"Kawi", Var, 21},
		{"Kayah_Li", Var, 0},
		{"Kharoshthi", Var, 0},
		{"Khitan_Small_Script", Var, 16},
		{"Khmer", Var, 0},
		{"Khojki", Var, 4},
		{"Khudawadi", Var, 4},
		{"L", Var, 0},
		{"Lao", Var, 0},
		{"Latin", Var, 0},
		{"Lepcha", Var, 0},
		{"Letter", Var, 0},
		{"Limbu", Var, 0},
		{"Linear_A", Var, 4},
		{"Linear_B", Var, 0},
		{"Lisu", Var, 0},
		{"Ll", Var, 0},
		{"Lm", Var, 0},
		{"Lo", Var, 0},
		{"Logical_Order_Exception", Var, 0},
		{"Lower", Var, 0},
		{"LowerCase", Const, 0},
		{"Lt", Var, 0},
		{"Lu", Var, 0},
		{"Lycian", Var, 0},
		{"Lydian", Var, 0},
		{"M", Var, 0},
		{"Mahajani", Var, 4},
		{"Makasar", Var, 13},
		{"Malayalam", Var, 0},
		{"Mandaic", Var, 0},
		{"Manichaean", Var, 4},
		{"Marchen", Var, 7},
		{"Mark", Var, 0},
		{"Masaram_Gondi", Var, 10},
		{"MaxASCII", Const, 0},
		{"MaxCase", Const, 0},
		{"MaxLatin1", Const, 0},
		{"MaxRune", Const, 0},
		{"Mc", Var, 0},
		{"Me", Var, 0},
		{"Medefaidrin", Var, 13},
		{"Meetei_Mayek", Var, 0},
		{"Mende_Kikakui", Var, 4},
		{"Meroitic_Cursive", Var, 1},
		{"Meroitic_Hieroglyphs", Var, 1},
		{"Miao", Var, 1},
		{"Mn", Var, 0},
		{"Modi", Var, 4},
		{"Mongolian", Var, 0},
		{"Mro", Var, 4},
		{"Multani", Var, 5},
		{"Myanmar", Var, 0},
		{"N", Var, 0},
		{"Nabataean", Var, 4},
		{"Nag_Mundari", Var, 21},
		{"Nandinagari", Var, 14},
		{"Nd", Var, 0},
		{"New_Tai_Lue", Var, 0},
		{"Newa", Var, 7},
		{"Nko", Var, 0},
		{"Nl", Var, 0},
		{"No", Var, 0},
		{"Noncharacter_Code_Point", Var, 0},
		{"Number", Var, 0},
		{"Nushu", Var, 10},
		{"Nyiakeng_Puachue_Hmong", Var, 14},
		{"Ogham", Var, 0},
		{"Ol_Chiki", Var, 0},
		{"Old_Hungarian", Var, 5},
		{"Old_Italic", Var, 0},
		{"Old_North_Arabian", Var, 4},
		{"Old_Permic", Var, 4},
		{"Old_Persian", Var, 0},
		{"Old_Sogdian", Var, 13},
		{"Old_South_Arabian", Var, 0},
		{"Old_Turkic", Var, 0},
		{"Old_Uyghur", Var, 21},
		{"Oriya", Var, 0},
		{"Osage", Var, 7},
		{"Osmanya", Var, 0},
		{"Other", Var, 0},
		{"Other_Alphabetic", Var, 0},
		{"Other_Default_Ignorable_Code_Point", Var, 0},
		{"Other_Grapheme_Extend", Var, 0},
		{"Other_ID_Continue", Var, 0},
		{"Other_ID_Start", Var, 0},
		{"Other_Lowercase", Var, 0},
		{"Other_Math", Var, 0},
		{"Other_Uppercase", Var, 0},
		{"P", Var, 0},
		{"Pahawh_Hmong", Var, 4},
		{"Palmyrene", Var, 4},
		{"Pattern_Syntax", Var, 0},
		{"Pattern_White_Space", Var, 0},
		{"Pau_Cin_Hau", Var, 4},
		{"Pc", Var, 0},
		{"Pd", Var, 0},
		{"Pe", Var, 0},
		{"Pf", Var, 0},
		{"Phags_Pa", Var, 0},
		{"Phoenician", Var, 0},
		{"Pi", Var, 0},
		{"Po", Var, 0},
		{"Prepended_Concatenation_Mark", Var, 7},
		{"PrintRanges", Var, 0},
		{"Properties", Var, 0},
		{"Ps", Var, 0},
		{"Psalter_Pahlavi", Var, 4},
		{"Punct", Var, 0},
		{"Quotation_Mark", Var, 0},
		{"Radical", Var, 0},
		{"Range16", Type, 0},
		{"Range16.Hi", Field, 0},
		{"Range16.Lo", Field, 0},
		{"Range16.Stride", Field, 0},
		{"Range32", Type, 0},
		{"Range32.Hi", Field, 0},
		{"Range32.Lo", Field, 0},
		{"Range32.Stride", Field, 0},
		{"RangeTable", Type, 0},
		{"RangeTable.LatinOffset", Field, 1},
		{"RangeTable.R16", Field, 0},
		{"RangeTable.R32", Field, 0},
		{"Regional_Indicator", Var, 10},
		{"Rejang", Var, 0},
		{"ReplacementChar", Const, 0},
		{"Runic", Var, 0},
		{"S", Var, 0},
		{"STerm", Var, 0},
		{"Samaritan", Var, 0},
		{"Saurashtra", Var, 0},
		{"Sc", Var, 0},
		{"Scripts", Var, 0},
		{"Sentence_Terminal", Var, 7},
		{"Sharada", Var, 1},
		{"Shavian", Var, 0},
		{"Siddham", Var, 4},
		{"SignWriting", Var, 5},
		{"SimpleFold", Func, 0},
		{"Sinhala", Var, 0},
		{"Sk", Var, 0},
		{"Sm", Var, 0},
		{"So", Var, 0},
		{"Soft_Dotted", Var, 0},
		{"Sogdian", Var, 13},
		{"Sora_Sompeng", Var, 1},
		{"Soyombo", Var, 10},
		{"Space", Var, 0},
		{"SpecialCase", Type, 0},
		{"Sundanese", Var, 0},
		{"Syloti_Nagri", Var, 0},
		{"Symbol", Var, 0},
		{"Syriac", Var, 0},
		{"Tagalog", Var, 0},
		{"Tagbanwa", Var, 0},
		{"Tai_Le", Var, 0},
		{"Tai_Tham", Var, 0},
		{"Tai_Viet", Var, 0},
		{"Takri", Var, 1},
		{"Tamil", Var, 0},
		{"Tangsa", Var, 21},
		{"Tangut", Var, 7},
		{"Telugu", Var, 0},
		{"Terminal_Punctuation", Var, 0},
		{"Thaana", Var, 0},
		{"Thai", Var, 0},
		{"Tibetan", Var, 0},
		{"Tifinagh", Var, 0},
		{"Tirhuta", Var, 4},
		{"Title", Var, 0},
		{"TitleCase", Const, 0},
		{"To", Func, 0},
		{"ToLower", Func, 0},
		{"ToTitle", Func, 0},
		{"ToUpper", Func, 0},
		{"Toto", Var, 21},
		{"TurkishCase", Var, 0},
		{"Ugaritic", Var, 0},
		{"Unified_Ideograph", Var, 0},
		{"Upper", Var, 0},
		{"UpperCase", Const, 0},
		{"UpperLower", Const, 0},
		{"Vai", Var, 0},
		{"Variation_Selector", Var, 0},
		{"Version", Const, 0},
		{"Vithkuqi", Var, 21},
		{"Wancho", Var, 14},
		{"Warang_Citi", Var, 4},
		{"White_Space", Var, 0},
		{"Yezidi", Var, 16},
		{"Yi", Var, 0},
		{"Z", Var, 0},
		{"Zanabazar_Square", Var, 10},
		{"Zl", Var, 0},
		{"Zp", Var, 0},
		{"Zs", Var, 0},
	},
	"unicode/utf16": {
		{"AppendRune", Func, 20},
		{"Decode", Func, 0},
		{"DecodeRune", Func, 0},
		{"Encode", Func, 0},
		{"EncodeRune", Func, 0},
		{"IsSurrogate", Func, 0},
		{"RuneLen", Func, 23},
	},
	"unicode/utf8": {
		{"AppendRune", Func, 18},
		{"DecodeLastRune", Func, 0},
		{"DecodeLastRuneInString", Func, 0},
		{"DecodeRune", Func, 0},
		{"DecodeRuneInString", Func, 0},
		{"EncodeRune", Func, 0},
		{"FullRune", Func, 0},
		{"FullRuneInString", Func, 0},
		{"MaxRune", Const, 0},
		{"RuneCount", Func, 0},
		{"RuneCountInString", Func, 0},
		{"RuneError", Const, 0},
		{"RuneLen", Func, 0},
		{"RuneSelf", Const, 0},
		{"RuneStart", Func, 0},
		{"UTFMax", Const, 0},
		{"Valid", Func, 0},
		{"ValidRune", Func, 1},
		{"ValidString", Func, 0},
	},
	"unique": {
		{"(Handle).Value", Method, 23},
		{"Handle", Type, 23},
		{"Make", Func, 23},
	},
	"unsafe": {
		{"Add", Func, 0},
		{"Alignof", Func, 0},
		{"Offsetof", Func, 0},
		{"Pointer", Type, 0},
		{"Sizeof", Func, 0},
		{"Slice", Func, 0},
		{"SliceData", Func, 0},
		{"String", Func, 0},
		{"StringData", Func, 0},
	},
}
```