Response: Let's break down the thought process for analyzing the provided Go code snippet.

1. **Identify the Core Purpose:** The first thing I notice is the package declaration: `package ir`. This immediately suggests that this code is part of the compiler's intermediate representation layer. The filename `fmt.go` strongly hints at formatting or string representation of these IR elements.

2. **Scan for Key Structures:**  I quickly skim the code looking for major data structures and functions. I see definitions for `Op`, `OpNames`, `OpPrec`, and then a `Node` concept. This suggests the code is dealing with different kinds of operations and nodes in the IR.

3. **Analyze `Op` and related structures:** The `Op` type seems like an enumeration of different operations (like `OADD`, `OSUB`, `OCALL`). `OpNames` maps these to their string representations (e.g., `OADD` to `"+"`). `OpPrec` likely defines operator precedence, useful for generating correct syntax with parentheses. The `GoString()` and `Format()` methods for `Op` confirm its role in string representation.

4. **Analyze `Node` and `fmtNode`:**  The comment before `fmtNode` is crucial: "Every Node implementation must define a Format method that calls fmtNode."  This tells me that `Node` is likely an interface or an abstract type, and `fmtNode` provides the core formatting logic. The different format verbs (`%v`, `%L`, `%+v`) indicate different levels of detail in the output.

5. **Examine `stmtFmt` and `exprFmt`:** The distinction between `stmtFmt` and `exprFmt` is important. This aligns with the concept of statements and expressions in a programming language. `OpPrec`'s negative values for statement-related `Op` constants reinforces this separation. I see logic for handling different kinds of statements (assignments, loops, conditionals) and expressions (binary operations, literals, function calls).

6. **Look for Debugging/Diagnostic Features:** The presence of `Dump`, `DumpList`, and `FDumpList` functions, along with the `%+v` format verb, signals that this code is also used for debugging and inspecting the IR. The `dumpNode` and `dumpNodes` functions confirm this, as does the `base.Debug.DumpPtrs` check.

7. **Infer Go Language Feature Implementation:** Based on the operations listed in `OpNames`, I can deduce some of the Go language features being represented. For example:
    * `OAPPEND`, `OCAP`, `OCLEAR`, `OCLOSE`, `OCONV`, `OCOPY`, `ODELETE`, `OLEN`, `OMAKE`, `ONEW`, `OPANIC`, `ORECOVER`: Built-in functions.
    * `OAS`, `OAS2`: Assignment statements.
    * `OBREAK`, `OCONTINUE`, `OFOR`, `OGOTO`, `OIF`, `ORANGE`, `ORETURN`, `OSELECT`, `OSWITCH`: Control flow statements.
    * Operators like `+`, `-`, `*`, `/`, `&&`, `||`, `&`, `|`, `^`.
    * `<-`: Channel receive and send operations.
    * `unsafe` package functions.

8. **Construct Examples:**  Now I can start constructing Go code examples that would likely result in the use of these IR elements. I'd think about simple expressions, assignments, control flow, and built-in functions.

9. **Consider Command-Line Parameters (Less Relevant Here):** The code doesn't explicitly parse command-line arguments. However, the `base.Debug` package is used, suggesting that other parts of the compiler likely use command-line flags to control the level of debugging output.

10. **Identify Potential Pitfalls:**  I look for areas where users of this formatting logic might make mistakes or have unexpected output. The different format verbs and their effects are one such area. The handling of `nil` nodes and the implicit operations are other subtle points.

11. **Refine and Organize:** Finally, I structure my analysis into the requested categories (functionality, Go feature implementation, examples, command-line parameters, and common mistakes), providing clear explanations and code snippets.

**Self-Correction/Refinement during the process:**

* Initially, I might have focused too much on the specific details of each `Op` constant. I realized that focusing on the broader categories of operations and their corresponding Go features is more efficient.
* I noted the comment about inlining and `ninits`. This is a detail that isn't fully handled in the current `fmt` code, indicating a potential area for future development or a current limitation. I decided to mention this as a constraint.
* I considered whether to go into extreme detail about operator precedence. I opted for a more general explanation, as the `OpPrec` array itself is the most comprehensive definition.
* When thinking about examples, I tried to cover a range of common Go constructs to demonstrate the breadth of the `ir` package's representation.
这段代码是Go编译器 `cmd/compile/internal/ir` 包中 `fmt.go` 文件的一部分，它的主要功能是**提供将编译器内部的中间表示（IR，Intermediate Representation）节点格式化为字符串的方法，方便开发者阅读和调试编译器生成的抽象语法树（AST）和进行代码分析。**

具体来说，它实现了以下功能：

1. **定义了操作符的字符串表示：**  `OpNames` 数组将内部的操作符常量（如 `OADD`, `OSUB`, `OCALL` 等）映射到它们在 Go 语言中的语法表示（如 `+`, `-`, `function call`）。

2. **为 `Op` 类型提供格式化方法：**
   - `GoString()` 方法返回操作符的 Go 语法表示。
   - `Format()` 方法实现了 `fmt.Formatter` 接口，允许使用 `fmt.Sprintf` 等函数来格式化 `Op` 类型。它支持两种格式：
     - `%v`:  输出 Go 语法表示（例如：`+`, `<-`, `print`）。
     - `%+v`: 输出调试语法表示（例如：`ADD`, `RECV`, `PRINT`）。

3. **为 `Node` 接口提供核心格式化逻辑：** `fmtNode` 函数实现了 `Node` 接口的格式化。`Node` 是 IR 中所有节点的基接口。
   - `%v`: 输出节点的 Go 语法表示。
   - `%L`: 输出节点的 Go 语法表示，并在已知类型的情况下附加类型信息。
   - `%+v`: 输出节点的调试语法表示，这会调用 `dumpNode` 函数进行更详细的输出。

4. **定义了操作符的优先级：** `OpPrec` 数组定义了不同操作符的优先级，这在格式化表达式时用于决定是否需要添加括号来保证运算顺序的正确性。

5. **区分语句和表达式的格式化：**
   - `stmtFmt` 函数负责格式化语句类型的节点（例如：赋值语句、循环语句、条件语句）。
   - `exprFmt` 函数负责格式化表达式类型的节点（例如：算术表达式、函数调用、字面量）。

6. **提供调试输出功能：**
   - `Dump` 函数打印带有消息的节点调试信息。
   - `DumpList` 和 `FDumpList` 函数打印带有消息的节点列表的调试信息。
   - `dumpNode` 和 `dumpNodes` 函数负责递归地打印节点的详细调试信息，包括节点类型、属性、子节点等。

7. **处理节点的初始化列表：** 代码考虑了语句可能带有初始化列表的情况，并根据情况决定如何格式化输出，以保证语法正确性。

8. **处理内联函数的调用：** 专门的 `OINLCALL` 情况用于格式化内联函数的调用。

**它可以推理出这是 Go 语言编译器内部用于表示和格式化代码的抽象语法树（AST）的一部分。**

**Go 代码举例说明:**

假设我们有以下简单的 Go 代码：

```go
package main

func main() {
	a := 10
	b := a + 5
	println(b)
}
```

当 Go 编译器编译这段代码时，会在内部生成一个 AST。`fmt.go` 中的代码就负责将 AST 中的节点转换为可读的字符串。

**假设的输入与输出（基于调试格式 `%+v`）：**

如果我们在编译过程中使用了调试选项，并尝试打印 `b := a + 5` 这个赋值语句对应的 AST 节点，可能会得到类似以下的输出：

```
OAS-init
.   ODCL-init
.   .   ONAME-a tc(2) #  main.go:3:2
.   .       type *types.Type p(0xc000086000) struct{ kind:6; ... } tc(2)
.   OLITERAL-10 tc(2) #  main.go:3:7
.       type *types.Type p(0xc000086080) int tc(2)
OAS def #  main.go:3:2
.   ONAME-b tc(2) #  main.go:4:2
.       type *types.Type p(0xc000086100) int tc(2)
.   OADD tc(2) #  main.go:4:7
.       type *types.Type p(0xc000086100) int tc(2)
.       ONAME-a tc(2) #  main.go:4:7
.           type *types.Type p(0xc000086000) struct{ kind:6; ... } tc(2)
.       OLITERAL-5 tc(2) #  main.go:4:11
.           type *types.Type p(0xc000086180) int tc(2)
```

**解释:**

* `OAS-init`: 表示这是一个赋值语句 (`OAS`)，并且有初始化部分 (`-init`)。
* `ODCL-init`:  表示初始化部分是一个变量声明 (`ODCL`).
* `ONAME-a`:  表示变量 `a` 的名称节点。
* `OLITERAL-10`: 表示字面量 `10`。
* `OAS def`: 表示一个赋值语句，并且是定义新的变量 (`def`)。
* `ONAME-b`: 表示变量 `b` 的名称节点。
* `OADD`: 表示加法运算。

**假设的输入与输出（基于 Go 语法格式 `%v`）：**

如果使用 `%v` 格式化同样的赋值语句节点，可能会得到：

```
b = a + 5
```

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。但是，Go 编译器 `compile` 命令通常会接受一些与调试和输出相关的参数，这些参数可能会影响到 `fmt.go` 中代码的行为。例如：

* **`-N`**: 禁用优化。这可能会影响到生成的 IR 结构。
* **`-l`**: 禁用内联。这会影响到 `OINLCALL` 节点的生成。
* **`-gcflags`**: 可以传递一些与垃圾回收和代码生成相关的标志，其中可能包含一些影响 IR 生成和输出的标志。
* **内部的调试标志（如 `base.Debug.DumpPtrs`）：** 这些标志通常通过编译器内部的机制进行设置，可能与特定的命令行参数有关，用于控制调试信息的详细程度。

**使用者易犯错的点:**

开发者通常不会直接使用 `cmd/compile/internal/ir/fmt.go` 中的函数，因为这是编译器内部的实现细节。然而，如果开发者尝试编写 Go 编译器的插件或进行深入的编译器分析，可能会遇到以下容易犯错的点：

1. **误解不同格式化动词的含义：**  不清楚 `%v` 和 `%+v` 的区别，导致输出的信息不符合预期。例如，期望看到详细的调试信息却使用了 `%v`。

   ```go
   // 假设 node 是一个 *ir.AssignStmt
   fmt.Printf("%v\n", node)   // 可能输出: b = a + 5
   fmt.Printf("%+v\n", node)  // 可能输出: OAS def # ... (更详细的调试信息)
   ```

2. **依赖于特定的 IR 结构：**  IR 的结构可能会随着 Go 版本的更新而发生变化。直接操作或解析 IR 节点的代码需要注意兼容性问题。

3. **忽略操作符优先级：** 在手动构建或解析 IR 代码时，可能会忘记考虑操作符的优先级，导致生成的代码在语义上出现错误。`OpPrec` 数组提供了这方面的信息。

4. **混淆语句和表达式的格式化：**  尝试使用 `exprFmt` 格式化语句节点或反之，可能会导致输出不完整或格式错误。

总而言之，`go/src/cmd/compile/internal/ir/fmt.go` 是 Go 编译器中至关重要的一个组成部分，它为开发者提供了查看和理解编译器内部工作方式的途径，对于编译器开发、代码优化和静态分析等场景具有重要意义。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ir/fmt.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ir

import (
	"bytes"
	"fmt"
	"go/constant"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"unicode/utf8"

	"cmd/compile/internal/base"
	"cmd/compile/internal/types"
	"cmd/internal/src"
)

// Op

var OpNames = []string{
	OADDR:             "&",
	OADD:              "+",
	OADDSTR:           "+",
	OANDAND:           "&&",
	OANDNOT:           "&^",
	OAND:              "&",
	OAPPEND:           "append",
	OAS:               "=",
	OAS2:              "=",
	OBREAK:            "break",
	OCALL:             "function call", // not actual syntax
	OCAP:              "cap",
	OCASE:             "case",
	OCLEAR:            "clear",
	OCLOSE:            "close",
	OCOMPLEX:          "complex",
	OBITNOT:           "^",
	OCONTINUE:         "continue",
	OCOPY:             "copy",
	ODELETE:           "delete",
	ODEFER:            "defer",
	ODIV:              "/",
	OEQ:               "==",
	OFALL:             "fallthrough",
	OFOR:              "for",
	OGE:               ">=",
	OGOTO:             "goto",
	OGT:               ">",
	OIF:               "if",
	OIMAG:             "imag",
	OINLMARK:          "inlmark",
	ODEREF:            "*",
	OLEN:              "len",
	OLE:               "<=",
	OLSH:              "<<",
	OLT:               "<",
	OMAKE:             "make",
	ONEG:              "-",
	OMAX:              "max",
	OMIN:              "min",
	OMOD:              "%",
	OMUL:              "*",
	ONEW:              "new",
	ONE:               "!=",
	ONOT:              "!",
	OOROR:             "||",
	OOR:               "|",
	OPANIC:            "panic",
	OPLUS:             "+",
	OPRINTLN:          "println",
	OPRINT:            "print",
	ORANGE:            "range",
	OREAL:             "real",
	ORECV:             "<-",
	ORECOVER:          "recover",
	ORETURN:           "return",
	ORSH:              ">>",
	OSELECT:           "select",
	OSEND:             "<-",
	OSUB:              "-",
	OSWITCH:           "switch",
	OUNSAFEADD:        "unsafe.Add",
	OUNSAFESLICE:      "unsafe.Slice",
	OUNSAFESLICEDATA:  "unsafe.SliceData",
	OUNSAFESTRING:     "unsafe.String",
	OUNSAFESTRINGDATA: "unsafe.StringData",
	OXOR:              "^",
}

// GoString returns the Go syntax for the Op, or else its name.
func (o Op) GoString() string {
	if int(o) < len(OpNames) && OpNames[o] != "" {
		return OpNames[o]
	}
	return o.String()
}

// Format implements formatting for an Op.
// The valid formats are:
//
//	%v	Go syntax ("+", "<-", "print")
//	%+v	Debug syntax ("ADD", "RECV", "PRINT")
func (o Op) Format(s fmt.State, verb rune) {
	switch verb {
	default:
		fmt.Fprintf(s, "%%!%c(Op=%d)", verb, int(o))
	case 'v':
		if s.Flag('+') {
			// %+v is OMUL instead of "*"
			io.WriteString(s, o.String())
			return
		}
		io.WriteString(s, o.GoString())
	}
}

// Node

// fmtNode implements formatting for a Node n.
// Every Node implementation must define a Format method that calls fmtNode.
// The valid formats are:
//
//	%v	Go syntax
//	%L	Go syntax followed by " (type T)" if type is known.
//	%+v	Debug syntax, as in Dump.
func fmtNode(n Node, s fmt.State, verb rune) {
	// %+v prints Dump.
	// Otherwise we print Go syntax.
	if s.Flag('+') && verb == 'v' {
		dumpNode(s, n, 1)
		return
	}

	if verb != 'v' && verb != 'S' && verb != 'L' {
		fmt.Fprintf(s, "%%!%c(*Node=%p)", verb, n)
		return
	}

	if n == nil {
		fmt.Fprint(s, "<nil>")
		return
	}

	t := n.Type()
	if verb == 'L' && t != nil {
		if t.Kind() == types.TNIL {
			fmt.Fprint(s, "nil")
		} else if n.Op() == ONAME && n.Name().AutoTemp() {
			fmt.Fprintf(s, "%v value", t)
		} else {
			fmt.Fprintf(s, "%v (type %v)", n, t)
		}
		return
	}

	// TODO inlining produces expressions with ninits. we can't print these yet.

	if OpPrec[n.Op()] < 0 {
		stmtFmt(n, s)
		return
	}

	exprFmt(n, s, 0)
}

var OpPrec = []int{
	OAPPEND:           8,
	OBYTES2STR:        8,
	OARRAYLIT:         8,
	OSLICELIT:         8,
	ORUNES2STR:        8,
	OCALLFUNC:         8,
	OCALLINTER:        8,
	OCALLMETH:         8,
	OCALL:             8,
	OCAP:              8,
	OCLEAR:            8,
	OCLOSE:            8,
	OCOMPLIT:          8,
	OCONVIFACE:        8,
	OCONVNOP:          8,
	OCONV:             8,
	OCOPY:             8,
	ODELETE:           8,
	OGETG:             8,
	OLEN:              8,
	OLITERAL:          8,
	OMAKESLICE:        8,
	OMAKESLICECOPY:    8,
	OMAKE:             8,
	OMAPLIT:           8,
	OMAX:              8,
	OMIN:              8,
	ONAME:             8,
	ONEW:              8,
	ONIL:              8,
	ONONAME:           8,
	OPANIC:            8,
	OPAREN:            8,
	OPRINTLN:          8,
	OPRINT:            8,
	ORUNESTR:          8,
	OSLICE2ARR:        8,
	OSLICE2ARRPTR:     8,
	OSTR2BYTES:        8,
	OSTR2RUNES:        8,
	OSTRUCTLIT:        8,
	OTYPE:             8,
	OUNSAFEADD:        8,
	OUNSAFESLICE:      8,
	OUNSAFESLICEDATA:  8,
	OUNSAFESTRING:     8,
	OUNSAFESTRINGDATA: 8,
	OINDEXMAP:         8,
	OINDEX:            8,
	OSLICE:            8,
	OSLICESTR:         8,
	OSLICEARR:         8,
	OSLICE3:           8,
	OSLICE3ARR:        8,
	OSLICEHEADER:      8,
	OSTRINGHEADER:     8,
	ODOTINTER:         8,
	ODOTMETH:          8,
	ODOTPTR:           8,
	ODOTTYPE2:         8,
	ODOTTYPE:          8,
	ODOT:              8,
	OXDOT:             8,
	OMETHVALUE:        8,
	OMETHEXPR:         8,
	OPLUS:             7,
	ONOT:              7,
	OBITNOT:           7,
	ONEG:              7,
	OADDR:             7,
	ODEREF:            7,
	ORECV:             7,
	OMUL:              6,
	ODIV:              6,
	OMOD:              6,
	OLSH:              6,
	ORSH:              6,
	OAND:              6,
	OANDNOT:           6,
	OADD:              5,
	OSUB:              5,
	OOR:               5,
	OXOR:              5,
	OEQ:               4,
	OLT:               4,
	OLE:               4,
	OGE:               4,
	OGT:               4,
	ONE:               4,
	OSEND:             3,
	OANDAND:           2,
	OOROR:             1,

	// Statements handled by stmtfmt
	OAS:         -1,
	OAS2:        -1,
	OAS2DOTTYPE: -1,
	OAS2FUNC:    -1,
	OAS2MAPR:    -1,
	OAS2RECV:    -1,
	OASOP:       -1,
	OBLOCK:      -1,
	OBREAK:      -1,
	OCASE:       -1,
	OCONTINUE:   -1,
	ODCL:        -1,
	ODEFER:      -1,
	OFALL:       -1,
	OFOR:        -1,
	OGOTO:       -1,
	OIF:         -1,
	OLABEL:      -1,
	OGO:         -1,
	ORANGE:      -1,
	ORETURN:     -1,
	OSELECT:     -1,
	OSWITCH:     -1,

	OEND: 0,
}

// StmtWithInit reports whether op is a statement with an explicit init list.
func StmtWithInit(op Op) bool {
	switch op {
	case OIF, OFOR, OSWITCH:
		return true
	}
	return false
}

func stmtFmt(n Node, s fmt.State) {
	// NOTE(rsc): This code used to support the text-based
	// which was more aggressive about printing full Go syntax
	// (for example, an actual loop instead of "for loop").
	// The code is preserved for now in case we want to expand
	// any of those shortenings later. Or maybe we will delete
	// the code. But for now, keep it.
	const exportFormat = false

	// some statements allow for an init, but at most one,
	// but we may have an arbitrary number added, eg by typecheck
	// and inlining. If it doesn't fit the syntax, emit an enclosing
	// block starting with the init statements.

	// if we can just say "for" n->ninit; ... then do so
	simpleinit := len(n.Init()) == 1 && len(n.Init()[0].Init()) == 0 && StmtWithInit(n.Op())

	// otherwise, print the inits as separate statements
	complexinit := len(n.Init()) != 0 && !simpleinit && exportFormat

	// but if it was for if/for/switch, put in an extra surrounding block to limit the scope
	extrablock := complexinit && StmtWithInit(n.Op())

	if extrablock {
		fmt.Fprint(s, "{")
	}

	if complexinit {
		fmt.Fprintf(s, " %v; ", n.Init())
	}

	switch n.Op() {
	case ODCL:
		n := n.(*Decl)
		fmt.Fprintf(s, "var %v %v", n.X.Sym(), n.X.Type())

	// Don't export "v = <N>" initializing statements, hope they're always
	// preceded by the DCL which will be re-parsed and typechecked to reproduce
	// the "v = <N>" again.
	case OAS:
		n := n.(*AssignStmt)
		if n.Def && !complexinit {
			fmt.Fprintf(s, "%v := %v", n.X, n.Y)
		} else {
			fmt.Fprintf(s, "%v = %v", n.X, n.Y)
		}

	case OASOP:
		n := n.(*AssignOpStmt)
		if n.IncDec {
			if n.AsOp == OADD {
				fmt.Fprintf(s, "%v++", n.X)
			} else {
				fmt.Fprintf(s, "%v--", n.X)
			}
			break
		}

		fmt.Fprintf(s, "%v %v= %v", n.X, n.AsOp, n.Y)

	case OAS2, OAS2DOTTYPE, OAS2FUNC, OAS2MAPR, OAS2RECV:
		n := n.(*AssignListStmt)
		if n.Def && !complexinit {
			fmt.Fprintf(s, "%.v := %.v", n.Lhs, n.Rhs)
		} else {
			fmt.Fprintf(s, "%.v = %.v", n.Lhs, n.Rhs)
		}

	case OBLOCK:
		n := n.(*BlockStmt)
		if len(n.List) != 0 {
			fmt.Fprintf(s, "%v", n.List)
		}

	case ORETURN:
		n := n.(*ReturnStmt)
		fmt.Fprintf(s, "return %.v", n.Results)

	case OTAILCALL:
		n := n.(*TailCallStmt)
		fmt.Fprintf(s, "tailcall %v", n.Call)

	case OINLMARK:
		n := n.(*InlineMarkStmt)
		fmt.Fprintf(s, "inlmark %d", n.Index)

	case OGO:
		n := n.(*GoDeferStmt)
		fmt.Fprintf(s, "go %v", n.Call)

	case ODEFER:
		n := n.(*GoDeferStmt)
		fmt.Fprintf(s, "defer %v", n.Call)

	case OIF:
		n := n.(*IfStmt)
		if simpleinit {
			fmt.Fprintf(s, "if %v; %v { %v }", n.Init()[0], n.Cond, n.Body)
		} else {
			fmt.Fprintf(s, "if %v { %v }", n.Cond, n.Body)
		}
		if len(n.Else) != 0 {
			fmt.Fprintf(s, " else { %v }", n.Else)
		}

	case OFOR:
		n := n.(*ForStmt)
		if !exportFormat { // TODO maybe only if FmtShort, same below
			fmt.Fprintf(s, "for loop")
			break
		}

		fmt.Fprint(s, "for")
		if n.DistinctVars {
			fmt.Fprint(s, " /* distinct */")
		}
		if simpleinit {
			fmt.Fprintf(s, " %v;", n.Init()[0])
		} else if n.Post != nil {
			fmt.Fprint(s, " ;")
		}

		if n.Cond != nil {
			fmt.Fprintf(s, " %v", n.Cond)
		}

		if n.Post != nil {
			fmt.Fprintf(s, "; %v", n.Post)
		} else if simpleinit {
			fmt.Fprint(s, ";")
		}

		fmt.Fprintf(s, " { %v }", n.Body)

	case ORANGE:
		n := n.(*RangeStmt)
		if !exportFormat {
			fmt.Fprint(s, "for loop")
			break
		}

		fmt.Fprint(s, "for")
		if n.Key != nil {
			fmt.Fprintf(s, " %v", n.Key)
			if n.Value != nil {
				fmt.Fprintf(s, ", %v", n.Value)
			}
			fmt.Fprint(s, " =")
		}
		fmt.Fprintf(s, " range %v { %v }", n.X, n.Body)
		if n.DistinctVars {
			fmt.Fprint(s, " /* distinct vars */")
		}

	case OSELECT:
		n := n.(*SelectStmt)
		if !exportFormat {
			fmt.Fprintf(s, "%v statement", n.Op())
			break
		}
		fmt.Fprintf(s, "select { %v }", n.Cases)

	case OSWITCH:
		n := n.(*SwitchStmt)
		if !exportFormat {
			fmt.Fprintf(s, "%v statement", n.Op())
			break
		}
		fmt.Fprintf(s, "switch")
		if simpleinit {
			fmt.Fprintf(s, " %v;", n.Init()[0])
		}
		if n.Tag != nil {
			fmt.Fprintf(s, " %v ", n.Tag)
		}
		fmt.Fprintf(s, " { %v }", n.Cases)

	case OCASE:
		n := n.(*CaseClause)
		if len(n.List) != 0 {
			fmt.Fprintf(s, "case %.v", n.List)
		} else {
			fmt.Fprint(s, "default")
		}
		fmt.Fprintf(s, ": %v", n.Body)

	case OBREAK, OCONTINUE, OGOTO, OFALL:
		n := n.(*BranchStmt)
		if n.Label != nil {
			fmt.Fprintf(s, "%v %v", n.Op(), n.Label)
		} else {
			fmt.Fprintf(s, "%v", n.Op())
		}

	case OLABEL:
		n := n.(*LabelStmt)
		fmt.Fprintf(s, "%v: ", n.Label)
	}

	if extrablock {
		fmt.Fprint(s, "}")
	}
}

func exprFmt(n Node, s fmt.State, prec int) {
	// NOTE(rsc): This code used to support the text-based
	// which was more aggressive about printing full Go syntax
	// (for example, an actual loop instead of "for loop").
	// The code is preserved for now in case we want to expand
	// any of those shortenings later. Or maybe we will delete
	// the code. But for now, keep it.
	const exportFormat = false

	for {
		if n == nil {
			fmt.Fprint(s, "<nil>")
			return
		}

		// Skip implicit operations introduced during typechecking.
		switch nn := n; nn.Op() {
		case OADDR:
			nn := nn.(*AddrExpr)
			if nn.Implicit() {
				n = nn.X
				continue
			}
		case ODEREF:
			nn := nn.(*StarExpr)
			if nn.Implicit() {
				n = nn.X
				continue
			}
		case OCONV, OCONVNOP, OCONVIFACE:
			nn := nn.(*ConvExpr)
			if nn.Implicit() {
				n = nn.X
				continue
			}
		}

		break
	}

	nprec := OpPrec[n.Op()]
	if n.Op() == OTYPE && n.Type() != nil && n.Type().IsPtr() {
		nprec = OpPrec[ODEREF]
	}

	if prec > nprec {
		fmt.Fprintf(s, "(%v)", n)
		return
	}

	switch n.Op() {
	case OPAREN:
		n := n.(*ParenExpr)
		fmt.Fprintf(s, "(%v)", n.X)

	case ONIL:
		fmt.Fprint(s, "nil")

	case OLITERAL:
		if n.Sym() != nil {
			fmt.Fprint(s, n.Sym())
			return
		}

		typ := n.Type()
		val := n.Val()

		// Special case for rune constants.
		if typ == types.RuneType || typ == types.UntypedRune {
			if x, ok := constant.Uint64Val(val); ok && x <= utf8.MaxRune {
				fmt.Fprintf(s, "%q", x)
				return
			}
		}

		// Only include typ if it's neither the default nor untyped type
		// for the constant value.
		if k := val.Kind(); typ == types.Types[types.DefaultKinds[k]] || typ == types.UntypedTypes[k] {
			fmt.Fprint(s, val)
		} else {
			fmt.Fprintf(s, "%v(%v)", typ, val)
		}

	case ODCLFUNC:
		n := n.(*Func)
		if sym := n.Sym(); sym != nil {
			fmt.Fprint(s, sym)
			return
		}
		fmt.Fprintf(s, "<unnamed Func>")

	case ONAME:
		n := n.(*Name)
		// Special case: name used as local variable in export.
		// _ becomes ~b%d internally; print as _ for export
		if !exportFormat && n.Sym() != nil && n.Sym().Name[0] == '~' && n.Sym().Name[1] == 'b' {
			fmt.Fprint(s, "_")
			return
		}
		fallthrough
	case ONONAME:
		fmt.Fprint(s, n.Sym())

	case OLINKSYMOFFSET:
		n := n.(*LinksymOffsetExpr)
		fmt.Fprintf(s, "(%v)(%s@%d)", n.Type(), n.Linksym.Name, n.Offset_)

	case OTYPE:
		if n.Type() == nil && n.Sym() != nil {
			fmt.Fprint(s, n.Sym())
			return
		}
		fmt.Fprintf(s, "%v", n.Type())

	case OCLOSURE:
		n := n.(*ClosureExpr)
		if !exportFormat {
			fmt.Fprint(s, "func literal")
			return
		}
		fmt.Fprintf(s, "%v { %v }", n.Type(), n.Func.Body)

	case OPTRLIT:
		n := n.(*AddrExpr)
		fmt.Fprintf(s, "&%v", n.X)

	case OCOMPLIT, OSTRUCTLIT, OARRAYLIT, OSLICELIT, OMAPLIT:
		n := n.(*CompLitExpr)
		if n.Implicit() {
			fmt.Fprintf(s, "... argument")
			return
		}
		fmt.Fprintf(s, "%v{%s}", n.Type(), ellipsisIf(len(n.List) != 0))

	case OKEY:
		n := n.(*KeyExpr)
		if n.Key != nil && n.Value != nil {
			fmt.Fprintf(s, "%v:%v", n.Key, n.Value)
			return
		}

		if n.Key == nil && n.Value != nil {
			fmt.Fprintf(s, ":%v", n.Value)
			return
		}
		if n.Key != nil && n.Value == nil {
			fmt.Fprintf(s, "%v:", n.Key)
			return
		}
		fmt.Fprint(s, ":")

	case OSTRUCTKEY:
		n := n.(*StructKeyExpr)
		fmt.Fprintf(s, "%v:%v", n.Field, n.Value)

	case OXDOT, ODOT, ODOTPTR, ODOTINTER, ODOTMETH, OMETHVALUE, OMETHEXPR:
		n := n.(*SelectorExpr)
		exprFmt(n.X, s, nprec)
		if n.Sel == nil {
			fmt.Fprint(s, ".<nil>")
			return
		}
		fmt.Fprintf(s, ".%s", n.Sel.Name)

	case ODOTTYPE, ODOTTYPE2:
		n := n.(*TypeAssertExpr)
		exprFmt(n.X, s, nprec)
		fmt.Fprintf(s, ".(%v)", n.Type())

	case OINDEX, OINDEXMAP:
		n := n.(*IndexExpr)
		exprFmt(n.X, s, nprec)
		fmt.Fprintf(s, "[%v]", n.Index)

	case OSLICE, OSLICESTR, OSLICEARR, OSLICE3, OSLICE3ARR:
		n := n.(*SliceExpr)
		exprFmt(n.X, s, nprec)
		fmt.Fprint(s, "[")
		if n.Low != nil {
			fmt.Fprint(s, n.Low)
		}
		fmt.Fprint(s, ":")
		if n.High != nil {
			fmt.Fprint(s, n.High)
		}
		if n.Op().IsSlice3() {
			fmt.Fprint(s, ":")
			if n.Max != nil {
				fmt.Fprint(s, n.Max)
			}
		}
		fmt.Fprint(s, "]")

	case OSLICEHEADER:
		n := n.(*SliceHeaderExpr)
		fmt.Fprintf(s, "sliceheader{%v,%v,%v}", n.Ptr, n.Len, n.Cap)

	case OCOMPLEX, OCOPY, OUNSAFEADD, OUNSAFESLICE:
		n := n.(*BinaryExpr)
		fmt.Fprintf(s, "%v(%v, %v)", n.Op(), n.X, n.Y)

	case OCONV,
		OCONVIFACE,
		OCONVNOP,
		OBYTES2STR,
		ORUNES2STR,
		OSTR2BYTES,
		OSTR2RUNES,
		ORUNESTR,
		OSLICE2ARR,
		OSLICE2ARRPTR:
		n := n.(*ConvExpr)
		if n.Type() == nil || n.Type().Sym() == nil {
			fmt.Fprintf(s, "(%v)", n.Type())
		} else {
			fmt.Fprintf(s, "%v", n.Type())
		}
		fmt.Fprintf(s, "(%v)", n.X)

	case OREAL,
		OIMAG,
		OCAP,
		OCLEAR,
		OCLOSE,
		OLEN,
		ONEW,
		OPANIC:
		n := n.(*UnaryExpr)
		fmt.Fprintf(s, "%v(%v)", n.Op(), n.X)

	case OAPPEND,
		ODELETE,
		OMAKE,
		OMAX,
		OMIN,
		ORECOVER,
		OPRINT,
		OPRINTLN:
		n := n.(*CallExpr)
		if n.IsDDD {
			fmt.Fprintf(s, "%v(%.v...)", n.Op(), n.Args)
			return
		}
		fmt.Fprintf(s, "%v(%.v)", n.Op(), n.Args)

	case OCALL, OCALLFUNC, OCALLINTER, OCALLMETH, OGETG:
		n := n.(*CallExpr)
		exprFmt(n.Fun, s, nprec)
		if n.IsDDD {
			fmt.Fprintf(s, "(%.v...)", n.Args)
			return
		}
		fmt.Fprintf(s, "(%.v)", n.Args)

	case OINLCALL:
		n := n.(*InlinedCallExpr)
		// TODO(mdempsky): Print Init and/or Body?
		if len(n.ReturnVars) == 1 {
			fmt.Fprintf(s, "%v", n.ReturnVars[0])
			return
		}
		fmt.Fprintf(s, "(.%v)", n.ReturnVars)

	case OMAKEMAP, OMAKECHAN, OMAKESLICE:
		n := n.(*MakeExpr)
		if n.Cap != nil {
			fmt.Fprintf(s, "make(%v, %v, %v)", n.Type(), n.Len, n.Cap)
			return
		}
		if n.Len != nil && (n.Op() == OMAKESLICE || !n.Len.Type().IsUntyped()) {
			fmt.Fprintf(s, "make(%v, %v)", n.Type(), n.Len)
			return
		}
		fmt.Fprintf(s, "make(%v)", n.Type())

	case OMAKESLICECOPY:
		n := n.(*MakeExpr)
		fmt.Fprintf(s, "makeslicecopy(%v, %v, %v)", n.Type(), n.Len, n.Cap)

	case OPLUS, ONEG, OBITNOT, ONOT, ORECV:
		// Unary
		n := n.(*UnaryExpr)
		fmt.Fprintf(s, "%v", n.Op())
		if n.X != nil && n.X.Op() == n.Op() {
			fmt.Fprint(s, " ")
		}
		exprFmt(n.X, s, nprec+1)

	case OADDR:
		n := n.(*AddrExpr)
		fmt.Fprintf(s, "%v", n.Op())
		if n.X != nil && n.X.Op() == n.Op() {
			fmt.Fprint(s, " ")
		}
		exprFmt(n.X, s, nprec+1)

	case ODEREF:
		n := n.(*StarExpr)
		fmt.Fprintf(s, "%v", n.Op())
		exprFmt(n.X, s, nprec+1)

		// Binary
	case OADD,
		OAND,
		OANDNOT,
		ODIV,
		OEQ,
		OGE,
		OGT,
		OLE,
		OLT,
		OLSH,
		OMOD,
		OMUL,
		ONE,
		OOR,
		ORSH,
		OSUB,
		OXOR:
		n := n.(*BinaryExpr)
		exprFmt(n.X, s, nprec)
		fmt.Fprintf(s, " %v ", n.Op())
		exprFmt(n.Y, s, nprec+1)

	case OANDAND,
		OOROR:
		n := n.(*LogicalExpr)
		exprFmt(n.X, s, nprec)
		fmt.Fprintf(s, " %v ", n.Op())
		exprFmt(n.Y, s, nprec+1)

	case OSEND:
		n := n.(*SendStmt)
		exprFmt(n.Chan, s, nprec)
		fmt.Fprintf(s, " <- ")
		exprFmt(n.Value, s, nprec+1)

	case OADDSTR:
		n := n.(*AddStringExpr)
		for i, n1 := range n.List {
			if i != 0 {
				fmt.Fprint(s, " + ")
			}
			exprFmt(n1, s, nprec)
		}
	default:
		fmt.Fprintf(s, "<node %v>", n.Op())
	}
}

func ellipsisIf(b bool) string {
	if b {
		return "..."
	}
	return ""
}

// Nodes

// Format implements formatting for a Nodes.
// The valid formats are:
//
//	%v	Go syntax, semicolon-separated
//	%.v	Go syntax, comma-separated
//	%+v	Debug syntax, as in DumpList.
func (l Nodes) Format(s fmt.State, verb rune) {
	if s.Flag('+') && verb == 'v' {
		// %+v is DumpList output
		dumpNodes(s, l, 1)
		return
	}

	if verb != 'v' {
		fmt.Fprintf(s, "%%!%c(Nodes)", verb)
		return
	}

	sep := "; "
	if _, ok := s.Precision(); ok { // %.v is expr list
		sep = ", "
	}

	for i, n := range l {
		fmt.Fprint(s, n)
		if i+1 < len(l) {
			fmt.Fprint(s, sep)
		}
	}
}

// Dump

// Dump prints the message s followed by a debug dump of n.
func Dump(s string, n Node) {
	fmt.Printf("%s%+v\n", s, n)
}

// DumpList prints the message s followed by a debug dump of each node in the list.
func DumpList(s string, list Nodes) {
	var buf bytes.Buffer
	FDumpList(&buf, s, list)
	os.Stdout.Write(buf.Bytes())
}

// FDumpList prints to w the message s followed by a debug dump of each node in the list.
func FDumpList(w io.Writer, s string, list Nodes) {
	io.WriteString(w, s)
	dumpNodes(w, list, 1)
	io.WriteString(w, "\n")
}

// indent prints indentation to w.
func indent(w io.Writer, depth int) {
	fmt.Fprint(w, "\n")
	for i := 0; i < depth; i++ {
		fmt.Fprint(w, ".   ")
	}
}

// EscFmt is set by the escape analysis code to add escape analysis details to the node print.
var EscFmt func(n Node) string

// dumpNodeHeader prints the debug-format node header line to w.
func dumpNodeHeader(w io.Writer, n Node) {
	// Useful to see which nodes in an AST printout are actually identical
	if base.Debug.DumpPtrs != 0 {
		fmt.Fprintf(w, " p(%p)", n)
	}

	if base.Debug.DumpPtrs != 0 && n.Name() != nil && n.Name().Defn != nil {
		// Useful to see where Defn is set and what node it points to
		fmt.Fprintf(w, " defn(%p)", n.Name().Defn)
	}

	if base.Debug.DumpPtrs != 0 && n.Name() != nil && n.Name().Curfn != nil {
		// Useful to see where Defn is set and what node it points to
		fmt.Fprintf(w, " curfn(%p)", n.Name().Curfn)
	}
	if base.Debug.DumpPtrs != 0 && n.Name() != nil && n.Name().Outer != nil {
		// Useful to see where Defn is set and what node it points to
		fmt.Fprintf(w, " outer(%p)", n.Name().Outer)
	}

	if EscFmt != nil {
		if esc := EscFmt(n); esc != "" {
			fmt.Fprintf(w, " %s", esc)
		}
	}

	if n.Sym() != nil && n.Op() != ONAME && n.Op() != ONONAME && n.Op() != OTYPE {
		fmt.Fprintf(w, " %+v", n.Sym())
	}

	// Print Node-specific fields of basic type in header line.
	v := reflect.ValueOf(n).Elem()
	t := v.Type()
	nf := t.NumField()
	for i := 0; i < nf; i++ {
		tf := t.Field(i)
		if tf.PkgPath != "" {
			// skip unexported field - Interface will fail
			continue
		}
		k := tf.Type.Kind()
		if reflect.Bool <= k && k <= reflect.Complex128 {
			name := strings.TrimSuffix(tf.Name, "_")
			vf := v.Field(i)
			vfi := vf.Interface()
			if name == "Offset" && vfi == types.BADWIDTH || name != "Offset" && vf.IsZero() {
				continue
			}
			if vfi == true {
				fmt.Fprintf(w, " %s", name)
			} else {
				fmt.Fprintf(w, " %s:%+v", name, vf.Interface())
			}
		}
	}

	// Print Node-specific booleans by looking for methods.
	// Different v, t from above - want *Struct not Struct, for methods.
	v = reflect.ValueOf(n)
	t = v.Type()
	nm := t.NumMethod()
	for i := 0; i < nm; i++ {
		tm := t.Method(i)
		if tm.PkgPath != "" {
			// skip unexported method - call will fail
			continue
		}
		m := v.Method(i)
		mt := m.Type()
		if mt.NumIn() == 0 && mt.NumOut() == 1 && mt.Out(0).Kind() == reflect.Bool {
			// TODO(rsc): Remove the func/defer/recover wrapping,
			// which is guarding against panics in miniExpr,
			// once we get down to the simpler state in which
			// nodes have no getter methods that aren't allowed to be called.
			func() {
				defer func() { recover() }()
				if m.Call(nil)[0].Bool() {
					name := strings.TrimSuffix(tm.Name, "_")
					fmt.Fprintf(w, " %s", name)
				}
			}()
		}
	}

	if n.Op() == OCLOSURE {
		n := n.(*ClosureExpr)
		if fn := n.Func; fn != nil && fn.Nname.Sym() != nil {
			fmt.Fprintf(w, " fnName(%+v)", fn.Nname.Sym())
		}
	}

	if n.Type() != nil {
		if n.Op() == OTYPE {
			fmt.Fprintf(w, " type")
		}
		fmt.Fprintf(w, " %+v", n.Type())
	}
	if n.Typecheck() != 0 {
		fmt.Fprintf(w, " tc(%d)", n.Typecheck())
	}

	if n.Pos().IsKnown() {
		fmt.Fprint(w, " # ")
		switch n.Pos().IsStmt() {
		case src.PosNotStmt:
			fmt.Fprint(w, "_") // "-" would be confusing
		case src.PosIsStmt:
			fmt.Fprint(w, "+")
		}
		sep := ""
		base.Ctxt.AllPos(n.Pos(), func(pos src.Pos) {
			fmt.Fprint(w, sep)
			sep = " "
			// TODO(mdempsky): Print line pragma details too.
			file := filepath.Base(pos.Filename())
			// Note: this output will be parsed by ssa/html.go:(*HTMLWriter).WriteAST. Keep in sync.
			fmt.Fprintf(w, "%s:%d:%d", file, pos.Line(), pos.Col())
		})
	}
}

func dumpNode(w io.Writer, n Node, depth int) {
	indent(w, depth)
	if depth > 40 {
		fmt.Fprint(w, "...")
		return
	}

	if n == nil {
		fmt.Fprint(w, "NilIrNode")
		return
	}

	if len(n.Init()) != 0 {
		fmt.Fprintf(w, "%+v-init", n.Op())
		dumpNodes(w, n.Init(), depth+1)
		indent(w, depth)
	}

	switch n.Op() {
	default:
		fmt.Fprintf(w, "%+v", n.Op())
		dumpNodeHeader(w, n)

	case OLITERAL:
		fmt.Fprintf(w, "%+v-%v", n.Op(), n.Val())
		dumpNodeHeader(w, n)
		return

	case ONAME, ONONAME:
		if n.Sym() != nil {
			fmt.Fprintf(w, "%+v-%+v", n.Op(), n.Sym())
		} else {
			fmt.Fprintf(w, "%+v", n.Op())
		}
		dumpNodeHeader(w, n)
		return

	case OLINKSYMOFFSET:
		n := n.(*LinksymOffsetExpr)
		fmt.Fprintf(w, "%+v-%v", n.Op(), n.Linksym)
		// Offset is almost always 0, so only print when it's interesting.
		if n.Offset_ != 0 {
			fmt.Fprintf(w, "%+v", n.Offset_)
		}
		dumpNodeHeader(w, n)

	case OASOP:
		n := n.(*AssignOpStmt)
		fmt.Fprintf(w, "%+v-%+v", n.Op(), n.AsOp)
		dumpNodeHeader(w, n)

	case OTYPE:
		fmt.Fprintf(w, "%+v %+v", n.Op(), n.Sym())
		dumpNodeHeader(w, n)
		return

	case OCLOSURE:
		fmt.Fprintf(w, "%+v", n.Op())
		dumpNodeHeader(w, n)

	case ODCLFUNC:
		// Func has many fields we don't want to print.
		// Bypass reflection and just print what we want.
		n := n.(*Func)
		fmt.Fprintf(w, "%+v", n.Op())
		dumpNodeHeader(w, n)
		fn := n
		if len(fn.Dcl) > 0 {
			indent(w, depth)
			fmt.Fprintf(w, "%+v-Dcl", n.Op())
			for _, dcl := range n.Dcl {
				dumpNode(w, dcl, depth+1)
			}
		}
		if len(fn.ClosureVars) > 0 {
			indent(w, depth)
			fmt.Fprintf(w, "%+v-ClosureVars", n.Op())
			for _, cv := range fn.ClosureVars {
				dumpNode(w, cv, depth+1)
			}
		}
		if len(fn.Body) > 0 {
			indent(w, depth)
			fmt.Fprintf(w, "%+v-body", n.Op())
			dumpNodes(w, fn.Body, depth+1)
		}
		return
	}

	v := reflect.ValueOf(n).Elem()
	t := reflect.TypeOf(n).Elem()
	nf := t.NumField()
	for i := 0; i < nf; i++ {
		tf := t.Field(i)
		vf := v.Field(i)
		if tf.PkgPath != "" {
			// skip unexported field - Interface will fail
			continue
		}
		switch tf.Type.Kind() {
		case reflect.Interface, reflect.Ptr, reflect.Slice:
			if vf.IsNil() {
				continue
			}
		}
		name := strings.TrimSuffix(tf.Name, "_")
		// Do not bother with field name header lines for the
		// most common positional arguments: unary, binary expr,
		// index expr, send stmt, go and defer call expression.
		switch name {
		case "X", "Y", "Index", "Chan", "Value", "Call":
			name = ""
		}
		switch val := vf.Interface().(type) {
		case Node:
			if name != "" {
				indent(w, depth)
				fmt.Fprintf(w, "%+v-%s", n.Op(), name)
			}
			dumpNode(w, val, depth+1)
		case Nodes:
			if len(val) == 0 {
				continue
			}
			if name != "" {
				indent(w, depth)
				fmt.Fprintf(w, "%+v-%s", n.Op(), name)
			}
			dumpNodes(w, val, depth+1)
		default:
			if vf.Kind() == reflect.Slice && vf.Type().Elem().Implements(nodeType) {
				if vf.Len() == 0 {
					continue
				}
				if name != "" {
					indent(w, depth)
					fmt.Fprintf(w, "%+v-%s", n.Op(), name)
				}
				for i, n := 0, vf.Len(); i < n; i++ {
					dumpNode(w, vf.Index(i).Interface().(Node), depth+1)
				}
			}
		}
	}
}

var nodeType = reflect.TypeOf((*Node)(nil)).Elem()

func dumpNodes(w io.Writer, list Nodes, depth int) {
	if len(list) == 0 {
		fmt.Fprintf(w, " <nil>")
		return
	}

	for _, n := range list {
		dumpNode(w, n, depth)
	}
}

"""



```