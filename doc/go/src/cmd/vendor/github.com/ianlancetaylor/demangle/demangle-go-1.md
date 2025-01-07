Response:
Let's break down the thought process for analyzing this Go code snippet and answering the user's request.

**1. Understanding the Request:**

The core request is to understand the functionality of this Go code, specifically a part of a demangler. The user wants to know:

* **Functionality:** What does this specific code do?
* **Go Feature:** Which Go language feature does it relate to (if any)?
* **Examples:**  Code examples demonstrating the functionality.
* **Command-line Arguments:** How does it handle command-line arguments?
* **Common Mistakes:**  What errors do users make?
* **Summary:** A concise summary of its function.

The user explicitly states this is part 2 of 2, implying the context of part 1 is relevant, even though we don't have it here. This snippet focuses on the expression demangling part.

**2. Initial Code Scan and Keyword Spotting:**

The first step is to quickly read through the code, looking for keywords and patterns that suggest functionality. I see:

* **`st *state`:** This suggests a stateful parsing process. The `state` struct likely holds the mangled string and other parsing information.
* **`st.advance(...)`:**  Indicates moving through the input string.
* **`st.fail(...)`:**  Suggests error handling during parsing.
* **`st.demangleType(...)`:** Clearly related to demangling type information.
* **`st.expression()`:**  Recursive call, indicating expression parsing is hierarchical.
* **`st.number()`, `st.compactNumber()`:** Parsing numeric values.
* **`st.operatorName(...)`:** Parsing operator names.
* **`st.templateArgs()`:** Parsing template arguments.
* **`st.sourceName()`:** Parsing source names (identifiers).
* **`AST`:**  A type likely representing the Abstract Syntax Tree of the demangled expression.
* **Structs like `FunctionParam`, `PtrMemCast`, `Unary`, `Binary`, `Trinary`, `New`, `Subobject`, `RequiresExpr`, `Literal`, `Closure`, `TemplateParamName`, `UnnamedType`, `Clone`:** These represent different kinds of expressions and names in C++.
* **Keywords like `if`, `else if`:**  Indicate conditional parsing based on the input string's structure.

**3. Grouping Functionality by `if/else if` Blocks:**

The code is structured with a large `if/else if` chain within the `expression()` function. Each block handles a specific pattern in the mangled name. This is the key to understanding the individual functionalities. I'd mentally (or actually) group these blocks:

* **`isDigit(st.str[2])`:** Looks like handling function parameters.
* **`st.str[0] == 'm' && st.str[1] == 'c'`:**  Pointer-to-member casts.
* **`isDigit(st.str[0]) || (st.str[0] == 'o' && ...)`:** Unqualified names and operator functions.
* **`(st.str[0] == 'i' || st.str[0] == 't') && ...`:** Initializer lists.
* **`st.str[0] == 's' && st.str[1] == 't'`:**  `sizeof` operator.
* **`st.str[0] == 'u'`:** Vendor-specific extensions (likely LLVM's `__uuidof`).
* **`st.str[0] == 'r' && (st.str[1] == 'q' || st.str[1] == 'Q')`:**  Requires expressions (C++20 concepts).
* **The final `else` block:**  A catch-all for various operators (unary, binary, trinary, `new`, `delete`).

**4. Connecting to C++ Concepts:**

As I analyze each `if/else if` block, I try to connect the mangling patterns with corresponding C++ language features. This requires some knowledge of C++ name mangling conventions (although the code itself provides strong hints):

* **Digits after a prefix:** Often indicate backreferences or indices.
* **`mc`:**  Likely related to member pointers and casts.
* **`on`:**  Operator name.
* **`il` or `tl`:** Initializer list.
* **`st`:**  `sizeof`.
* **`u`:**  Extensions.
* **`rq` or `rQ`:** Requires clauses.
* **`pp`, `mm`:** Increment/decrement operators.
* **`sc`, `dc`, `cc`, `rc`:**  Static, dynamic, const, reinterpret casts.
* **`cl`, `cp`:** Function call and pointer-to-member call.
* **`dt`, `pt`:** Member access (dot and arrow).
* **`nw`, `na`:** `new` and `new[]`.
* **`dl`, `da`:** `delete` and `delete[]`.

**5. Formulating Examples (Mental or Actual Code):**

For each identified C++ feature, I would think of a simple C++ code example and how its mangled name might look (even if I don't know the exact mangling rules). This helps in understanding the purpose of the code block. For example:

* **Function Parameter:** `void foo(int arg)`  -> mangled name might contain an index referring to `arg`.
* **Pointer-to-Member Cast:** `(int Class::*)ptr` -> mangled name might have `mc` followed by type and expression.
* **Initializer List:** `std::vector<int> v = {1, 2, 3};` -> mangled name might have `il` followed by the list elements.
* **Requires Expression:** `template<typename T> concept Addable = requires(T a, T b) { a + b; };` -> mangled name likely starts with `rq` or `rQ`.

**6. Command-line Arguments and Common Mistakes:**

Since this is just a snippet of the `demangle.go` file, I can't see the command-line argument parsing directly. I would infer that there might be options to control the demangling process (like verbosity), but I can't be specific without the surrounding code.

Common mistakes in *using* a demangler usually involve:

* **Providing an incorrect or incomplete mangled name.**
* **Not understanding the specific mangling scheme used by the compiler.**
* **Expecting perfect demangling for all possible C++ constructs (demangling can be complex and sometimes lossy).**

However, the question asks for mistakes in *using* the *Go code*, which is more about the API if this were exposed as a library. Since it's likely an internal part of a larger tool, common mistakes might be less relevant here.

**7. Synthesizing the Summary:**

Finally, I would combine the understanding gained from the previous steps into a concise summary of the code's functionality. The key is to highlight that it's responsible for parsing the expression part of a mangled C++ symbol name, identifying different types of expressions (function parameters, casts, operators, etc.) based on prefixes in the mangled string.

**Self-Correction/Refinement During the Process:**

* **Initially, I might not recognize all the mangling prefixes.** I'd refer to C++ name mangling documentation or look for patterns in the code.
* **If a code block is unclear, I'd look at the `AST` struct definitions** to see what kind of information is being extracted.
* **The "vendor extended expression" part (`st.str[0] == 'u'`) might be initially ambiguous.** I'd notice the `__uuidof` special case and realize it's handling compiler-specific extensions.
* **The `substitution()` function suggests that mangled names can have references to previously seen components.** This adds another layer of complexity to the demangling process.

By following these steps, combining code analysis, C++ knowledge, and a bit of inference, I can arrive at a comprehensive understanding of the provided Go code snippet and formulate the detailed answer provided previously.
这是路径为go/src/cmd/vendor/github.com/ianlancetaylor/demangle/demangle.go的go语言实现的一部分， 请列举一下它的功能,

* **解析函数参数引用:**  当遇到特定的编码模式（以数字开头，后跟 'p'）时，解析对函数参数的引用。它提取参数的索引。

* **解析指针到成员的转换:**  当遇到 "mc" 前缀时，解析从一种类型到指向其成员的指针的转换。它提取目标类型、被转换的表达式以及可能的偏移量。

* **解析非限定名称和运算符函数:** 解析不带作用域限定的名称。如果遇到 "on" 前缀，则解析运算符函数。如果名称后跟 'I'，则表示这是一个模板，并解析模板参数。

* **解析初始化列表:** 当遇到 "il" 或 "tl" 前缀时，解析用花括号括起来的初始化列表。它会区分是否有类型信息。

* **解析 `sizeof` 运算符:** 当遇到 "st" 前缀时，解析 `sizeof` 运算符，提取其操作数的类型。

* **解析供应商扩展表达式 (例如 `__uuidof`):** 当遇到 "u" 前缀时，处理供应商特定的表达式。一个特殊的例子是 `__uuidof`，它可以后跟类型或表达式。

* **解析 requires 表达式 (C++20 Concepts):** 当遇到 "rq" 或 "rQ" 前缀时，解析 C++20 的 requires 表达式，提取参数和各种 requirement（表达式、类型、嵌套）。

* **解析各种运算符:**  当遇到其他特定的双字符前缀时，解析各种 C++ 运算符，包括：
    * **空操作符 (Nullary):** 例如 `new`，`delete` 的基本形式。
    * **一元操作符 (Unary):** 例如前缀和后缀的 `++` 和 `--`，以及类型转换。
    * **二元操作符 (Binary):** 例如加法、减法、赋值、比较等。
    * **三元操作符 (Trinary):** 例如条件运算符 `?:`。
    * **带有 placement 的 new 表达式 (New with placement):**  解析带有额外参数的 `new` 表达式。
    * **折叠表达式 (Fold Expressions):**  解析 C++17 的折叠表达式。

* **解析子对象:** 当遇到 "so" 前缀时，解析对子对象的引用，提取类型、子表达式、偏移量和 union 选择器。

* **解析未决名称:**  当遇到 "sr" 或 "gs" 前缀时，解析尚未完全解析的名称，可能包含模板参数。这部分处理了各种不同的未决名称的编码方式，包括全局作用域和带作用域的名称。

* **解析基本未决名称:**  解析未决名称的核心部分，可能是简单标识符、运算符名称或析构函数名称。

* **解析主表达式 (Primary Expression):** 当遇到 "L" 前缀时，解析主表达式，例如字面量（数字、浮点数）、字符串字面量或者 mangled 的名称。

* **解析鉴别符 (Discriminator):**  解析附加在名称后面的用于区分重载函数的数字。

* **解析闭包类型名称 (Closure Type Name / Lambda):**  当遇到 "Ul" 前缀时，解析 lambda 表达式的类型名称，包括模板参数和函数签名。

* **解析模板参数声明:**  解析模板参数的声明，包括类型参数、带约束的类型参数、非类型参数、模板模板参数和参数包。

* **解析未命名类型名称:** 当遇到 "Ut" 前缀时，解析未命名的类型（通常是编译器生成的）。

* **解析约束表达式:** 当遇到 "Q" 前缀时，解析约束表达式（用于 C++20 concepts）。

* **识别克隆后缀:** 识别 GCC 在克隆函数时添加的特殊后缀。

* **处理 substitution (替换):**  当遇到 "S" 前缀时，处理对之前解析过的 AST 节点的引用，避免重复解析。

如果你能推理出它是什么go语言功能的实现，请用go代码举例说明,

这段代码是 C++ 符号名称 **demangling（反修饰）** 功能的实现。C++ 编译器为了支持函数重载、命名空间、模板等特性，会对符号名称进行编码（mangling），使得在链接时能够区分不同的实体。demangling 的过程就是将这种编码后的名称还原成人类可读的形式。

虽然这段代码是用 Go 写的，但它旨在解析和理解 C++ 的 mangled name 格式。因此，Go 语言本身并没有直接对应的 "demangling" 功能。这段代码是为一个工具或库提供解析 C++ 符号名称的能力。

**Go 代码示例（展示 demangling 的概念，而非直接使用这段代码）:**

假设我们有一个 C++ 的 mangled name，例如 `_Z3fooi` (表示一个接受 `int` 类型参数的函数 `foo`)。  demangling 的目标是将它转换为 `foo(int)`。

```go
package main

import (
	"fmt"
	"regexp"
	"strings"
)

// 简单的 C++ demangler 示例 (仅用于演示概念，并非真实实现)
func simpleCPPDemangle(mangled string) string {
	if strings.HasPrefix(mangled, "_Z") {
		// 移除前缀
		rest := mangled[2:]

		// 简单假设：数字表示函数名长度
		nameLenStr := ""
		for _, r := range rest {
			if r >= '0' && r <= '9' {
				nameLenStr += string(r)
			} else {
				break
			}
		}
		if nameLenStr == "" {
			return mangled // 无法解析
		}
		nameLen := 0
		fmt.Sscan(nameLenStr, &nameLen)
		rest = rest[len(nameLenStr):]

		if len(rest) < nameLen {
			return mangled // 无法解析
		}
		functionName := rest[:nameLen]
		rest = rest[nameLen:]

		// 简单假设：'i' 表示 int
		parameters := ""
		for _, r := range rest {
			if r == 'i' {
				parameters += "int"
				break // 假设只有一个参数
			} else {
				break
			}
		}

		return fmt.Sprintf("%s(%s)", functionName, parameters)
	}
	return mangled // 不是 mangled name
}

func main() {
	mangledName := "_Z3fooi"
	demangledName := simpleCPPDemangle(mangledName)
	fmt.Printf("Mangled: %s\nDemangled: %s\n", mangledName, demangledName)
}
```

**假设的输入与输出：**

* **输入:** `_Z3fooi`
* **输出:** `foo(int)`

**请注意：** 上面的 Go 代码只是一个非常简化的示例，用于说明 demangling 的基本概念。真实的 C++ demangling 非常复杂，需要处理各种不同的 mangling 规则。 `demangle.go` 中的代码就是这样一个更完整和健壮的实现。

如果涉及命令行参数的具体处理，请详细介绍一下，

由于你提供的只是 `demangle.go` 文件的一部分，并没有包含处理命令行参数的代码。通常，命令行参数的处理会在 `main` 函数或者相关的入口点中进行。

一般来说，一个使用 `demangle.go` 库的命令行工具可能会使用 `flag` 包来处理命令行参数。  可能的命令行参数包括：

* **要 demangle 的 mangled name:**  这是最基本的参数，通常是一个或多个字符串。
* **`-v` 或 `--verbose`:**  启用详细输出，可能会显示更多的 demangling 细节。 正如代码中看到的 `st.verbose` 字段，这个参数会影响某些 substitution 的输出形式。
* **`-s` 或 `--simplify`:**  简化输出，去除不必要的模板参数或限定符。
* **`--format=plain|gnu-v3`:**  指定输出格式，例如 `plain` 是简单的形式，`gnu-v3` 模拟 `c++filt` 的输出。
* **`- کمک` 或 `--help`:** 显示帮助信息。

**假设的命令行工具使用方式：**

```bash
# demangle 单个 mangled name
demangler _Z3fooi

# demangle 多个 mangled names
demangler _Z3fooi _ZN3BarIiE4testEv

# 使用 verbose 输出
demangler -v _ZN3BarIiE4testEv

# 指定输出格式
demangler --format=gnu-v3 _Z3fooi
```

**`demangle.go` 代码中可能涉及的命令行参数影响：**

在提供的代码片段中，可以看到 `st *state` 结构体被用作解析状态的载体。 这个 `state` 结构体很可能包含了从命令行参数中读取的配置信息，例如 `st.verbose`。

* **`st.verbose`:**  在 `substitution()` 函数中被使用。如果 `st.verbose` 为真，某些标准库类型的 substitution 将会展开成更长的形式，模拟 `c++filt -v` 的行为。

```go
// ... 在 substitution 函数中
	m := subAST
	if st.verbose {
		m = verboseAST
	}
// ...
```

如果没有哪些使用者易犯错的点，请举例说明，没有则不必说明，

**使用者易犯错的点：**

* **提供不完整的或错误的 Mangled Name:**  C++ 的 mangled name 格式非常复杂，细微的错误或截断都可能导致 demangling 失败。 例如，如果用户只复制了部分 mangled name，或者在复制过程中引入了空格或错误字符，demangler 就无法正确解析。
    * **示例:**  用户想 demangle `_ZN3BarIiE4testEv`，但错误地输入了 `_ZN3BarI`，demangler 会报错或者给出不正确的结果。

* **期望完美的 Demangling 适用于所有情况:**  虽然 demangling 工具尽力还原原始名称，但某些极端复杂的 C++ 构造，或者某些编译器特定的 mangling 方式，可能无法完全准确地 demangle。 用户可能会期望 demangler 能够处理所有情况，但实际并非如此。
    * **示例:**  某些使用了非常规模板或复杂的类型推导的函数，其 demangled name 可能与原始声明略有不同。

* **混淆不同编译器的 Mangling 规则:** 不同的 C++ 编译器（例如 GCC、Clang、MSVC）使用不同的 mangling 规则。 为一个编译器生成的 mangled name 使用另一个编译器的 demangler 可能会失败或产生错误的结果。  `demangle.go` 的目标是解析 GCC 和 Clang 的 mangled names，因此它可能无法处理 MSVC 的 mangled names。
    * **示例:**  尝试使用 `demangle.go` 去 demangle 由 MSVC 编译器生成的 mangled name。

* **不理解 Demangling 的局限性:**  Demangling 的目的是将编码后的名称转换回可读的形式，但它并不总是能还原所有的类型信息或模板参数的默认值。 用户可能会期望 demangler 能够提供比实际更多的信息。

这是第2部分，共2部分，请归纳一下它的功能

总的来说，这段 Go 代码（`demangle.go` 的一部分）的核心功能是 **解析和理解 C++ 编译器生成的 mangled name 中代表表达式的部分**。

它能够识别并解码各种 C++ 表达式的编码模式，包括：

* **函数参数引用**
* **指针到成员的转换**
* **非限定名称和运算符函数**
* **初始化列表**
* **`sizeof` 运算符**
* **供应商特定的扩展表达式 (例如 `__uuidof`)**
* **C++20 的 requires 表达式**
* **各种一元、二元和三元运算符**
* **带有 placement 的 `new` 表达式**
* **折叠表达式**
* **子对象引用**
* **未决名称**
* **基本未决名称**
* **字面量等主表达式**
* **lambda 表达式的类型名称**
* **模板参数声明**
* **未命名类型**
* **约束表达式**

此外，它还处理了 **substitution (替换)** 机制，用于引用之前解析过的部分，以及识别 **GCC 的克隆函数后缀**。

结合第一部分（虽然我们没有看到），可以推测 `demangle.go` 完整的目的是提供一个 **C++ mangled name 的 demangler 库**，能够将编译器编码后的符号名称转换回人类可读的 C++ 声明形式。  `st.verbose` 字段暗示了它可能支持不同的输出详细程度。

Prompt: 
```
这是路径为go/src/cmd/vendor/github.com/ianlancetaylor/demangle/demangle.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

"""
isDigit(st.str[2]) {
		st.advance(2)
		// We don't include the scope count in the demangled string.
		st.number()
		if len(st.str) == 0 || st.str[0] != 'p' {
			st.fail("expected p after function parameter scope count")
		}
		st.advance(1)
		// We can see qualifiers here, but we don't include them
		// in the demangled string.
		st.cvQualifiers()
		index := st.compactNumber()
		return &FunctionParam{Index: index + 1}
	} else if st.str[0] == 'm' && len(st.str) > 1 && st.str[1] == 'c' {
		st.advance(2)
		typ := st.demangleType(false)
		expr := st.expression()
		offset := 0
		if len(st.str) > 0 && (st.str[0] == 'n' || isDigit(st.str[0])) {
			offset = st.number()
		}
		if len(st.str) == 0 || st.str[0] != 'E' {
			st.fail("expected E after pointer-to-member conversion")
		}
		st.advance(1)
		return &PtrMemCast{
			Type:   typ,
			Expr:   expr,
			Offset: offset,
		}
	} else if isDigit(st.str[0]) || (st.str[0] == 'o' && len(st.str) > 1 && st.str[1] == 'n') {
		if st.str[0] == 'o' {
			// Skip operator function ID.
			st.advance(2)
		}
		n, _ := st.unqualifiedName(nil)
		if len(st.str) > 0 && st.str[0] == 'I' {
			args := st.templateArgs()
			n = &Template{Name: n, Args: args}
		}
		return n
	} else if (st.str[0] == 'i' || st.str[0] == 't') && len(st.str) > 1 && st.str[1] == 'l' {
		// Brace-enclosed initializer list.
		c := st.str[0]
		st.advance(2)
		var t AST
		if c == 't' {
			t = st.demangleType(false)
		}
		exprs := st.exprList('E')
		return &InitializerList{Type: t, Exprs: exprs}
	} else if st.str[0] == 's' && len(st.str) > 1 && st.str[1] == 't' {
		o, _ := st.operatorName(true)
		t := st.demangleType(false)
		return &Unary{Op: o, Expr: t, Suffix: false, SizeofType: true}
	} else if st.str[0] == 'u' {
		st.advance(1)
		name := st.sourceName()
		// Special case __uuidof followed by type or
		// expression, as used by LLVM.
		if n, ok := name.(*Name); ok && n.Name == "__uuidof" {
			if len(st.str) < 2 {
				st.fail("missing uuidof argument")
			}
			var operand AST
			if st.str[0] == 't' {
				st.advance(1)
				operand = st.demangleType(false)
			} else if st.str[0] == 'z' {
				st.advance(1)
				operand = st.expression()
			}
			if operand != nil {
				return &Binary{
					Op:   &Operator{Name: "()"},
					Left: name,
					Right: &ExprList{
						Exprs: []AST{operand},
					},
				}
			}
		}
		var args []AST
		for {
			if len(st.str) == 0 {
				st.fail("missing argument in vendor extended expressoin")
			}
			if st.str[0] == 'E' {
				st.advance(1)
				break
			}
			arg := st.templateArg(nil)
			args = append(args, arg)
		}
		return &Binary{
			Op:    &Operator{Name: "()"},
			Left:  name,
			Right: &ExprList{Exprs: args},
		}
	} else if st.str[0] == 'r' && len(st.str) > 1 && (st.str[1] == 'q' || st.str[1] == 'Q') {
		return st.requiresExpr()
	} else {
		if len(st.str) < 2 {
			st.fail("missing operator code")
		}
		code := st.str[:2]
		o, args := st.operatorName(true)
		switch args {
		case 0:
			return &Nullary{Op: o}

		case 1:
			suffix := false
			if code == "pp" || code == "mm" {
				if len(st.str) > 0 && st.str[0] == '_' {
					st.advance(1)
				} else {
					suffix = true
				}
			}
			var operand AST
			if _, ok := o.(*Cast); ok && len(st.str) > 0 && st.str[0] == '_' {
				st.advance(1)
				operand = st.exprList('E')
			} else {
				operand = st.expression()
			}
			return &Unary{Op: o, Expr: operand, Suffix: suffix, SizeofType: false}

		case 2:
			var left, right AST
			if code == "sc" || code == "dc" || code == "cc" || code == "rc" {
				left = st.demangleType(false)
			} else if code[0] == 'f' {
				left, _ = st.operatorName(true)
				right = st.expression()
				return &Fold{Left: code[1] == 'l', Op: left, Arg1: right, Arg2: nil}
			} else if code == "di" {
				left, _ = st.unqualifiedName(nil)
			} else {
				left = st.expression()
			}
			if code == "cl" || code == "cp" {
				right = st.exprList('E')
			} else if code == "dt" || code == "pt" {
				if len(st.str) > 0 && st.str[0] == 'L' {
					right = st.exprPrimary()
				} else {
					right = st.unresolvedName()
					if len(st.str) > 0 && st.str[0] == 'I' {
						args := st.templateArgs()
						right = &Template{Name: right, Args: args}
					}
				}
			} else {
				right = st.expression()
			}
			return &Binary{Op: o, Left: left, Right: right}

		case 3:
			if code[0] == 'n' {
				if code[1] != 'w' && code[1] != 'a' {
					panic("internal error")
				}
				place := st.exprList('_')
				if place.(*ExprList).Exprs == nil {
					place = nil
				}
				t := st.demangleType(false)
				var ini AST
				if len(st.str) > 0 && st.str[0] == 'E' {
					st.advance(1)
				} else if len(st.str) > 1 && st.str[0] == 'p' && st.str[1] == 'i' {
					// Parenthesized initializer.
					st.advance(2)
					ini = st.exprList('E')
				} else if len(st.str) > 1 && st.str[0] == 'i' && st.str[1] == 'l' {
					// Initializer list.
					ini = st.expression()
				} else {
					st.fail("unrecognized new initializer")
				}
				return &New{Op: o, Place: place, Type: t, Init: ini}
			} else if code[0] == 'f' {
				first, _ := st.operatorName(true)
				second := st.expression()
				third := st.expression()
				return &Fold{Left: code[1] == 'L', Op: first, Arg1: second, Arg2: third}
			} else {
				first := st.expression()
				second := st.expression()
				third := st.expression()
				return &Trinary{Op: o, First: first, Second: second, Third: third}
			}

		default:
			st.fail(fmt.Sprintf("unsupported number of operator arguments: %d", args))
			panic("not reached")
		}
	}
}

// subobject parses:
//
//	<expression> ::= so <referent type> <expr> [<offset number>] <union-selector>* [p] E
//	<union-selector> ::= _ [<number>]
func (st *state) subobject() AST {
	typ := st.demangleType(false)
	expr := st.expression()
	offset := 0
	if len(st.str) > 0 && (st.str[0] == 'n' || isDigit(st.str[0])) {
		offset = st.number()
	}
	var selectors []int
	for len(st.str) > 0 && st.str[0] == '_' {
		st.advance(1)
		selector := 0
		if len(st.str) > 0 && (st.str[0] == 'n' || isDigit(st.str[0])) {
			selector = st.number()
		}
		selectors = append(selectors, selector)
	}
	pastEnd := false
	if len(st.str) > 0 && st.str[0] == 'p' {
		st.advance(1)
		pastEnd = true
	}
	if len(st.str) == 0 || st.str[0] != 'E' {
		st.fail("expected E after subobject")
	}
	st.advance(1)
	return &Subobject{
		Type:      typ,
		SubExpr:   expr,
		Offset:    offset,
		Selectors: selectors,
		PastEnd:   pastEnd,
	}
}

// unresolvedName parses:
//
//	<unresolved-name> ::= [gs] <base-unresolved-name>
//	                  ::= sr <unresolved-type> <base-unresolved-name>
//	                  ::= srN <unresolved-type> <unresolved-qualifier-level>+ E <base-unresolved-name>
//	                  ::= [gs] sr <unresolved-qualifier-level>+ E <base-unresolved-name>
func (st *state) unresolvedName() AST {
	if len(st.str) >= 2 && st.str[:2] == "gs" {
		st.advance(2)
		n := st.unresolvedName()
		return &Unary{
			Op:         &Operator{Name: "::"},
			Expr:       n,
			Suffix:     false,
			SizeofType: false,
		}
	} else if len(st.str) >= 2 && st.str[:2] == "sr" {
		st.advance(2)
		if len(st.str) == 0 {
			st.fail("expected unresolved type")
		}
		switch st.str[0] {
		case 'T', 'D', 'S':
			t := st.demangleType(false)
			n := st.baseUnresolvedName()
			n = &Qualified{Scope: t, Name: n, LocalName: false}
			if len(st.str) > 0 && st.str[0] == 'I' {
				args := st.templateArgs()
				n = &Template{Name: n, Args: args}
				st.subs.add(n)
			}
			return n
		default:
			var s AST
			if st.str[0] == 'N' {
				st.advance(1)
				s = st.demangleType(false)
			}
			for len(st.str) == 0 || st.str[0] != 'E' {
				// GCC does not seem to follow the ABI here.
				// It can emit type/name without an 'E'.
				if s != nil && len(st.str) > 0 && !isDigit(st.str[0]) {
					if q, ok := s.(*Qualified); ok {
						a := q.Scope
						if t, ok := a.(*Template); ok {
							st.subs.add(t.Name)
							st.subs.add(t)
						} else {
							st.subs.add(a)
						}
						return s
					}
				}
				n := st.sourceName()
				if len(st.str) > 0 && st.str[0] == 'I' {
					st.subs.add(n)
					args := st.templateArgs()
					n = &Template{Name: n, Args: args}
				}
				if s == nil {
					s = n
				} else {
					s = &Qualified{Scope: s, Name: n, LocalName: false}
				}
			}
			if s == nil {
				st.fail("missing scope in unresolved name")
			}
			st.advance(1)
			n := st.baseUnresolvedName()
			return &Qualified{Scope: s, Name: n, LocalName: false}
		}
	} else {
		return st.baseUnresolvedName()
	}
}

// baseUnresolvedName parses:
//
//	<base-unresolved-name> ::= <simple-id>
//	                       ::= on <operator-name>
//	                       ::= on <operator-name> <template-args>
//	                       ::= dn <destructor-name>
//
//	<simple-id> ::= <source-name> [ <template-args> ]
func (st *state) baseUnresolvedName() AST {
	var n AST
	if len(st.str) >= 2 && st.str[:2] == "on" {
		st.advance(2)
		n, _ = st.operatorName(true)
	} else if len(st.str) >= 2 && st.str[:2] == "dn" {
		st.advance(2)
		if len(st.str) > 0 && isDigit(st.str[0]) {
			n = st.sourceName()
		} else {
			n = st.demangleType(false)
		}
		n = &Destructor{Name: n}
	} else if len(st.str) > 0 && isDigit(st.str[0]) {
		n = st.sourceName()
	} else {
		// GCC seems to not follow the ABI here: it can have
		// an operator name without on.
		// See https://gcc.gnu.org/PR70182.
		n, _ = st.operatorName(true)
	}
	if len(st.str) > 0 && st.str[0] == 'I' {
		args := st.templateArgs()
		n = &Template{Name: n, Args: args}
	}
	return n
}

// requiresExpr parses:
//
//	<expression> ::= rQ <bare-function-type> _ <requirement>+ E
//	             ::= rq <requirement>+ E
//	<requirement> ::= X <expression> [N] [R <type-constraint>]
//	              ::= T <type>
//	              ::= Q <constraint-expression>
func (st *state) requiresExpr() AST {
	st.checkChar('r')
	if len(st.str) == 0 || (st.str[0] != 'q' && st.str[0] != 'Q') {
		st.fail("expected q or Q in requires clause in expression")
	}
	kind := st.str[0]
	st.advance(1)

	var params []AST
	if kind == 'Q' {
		for len(st.str) > 0 && st.str[0] != '_' {
			typ := st.demangleType(false)
			params = append(params, typ)
		}
		st.advance(1)
	}

	var requirements []AST
	for len(st.str) > 0 && st.str[0] != 'E' {
		var req AST
		switch st.str[0] {
		case 'X':
			st.advance(1)
			expr := st.expression()
			var noexcept bool
			if len(st.str) > 0 && st.str[0] == 'N' {
				st.advance(1)
				noexcept = true
			}
			var typeReq AST
			if len(st.str) > 0 && st.str[0] == 'R' {
				st.advance(1)
				typeReq, _ = st.name()
			}
			req = &ExprRequirement{
				Expr:     expr,
				Noexcept: noexcept,
				TypeReq:  typeReq,
			}

		case 'T':
			st.advance(1)
			typ := st.demangleType(false)
			req = &TypeRequirement{Type: typ}

		case 'Q':
			st.advance(1)
			// We parse a regular expression rather than a
			// constraint expression.
			expr := st.expression()
			req = &NestedRequirement{Constraint: expr}

		default:
			st.fail("unrecognized requirement code")
		}

		requirements = append(requirements, req)
	}

	if len(st.str) == 0 || st.str[0] != 'E' {
		st.fail("expected E after requirements")
	}
	st.advance(1)

	return &RequiresExpr{
		Params:       params,
		Requirements: requirements,
	}
}

// exprPrimary parses:
//
//	<expr-primary> ::= L <type> <(value) number> E
//	               ::= L <type> <(value) float> E
//	               ::= L <mangled-name> E
func (st *state) exprPrimary() AST {
	st.checkChar('L')
	if len(st.str) == 0 {
		st.fail("expected primary expression")

	}

	// Check for 'Z' here because g++ incorrectly omitted the
	// underscore until -fabi-version=3.
	var ret AST
	if st.str[0] == '_' || st.str[0] == 'Z' {
		if st.str[0] == '_' {
			st.advance(1)
		}
		if len(st.str) == 0 || st.str[0] != 'Z' {
			st.fail("expected mangled name")
		}
		st.advance(1)
		ret = st.encoding(true, notForLocalName)
	} else {
		t := st.demangleType(false)

		isArrayType := func(typ AST) bool {
			if twq, ok := typ.(*TypeWithQualifiers); ok {
				typ = twq.Base
			}
			_, ok := typ.(*ArrayType)
			return ok
		}

		neg := false
		if len(st.str) > 0 && st.str[0] == 'n' {
			neg = true
			st.advance(1)
		}
		if len(st.str) > 0 && st.str[0] == 'E' {
			if bt, ok := t.(*BuiltinType); ok && bt.Name == "decltype(nullptr)" {
				// A nullptr should not have a value.
				// We accept one if present because GCC
				// used to generate one.
				// https://gcc.gnu.org/PR91979.
			} else if cl, ok := t.(*Closure); ok {
				// A closure doesn't have a value.
				st.advance(1)
				return &LambdaExpr{Type: cl}
			} else if isArrayType(t) {
				st.advance(1)
				return &StringLiteral{Type: t}
			} else {
				st.fail("missing literal value")
			}
		}
		i := 0
		for len(st.str) > i && st.str[i] != 'E' {
			i++
		}
		val := st.str[:i]
		st.advance(i)
		ret = &Literal{Type: t, Val: val, Neg: neg}
	}
	if len(st.str) == 0 || st.str[0] != 'E' {
		st.fail("expected E after literal")
	}
	st.advance(1)
	return ret
}

// discriminator parses:
//
//	<discriminator> ::= _ <(non-negative) number> (when number < 10)
//	                    __ <(non-negative) number> _ (when number >= 10)
func (st *state) discriminator(a AST) AST {
	if len(st.str) == 0 || st.str[0] != '_' {
		// clang can generate a discriminator at the end of
		// the string with no underscore.
		for i := 0; i < len(st.str); i++ {
			if !isDigit(st.str[i]) {
				return a
			}
		}
		// Skip the trailing digits.
		st.advance(len(st.str))
		return a
	}
	off := st.off
	st.advance(1)
	trailingUnderscore := false
	if len(st.str) > 0 && st.str[0] == '_' {
		st.advance(1)
		trailingUnderscore = true
	}
	d := st.number()
	if d < 0 {
		st.failEarlier("invalid negative discriminator", st.off-off)
	}
	if trailingUnderscore && d >= 10 {
		if len(st.str) == 0 || st.str[0] != '_' {
			st.fail("expected _ after discriminator >= 10")
		}
		st.advance(1)
	}
	// We don't currently print out the discriminator, so we don't
	// save it.
	return a
}

// closureTypeName parses:
//
//	<closure-type-name> ::= Ul <lambda-sig> E [ <nonnegative number> ] _
//	<lambda-sig> ::= <parameter type>+
func (st *state) closureTypeName() AST {
	st.checkChar('U')
	st.checkChar('l')

	oldLambdaTemplateLevel := st.lambdaTemplateLevel
	st.lambdaTemplateLevel = len(st.templates) + 1

	var templateArgs []AST
	var template *Template
	for len(st.str) > 1 && st.str[0] == 'T' {
		arg, templateVal := st.templateParamDecl()
		if arg == nil {
			break
		}
		templateArgs = append(templateArgs, arg)
		if template == nil {
			template = &Template{
				Name: &Name{Name: "lambda"},
			}
			st.templates = append(st.templates, template)
		}
		template.Args = append(template.Args, templateVal)
	}

	var templateArgsConstraint AST
	if len(st.str) > 0 && st.str[0] == 'Q' {
		templateArgsConstraint = st.constraintExpr()
	}

	types := st.parmlist(false)

	st.lambdaTemplateLevel = oldLambdaTemplateLevel

	if template != nil {
		st.templates = st.templates[:len(st.templates)-1]
	}

	var callConstraint AST
	if len(st.str) > 0 && st.str[0] == 'Q' {
		callConstraint = st.constraintExpr()
	}

	if len(st.str) == 0 || st.str[0] != 'E' {
		st.fail("expected E after closure type name")
	}
	st.advance(1)
	num := st.compactNumber()
	return &Closure{
		TemplateArgs:           templateArgs,
		TemplateArgsConstraint: templateArgsConstraint,
		Types:                  types,
		Num:                    num,
		CallConstraint:         callConstraint,
	}
}

// templateParamDecl parses:
//
//	<template-param-decl> ::= Ty                          # type parameter
//	                      ::= Tk <concept name> [<template-args>] # constrained type parameter
//	                      ::= Tn <type>                   # non-type parameter
//	                      ::= Tt <template-param-decl>* E # template parameter
//	                      ::= Tp <template-param-decl>    # parameter pack
//
// Returns the new AST to include in the AST we are building and the
// new AST to add to the list of template parameters.
//
// Returns nil, nil if not looking at a template-param-decl.
func (st *state) templateParamDecl() (AST, AST) {
	if len(st.str) < 2 || st.str[0] != 'T' {
		return nil, nil
	}
	mk := func(prefix string, p *int) AST {
		idx := *p
		(*p)++
		return &TemplateParamName{
			Prefix: prefix,
			Index:  idx,
		}
	}
	switch st.str[1] {
	case 'y':
		st.advance(2)
		name := mk("$T", &st.typeTemplateParamCount)
		tp := &TypeTemplateParam{
			Name: name,
		}
		return tp, name
	case 'k':
		// We don't track enclosing template parameter levels.
		// Don't try to demangle template parameter substitutions
		// in constraints.
		hold := st.parsingConstraint
		st.parsingConstraint = true
		defer func() { st.parsingConstraint = hold }()

		st.advance(2)
		constraint, _ := st.name()
		name := mk("$T", &st.typeTemplateParamCount)
		tp := &ConstrainedTypeTemplateParam{
			Name:       name,
			Constraint: constraint,
		}
		return tp, name
	case 'n':
		st.advance(2)
		name := mk("$N", &st.nonTypeTemplateParamCount)
		typ := st.demangleType(false)
		tp := &NonTypeTemplateParam{
			Name: name,
			Type: typ,
		}
		return tp, name
	case 't':
		st.advance(2)
		name := mk("$TT", &st.templateTemplateParamCount)
		var params []AST
		var template *Template
		var constraint AST
		for {
			if len(st.str) == 0 {
				st.fail("expected closure template parameter")
			}
			if st.str[0] == 'E' {
				st.advance(1)
				break
			}
			off := st.off
			param, templateVal := st.templateParamDecl()
			if param == nil {
				st.failEarlier("expected closure template parameter", st.off-off)
			}
			params = append(params, param)
			if template == nil {
				template = &Template{
					Name: &Name{Name: "template_template"},
				}
				st.templates = append(st.templates, template)
			}
			template.Args = append(template.Args, templateVal)

			if len(st.str) > 0 && st.str[0] == 'Q' {
				// A list of template template
				// parameters can have a constraint.
				constraint = st.constraintExpr()
				if len(st.str) == 0 || st.str[0] != 'E' {
					st.fail("expected end of template template parameters after constraint")
				}
			}
		}
		if template != nil {
			st.templates = st.templates[:len(st.templates)-1]
		}
		tp := &TemplateTemplateParam{
			Name:       name,
			Params:     params,
			Constraint: constraint,
		}
		return tp, name
	case 'p':
		st.advance(2)
		off := st.off
		param, templateVal := st.templateParamDecl()
		if param == nil {
			st.failEarlier("expected lambda template parameter", st.off-off)
		}
		return &TemplateParamPack{Param: param}, templateVal
	default:
		return nil, nil
	}
}

// unnamedTypeName parses:
//
//	<unnamed-type-name> ::= Ut [ <nonnegative number> ] _
func (st *state) unnamedTypeName() AST {
	st.checkChar('U')
	st.checkChar('t')
	num := st.compactNumber()
	ret := &UnnamedType{Num: num}
	st.subs.add(ret)
	return ret
}

// constraintExpr parses a constraint expression. This is just a
// regular expression, but template parameters are handled specially.
func (st *state) constraintExpr() AST {
	st.checkChar('Q')

	hold := st.parsingConstraint
	st.parsingConstraint = true
	defer func() { st.parsingConstraint = hold }()

	return st.expression()
}

// Recognize a clone suffix.  These are not part of the mangling API,
// but are added by GCC when cloning functions.
func (st *state) cloneSuffix(a AST) AST {
	i := 0
	if len(st.str) > 1 && st.str[0] == '.' && (isLower(st.str[1]) || isDigit(st.str[1]) || st.str[1] == '_') {
		i += 2
		for len(st.str) > i && (isLower(st.str[i]) || isDigit(st.str[i]) || st.str[i] == '_') {
			i++
		}
	}
	for len(st.str) > i+1 && st.str[i] == '.' && isDigit(st.str[i+1]) {
		i += 2
		for len(st.str) > i && isDigit(st.str[i]) {
			i++
		}
	}
	suffix := st.str[:i]
	st.advance(i)
	return &Clone{Base: a, Suffix: suffix}
}

// substitutions is the list of substitution candidates that may
// appear later in the string.
type substitutions []AST

// add adds a new substitution candidate.
func (subs *substitutions) add(a AST) {
	*subs = append(*subs, a)
}

// subAST maps standard substitution codes to the corresponding AST.
var subAST = map[byte]AST{
	't': &Name{Name: "std"},
	'a': &Qualified{Scope: &Name{Name: "std"}, Name: &Name{Name: "allocator"}},
	'b': &Qualified{Scope: &Name{Name: "std"}, Name: &Name{Name: "basic_string"}},
	's': &Qualified{Scope: &Name{Name: "std"}, Name: &Name{Name: "string"}},
	'i': &Qualified{Scope: &Name{Name: "std"}, Name: &Name{Name: "istream"}},
	'o': &Qualified{Scope: &Name{Name: "std"}, Name: &Name{Name: "ostream"}},
	'd': &Qualified{Scope: &Name{Name: "std"}, Name: &Name{Name: "iostream"}},
}

// verboseAST maps standard substitution codes to the long form of the
// corresponding AST.  We use this when the Verbose option is used, to
// match the standard demangler.
var verboseAST = map[byte]AST{
	't': &Name{Name: "std"},
	'a': &Qualified{Scope: &Name{Name: "std"}, Name: &Name{Name: "allocator"}},
	'b': &Qualified{Scope: &Name{Name: "std"}, Name: &Name{Name: "basic_string"}},

	// std::basic_string<char, std::char_traits<char>, std::allocator<char> >
	's': &Template{
		Name: &Qualified{Scope: &Name{Name: "std"}, Name: &Name{Name: "basic_string"}},
		Args: []AST{
			&BuiltinType{Name: "char"},
			&Template{
				Name: &Qualified{Scope: &Name{Name: "std"}, Name: &Name{Name: "char_traits"}},
				Args: []AST{&BuiltinType{Name: "char"}}},
			&Template{
				Name: &Qualified{Scope: &Name{Name: "std"}, Name: &Name{Name: "allocator"}},
				Args: []AST{&BuiltinType{Name: "char"}}}}},
	// std::basic_istream<char, std::char_traits<char> >
	'i': &Template{
		Name: &Qualified{Scope: &Name{Name: "std"}, Name: &Name{Name: "basic_istream"}},
		Args: []AST{
			&BuiltinType{Name: "char"},
			&Template{
				Name: &Qualified{Scope: &Name{Name: "std"}, Name: &Name{Name: "char_traits"}},
				Args: []AST{&BuiltinType{Name: "char"}}}}},
	// std::basic_ostream<char, std::char_traits<char> >
	'o': &Template{
		Name: &Qualified{Scope: &Name{Name: "std"}, Name: &Name{Name: "basic_ostream"}},
		Args: []AST{
			&BuiltinType{Name: "char"},
			&Template{
				Name: &Qualified{Scope: &Name{Name: "std"}, Name: &Name{Name: "char_traits"}},
				Args: []AST{&BuiltinType{Name: "char"}}}}},
	// std::basic_iostream<char, std::char_traits<char> >
	'd': &Template{
		Name: &Qualified{Scope: &Name{Name: "std"}, Name: &Name{Name: "basic_iostream"}},
		Args: []AST{
			&BuiltinType{Name: "char"},
			&Template{
				Name: &Qualified{Scope: &Name{Name: "std"}, Name: &Name{Name: "char_traits"}},
				Args: []AST{&BuiltinType{Name: "char"}}}}},
}

// substitution parses:
//
//	<substitution> ::= S <seq-id> _
//	               ::= S_
//	               ::= St
//	               ::= Sa
//	               ::= Sb
//	               ::= Ss
//	               ::= Si
//	               ::= So
//	               ::= Sd
func (st *state) substitution(forPrefix bool) AST {
	st.checkChar('S')
	if len(st.str) == 0 {
		st.fail("missing substitution index")
	}
	c := st.str[0]
	off := st.off
	if c == '_' || isDigit(c) || isUpper(c) {
		id := st.seqID(false)
		if id >= len(st.subs) {
			st.failEarlier(fmt.Sprintf("substitution index out of range (%d >= %d)", id, len(st.subs)), st.off-off)
		}

		ret := st.subs[id]

		// We need to update any references to template
		// parameters to refer to the currently active
		// template.

		// When copying a Typed we may need to adjust
		// the templates.
		copyTemplates := st.templates
		var oldLambdaTemplateLevel []int

		// pushTemplate is called from skip, popTemplate from copy.
		pushTemplate := func(template *Template) {
			copyTemplates = append(copyTemplates, template)
			oldLambdaTemplateLevel = append(oldLambdaTemplateLevel, st.lambdaTemplateLevel)
			st.lambdaTemplateLevel = 0
		}
		popTemplate := func() {
			copyTemplates = copyTemplates[:len(copyTemplates)-1]
			st.lambdaTemplateLevel = oldLambdaTemplateLevel[len(oldLambdaTemplateLevel)-1]
			oldLambdaTemplateLevel = oldLambdaTemplateLevel[:len(oldLambdaTemplateLevel)-1]
		}

		copy := func(a AST) AST {
			var index int
			switch a := a.(type) {
			case *Typed:
				// Remove the template added in skip.
				if _, ok := a.Name.(*Template); ok {
					popTemplate()
				}
				return nil
			case *Closure:
				// Undo the save in skip.
				st.lambdaTemplateLevel = oldLambdaTemplateLevel[len(oldLambdaTemplateLevel)-1]
				oldLambdaTemplateLevel = oldLambdaTemplateLevel[:len(oldLambdaTemplateLevel)-1]
				return nil
			case *TemplateParam:
				index = a.Index
			case *LambdaAuto:
				// A lambda auto parameter is represented
				// as a template parameter, so we may have
				// to change back when substituting.
				index = a.Index
			default:
				return nil
			}
			if st.parsingConstraint {
				// We don't try to substitute template
				// parameters in a constraint expression.
				return &Name{Name: fmt.Sprintf("T%d", index)}
			}
			if st.lambdaTemplateLevel > 0 {
				if _, ok := a.(*LambdaAuto); ok {
					return nil
				}
				return &LambdaAuto{Index: index}
			}
			var template *Template
			if len(copyTemplates) > 0 {
				template = copyTemplates[len(copyTemplates)-1]
			} else if rt, ok := ret.(*Template); ok {
				// At least with clang we can see a template
				// to start, and sometimes we need to refer
				// to it. There is probably something wrong
				// here.
				template = rt
			} else {
				st.failEarlier("substituted template parameter not in scope of template", st.off-off)
			}
			if template == nil {
				// This template parameter is within
				// the scope of a cast operator.
				return &TemplateParam{Index: index, Template: nil}
			}

			if index >= len(template.Args) {
				st.failEarlier(fmt.Sprintf("substituted template index out of range (%d >= %d)", index, len(template.Args)), st.off-off)
			}

			return &TemplateParam{Index: index, Template: template}
		}
		seen := make(map[AST]bool)
		skip := func(a AST) bool {
			switch a := a.(type) {
			case *Typed:
				if template, ok := a.Name.(*Template); ok {
					// This template is removed in copy.
					pushTemplate(template)
				}
				return false
			case *Closure:
				// This is undone in copy.
				oldLambdaTemplateLevel = append(oldLambdaTemplateLevel, st.lambdaTemplateLevel)
				st.lambdaTemplateLevel = len(copyTemplates) + 1
				return false
			case *TemplateParam, *LambdaAuto:
				return false
			}
			if seen[a] {
				return true
			}
			seen[a] = true
			return false
		}

		if c := ret.Copy(copy, skip); c != nil {
			return c
		}

		return ret
	} else {
		st.advance(1)
		m := subAST
		if st.verbose {
			m = verboseAST
		}
		// For compatibility with the standard demangler, use
		// a longer name for a constructor or destructor.
		if forPrefix && len(st.str) > 0 && (st.str[0] == 'C' || st.str[0] == 'D') {
			m = verboseAST
		}
		a, ok := m[c]
		if !ok {
			st.failEarlier("unrecognized substitution code", 1)
		}

		if len(st.str) > 0 && st.str[0] == 'B' {
			a = st.taggedName(a)
			st.subs.add(a)
		}

		return a
	}
}

// isDigit returns whetner c is a digit for demangling purposes.
func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

// isUpper returns whether c is an upper case letter for demangling purposes.
func isUpper(c byte) bool {
	return c >= 'A' && c <= 'Z'
}

// isLower returns whether c is a lower case letter for demangling purposes.
func isLower(c byte) bool {
	return c >= 'a' && c <= 'z'
}

// simplify replaces template parameters with their expansions, and
// merges qualifiers.
func simplify(a AST) AST {
	seen := make(map[AST]bool)
	skip := func(a AST) bool {
		if seen[a] {
			return true
		}
		seen[a] = true
		return false
	}
	if r := a.Copy(simplifyOne, skip); r != nil {
		return r
	}
	return a
}

// simplifyOne simplifies a single AST.  It returns nil if there is
// nothing to do.
func simplifyOne(a AST) AST {
	switch a := a.(type) {
	case *TemplateParam:
		if a.Template != nil && a.Index < len(a.Template.Args) {
			return a.Template.Args[a.Index]
		}
	case *MethodWithQualifiers:
		if m, ok := a.Method.(*MethodWithQualifiers); ok {
			ref := a.RefQualifier
			if ref == "" {
				ref = m.RefQualifier
			} else if m.RefQualifier != "" {
				if ref == "&" || m.RefQualifier == "&" {
					ref = "&"
				}
			}
			return &MethodWithQualifiers{Method: m.Method, Qualifiers: mergeQualifiers(a.Qualifiers, m.Qualifiers), RefQualifier: ref}
		}
		if t, ok := a.Method.(*TypeWithQualifiers); ok {
			return &MethodWithQualifiers{Method: t.Base, Qualifiers: mergeQualifiers(a.Qualifiers, t.Qualifiers), RefQualifier: a.RefQualifier}
		}
	case *TypeWithQualifiers:
		if ft, ok := a.Base.(*FunctionType); ok {
			return &MethodWithQualifiers{Method: ft, Qualifiers: a.Qualifiers, RefQualifier: ""}
		}
		if t, ok := a.Base.(*TypeWithQualifiers); ok {
			return &TypeWithQualifiers{Base: t.Base, Qualifiers: mergeQualifiers(a.Qualifiers, t.Qualifiers)}
		}
		if m, ok := a.Base.(*MethodWithQualifiers); ok {
			return &MethodWithQualifiers{Method: m.Method, Qualifiers: mergeQualifiers(a.Qualifiers, m.Qualifiers), RefQualifier: m.RefQualifier}
		}
	case *ReferenceType:
		if rt, ok := a.Base.(*ReferenceType); ok {
			return rt
		}
		if rrt, ok := a.Base.(*RvalueReferenceType); ok {
			return &ReferenceType{Base: rrt.Base}
		}
	case *RvalueReferenceType:
		if rrt, ok := a.Base.(*RvalueReferenceType); ok {
			return rrt
		}
		if rt, ok := a.Base.(*ReferenceType); ok {
			return rt
		}
	case *ArrayType:
		// Qualifiers on the element of an array type
		// go on the whole array type.
		if q, ok := a.Element.(*TypeWithQualifiers); ok {
			return &TypeWithQualifiers{
				Base:       &ArrayType{Dimension: a.Dimension, Element: q.Base},
				Qualifiers: q.Qualifiers,
			}
		}
	case *PackExpansion:
		// Expand the pack and replace it with a list of
		// expressions.
		if a.Pack != nil {
			exprs := make([]AST, len(a.Pack.Args))
			for i, arg := range a.Pack.Args {
				copy := func(sub AST) AST {
					// Replace the ArgumentPack
					// with a specific argument.
					if sub == a.Pack {
						return arg
					}
					// Copy everything else.
					return nil
				}

				seen := make(map[AST]bool)
				skip := func(sub AST) bool {
					// Don't traverse into another
					// pack expansion.
					if _, ok := sub.(*PackExpansion); ok {
						return true
					}
					if seen[sub] {
						return true
					}
					seen[sub] = true
					return false
				}

				b := a.Base.Copy(copy, skip)
				if b == nil {
					b = a.Base
				}
				exprs[i] = simplify(b)
			}
			return &ExprList{Exprs: exprs}
		}
	}
	return nil
}

// findArgumentPack walks the AST looking for the argument pack for a
// pack expansion.  We find it via a template parameter.
func (st *state) findArgumentPack(a AST) *ArgumentPack {
	seen := make(map[AST]bool)
	var ret *ArgumentPack
	a.Traverse(func(a AST) bool {
		if ret != nil {
			return false
		}
		switch a := a.(type) {
		case *TemplateParam:
			if a.Template == nil || a.Index >= len(a.Template.Args) {
				return true
			}
			if pack, ok := a.Template.Args[a.Index].(*ArgumentPack); ok {
				ret = pack
				return false
			}
		case *PackExpansion, *Closure, *Name:
			return false
		case *TaggedName, *Operator, *BuiltinType, *FunctionParam:
			return false
		case *UnnamedType, *FixedType, *DefaultArg:
			return false
		}
		if seen[a] {
			return false
		}
		seen[a] = true
		return true
	})
	return ret
}

"""




```