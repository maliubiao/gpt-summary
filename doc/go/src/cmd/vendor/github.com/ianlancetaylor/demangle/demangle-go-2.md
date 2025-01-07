Response:
The user is asking for a summary of the functionality of the provided Go code snippet. This code is part of a larger Go program that demangles C++ symbol names. The goal is to convert mangled (encoded) C++ symbol names back into a more readable, human-friendly format.

Here's a breakdown of how to arrive at the summary:

1. **Identify the core function:** The code snippet primarily consists of a single large function named `expression()` within the `state` struct. This suggests that the central task of this code section is to parse and interpret parts of a mangled name that represent expressions.

2. **Analyze the `switch` statement:**  The `expression()` function has a large `switch` statement that branches based on the initial characters of the remaining mangled string (`st.str`). Each `case` handles a different type of C++ expression or construct.

3. **Map `case` conditions to C++ constructs:**  Go through each `case` and try to identify the corresponding C++ feature being parsed. Keywords and patterns in the mangled name (like 'p', 'mc', 'E', 'il', 'st', 'u', 'rq', 'rQ', 'L') are clues. The comments within the code are also very helpful.

4. **Recognize helper functions:** Notice the calls to other methods within the `state` struct, like `demangleType()`, `number()`, `compactNumber()`, `unqualifiedName()`, `templateArgs()`, `operatorName()`, `exprList()`, `sourceName()`, `requiresExpr()`, `exprPrimary()`. These indicate that the `expression()` function relies on other parts of the demangling logic to handle sub-components of the expressions.

5. **Infer the overall purpose:**  The repeated parsing and construction of `AST` (Abstract Syntax Tree) nodes within the `expression()` function and its helper functions strongly suggests that the code is building a tree-like representation of the C++ expression encoded in the mangled name.

6. **Focus on the specific code provided:**  The prompt specifically asks about *this* part of the code. So, while acknowledging the broader demangling context, the summary should focus on the expression parsing aspect.

7. **Address the specific points in the prompt:**
    * **Functionality:** List the types of expressions the code handles.
    * **Go language feature (if applicable):**  While not directly implementing a specific Go language *feature*, the code demonstrates parsing and data structure manipulation, core aspects of Go programming. The `AST` construction is a key pattern.
    * **Go code example:** Create simple examples of C++ code that would lead to the parsing logic in the provided snippet being executed. Provide the likely mangled input and the expected output based on the AST structure.
    * **Command-line arguments:** Since the snippet is part of a larger demangler, speculate on possible command-line arguments that might influence its behavior (like verbosity).
    * **Common mistakes:** Think about potential errors users might encounter when using a demangler, such as incorrect mangled names.
    * **Summary:** Concisely reiterate the main function of the code.

8. **Structure the answer in Chinese:** As requested, provide the answer in Chinese.

By following these steps, we can create a comprehensive and accurate summary of the provided Go code snippet, addressing all the user's requirements.
这段Go语言代码实现了C++符号解密（demangling）功能的一部分，具体来说，它专注于**解析C++表达式**。

**核心功能归纳：**

这段代码中的 `expression()` 方法是解析C++表达式的核心入口。它根据 mangled 字符串的开头字符，判断当前需要解析的表达式类型，并调用相应的逻辑进行解析，最终生成一个表示该表达式的抽象语法树（AST）节点。

**具体功能点：**

* **函数参数引用 (`st.str[0] == 'f'`)：**  解析对函数参数的引用。这种引用通常用于 lambda 表达式或者涉及作用域的复杂场景。
* **指向成员的指针转换 (`st.str[0] == 'm' && st.str[1] == 'c'`)：** 解析将一个表达式转换为指向类成员指针的操作。
* **非限定名称 (`isDigit(st.str[0]) || (st.str[0] == 'o' && len(st.str) > 1 && st.str[1] == 'n')`)：** 解析不带任何作用域限定的名称，可能是变量名、函数名等。如果名称后面跟着 'I'，则表示这是一个模板。
* **花括号包围的初始化列表 (`(st.str[0] == 'i' || st.str[0] == 't') && len(st.str) > 1 && st.str[1] == 'l'`)：** 解析使用花括号 `{}` 进行初始化的列表，可以指定类型（`tl`）或不指定类型（`il`）。
* **`sizeof` 类型操作符 (`st.str[0] == 's' && len(st.str) > 1 && st.str[1] == 't'`)：** 解析 `sizeof(type)` 这种操作。
* **供应商扩展表达式 (`st.str[0] == 'u'`)：**  处理特定编译器（例如 LLVM）引入的非标准扩展表达式，例如 `__uuidof`。
* **requires 表达式 (`st.str[0] == 'r' && len(st.str) > 1 && (st.str[1] == 'q' || st.str[1] == 'Q')`)：**  解析 C++20 引入的 requires 表达式，用于约束模板参数。
* **各种运算符表达式：**  处理各种一元、二元和三元运算符，例如加减乘除、逻辑运算、赋值、类型转换等。代码会根据 mangled 字符串中的操作符编码（例如 "pp" 表示后置自增，"nw" 表示 new）来识别并解析。
* **子对象 (`subobject()` 方法)：** 解析对对象内部子对象的访问，包括可能的偏移量和联合体选择器。
* **未解析名称 (`unresolvedName()` 方法)：** 解析包含作用域信息的名称，可能需要后续的查找才能完全确定其含义。
* **基本未解析名称 (`baseUnresolvedName()` 方法)：**  解析未解析名称的基础部分，例如简单标识符、操作符名称、析构函数名称。
* **主表达式 (`exprPrimary()` 方法)：** 解析字面量（例如数字、字符串）或已编码的名称。
* **判别符 (`discriminator()` 方法)：** 解析用于区分具有相同名称的实体的判别符，通常用于函数局部静态变量。
* **闭包类型名称 (`closureTypeName()` 方法)：** 解析 lambda 表达式生成的闭包类型名称。
* **模板参数声明 (`templateParamDecl()` 方法)：** 解析模板参数的声明，包括类型参数、非类型参数、模板模板参数和参数包。
* **未命名类型名称 (`unnamedTypeName()` 方法)：** 解析编译器生成的未命名类型。
* **约束表达式 (`constraintExpr()` 方法)：** 解析模板约束表达式。
* **克隆后缀 (`cloneSuffix()` 方法)：** 识别并解析 GCC 编译器在克隆函数时添加的后缀。
* **替换 (`substitution()` 方法)：**  处理 mangled 字符串中的替换引用，用于避免重复编码相同的类型或名称。代码中维护了一个 `subs` 列表来存储已经解析过的 AST 节点，后续可以通过索引进行引用。

**它是什么Go语言功能的实现：**

这段代码是实现 C++ 符号解密器的一部分。符号解密是将编译器生成的、难以阅读的 mangled 符号名称转换回更易懂的原始名称的过程。这对于调试、性能分析以及理解底层实现非常有用。

**Go代码举例说明（假设输入与输出）：**

假设有如下 C++ 代码：

```c++
int add(int a, int b) {
  return a + b;
}
```

其 mangled 后的符号名可能是（实际的 mangled 名称会因编译器和编译选项而异）：

```
_Z3addii
```

当我们解析到表示 "a + b" 这个表达式的部分时，假设当前的 `st.str` 是表示加法运算的 mangled 字符串，例如：`pl`.

```go
package main

import (
	"fmt"
	"strings"
)

// 假设的 AST 结构定义 (简化)
type AST interface {
	String() string
}

type Binary struct {
	Op    string
	Left  AST
	Right AST
}

func (b *Binary) String() string {
	return fmt.Sprintf("(%s %s %s)", b.Left, b.Op, b.Right)
}

type Name struct {
	Name string
}

func (n *Name) String() string {
	return n.Name
}

// 假设的 state 结构 (简化)
type state struct {
	str string
}

func (st *state) advance(n int) {
	st.str = st.str[n:]
}

// 假设的 expression 解析函数 (简化，只处理加法)
func (st *state) expression() AST {
	if strings.HasPrefix(st.str, "pl") {
		st.advance(2)
		left := st.expression() // 递归解析左操作数
		right := st.expression() // 递归解析右操作数
		return &Binary{Op: "+", Left: left, Right: right}
	} else if strings.HasPrefix(st.str, "a") {
		st.advance(1)
		return &Name{Name: "a"}
	} else if strings.HasPrefix(st.str, "b") {
		st.advance(1)
		return &Name{Name: "b"}
	}
	return nil // 简化处理，实际情况需要更完善的错误处理
}

func main() {
	mangledExpr := "pla"+"b" // 假设 'a' 代表变量 a, 'b' 代表变量 b
	st := &state{str: mangledExpr}
	astNode := st.expression()
	fmt.Println(astNode) // 输出: (&{+ &{a} &{b}})
	fmt.Println(astNode.String()) // 输出: ((a + b))
}
```

**假设的输入与输出：**

* **假设输入 (`st.str`)**: `"pla" + "b"`  （表示 `a + b` 的 mangled 形式）
* **假设输出 (AST 节点的字符串表示)**: `((a + b))`

**命令行参数的具体处理：**

这段代码片段本身没有直接处理命令行参数。但是，作为 `demangle.go` 的一部分，它很可能被一个命令行工具调用。该工具可能会有如下命令行参数：

* **`-v` 或 `--verbose`**: 启用详细输出，可能会影响 `substitution()` 方法中选择 `verboseAST`。
* **要解密的 mangled 符号名**: 这是工具的主要输入。

**使用者易犯错的点：**

由于这段代码是符号解密器的一部分，使用者在使用解密工具时可能犯的错误包括：

* **提供错误的 mangled 符号名**: 如果输入的字符串不是有效的 mangled 符号，解密器可能会失败或者产生不正确的输出。
* **使用了不兼容的解密器版本**: 不同编译器和编译器版本生成的 mangled 符号格式可能略有不同，使用不兼容的解密器可能导致解密失败。

**总结：**

这段 Go 代码是 C++ 符号解密器中负责解析 C++ 表达式的核心部分。它通过分析 mangled 字符串的结构，识别不同的表达式类型，并构建出相应的抽象语法树，从而将编译器生成的晦涩符号名转换回易于理解的形式。它处理了包括函数参数引用、指针转换、各种运算符、初始化列表、requires 表达式等多种 C++ 表达式。

Prompt: 
```
这是路径为go/src/cmd/vendor/github.com/ianlancetaylor/demangle/demangle.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第3部分，共3部分，请归纳一下它的功能

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