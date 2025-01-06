Response: Let's break down the thought process to analyze the provided Go code snippet.

1. **Understand the Goal:** The request asks for the functionality of the `fmt.go` file within the `cmd/compile/internal/types` package. Specifically, it wants a list of features, inference of the Go language functionality it implements, code examples, command-line argument handling (if applicable), and common mistakes.

2. **Initial Scan and Keyword Identification:** Read through the code, paying attention to package imports, type definitions, function names, constants, and comments. Keywords that stand out are: `fmt`, `Sym`, `Type`, `Pkg`, `Format`, `String`, `LinkString`, `NameString`, `tconv`, `sconv`, `fmtMode`, and the various `fmtMode` constants.

3. **Identify Core Data Structures:** Recognize the central roles of `Sym` (symbol), `Type`, and `Pkg` (package). These are likely the core data being manipulated and formatted.

4. **Focus on Formatting:** The presence of the `Format` methods for `Sym` and `Type`, along with functions like `sconv`, `tconv`, `sconv2`, `tconv2`, and `pkgqual`, strongly suggests that this file is primarily concerned with formatting these data structures into strings. The different `fmtMode` constants (`fmtGo`, `fmtDebug`, `fmtTypeID`, `fmtTypeIDName`) indicate different formatting styles.

5. **Infer Functionality - Formatting Symbols:**
    * The `Sym` struct likely represents a symbol (like a variable name, function name, or type name).
    * The `Format` method for `Sym` handles different formatting verbs (`%v`, `%+v`, `%S`).
    * `sconv` seems to be the core function for converting a `Sym` to a string based on the formatting mode.
    * `pkgqual` likely determines how the package name should be included in the output.
    * **Hypothesis:** This part of the code is responsible for converting symbols into human-readable strings, with variations for debugging and internal representations.

6. **Infer Functionality - Formatting Types:**
    * The `Type` struct represents a Go type.
    * Similar to `Sym`, `Type` has a `Format` method and corresponding formatting verbs (`%v`, `%+v`, `%L`, `%S`, `%-S`).
    * `tconv` and `tconv2` are the core functions for converting a `Type` to a string.
    * `BasicTypeNames` suggests handling of built-in types.
    * `LinkString` and `NameString` imply different types of unique string representations for types.
    * **Hypothesis:** This part focuses on converting Go types into string representations, again with variations for user display, debugging, and internal identifiers.

7. **Connect to Go Language Features:** The formatting of symbols and types is fundamental to how the Go compiler and related tools present information to developers. This includes:
    * **Error Messages:** When the compiler encounters an error, it needs to display the types and symbols involved.
    * **Debugging Output:** Tools like `gdb` or internal compiler dumps need to represent types and symbols.
    * **Reflection:** The `reflect` package relies on understanding and representing types.
    * **Type Identity:** The `LinkString` functionality is explicitly mentioned as being related to type identity.
    * **Function Signatures:** Formatting function parameters and return types.

8. **Code Examples (Mental Walkthrough):**
    * **Symbol Formatting:** Imagine a variable `x` in the current package and a variable `y` in an imported package `mypkg`. `%v` for `x` would be "x", and for `y` would be "mypkg.y". `%+v` would be "currentpkg.x" and "mypkg.y". `%S` would be "x" and "y".
    * **Type Formatting:** Consider `int`, `*int`, `[]string`, `map[string]int`, `func(int) string`. Mentally go through how `tconv` might handle these with different verbs and modes. For example, `%v` for `*int` would be `*int`. `%+v` would be `*types.TPTR-*int`.

9. **Command-Line Arguments:**  A careful read reveals no direct handling of command-line arguments *within this specific file*. This file provides *functionality* used by the compiler, which *does* take command-line arguments.

10. **Common Mistakes:**  Think about situations where the output of these formatting functions might be misinterpreted.
    * **Assuming `%v` is always unique:**  If two packages have the same name, `%v` might be ambiguous.
    * **Misunderstanding `%L`:** Not realizing it's only for named types.
    * **Not knowing the difference between `LinkString` and `NameString`:**  One is for true type identity, the other is more human-readable but potentially less unique.

11. **Refine and Organize:** Structure the findings into the requested sections: Functionality, Go Language Feature Implementation, Code Examples, Command-Line Arguments, and Common Mistakes. Use clear and concise language. Provide concrete examples where possible.

12. **Self-Correction/Review:**  Read through the generated answer. Does it accurately reflect the code? Are there any inconsistencies or omissions?  For example, initially, I might have focused too much on just the `fmt` package aspect. Realizing this is in `cmd/compile/internal/types` shifts the focus to the *compiler's internal representation* needs. The comments about hashing and linker symbols further solidify this.

This iterative process of scanning, identifying patterns, making hypotheses, connecting to broader concepts, and refining is key to understanding even moderately complex code snippets.
`go/src/cmd/compile/internal/types/fmt.go` 文件的主要功能是为 `cmd/compile/internal/types` 包中的 `Sym` (符号) 和 `Type` (类型) 提供自定义的格式化输出能力。它扩展了 Go 语言标准库 `fmt` 包的功能，以便在编译器的内部表示中使用更易读和更精确的类型和符号信息。

以下是该文件的主要功能点：

**1. 自定义 `Sym` 的格式化：**

* **多种格式输出：**  `Sym` 结构体实现了 `fmt.Formatter` 接口，提供了 `Format` 方法，支持以下格式动词：
    * `%v`: 输出 Go 语法形式的符号名。对于本地包的符号，只输出名称；对于导入包的符号，输出 `PkgName.Name`。
    * `%+v`: 输出调试语法形式的符号名。始终包含包名前缀 `PkgName.`，即使是本地符号。
    * `%S`: 输出短语法形式的符号名。只输出符号名称，不包含包名。
* **`String()` 方法：** 提供了默认的 Go 语法形式的字符串表示，等价于 `%v`。
* **`sconv()` 函数：**  核心的 `Sym` 到字符串的转换函数，根据不同的 `fmtMode` 和格式动词进行格式化。
* **`pkgqual()` 函数：**  确定符号所属包的限定符（包名或包路径）。它会根据 `fmtMode` 和是否与其他同名包冲突来决定是否需要添加包限定。

**2. 自定义 `Type` 的格式化：**

* **多种格式输出：** `Type` 结构体也实现了 `fmt.Formatter` 接口，提供了 `Format` 方法，支持以下格式动词：
    * `%v`: 输出 Go 语法形式的类型。
    * `%+v`: 输出调试语法形式的类型，对于非内置类型会添加 `KIND-` 前缀。
    * `%L`:  如果类型是命名类型，则输出其底层类型的 Go 语法形式。
    * `%S`: 输出简短的 Go 语法形式的类型，例如，在函数类型中省略 "func" 关键字。
    * `%-S`:  为方法接收者符号提供特殊情况，输出简短的类型 ID 格式。
* **`String()` 方法：** 提供了默认的 Go 语法形式的字符串表示，等价于 `%v`。
* **`LinkString()` 方法：**  生成一个适用于链接符号的字符串描述，这个描述对应于类型标识。相同的类型会生成相同的 `LinkString()`。这对于实现基于类型标识的 map 非常有用。
* **`NameString()` 方法：** 生成用户可读的、基本唯一的字符串描述。`NameString()` 对标识符进行包名限定，但当不同包共享相同名称和标识符时，可能会发生冲突。它也不区分函数作用域定义的类型与包作用域定义的类型。
* **`tconv()` 函数：** 核心的 `Type` 到字符串的转换函数，根据不同的 `fmtMode` 和格式动词进行格式化。它内部调用 `tconv2` 来处理递归类型。
* **`tconv2()` 函数：**  实际执行 `Type` 到字符串转换的函数，可以处理递归类型，避免无限循环。它使用 `visited` map 来跟踪已访问的类型。
* **`formatParams()` 函数：**  格式化函数或方法的参数列表。
* **`fldconv()` 函数：**  格式化结构体字段或函数参数。

**3. 辅助功能：**

* **`fmtMode` 类型：** 定义了不同的打印模式，包括：
    * `fmtGo`:  常规 Go 语法。
    * `fmtDebug`:  用于调试，类似于 `fmtGo`，但会打印类型 kind。
    * `fmtTypeID`:  用于生成类型唯一表示，用于哈希、链接器和函数/方法实例化。
    * `fmtTypeIDName`: 类似于 `fmtTypeID`，但用于某些特定的类型表示场景。
* **预定义的包：** 定义了 `BuiltinPkg` (内置包)、`LocalPkg` (当前编译的包) 和 `UnsafePkg` (unsafe 包) 的全局变量。
* **`BlankSym`：**  表示空标识符 `_` 的符号。
* **`NumImport`：**  记录具有给定名称的包被导入的次数，用于在错误消息中提供更清晰的包路径。
* **`BasicTypeNames`：**  存储基本类型名称的字符串切片。
* **`fmtBufferPool`：**  一个 `sync.Pool`，用于复用 `bytes.Buffer`，提高性能。
* **`SplitVargenSuffix()` 函数：**  将名称分割为基本字符串和 `·N` 后缀（如果存在）。这用于处理编译器生成的具有数字后缀的变量名。
* **`TypeHash()` 函数：**  计算类型的哈希值，用于类型 switch 语句。它使用 `LinkString()` 获取类型的唯一字符串表示，并对其进行哈希。

**推断的 Go 语言功能实现:**

该文件是 Go 编译器中类型系统实现的关键部分，特别是负责将编译器内部表示的类型和符号转换为可读的字符串。这在以下 Go 语言功能的实现中至关重要：

* **编译错误和警告信息：** 当编译器遇到类型错误或需要显示类型信息时，会使用这里的格式化功能生成清晰的错误消息。例如，当类型不匹配时，编译器需要显示涉及的类型名称。
* **调试信息：**  编译器或调试工具 (如 `gdb`) 在输出类型和符号信息时会使用这些格式化函数。`fmtDebug` 模式就是为此设计的。
* **反射 (Reflection)：**  虽然这个文件不直接属于 `reflect` 包，但编译器生成的类型信息最终会被 `reflect` 包使用。这里的 `LinkString()` 和 `NameString()` 生成的唯一类型标识符在反射的类型比较和查找中扮演重要角色。
* **泛型 (Generics)：**  在 Go 1.18 引入泛型后，类型参数和类型实例化需要一种标准的方式来表示。`fmtTypeID` 和 `fmtTypeIDName` 模式可能在泛型的实现中用于生成唯一的类型标识符。
* **类型断言和类型 Switch：** `TypeHash()` 函数用于计算类型的哈希值，这在 `type switch` 语句的实现中被使用，以快速比较类型。

**Go 代码举例说明:**

```go
package main

import (
	"fmt"
	"cmd/compile/internal/types"
)

func main() {
	// 假设我们已经有了一个 types.Type 和 types.Sym 的实例 (这在编译器的上下文中发生)
	// 这里为了演示，我们创建一个简单的类型和符号

	pkg := &types.Pkg{Name: "main", Path: "main"}
	sym := &types.Sym{Name: "myVariable", Pkg: pkg}
	basicType := types.Types[types.TINT] // 获取 int 类型的 types.Type

	ptrType := types.NewPtr(basicType)

	fmt.Printf("Symbol (%%v): %v\n", sym)
	fmt.Printf("Symbol (%%+v): %+v\n", sym)
	fmt.Printf("Symbol (%%S): %S\n", sym)

	fmt.Printf("Type (%%v): %v\n", basicType)
	fmt.Printf("Type (%%+v): %+v\n", basicType)
	fmt.Printf("Type (%%L): %L\n", basicType)
	fmt.Printf("Type (%%S): %S\n", basicType)

	fmt.Printf("Pointer Type (%%v): %v\n", ptrType)
	fmt.Printf("Pointer Type LinkString: %s\n", ptrType.LinkString())
	fmt.Printf("Pointer Type NameString: %s\n", ptrType.NameString())
}
```

**假设的输入与输出:**

运行上面的示例代码，假设 `types.LocalPkg` 指向 `main` 包，输出可能如下：

```
Symbol (%v): myVariable
Symbol (%+v): main.myVariable
Symbol (%S): myVariable
Type (%v): int
Type (%+v): types.TINT-int
Type (%L): int
Type (%S): int
Pointer Type (%v): *int
Pointer Type LinkString: *int
Pointer Type NameString: *int
```

**涉及命令行参数的具体处理:**

这个 `fmt.go` 文件本身 **不直接处理** 命令行参数。它的功能是为 `cmd/compile` (Go 编译器) 提供类型和符号的格式化能力。`cmd/compile` 在执行时会接收各种命令行参数，例如源文件路径、目标架构、优化选项等。

`cmd/compile` 内部的代码会使用 `types` 包提供的类型信息，并可能间接地通过调用这里的格式化函数来生成错误消息或调试输出，而这些输出可能会受到某些命令行参数的影响（例如，更详细的调试级别可能会导致更多 `%+v` 风格的输出）。

**使用者易犯错的点:**

由于 `fmt.go` 是编译器内部使用的，普通 Go 开发者不会直接使用它。但是，理解其背后的格式化逻辑有助于理解编译器输出的信息。

一个可能相关的误解是，在某些情况下，类型或符号的字符串表示可能看起来相同，但实际上是不同的类型。例如，如果两个不同的包定义了同名的类型，它们的 `%v` 表示可能相同，但它们的 `LinkString()` 将不同，因为它们是不同的类型。

**示例说明易犯错的点 (假设场景):**

假设有两个不同的包 `mypkg1` 和 `mypkg2`，它们都定义了一个名为 `MyInt` 的类型：

```go
// mypkg1/mypkg1.go
package mypkg1

type MyInt int
```

```go
// mypkg2/mypkg2.go
package mypkg2

type MyInt int
```

在编译器的错误消息或调试输出中，如果只使用 `%v` 格式，可能会都显示为 `MyInt`，从而导致混淆。编译器在内部会使用更精确的表示（例如包含包路径的 `LinkString()`）来区分它们。

总结来说，`go/src/cmd/compile/internal/types/fmt.go` 提供了一套强大的类型和符号格式化机制，是 Go 编译器内部表示与外部信息展示之间的桥梁，对于生成清晰的错误消息、调试信息以及支持反射等功能至关重要。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/types/fmt.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package types

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strconv"
	"sync"

	"cmd/compile/internal/base"
	"cmd/internal/hash"
)

// BuiltinPkg is a fake package that declares the universe block.
var BuiltinPkg *Pkg

// LocalPkg is the package being compiled.
var LocalPkg *Pkg

// UnsafePkg is package unsafe.
var UnsafePkg *Pkg

// BlankSym is the blank (_) symbol.
var BlankSym *Sym

// numImport tracks how often a package with a given name is imported.
// It is used to provide a better error message (by using the package
// path to disambiguate) if a package that appears multiple times with
// the same name appears in an error message.
var NumImport = make(map[string]int)

// fmtMode represents the kind of printing being done.
// The default is regular Go syntax (fmtGo).
// fmtDebug is like fmtGo but for debugging dumps and prints the type kind too.
// fmtTypeID and fmtTypeIDName are for generating various unique representations
// of types used in hashes, the linker, and function/method instantiations.
type fmtMode int

const (
	fmtGo fmtMode = iota
	fmtDebug
	fmtTypeID
	fmtTypeIDName
)

// Sym

// Format implements formatting for a Sym.
// The valid formats are:
//
//	%v	Go syntax: Name for symbols in the local package, PkgName.Name for imported symbols.
//	%+v	Debug syntax: always include PkgName. prefix even for local names.
//	%S	Short syntax: Name only, no matter what.
func (s *Sym) Format(f fmt.State, verb rune) {
	mode := fmtGo
	switch verb {
	case 'v', 'S':
		if verb == 'v' && f.Flag('+') {
			mode = fmtDebug
		}
		fmt.Fprint(f, sconv(s, verb, mode))

	default:
		fmt.Fprintf(f, "%%!%c(*types.Sym=%p)", verb, s)
	}
}

func (s *Sym) String() string {
	return sconv(s, 0, fmtGo)
}

// See #16897 for details about performance implications
// before changing the implementation of sconv.
func sconv(s *Sym, verb rune, mode fmtMode) string {
	if verb == 'L' {
		panic("linksymfmt")
	}

	if s == nil {
		return "<S>"
	}

	q := pkgqual(s.Pkg, verb, mode)
	if q == "" {
		return s.Name
	}

	buf := fmtBufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer fmtBufferPool.Put(buf)

	buf.WriteString(q)
	buf.WriteByte('.')
	buf.WriteString(s.Name)
	return InternString(buf.Bytes())
}

func sconv2(b *bytes.Buffer, s *Sym, verb rune, mode fmtMode) {
	if verb == 'L' {
		panic("linksymfmt")
	}
	if s == nil {
		b.WriteString("<S>")
		return
	}

	symfmt(b, s, verb, mode)
}

func symfmt(b *bytes.Buffer, s *Sym, verb rune, mode fmtMode) {
	name := s.Name
	if q := pkgqual(s.Pkg, verb, mode); q != "" {
		b.WriteString(q)
		b.WriteByte('.')
	}
	b.WriteString(name)
}

// pkgqual returns the qualifier that should be used for printing
// symbols from the given package in the given mode.
// If it returns the empty string, no qualification is needed.
func pkgqual(pkg *Pkg, verb rune, mode fmtMode) string {
	if pkg == nil {
		return ""
	}
	if verb != 'S' {
		switch mode {
		case fmtGo: // This is for the user
			if pkg == BuiltinPkg || pkg == LocalPkg {
				return ""
			}

			// If the name was used by multiple packages, display the full path,
			if pkg.Name != "" && NumImport[pkg.Name] > 1 {
				return strconv.Quote(pkg.Path)
			}
			return pkg.Name

		case fmtDebug:
			return pkg.Name

		case fmtTypeIDName:
			// dcommontype, typehash
			return pkg.Name

		case fmtTypeID:
			// (methodsym), typesym, weaksym
			return pkg.Prefix
		}
	}

	return ""
}

// Type

var BasicTypeNames = []string{
	TINT:        "int",
	TUINT:       "uint",
	TINT8:       "int8",
	TUINT8:      "uint8",
	TINT16:      "int16",
	TUINT16:     "uint16",
	TINT32:      "int32",
	TUINT32:     "uint32",
	TINT64:      "int64",
	TUINT64:     "uint64",
	TUINTPTR:    "uintptr",
	TFLOAT32:    "float32",
	TFLOAT64:    "float64",
	TCOMPLEX64:  "complex64",
	TCOMPLEX128: "complex128",
	TBOOL:       "bool",
	TANY:        "any",
	TSTRING:     "string",
	TNIL:        "nil",
	TIDEAL:      "untyped number",
	TBLANK:      "blank",
}

var fmtBufferPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

// Format implements formatting for a Type.
// The valid formats are:
//
//	%v	Go syntax
//	%+v	Debug syntax: Go syntax with a KIND- prefix for all but builtins.
//	%L	Go syntax for underlying type if t is named
//	%S	short Go syntax: drop leading "func" in function type
//	%-S	special case for method receiver symbol
func (t *Type) Format(s fmt.State, verb rune) {
	mode := fmtGo
	switch verb {
	case 'v', 'S', 'L':
		if verb == 'v' && s.Flag('+') { // %+v is debug format
			mode = fmtDebug
		}
		if verb == 'S' && s.Flag('-') { // %-S is special case for receiver - short typeid format
			mode = fmtTypeID
		}
		fmt.Fprint(s, tconv(t, verb, mode))
	default:
		fmt.Fprintf(s, "%%!%c(*Type=%p)", verb, t)
	}
}

// String returns the Go syntax for the type t.
func (t *Type) String() string {
	return tconv(t, 0, fmtGo)
}

// LinkString returns a string description of t, suitable for use in
// link symbols.
//
// The description corresponds to type identity. That is, for any pair
// of types t1 and t2, Identical(t1, t2) == (t1.LinkString() ==
// t2.LinkString()) is true. Thus it's safe to use as a map key to
// implement a type-identity-keyed map.
func (t *Type) LinkString() string {
	return tconv(t, 0, fmtTypeID)
}

// NameString generates a user-readable, mostly unique string
// description of t. NameString always returns the same description
// for identical types, even across compilation units.
//
// NameString qualifies identifiers by package name, so it has
// collisions when different packages share the same names and
// identifiers. It also does not distinguish function-scope defined
// types from package-scoped defined types or from each other.
func (t *Type) NameString() string {
	return tconv(t, 0, fmtTypeIDName)
}

func tconv(t *Type, verb rune, mode fmtMode) string {
	buf := fmtBufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer fmtBufferPool.Put(buf)

	tconv2(buf, t, verb, mode, nil)
	return InternString(buf.Bytes())
}

// tconv2 writes a string representation of t to b.
// flag and mode control exactly what is printed.
// Any types x that are already in the visited map get printed as @%d where %d=visited[x].
// See #16897 before changing the implementation of tconv.
func tconv2(b *bytes.Buffer, t *Type, verb rune, mode fmtMode, visited map[*Type]int) {
	if off, ok := visited[t]; ok {
		// We've seen this type before, so we're trying to print it recursively.
		// Print a reference to it instead.
		fmt.Fprintf(b, "@%d", off)
		return
	}
	if t == nil {
		b.WriteString("<T>")
		return
	}
	if t.Kind() == TSSA {
		b.WriteString(t.extra.(string))
		return
	}
	if t.Kind() == TTUPLE {
		b.WriteString(t.FieldType(0).String())
		b.WriteByte(',')
		b.WriteString(t.FieldType(1).String())
		return
	}

	if t.Kind() == TRESULTS {
		tys := t.extra.(*Results).Types
		for i, et := range tys {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(et.String())
		}
		return
	}

	if t == AnyType || t == ByteType || t == RuneType {
		// in %-T mode collapse predeclared aliases with their originals.
		switch mode {
		case fmtTypeIDName, fmtTypeID:
			t = Types[t.Kind()]
		default:
			sconv2(b, t.Sym(), 'S', mode)
			return
		}
	}
	if t == ErrorType {
		b.WriteString("error")
		return
	}

	// Unless the 'L' flag was specified, if the type has a name, just print that name.
	if verb != 'L' && t.Sym() != nil && t != Types[t.Kind()] {
		// Default to 'v' if verb is invalid.
		if verb != 'S' {
			verb = 'v'
		}

		// In unified IR, function-scope defined types will have a ·N
		// suffix embedded directly in their Name. Trim this off for
		// non-fmtTypeID modes.
		sym := t.Sym()
		if mode != fmtTypeID {
			base, _ := SplitVargenSuffix(sym.Name)
			if len(base) < len(sym.Name) {
				sym = &Sym{Pkg: sym.Pkg, Name: base}
			}
		}
		sconv2(b, sym, verb, mode)
		return
	}

	if int(t.Kind()) < len(BasicTypeNames) && BasicTypeNames[t.Kind()] != "" {
		var name string
		switch t {
		case UntypedBool:
			name = "untyped bool"
		case UntypedString:
			name = "untyped string"
		case UntypedInt:
			name = "untyped int"
		case UntypedRune:
			name = "untyped rune"
		case UntypedFloat:
			name = "untyped float"
		case UntypedComplex:
			name = "untyped complex"
		default:
			name = BasicTypeNames[t.Kind()]
		}
		b.WriteString(name)
		return
	}

	if mode == fmtDebug {
		b.WriteString(t.Kind().String())
		b.WriteByte('-')
		tconv2(b, t, 'v', fmtGo, visited)
		return
	}

	// At this point, we might call tconv2 recursively. Add the current type to the visited list so we don't
	// try to print it recursively.
	// We record the offset in the result buffer where the type's text starts. This offset serves as a reference
	// point for any later references to the same type.
	// Note that we remove the type from the visited map as soon as the recursive call is done.
	// This prevents encoding types like map[*int]*int as map[*int]@4. (That encoding would work,
	// but I'd like to use the @ notation only when strictly necessary.)
	if visited == nil {
		visited = map[*Type]int{}
	}
	visited[t] = b.Len()
	defer delete(visited, t)

	switch t.Kind() {
	case TPTR:
		b.WriteByte('*')
		switch mode {
		case fmtTypeID, fmtTypeIDName:
			if verb == 'S' {
				tconv2(b, t.Elem(), 'S', mode, visited)
				return
			}
		}
		tconv2(b, t.Elem(), 'v', mode, visited)

	case TARRAY:
		b.WriteByte('[')
		b.WriteString(strconv.FormatInt(t.NumElem(), 10))
		b.WriteByte(']')
		tconv2(b, t.Elem(), 0, mode, visited)

	case TSLICE:
		b.WriteString("[]")
		tconv2(b, t.Elem(), 0, mode, visited)

	case TCHAN:
		switch t.ChanDir() {
		case Crecv:
			b.WriteString("<-chan ")
			tconv2(b, t.Elem(), 0, mode, visited)
		case Csend:
			b.WriteString("chan<- ")
			tconv2(b, t.Elem(), 0, mode, visited)
		default:
			b.WriteString("chan ")
			if t.Elem() != nil && t.Elem().IsChan() && t.Elem().Sym() == nil && t.Elem().ChanDir() == Crecv {
				b.WriteByte('(')
				tconv2(b, t.Elem(), 0, mode, visited)
				b.WriteByte(')')
			} else {
				tconv2(b, t.Elem(), 0, mode, visited)
			}
		}

	case TMAP:
		b.WriteString("map[")
		tconv2(b, t.Key(), 0, mode, visited)
		b.WriteByte(']')
		tconv2(b, t.Elem(), 0, mode, visited)

	case TINTER:
		if t.IsEmptyInterface() {
			b.WriteString("interface {}")
			break
		}
		b.WriteString("interface {")
		for i, f := range t.AllMethods() {
			if i != 0 {
				b.WriteByte(';')
			}
			b.WriteByte(' ')
			switch {
			case f.Sym == nil:
				// Check first that a symbol is defined for this type.
				// Wrong interface definitions may have types lacking a symbol.
				break
			case IsExported(f.Sym.Name):
				sconv2(b, f.Sym, 'S', mode)
			default:
				if mode != fmtTypeIDName {
					mode = fmtTypeID
				}
				sconv2(b, f.Sym, 'v', mode)
			}
			tconv2(b, f.Type, 'S', mode, visited)
		}
		if len(t.AllMethods()) != 0 {
			b.WriteByte(' ')
		}
		b.WriteByte('}')

	case TFUNC:
		if verb == 'S' {
			// no leading func
		} else {
			if t.Recv() != nil {
				b.WriteString("method")
				formatParams(b, t.Recvs(), mode, visited)
				b.WriteByte(' ')
			}
			b.WriteString("func")
		}
		formatParams(b, t.Params(), mode, visited)

		switch t.NumResults() {
		case 0:
			// nothing to do

		case 1:
			b.WriteByte(' ')
			tconv2(b, t.Result(0).Type, 0, mode, visited) // struct->field->field's type

		default:
			b.WriteByte(' ')
			formatParams(b, t.Results(), mode, visited)
		}

	case TSTRUCT:
		if m := t.StructType().Map; m != nil {
			mt := m.MapType()
			// Format the bucket struct for map[x]y as map.bucket[x]y.
			// This avoids a recursive print that generates very long names.
			switch t {
			case mt.OldBucket:
				b.WriteString("map.bucket[")
			case mt.SwissGroup:
				b.WriteString("map.group[")
			default:
				base.Fatalf("unknown internal map type")
			}
			tconv2(b, m.Key(), 0, mode, visited)
			b.WriteByte(']')
			tconv2(b, m.Elem(), 0, mode, visited)
			break
		}

		b.WriteString("struct {")
		for i, f := range t.Fields() {
			if i != 0 {
				b.WriteByte(';')
			}
			b.WriteByte(' ')
			fldconv(b, f, 'L', mode, visited, false)
		}
		if t.NumFields() != 0 {
			b.WriteByte(' ')
		}
		b.WriteByte('}')

	case TFORW:
		b.WriteString("undefined")
		if t.Sym() != nil {
			b.WriteByte(' ')
			sconv2(b, t.Sym(), 'v', mode)
		}

	case TUNSAFEPTR:
		b.WriteString("unsafe.Pointer")

	case Txxx:
		b.WriteString("Txxx")

	default:
		// Don't know how to handle - fall back to detailed prints
		b.WriteString(t.Kind().String())
		b.WriteString(" <")
		sconv2(b, t.Sym(), 'v', mode)
		b.WriteString(">")

	}
}

func formatParams(b *bytes.Buffer, params []*Field, mode fmtMode, visited map[*Type]int) {
	b.WriteByte('(')
	fieldVerb := 'v'
	switch mode {
	case fmtTypeID, fmtTypeIDName, fmtGo:
		// no argument names on function signature, and no "noescape"/"nosplit" tags
		fieldVerb = 'S'
	}
	for i, param := range params {
		if i != 0 {
			b.WriteString(", ")
		}
		fldconv(b, param, fieldVerb, mode, visited, true)
	}
	b.WriteByte(')')
}

func fldconv(b *bytes.Buffer, f *Field, verb rune, mode fmtMode, visited map[*Type]int, isParam bool) {
	if f == nil {
		b.WriteString("<T>")
		return
	}

	var name string
	nameSep := " "
	if verb != 'S' {
		s := f.Sym

		// Using type aliases and embedded fields, it's possible to
		// construct types that can't be directly represented as a
		// type literal. For example, given "type Int = int" (#50190),
		// it would be incorrect to format "struct{ Int }" as either
		// "struct{ int }" or "struct{ Int int }", because those each
		// represent other, distinct types.
		//
		// So for the purpose of LinkString (i.e., fmtTypeID), we use
		// the non-standard syntax "struct{ Int = int }" to represent
		// embedded fields that have been renamed through the use of
		// type aliases.
		if f.Embedded != 0 {
			if mode == fmtTypeID {
				nameSep = " = "

				// Compute tsym, the symbol that would normally be used as
				// the field name when embedding f.Type.
				// TODO(mdempsky): Check for other occurrences of this logic
				// and deduplicate.
				typ := f.Type
				if typ.IsPtr() {
					base.Assertf(typ.Sym() == nil, "embedded pointer type has name: %L", typ)
					typ = typ.Elem()
				}
				tsym := typ.Sym()

				// If the field name matches the embedded type's name, then
				// suppress printing of the field name. For example, format
				// "struct{ T }" as simply that instead of "struct{ T = T }".
				if tsym != nil && (s == tsym || IsExported(tsym.Name) && s.Name == tsym.Name) {
					s = nil
				}
			} else {
				// Suppress the field name for embedded fields for
				// non-LinkString formats, to match historical behavior.
				// TODO(mdempsky): Re-evaluate this.
				s = nil
			}
		}

		if s != nil {
			if isParam {
				name = fmt.Sprint(f.Nname)
			} else if verb == 'L' {
				name = s.Name
				if !IsExported(name) && mode != fmtTypeIDName {
					name = sconv(s, 0, mode) // qualify non-exported names (used on structs, not on funarg)
				}
			} else {
				name = sconv(s, 0, mode)
			}
		}
	}

	if name != "" {
		b.WriteString(name)
		b.WriteString(nameSep)
	}

	if f.IsDDD() {
		var et *Type
		if f.Type != nil {
			et = f.Type.Elem()
		}
		b.WriteString("...")
		tconv2(b, et, 0, mode, visited)
	} else {
		tconv2(b, f.Type, 0, mode, visited)
	}

	if verb != 'S' && !isParam && f.Note != "" {
		b.WriteString(" ")
		b.WriteString(strconv.Quote(f.Note))
	}
}

// SplitVargenSuffix returns name split into a base string and a ·N
// suffix, if any.
func SplitVargenSuffix(name string) (base, suffix string) {
	i := len(name)
	for i > 0 && name[i-1] >= '0' && name[i-1] <= '9' {
		i--
	}
	const dot = "·"
	if i >= len(dot) && name[i-len(dot):i] == dot {
		i -= len(dot)
		return name[:i], name[i:]
	}
	return name, ""
}

// TypeHash computes a hash value for type t to use in type switch statements.
func TypeHash(t *Type) uint32 {
	p := t.LinkString()

	// Using 16 bytes hash is overkill, but reduces accidental collisions.
	h := hash.Sum16([]byte(p))
	return binary.LittleEndian.Uint32(h[:4])
}

"""



```