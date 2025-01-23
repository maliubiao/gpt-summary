Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Initial Scan and Keywords:** I first quickly scanned the code, looking for familiar Go keywords and patterns. I noticed:
    * `package types`: This immediately tells me it's dealing with Go type system concepts.
    * `// Code generated`:  This is a strong hint that the file is auto-generated, and the *source* of truth is elsewhere (in this case, `../../cmd/compile/internal/types2/universe.go`). This means I should focus on the *effect* of the code, not how it's constructed.
    * `var Universe *Scope`:  The name "Universe" suggests something fundamental and global. Combined with "*Scope*", it strongly indicates the global scope where all built-in types and functions reside.
    * `var Unsafe *Package`:  Similarly, "Unsafe" and "*Package*" suggest the special `unsafe` package.
    * Lists of `Typ`, `basicAliases`, `predeclaredConsts`, `predeclaredFuncs`: These are clearly defining the basic building blocks of the Go language.
    * `defPredeclared...` functions: These functions are populating the `Universe` scope with the items defined in the lists.
    * `builtinId` and the `const` block: These are enumerating the built-in functions.
    * `init()` function: This standard Go function runs at package initialization and is where the `Universe` and `Unsafe` are created and populated.
    * The `def(obj Object)` function: This is the core mechanism for adding objects to the appropriate scope (Universe or Unsafe).

2. **High-Level Purpose:** Based on these observations, I concluded that this code is responsible for setting up the fundamental environment of the Go type system. It defines the predeclared types (like `int`, `string`, `bool`), constants (`true`, `false`, `iota`), built-in functions (`len`, `cap`, `append`), and the special `unsafe` package.

3. **Detailed Function Analysis (Iterative):**  I then went through each significant part in more detail:

    * **`Universe` and `Unsafe`:**  Confirmed their roles as the global scope and the `unsafe` package.
    * **`universeIota`, `universeByte`, etc.:** Identified these as specific instances of predeclared objects/types. The comments are helpful here, particularly for `byte` and `rune`.
    * **`Typ`:**  Recognized this as the array holding the basic types, indexed by `BasicKind`. The comments clarify that `Universe.Lookup` is needed to get the named aliases (`byte`, `rune`).
    * **`basicAliases`:** Noticed these are the named aliases for basic types.
    * **`defPredeclaredTypes()`:**  Understood this function adds the types from `Typ` and `basicAliases` to the `Universe` scope. The section on `any` with both aliased and non-aliased versions is more complex and requires careful reading of the comments. I focused on *why* they have two versions (compatibility during type checking).
    * **`defPredeclaredConsts()`:**  Straightforward - adds the predefined constants to the `Universe`.
    * **`defPredeclaredNil()`:**  Adds the `nil` value.
    * **`builtinId` and `predeclaredFuncs`:**  Realized this defines and enumerates the built-in functions, distinguishing between universe-level and `unsafe` package built-ins. The `exprKind` hinted at whether they are expressions or statements.
    * **`defPredeclaredFuncs()`:**  Adds the built-in functions to their respective scopes. The conditional definition for `assert` and `trace` for testing was noted.
    * **`DefPredeclaredTestFuncs()`:**  Specifically for defining test-related built-ins.
    * **`init()`:**  Observed its role in orchestrating the initialization process.
    * **`def(obj Object)`:**  This function is crucial. I noted its logic for placing objects into either the `Universe` or `Unsafe` scope based on whether the name is exported. The comment about fixing the `Obj` link for named types is important for understanding the internal structure.

4. **Inferring Go Functionality and Examples:** With the understanding of the code's purpose, I could now infer the Go language features it supports.

    * **Predeclared Types:**  The `Typ` array directly maps to Go's basic types. The examples show how to use these types in declarations.
    * **Predeclared Constants:**  `true`, `false`, and `iota` are fundamental. The examples demonstrate their usage.
    * **Built-in Functions:** The `predeclaredFuncs` list provides all the common built-in functions. The examples illustrate how to use a few of them.
    * **`unsafe` Package:** The definitions related to `_Add`, `_Sizeof`, etc., clearly point to the functionalities of the `unsafe` package. The example demonstrates its use, along with a cautionary note.
    * **`any` and `error`:** The special handling of `any` and `error` highlighted their importance as fundamental interface types.

5. **Code Reasoning (Input/Output):** For code reasoning, I selected simpler examples. For instance, when looking up a basic type, the input is the name (e.g., "int"), and the output is the `Type` object. For built-in functions, the input is the name (e.g., "len"), and the output is the `Builtin` object.

6. **Command-Line Arguments:** I recognized that this specific code doesn't directly handle command-line arguments. The "go test" comment at the top refers to the *generation* of this file, not its runtime behavior.

7. **Common Mistakes:** I thought about how developers might misuse these fundamental elements. The `unsafe` package is the most obvious source of errors due to its potential for memory corruption. Misunderstanding the difference between `byte` and `uint8` or `rune` and `int32` could also lead to confusion.

8. **Structuring the Answer:** Finally, I organized the information into the requested sections: Functions, Go Feature Implementation, Code Examples, Command-Line Arguments, and Common Mistakes. I used clear headings and bullet points to make the information easily digestible. I made sure to use Chinese as requested.

Self-Correction/Refinement during the process:

* Initially, I might have focused too much on the generated nature of the file. I corrected myself to concentrate on its runtime effect within the `types` package.
* I initially overlooked the significance of the two representations of `any`. Reading the comments more carefully helped me understand the reason.
* I made sure to provide concrete code examples to illustrate the functionalities instead of just describing them abstractly.
* I double-checked that my examples used correct Go syntax.
* I ensured that the language used was clear and concise in Chinese.这段代码是 Go 语言 `types` 包中 `universe.go` 文件的一部分，它的主要功能是**定义和初始化 Go 语言的宇宙作用域（Universe scope）以及 `unsafe` 包**。宇宙作用域包含了 Go 语言中所有预定义的标识符，例如基本类型、常量和内置函数。`unsafe` 包则提供了一些不安全的底层操作。

下面列举一下它的具体功能：

1. **定义宇宙作用域 `Universe`:**
   - `var Universe *Scope` 定义了一个全局变量 `Universe`，类型为 `*Scope`。这个 `Scope` 对象代表了 Go 语言的最外层作用域，所有预定义的类型、常量、函数等都存在于这个作用域中。

2. **定义 `unsafe` 包 `Unsafe`:**
   - `var Unsafe *Package` 定义了一个全局变量 `Unsafe`，类型为 `*Package`。这个 `Package` 对象代表了 Go 语言的 `unsafe` 包。

3. **定义预定义的类型相关的变量:**
   - `universeIota Object`: 代表预定义常量 `iota`。
   - `universeByte Type`:  代表预定义类型 `byte`（`uint8` 的别名）。
   - `universeRune Type`:  代表预定义类型 `rune`（`int32` 的别名）。
   - `universeAnyNoAlias *TypeName`, `universeAnyAlias *TypeName`: 代表预定义类型 `any`（空接口 `interface{}`）。这里定义了两种表示方式，是为了兼容不同的 Go 版本，处理接口别名的问题。
   - `universeError Type`: 代表预定义类型 `error`（一个包含 `Error() string` 方法的接口）。
   - `universeComparable Object`: 代表预定义类型 `comparable`（一个标记为可比较的空接口）。

4. **定义基本类型切片 `Typ`:**
   - `var Typ = []*Basic{ ... }` 定义了一个 `*Basic` 类型的切片 `Typ`，其中包含了 Go 语言所有预定义的**基本类型**，例如 `bool`、`int`、`string` 等。每个 `Basic` 结构体包含了类型的种类、标志和名称。

5. **定义基本类型别名切片 `basicAliases`:**
   - `var basicAliases = [...] *Basic{ ... }` 定义了一个 `*Basic` 类型的数组 `basicAliases`，包含了 `byte` 和 `rune` 这两个基本类型的别名。

6. **定义 `defPredeclaredTypes()` 函数:**
   - 这个函数负责将 `Typ` 和 `basicAliases` 中定义的基本类型和它们的别名添加到 `Universe` 作用域中。它还负责定义 `any` 和 `error` 这两个特殊的接口类型，以及 `comparable` 接口。

7. **定义预定义的常量数组 `predeclaredConsts`:**
   - `var predeclaredConsts = [...]struct { ... }` 定义了一个结构体数组 `predeclaredConsts`，包含了预定义的常量 `true`、`false` 和 `iota` 及其类型和值。

8. **定义 `defPredeclaredConsts()` 函数:**
   - 这个函数负责将 `predeclaredConsts` 中定义的常量添加到 `Universe` 作用域中。

9. **定义 `defPredeclaredNil()` 函数:**
   - 这个函数负责将预定义的 `nil` 值添加到 `Universe` 作用域中。

10. **定义内置函数 ID 枚举 `builtinId`:**
    - `type builtinId int` 和 `const (...)` 定义了一个枚举类型 `builtinId`，用于标识不同的内置函数。

11. **定义预定义的函数数组 `predeclaredFuncs`:**
    - `var predeclaredFuncs = [...]struct { ... }` 定义了一个结构体数组 `predeclaredFuncs`，包含了 Go 语言的内置函数，例如 `append`、`len`、`make` 等，以及 `unsafe` 包中的函数，例如 `Add`、`Sizeof` 等。结构体中包含了函数的名称、参数个数、是否是可变参数以及表达式的种类。

12. **定义 `defPredeclaredFuncs()` 函数:**
    - 这个函数负责将 `predeclaredFuncs` 中定义的内置函数添加到相应的作用域中（宇宙作用域或 `unsafe` 包的作用域）。

13. **定义 `DefPredeclaredTestFuncs()` 函数:**
    - 这个函数用于定义 `assert` 和 `trace` 这两个内置函数，它们主要用于测试环境。

14. **定义 `init()` 函数:**
    - `func init() { ... }` 是一个特殊的初始化函数，在 `types` 包被导入时自动执行。它负责：
        - 创建 `Universe` 作用域。
        - 创建 `Unsafe` 包。
        - 调用 `defPredeclaredTypes()`、`defPredeclaredConsts()`、`defPredeclaredNil()` 和 `defPredeclaredFuncs()` 来填充宇宙作用域和 `unsafe` 包。
        - 查找并赋值一些常用的预定义对象到全局变量，例如 `universeIota`、`universeByte` 等。

15. **定义 `def(obj Object)` 函数:**
    - 这个函数是添加对象到作用域的核心函数。它接收一个 `Object` 类型的参数，并根据对象的名称是否是导出的，将其添加到 `Universe` 作用域或 `Unsafe` 包的作用域中。

**推理 Go 语言功能实现:**

这段代码是 Go 语言类型系统和内置功能的基础实现。它定义了 Go 语言中最核心的类型、常量和函数，使得编译器和类型检查器能够理解和处理这些预定义的概念。

**Go 代码举例说明:**

以下代码展示了如何使用这段代码中定义的预定义类型和函数：

```go
package main

import (
	"fmt"
	"unsafe"
)

func main() {
	// 使用预定义的基本类型
	var i int = 10
	var s string = "hello"
	var b bool = true

	fmt.Println(i, s, b) // 输出: 10 hello true

	// 使用预定义的常量
	const c = iota // 这里 iota 在 main 包中会重新计数，但在 universe 作用域中定义了初始值
	fmt.Println(c)    // 输出: 0

	// 使用内置函数
	numbers := []int{1, 2, 3}
	length := len(numbers)
	fmt.Println("Length:", length) // 输出: Length: 3

	appendedNumbers := append(numbers, 4)
	fmt.Println("Appended:", appendedNumbers) // 输出: Appended: [1 2 3 4]

	// 使用 unsafe 包 (谨慎使用)
	var x int32 = 10
	ptr := unsafe.Pointer(&x)
	// 将指针转换为 uintptr 进行指针运算 (不安全)
	ptrPlusOne := unsafe.Add(ptr, unsafe.Sizeof(int32(0)))
	fmt.Println("Pointer:", ptr, "Pointer + 1:", ptrPlusOne)
}
```

**假设的输入与输出（代码推理）:**

假设我们调用 `Universe.Lookup("int")`，这个操作会在 `Universe` 作用域中查找名称为 "int" 的对象。根据 `defPredeclaredTypes()` 函数的逻辑，它会将 `Typ` 数组中 `Int` 对应的 `Basic` 类型通过 `NewTypeName` 创建一个 `TypeName` 对象并插入到 `Universe` 作用域中。

**输入:** `Universe.Lookup("int")`

**输出:** 一个 `*TypeName` 对象，其内部包含了 `int` 类型的相关信息。我们可以通过这个对象的 `Type()` 方法获取到 `*Basic` 类型的 `int`。

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。它是在 Go 语言编译器的内部 `types` 包中使用的，负责构建类型系统。命令行参数的处理通常发生在 `main` 包的 `main` 函数中，或者通过 `flag` 等标准库进行处理。

**使用者易犯错的点:**

1. **滥用 `unsafe` 包:**  `unsafe` 包提供了绕过 Go 语言类型安全机制的能力，例如直接进行指针运算。虽然在某些底层操作中是必要的，但过度或不当使用 `unsafe` 包可能导致程序崩溃、内存错误等严重问题。

   ```go
   package main

   import (
       "fmt"
       "unsafe"
   )

   func main() {
       var i int = 10
       ptr := unsafe.Pointer(&i)
       // 错误地将 *int 转换为 *string，并尝试访问其数据
       strPtr := (*string)(ptr)
       // 这样做会导致程序崩溃或不可预测的行为
       // fmt.Println(*strPtr)
       _ = strPtr // 避免编译错误
       fmt.Println("Potential crash avoided by commenting out")
   }
   ```

2. **误解 `byte` 和 `rune`:**  虽然 `byte` 是 `uint8` 的别名，`rune` 是 `int32` 的别名，但在某些特定场景下（例如处理字符字面量），它们的含义有所不同。容易混淆它们在不同上下文中的使用。

   ```go
   package main

   import "fmt"

   func main() {
       var b byte = 'a' // byte 可以直接赋值字符字面量
       var u uint8 = 'a'

       var r rune = '你' // rune 用于表示 Unicode 码点
       var i int32 = '你'

       fmt.Printf("byte: %c, uint8: %c\n", b, u) // 输出: byte: a, uint8: a
       fmt.Printf("rune: %c, int32: %c\n", r, i)     // 输出: rune: 你, int32: 你
   }
   ```

这段代码是 Go 语言类型系统的基石，理解它的功能对于深入了解 Go 语言的内部机制至关重要。

### 提示词
```
这是路径为go/src/go/types/universe.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Code generated by "go test -run=Generate -write=all"; DO NOT EDIT.
// Source: ../../cmd/compile/internal/types2/universe.go

// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file sets up the universe scope and the unsafe package.

package types

import (
	"go/constant"
	"strings"
)

// The Universe scope contains all predeclared objects of Go.
// It is the outermost scope of any chain of nested scopes.
var Universe *Scope

// The Unsafe package is the package returned by an importer
// for the import path "unsafe".
var Unsafe *Package

var (
	universeIota       Object
	universeByte       Type // uint8 alias, but has name "byte"
	universeRune       Type // int32 alias, but has name "rune"
	universeAnyNoAlias *TypeName
	universeAnyAlias   *TypeName
	universeError      Type
	universeComparable Object
)

// Typ contains the predeclared *Basic types indexed by their
// corresponding BasicKind.
//
// The *Basic type for Typ[Byte] will have the name "uint8".
// Use Universe.Lookup("byte").Type() to obtain the specific
// alias basic type named "byte" (and analogous for "rune").
var Typ = []*Basic{
	Invalid: {Invalid, 0, "invalid type"},

	Bool:          {Bool, IsBoolean, "bool"},
	Int:           {Int, IsInteger, "int"},
	Int8:          {Int8, IsInteger, "int8"},
	Int16:         {Int16, IsInteger, "int16"},
	Int32:         {Int32, IsInteger, "int32"},
	Int64:         {Int64, IsInteger, "int64"},
	Uint:          {Uint, IsInteger | IsUnsigned, "uint"},
	Uint8:         {Uint8, IsInteger | IsUnsigned, "uint8"},
	Uint16:        {Uint16, IsInteger | IsUnsigned, "uint16"},
	Uint32:        {Uint32, IsInteger | IsUnsigned, "uint32"},
	Uint64:        {Uint64, IsInteger | IsUnsigned, "uint64"},
	Uintptr:       {Uintptr, IsInteger | IsUnsigned, "uintptr"},
	Float32:       {Float32, IsFloat, "float32"},
	Float64:       {Float64, IsFloat, "float64"},
	Complex64:     {Complex64, IsComplex, "complex64"},
	Complex128:    {Complex128, IsComplex, "complex128"},
	String:        {String, IsString, "string"},
	UnsafePointer: {UnsafePointer, 0, "Pointer"},

	UntypedBool:    {UntypedBool, IsBoolean | IsUntyped, "untyped bool"},
	UntypedInt:     {UntypedInt, IsInteger | IsUntyped, "untyped int"},
	UntypedRune:    {UntypedRune, IsInteger | IsUntyped, "untyped rune"},
	UntypedFloat:   {UntypedFloat, IsFloat | IsUntyped, "untyped float"},
	UntypedComplex: {UntypedComplex, IsComplex | IsUntyped, "untyped complex"},
	UntypedString:  {UntypedString, IsString | IsUntyped, "untyped string"},
	UntypedNil:     {UntypedNil, IsUntyped, "untyped nil"},
}

var basicAliases = [...]*Basic{
	{Byte, IsInteger | IsUnsigned, "byte"},
	{Rune, IsInteger, "rune"},
}

func defPredeclaredTypes() {
	for _, t := range Typ {
		def(NewTypeName(nopos, nil, t.name, t))
	}
	for _, t := range basicAliases {
		def(NewTypeName(nopos, nil, t.name, t))
	}

	// type any = interface{}
	//
	// Implement two representations of any: one for the legacy gotypesalias=0,
	// and one for gotypesalias=1. This is necessary for consistent
	// representation of interface aliases during type checking, and is
	// implemented via hijacking [Scope.Lookup] for the [Universe] scope.
	//
	// Both representations use the same distinguished pointer for their RHS
	// interface type, allowing us to detect any (even with the legacy
	// representation), and format it as "any" rather than interface{}, which
	// clarifies user-facing error messages significantly.
	//
	// TODO(rfindley): once the gotypesalias GODEBUG variable is obsolete (and we
	// consistently use the Alias node), we should be able to clarify user facing
	// error messages without using a distinguished pointer for the any
	// interface.
	{
		universeAnyNoAlias = NewTypeName(nopos, nil, "any", &Interface{complete: true, tset: &topTypeSet})
		universeAnyNoAlias.setColor(black)
		// ensure that the any TypeName reports a consistent Parent, after
		// hijacking Universe.Lookup with gotypesalias=0.
		universeAnyNoAlias.setParent(Universe)

		// It shouldn't matter which representation of any is actually inserted
		// into the Universe, but we lean toward the future and insert the Alias
		// representation.
		universeAnyAlias = NewTypeName(nopos, nil, "any", nil)
		universeAnyAlias.setColor(black)
		_ = NewAlias(universeAnyAlias, universeAnyNoAlias.Type().Underlying()) // Link TypeName and Alias
		def(universeAnyAlias)
	}

	// type error interface{ Error() string }
	{
		obj := NewTypeName(nopos, nil, "error", nil)
		obj.setColor(black)
		typ := NewNamed(obj, nil, nil)

		// error.Error() string
		recv := NewVar(nopos, nil, "", typ)
		res := NewVar(nopos, nil, "", Typ[String])
		sig := NewSignatureType(recv, nil, nil, nil, NewTuple(res), false)
		err := NewFunc(nopos, nil, "Error", sig)

		// interface{ Error() string }
		ityp := &Interface{methods: []*Func{err}, complete: true}
		computeInterfaceTypeSet(nil, nopos, ityp) // prevent races due to lazy computation of tset

		typ.SetUnderlying(ityp)
		def(obj)
	}

	// type comparable interface{} // marked as comparable
	{
		obj := NewTypeName(nopos, nil, "comparable", nil)
		obj.setColor(black)
		typ := NewNamed(obj, nil, nil)

		// interface{} // marked as comparable
		ityp := &Interface{complete: true, tset: &_TypeSet{nil, allTermlist, true}}

		typ.SetUnderlying(ityp)
		def(obj)
	}
}

var predeclaredConsts = [...]struct {
	name string
	kind BasicKind
	val  constant.Value
}{
	{"true", UntypedBool, constant.MakeBool(true)},
	{"false", UntypedBool, constant.MakeBool(false)},
	{"iota", UntypedInt, constant.MakeInt64(0)},
}

func defPredeclaredConsts() {
	for _, c := range predeclaredConsts {
		def(NewConst(nopos, nil, c.name, Typ[c.kind], c.val))
	}
}

func defPredeclaredNil() {
	def(&Nil{object{name: "nil", typ: Typ[UntypedNil], color_: black}})
}

// A builtinId is the id of a builtin function.
type builtinId int

const (
	// universe scope
	_Append builtinId = iota
	_Cap
	_Clear
	_Close
	_Complex
	_Copy
	_Delete
	_Imag
	_Len
	_Make
	_Max
	_Min
	_New
	_Panic
	_Print
	_Println
	_Real
	_Recover

	// package unsafe
	_Add
	_Alignof
	_Offsetof
	_Sizeof
	_Slice
	_SliceData
	_String
	_StringData

	// testing support
	_Assert
	_Trace
)

var predeclaredFuncs = [...]struct {
	name     string
	nargs    int
	variadic bool
	kind     exprKind
}{
	_Append:  {"append", 1, true, expression},
	_Cap:     {"cap", 1, false, expression},
	_Clear:   {"clear", 1, false, statement},
	_Close:   {"close", 1, false, statement},
	_Complex: {"complex", 2, false, expression},
	_Copy:    {"copy", 2, false, statement},
	_Delete:  {"delete", 2, false, statement},
	_Imag:    {"imag", 1, false, expression},
	_Len:     {"len", 1, false, expression},
	_Make:    {"make", 1, true, expression},
	// To disable max/min, remove the next two lines.
	_Max:     {"max", 1, true, expression},
	_Min:     {"min", 1, true, expression},
	_New:     {"new", 1, false, expression},
	_Panic:   {"panic", 1, false, statement},
	_Print:   {"print", 0, true, statement},
	_Println: {"println", 0, true, statement},
	_Real:    {"real", 1, false, expression},
	_Recover: {"recover", 0, false, statement},

	_Add:        {"Add", 2, false, expression},
	_Alignof:    {"Alignof", 1, false, expression},
	_Offsetof:   {"Offsetof", 1, false, expression},
	_Sizeof:     {"Sizeof", 1, false, expression},
	_Slice:      {"Slice", 2, false, expression},
	_SliceData:  {"SliceData", 1, false, expression},
	_String:     {"String", 2, false, expression},
	_StringData: {"StringData", 1, false, expression},

	_Assert: {"assert", 1, false, statement},
	_Trace:  {"trace", 0, true, statement},
}

func defPredeclaredFuncs() {
	for i := range predeclaredFuncs {
		id := builtinId(i)
		if id == _Assert || id == _Trace {
			continue // only define these in testing environment
		}
		def(newBuiltin(id))
	}
}

// DefPredeclaredTestFuncs defines the assert and trace built-ins.
// These built-ins are intended for debugging and testing of this
// package only.
func DefPredeclaredTestFuncs() {
	if Universe.Lookup("assert") != nil {
		return // already defined
	}
	def(newBuiltin(_Assert))
	def(newBuiltin(_Trace))
}

func init() {
	Universe = NewScope(nil, nopos, nopos, "universe")
	Unsafe = NewPackage("unsafe", "unsafe")
	Unsafe.complete = true

	defPredeclaredTypes()
	defPredeclaredConsts()
	defPredeclaredNil()
	defPredeclaredFuncs()

	universeIota = Universe.Lookup("iota")
	universeByte = Universe.Lookup("byte").Type()
	universeRune = Universe.Lookup("rune").Type()
	universeError = Universe.Lookup("error").Type()
	universeComparable = Universe.Lookup("comparable")
}

// Objects with names containing blanks are internal and not entered into
// a scope. Objects with exported names are inserted in the unsafe package
// scope; other objects are inserted in the universe scope.
func def(obj Object) {
	assert(obj.color() == black)
	name := obj.Name()
	if strings.Contains(name, " ") {
		return // nothing to do
	}
	// fix Obj link for named types
	if typ := asNamed(obj.Type()); typ != nil {
		typ.obj = obj.(*TypeName)
	}
	// exported identifiers go into package unsafe
	scope := Universe
	if obj.Exported() {
		scope = Unsafe.scope
		// set Pkg field
		switch obj := obj.(type) {
		case *TypeName:
			obj.pkg = Unsafe
		case *Builtin:
			obj.pkg = Unsafe
		default:
			panic("unreachable")
		}
	}
	if scope.Insert(obj) != nil {
		panic("double declaration of predeclared identifier")
	}
}
```