Response: My thought process to answer the request about `go/src/cmd/compile/internal/types/type.go` goes like this:

1. **Understand the Goal:** The request asks for the functionality of the file, inferences about the Go feature it implements, code examples, handling of command-line arguments (if any), and common mistakes.

2. **Initial Scan and High-Level Understanding:** I first read through the code, paying attention to package name (`types`), important data structures (like `Type`, `Kind`, `Field`), and key functions (like `NewType`, `NewArray`, `NewPtr`, `SubstAny`, `Compare`). This gives me a general sense that this file is about representing and manipulating Go types within the compiler.

3. **Identify Core Functionality (Instruction 1):** Based on the data structures and functions, I can list the core functionalities:
    * Defining and representing Go types (primitive, composite, named).
    * Describing type properties (size, alignment, kind, methods, fields).
    * Creating new types (arrays, slices, pointers, maps, functions, etc.).
    * Comparing types.
    * Substituting type parameters (related to generics).
    * Managing method sets.
    * Providing utility functions to check type characteristics (e.g., `IsInteger`, `IsPtr`, `HasPointers`).

4. **Infer Go Feature Implementation (Instruction 2):**  The presence of `SubstAny`, the `TANY` kind, `IsShape`, and `HasShape` flags strongly suggest this code is involved in the implementation of **Go generics**. The file provides the foundational type system that allows generic type parameters to be represented and manipulated.

5. **Code Example (Instruction 2):** To illustrate generics, I need a simple generic function. I choose a `min` function because it's easy to understand and commonly used in examples. I need to show:
    * The generic function definition.
    * Instantiation with concrete types.
    * The compiler's internal representation of the types involved (though not directly accessible, I explain what's happening).
    * Input and expected output for the example.

6. **Command-Line Arguments (Instruction 4):** I carefully scan the code for any direct interaction with `os.Args` or flags from the `flag` package. I don't see any. Therefore, I conclude that this file itself doesn't directly handle command-line arguments. However, I know it's *part of the compiler*, which *does* take command-line arguments. So, I explain that while *this file* doesn't, the compiler driver (like `go build`) uses arguments that influence how this code operates (e.g., optimization levels, target architecture).

7. **Code Reasoning (Instruction 3):** The `Compare` function is a good example of code reasoning. I break down its logic:
    * **Input:** Two `*Type` instances.
    * **Output:** `CMPlt`, `CMPeq`, or `CMPgt`.
    * **Logic:**  It performs a multi-level comparison, first by kind, then by symbol (for named types), and finally by structure (for composite types). It handles special cases like `byte` vs. `uint8`. I create a table to illustrate potential input types and the expected comparison result.

8. **Common Mistakes (Instruction 5):**  I think about how developers interact with types in Go and what errors might arise from a compiler's perspective.
    * **Incorrect type assertions:**  The `Object` interface requires type assertions, and incorrect ones will cause panics.
    * **Assuming type equality by name:**  Two types with the same name in different packages are distinct.
    * **Misunderstanding untyped constants:**  Forgetting that untyped constants have a default type.
    * **Modifying cached types:** Although the code has caching, users don't directly interact with the cache. This is more of an internal compiler detail, so I don't emphasize it as a common user mistake.

9. **Review and Refine:** I reread my answer to ensure it's clear, accurate, and addresses all parts of the request. I check for any inconsistencies or areas that need more explanation. For example, clarifying the role of `Object` as a way to avoid import cycles. I also double-check the code examples to make sure they are valid Go.

This iterative process of scanning, understanding, inferring, illustrating, and refining allows me to construct a comprehensive answer to the request. The key is to connect the low-level details of the code with the higher-level concepts of the Go language and the compilation process.
`go/src/cmd/compile/internal/types/type.go` 文件是 Go 编译器中 `types` 包的核心部分，负责定义和操作 Go 语言的类型系统。它不直接对应于某个单一的 Go 语言功能，而是 Go 语言类型系统的基础架构，被编译器的许多部分使用。

以下是 `type.go` 文件的主要功能：

1. **定义了 `Type` 结构体:**  `Type` 结构体是 Go 语言类型在编译器内部的表示。它包含了类型的所有关键信息，例如类型的种类（`Kind`），大小（`width`），对齐方式（`align`），以及特定类型可能需要的额外信息（例如，`Map` 结构体用于表示 map 类型，`Struct` 结构体用于表示 struct 类型）。

2. **枚举了 `Kind` 类型:** `Kind` 是一个枚举类型，定义了 Go 语言中所有可能的类型种类，例如 `TINT`, `TSTRING`, `TSTRUCT`, `TFUNC`, `TSLICE` 等。它帮助区分不同的类型。

3. **定义了其他辅助结构体:**  为了更详细地描述复合类型，文件中定义了 `Map`, `Forward`, `Func`, `Struct`, `Interface`, `Ptr`, `Chan`, `Array`, `Slice`, `Field` 等结构体。这些结构体作为 `Type` 结构体的 `extra` 字段存在，用于存储特定类型独有的信息。

4. **定义了预声明类型:** 文件中声明了一些预定义的类型，例如 `Types[TINT]`, `Types[TSTRING]`, `ErrorType`, `ComparableType` 等。这些是 Go 语言内置的类型。

5. **定义了 untyped 常量类型:**  例如 `UntypedInt`, `UntypedFloat`, `UntypedString` 等，用于表示无类型的常量。

6. **提供了创建新类型的方法:**  例如 `NewType`, `NewArray`, `NewSlice`, `NewPtr`, `NewMap`, `NewSignature`, `NewStruct`, `NewInterface` 等函数，用于在编译过程中创建新的类型对象。

7. **提供了操作类型的方法:**  例如 `Size()`, `Alignment()`, `Elem()`, `Key()`, `Fields()`, `Methods()`, `Compare()` 等函数，用于获取类型的属性和比较类型。

8. **支持泛型相关的类型表示:** 文件中包含了 `TANY` 类型（用于表示泛型类型参数）和 `SubstAny` 函数（用于替换泛型类型参数）。`typeIsShape` 和 `typeHasShape` 等 flags 也与泛型实现有关。

9. **支持 SSA 后端类型:** 定义了 `TSSA`, `TTUPLE`, `TRESULTS` 等类型，用于表示在静态单赋值（SSA）形式中间表示中使用的类型。

**推理 Go 语言功能的实现 (泛型):**

从代码中可以观察到与泛型实现相关的迹象：

* **`TANY` 类型:**  `TANY` 常量被定义，并且注释说明它是 `SubstArgTypes` 识别的占位符 "any" 类型。这暗示了在类型替换过程中使用。
* **`SubstAny` 函数:** 该函数接收一个 `Type` 和一个 `[]*Type`，其功能是遍历类型 `t`，并将 "any" 的实例替换为从 `types` 中取出的连续元素。这正是泛型实例化时类型参数替换的过程。
* **`typeIsShape` 和 `typeHasShape` flags:**  这些 flags 用于标记类型是否是 shape 类型或包含 shape 类型，这与泛型的类型推断和实例化有关。
* **`ShapePkg`:** 定义了一个名为 `ShapePkg` 的包，注释说明它用于 shape 类型（与泛型相关）。

**Go 代码示例 (泛型):**

假设我们有以下 Go 泛型代码：

```go
package main

import "fmt"

func Min[T interface{ Less(T) bool }](a, b T) T {
	if a.Less(b) {
		return a
	}
	return b
}

type Integer int

func (i Integer) Less(j Integer) bool {
	return i < j
}

func main() {
	fmt.Println(Min(Integer(1), Integer(2))) // Output: 1
}
```

**假设的编译器内部处理 (涉及 `type.go`):**

1. **解析和类型检查:** 编译器解析 `Min` 函数的定义，遇到类型参数 `T` 和约束 `interface{ Less(T) bool }`。在 `type.go` 中，可能会创建一个表示该接口类型的 `Type` 结构体，其中方法集合包含 `Less` 方法。类型参数 `T` 可能在内部被表示为 `TANY` 类型的占位符。

2. **实例化:** 当调用 `Min(Integer(1), Integer(2))` 时，编译器会进行泛型实例化，将类型参数 `T` 替换为 `Integer`。`SubstAny` 函数可能会被调用，将 `Min` 函数签名中的 `TANY` 替换为表示 `Integer` 类型的 `Type` 结构体。

3. **类型表示:** `Integer` 类型在编译器内部会有一个对应的 `Type` 结构体，其 `Kind` 为 `TINT` (假设基于底层类型)，并可能关联到 `Integer` 类型定义的符号信息。

**代码推理的假设输入与输出:**

假设 `SubstAny` 函数的输入是：

* `t`: 代表 `Min` 函数签名的 `Type` 结构体，其中类型参数 `T` 的位置是 `TANY`。例如，参数 `a` 的类型可能是 `TANY`。
* `types`:  一个 `[]*Type`，其中第一个元素是指向 `Integer` 类型的 `Type` 结构体的指针。

`SubstAny` 函数的输出将是一个新的 `Type` 结构体，代表 `Min` 函数签名，但其中的 `TANY` 已经被替换为 `Integer` 类型的 `Type` 结构体。例如，参数 `a` 的类型将是 `Integer`。

**命令行参数的具体处理:**

`go/src/cmd/compile/internal/types/type.go` 文件本身**不直接处理**命令行参数。它是一个定义类型系统的核心数据结构和操作的库。

命令行参数的处理发生在编译器的其他部分，例如：

* **`go/src/cmd/compile/internal/gc/main.go`:** 这是 `compile` 命令的主入口，负责解析命令行参数，例如 `-o` (输出文件)，`-p` (包路径)，以及各种优化相关的参数。
* **`go/src/cmd/go/internal/work/build.go`:** `go build` 命令会调用编译器，并将相关的构建参数传递给编译器。

这些命令行参数会影响编译过程，间接地影响 `types` 包的使用方式，例如：

* **`-p` (importpath):**  影响包的导入和类型的查找。
* **优化相关的参数 (例如 `-N`, `-l`):**  可能会影响内联、逃逸分析等，这些分析会使用 `types` 包中的类型信息。
* **目标架构相关的参数 (例如 `GOOS`, `GOARCH`):** 影响类型的大小和对齐方式 (`width`, `align`) 的计算。

**使用者易犯错的点:**

由于 `go/src/cmd/compile/internal/types/type.go` 是编译器内部的实现，普通的 Go 开发者**不会直接使用或操作**这个文件中的类型和函数。

但是，理解其背后的概念可以帮助开发者避免一些与类型相关的错误：

1. **类型断言错误:** 当使用 `Object` 接口时（虽然开发者不会直接使用 `Object`，但理解其原理有助于理解接口），需要进行类型断言。如果断言的类型不正确，会导致 panic。

   ```go
   // 假设在编译器内部有类似的操作
   var obj Object = ... // 可能是 *ir.Name 或其他实现了 Object 接口的类型
   node, ok := obj.(*ir.Name)
   if !ok {
       // 类型断言失败
   }
   ```

2. **混淆命名类型和非命名类型:**  理解命名类型（例如 `type MyInt int`）和非命名类型（例如 `[]int`）在编译器内部的表示是不同的。对于开发者来说，这意味着需要注意类型匹配的规则。

3. **对 untyped 常量的理解不足:**  例如，`1` 是一个 untyped integer constant，它可以被隐式转换为不同的整数类型。理解 untyped 常量的默认类型和类型推断规则很重要。

   ```go
   var i int = 1 // 隐式将 untyped int 常量 1 转换为 int
   var f float64 = 1 // 隐式将 untyped int 常量 1 转换为 float64
   ```

4. **对类型比较的理解:**  编译器内部的 `Compare` 函数定义了类型比较的规则。开发者需要理解 Go 语言的类型相等性（例如，结构体类型只有在字段类型和顺序都一致时才相等）。

总而言之，`go/src/cmd/compile/internal/types/type.go` 是 Go 编译器类型系统的基石，虽然普通开发者不会直接接触它，但理解其功能有助于更深入地理解 Go 语言的类型系统和避免相关的编程错误。

### 提示词
```
这是路径为go/src/cmd/compile/internal/types/type.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package types

import (
	"cmd/compile/internal/base"
	"cmd/internal/objabi"
	"cmd/internal/src"
	"fmt"
	"go/constant"
	"internal/buildcfg"
	"internal/types/errors"
	"sync"
)

// Object represents an ir.Node, but without needing to import cmd/compile/internal/ir,
// which would cause an import cycle. The uses in other packages must type assert
// values of type Object to ir.Node or a more specific type.
type Object interface {
	Pos() src.XPos
	Sym() *Sym
	Type() *Type
}

//go:generate stringer -type Kind -trimprefix T type.go

// Kind describes a kind of type.
type Kind uint8

const (
	Txxx Kind = iota

	TINT8
	TUINT8
	TINT16
	TUINT16
	TINT32
	TUINT32
	TINT64
	TUINT64
	TINT
	TUINT
	TUINTPTR

	TCOMPLEX64
	TCOMPLEX128

	TFLOAT32
	TFLOAT64

	TBOOL

	TPTR
	TFUNC
	TSLICE
	TARRAY
	TSTRUCT
	TCHAN
	TMAP
	TINTER
	TFORW
	TANY
	TSTRING
	TUNSAFEPTR

	// pseudo-types for literals
	TIDEAL // untyped numeric constants
	TNIL
	TBLANK

	// pseudo-types used temporarily only during frame layout (CalcSize())
	TFUNCARGS
	TCHANARGS

	// SSA backend types
	TSSA     // internal types used by SSA backend (flags, memory, etc.)
	TTUPLE   // a pair of types, used by SSA backend
	TRESULTS // multiple types; the result of calling a function or method, with a memory at the end.

	NTYPE
)

// ChanDir is whether a channel can send, receive, or both.
type ChanDir uint8

func (c ChanDir) CanRecv() bool { return c&Crecv != 0 }
func (c ChanDir) CanSend() bool { return c&Csend != 0 }

const (
	// types of channel
	// must match ../../../../reflect/type.go:/ChanDir
	Crecv ChanDir = 1 << 0
	Csend ChanDir = 1 << 1
	Cboth ChanDir = Crecv | Csend
)

// Types stores pointers to predeclared named types.
//
// It also stores pointers to several special types:
//   - Types[TANY] is the placeholder "any" type recognized by SubstArgTypes.
//   - Types[TBLANK] represents the blank variable's type.
//   - Types[TINTER] is the canonical "interface{}" type.
//   - Types[TNIL] represents the predeclared "nil" value's type.
//   - Types[TUNSAFEPTR] is package unsafe's Pointer type.
var Types [NTYPE]*Type

var (
	// Predeclared alias types. These are actually created as distinct
	// defined types for better error messages, but are then specially
	// treated as identical to their respective underlying types.
	AnyType  *Type
	ByteType *Type
	RuneType *Type

	// Predeclared error interface type.
	ErrorType *Type
	// Predeclared comparable interface type.
	ComparableType *Type

	// Types to represent untyped string and boolean constants.
	UntypedString = newType(TSTRING)
	UntypedBool   = newType(TBOOL)

	// Types to represent untyped numeric constants.
	UntypedInt     = newType(TIDEAL)
	UntypedRune    = newType(TIDEAL)
	UntypedFloat   = newType(TIDEAL)
	UntypedComplex = newType(TIDEAL)
)

// UntypedTypes maps from a constant.Kind to its untyped Type
// representation.
var UntypedTypes = [...]*Type{
	constant.Bool:    UntypedBool,
	constant.String:  UntypedString,
	constant.Int:     UntypedInt,
	constant.Float:   UntypedFloat,
	constant.Complex: UntypedComplex,
}

// DefaultKinds maps from a constant.Kind to its default Kind.
var DefaultKinds = [...]Kind{
	constant.Bool:    TBOOL,
	constant.String:  TSTRING,
	constant.Int:     TINT,
	constant.Float:   TFLOAT64,
	constant.Complex: TCOMPLEX128,
}

// A Type represents a Go type.
//
// There may be multiple unnamed types with identical structure. However, there must
// be a unique Type object for each unique named (defined) type. After noding, a
// package-level type can be looked up by building its unique symbol sym (sym =
// package.Lookup(name)) and checking sym.Def. If sym.Def is non-nil, the type
// already exists at package scope and is available at sym.Def.(*ir.Name).Type().
// Local types (which may have the same name as a package-level type) are
// distinguished by their vargen, which is embedded in their symbol name.
type Type struct {
	// extra contains extra etype-specific fields.
	// As an optimization, those etype-specific structs which contain exactly
	// one pointer-shaped field are stored as values rather than pointers when possible.
	//
	// TMAP: *Map
	// TFORW: *Forward
	// TFUNC: *Func
	// TSTRUCT: *Struct
	// TINTER: *Interface
	// TFUNCARGS: FuncArgs
	// TCHANARGS: ChanArgs
	// TCHAN: *Chan
	// TPTR: Ptr
	// TARRAY: *Array
	// TSLICE: Slice
	// TSSA: string
	extra interface{}

	// width is the width of this Type in bytes.
	width int64 // valid if Align > 0

	// list of base methods (excluding embedding)
	methods fields
	// list of all methods (including embedding)
	allMethods fields

	// canonical OTYPE node for a named type (should be an ir.Name node with same sym)
	obj Object
	// the underlying type (type literal or predeclared type) for a defined type
	underlying *Type

	// Cache of composite types, with this type being the element type.
	cache struct {
		ptr   *Type // *T, or nil
		slice *Type // []T, or nil
	}

	kind  Kind  // kind of type
	align uint8 // the required alignment of this type, in bytes (0 means Width and Align have not yet been computed)

	intRegs, floatRegs uint8 // registers needed for ABIInternal

	flags bitset8
	alg   AlgKind // valid if Align > 0

	// size of prefix of object that contains all pointers. valid if Align > 0.
	// Note that for pointers, this is always PtrSize even if the element type
	// is NotInHeap. See size.go:PtrDataSize for details.
	ptrBytes int64
}

// Registers returns the number of integer and floating-point
// registers required to represent a parameter of this type under the
// ABIInternal calling conventions.
//
// If t must be passed by memory, Registers returns (math.MaxUint8,
// math.MaxUint8).
func (t *Type) Registers() (uint8, uint8) {
	CalcSize(t)
	return t.intRegs, t.floatRegs
}

func (*Type) CanBeAnSSAAux() {}

const (
	typeNotInHeap  = 1 << iota // type cannot be heap allocated
	typeNoalg                  // suppress hash and eq algorithm generation
	typeDeferwidth             // width computation has been deferred and type is on deferredTypeStack
	typeRecur
	typeIsShape  // represents a set of closely related types, for generics
	typeHasShape // there is a shape somewhere in the type
	// typeIsFullyInstantiated reports whether a type is fully instantiated generic type; i.e.
	// an instantiated generic type where all type arguments are non-generic or fully instantiated generic types.
	typeIsFullyInstantiated
)

func (t *Type) NotInHeap() bool           { return t.flags&typeNotInHeap != 0 }
func (t *Type) Noalg() bool               { return t.flags&typeNoalg != 0 }
func (t *Type) Deferwidth() bool          { return t.flags&typeDeferwidth != 0 }
func (t *Type) Recur() bool               { return t.flags&typeRecur != 0 }
func (t *Type) IsShape() bool             { return t.flags&typeIsShape != 0 }
func (t *Type) HasShape() bool            { return t.flags&typeHasShape != 0 }
func (t *Type) IsFullyInstantiated() bool { return t.flags&typeIsFullyInstantiated != 0 }

func (t *Type) SetNotInHeap(b bool)           { t.flags.set(typeNotInHeap, b) }
func (t *Type) SetNoalg(b bool)               { t.flags.set(typeNoalg, b) }
func (t *Type) SetDeferwidth(b bool)          { t.flags.set(typeDeferwidth, b) }
func (t *Type) SetRecur(b bool)               { t.flags.set(typeRecur, b) }
func (t *Type) SetIsFullyInstantiated(b bool) { t.flags.set(typeIsFullyInstantiated, b) }

// Should always do SetHasShape(true) when doing SetIsShape(true).
func (t *Type) SetIsShape(b bool)  { t.flags.set(typeIsShape, b) }
func (t *Type) SetHasShape(b bool) { t.flags.set(typeHasShape, b) }

// Kind returns the kind of type t.
func (t *Type) Kind() Kind { return t.kind }

// Sym returns the name of type t.
func (t *Type) Sym() *Sym {
	if t.obj != nil {
		return t.obj.Sym()
	}
	return nil
}

// Underlying returns the underlying type of type t.
func (t *Type) Underlying() *Type { return t.underlying }

// Pos returns a position associated with t, if any.
// This should only be used for diagnostics.
func (t *Type) Pos() src.XPos {
	if t.obj != nil {
		return t.obj.Pos()
	}
	return src.NoXPos
}

// Map contains Type fields specific to maps.
type Map struct {
	Key  *Type // Key type
	Elem *Type // Val (elem) type

	// Note: It would be cleaner to completely split Map into OldMap and
	// SwissMap, but 99% of the types map code doesn't care about the
	// implementation at all, so it is tons of churn to split the type.
	// Only code that looks at the bucket field can care about the
	// implementation.

	// GOEXPERIMENT=noswissmap fields
	OldBucket *Type // internal struct type representing a hash bucket

	// GOEXPERIMENT=swissmap fields
	SwissGroup *Type // internal struct type representing a slot group
}

// MapType returns t's extra map-specific fields.
func (t *Type) MapType() *Map {
	t.wantEtype(TMAP)
	return t.extra.(*Map)
}

// Forward contains Type fields specific to forward types.
type Forward struct {
	Copyto      []*Type  // where to copy the eventual value to
	Embedlineno src.XPos // first use of this type as an embedded type
}

// forwardType returns t's extra forward-type-specific fields.
func (t *Type) forwardType() *Forward {
	t.wantEtype(TFORW)
	return t.extra.(*Forward)
}

// Func contains Type fields specific to func types.
type Func struct {
	allParams []*Field // slice of all parameters, in receiver/params/results order

	startParams  int // index of the start of the (regular) parameters section
	startResults int // index of the start of the results section

	resultsTuple *Type // struct-like type representing multi-value results

	// Argwid is the total width of the function receiver, params, and results.
	// It gets calculated via a temporary TFUNCARGS type.
	// Note that TFUNC's Width is Widthptr.
	Argwid int64
}

func (ft *Func) recvs() []*Field         { return ft.allParams[:ft.startParams] }
func (ft *Func) params() []*Field        { return ft.allParams[ft.startParams:ft.startResults] }
func (ft *Func) results() []*Field       { return ft.allParams[ft.startResults:] }
func (ft *Func) recvParams() []*Field    { return ft.allParams[:ft.startResults] }
func (ft *Func) paramsResults() []*Field { return ft.allParams[ft.startParams:] }

// funcType returns t's extra func-specific fields.
func (t *Type) funcType() *Func {
	t.wantEtype(TFUNC)
	return t.extra.(*Func)
}

// StructType contains Type fields specific to struct types.
type Struct struct {
	fields fields

	// Maps have three associated internal structs (see struct MapType).
	// Map links such structs back to their map type.
	Map *Type

	ParamTuple bool // whether this struct is actually a tuple of signature parameters
}

// StructType returns t's extra struct-specific fields.
func (t *Type) StructType() *Struct {
	t.wantEtype(TSTRUCT)
	return t.extra.(*Struct)
}

// Interface contains Type fields specific to interface types.
type Interface struct {
}

// Ptr contains Type fields specific to pointer types.
type Ptr struct {
	Elem *Type // element type
}

// ChanArgs contains Type fields specific to TCHANARGS types.
type ChanArgs struct {
	T *Type // reference to a chan type whose elements need a width check
}

// FuncArgs contains Type fields specific to TFUNCARGS types.
type FuncArgs struct {
	T *Type // reference to a func type whose elements need a width check
}

// Chan contains Type fields specific to channel types.
type Chan struct {
	Elem *Type   // element type
	Dir  ChanDir // channel direction
}

// chanType returns t's extra channel-specific fields.
func (t *Type) chanType() *Chan {
	t.wantEtype(TCHAN)
	return t.extra.(*Chan)
}

type Tuple struct {
	first  *Type
	second *Type
	// Any tuple with a memory type must put that memory type second.
}

// Results are the output from calls that will be late-expanded.
type Results struct {
	Types []*Type // Last element is memory output from call.
}

// Array contains Type fields specific to array types.
type Array struct {
	Elem  *Type // element type
	Bound int64 // number of elements; <0 if unknown yet
}

// Slice contains Type fields specific to slice types.
type Slice struct {
	Elem *Type // element type
}

// A Field is a (Sym, Type) pairing along with some other information, and,
// depending on the context, is used to represent:
//   - a field in a struct
//   - a method in an interface or associated with a named type
//   - a function parameter
type Field struct {
	flags bitset8

	Embedded uint8 // embedded field

	Pos src.XPos

	// Name of field/method/parameter. Can be nil for interface fields embedded
	// in interfaces and unnamed parameters.
	Sym  *Sym
	Type *Type  // field type
	Note string // literal string annotation

	// For fields that represent function parameters, Nname points to the
	// associated ONAME Node. For fields that represent methods, Nname points to
	// the function name node.
	Nname Object

	// Offset in bytes of this field or method within its enclosing struct
	// or interface Type. For parameters, this is BADWIDTH.
	Offset int64
}

const (
	fieldIsDDD = 1 << iota // field is ... argument
	fieldNointerface
)

func (f *Field) IsDDD() bool       { return f.flags&fieldIsDDD != 0 }
func (f *Field) Nointerface() bool { return f.flags&fieldNointerface != 0 }

func (f *Field) SetIsDDD(b bool)       { f.flags.set(fieldIsDDD, b) }
func (f *Field) SetNointerface(b bool) { f.flags.set(fieldNointerface, b) }

// End returns the offset of the first byte immediately after this field.
func (f *Field) End() int64 {
	return f.Offset + f.Type.width
}

// IsMethod reports whether f represents a method rather than a struct field.
func (f *Field) IsMethod() bool {
	return f.Type.kind == TFUNC && f.Type.Recv() != nil
}

// CompareFields compares two Field values by name.
func CompareFields(a, b *Field) int {
	return CompareSyms(a.Sym, b.Sym)
}

// fields is a pointer to a slice of *Field.
// This saves space in Types that do not have fields or methods
// compared to a simple slice of *Field.
type fields struct {
	s *[]*Field
}

// Slice returns the entries in f as a slice.
// Changes to the slice entries will be reflected in f.
func (f *fields) Slice() []*Field {
	if f.s == nil {
		return nil
	}
	return *f.s
}

// Set sets f to a slice.
// This takes ownership of the slice.
func (f *fields) Set(s []*Field) {
	if len(s) == 0 {
		f.s = nil
	} else {
		// Copy s and take address of t rather than s to avoid
		// allocation in the case where len(s) == 0.
		t := s
		f.s = &t
	}
}

// newType returns a new Type of the specified kind.
func newType(et Kind) *Type {
	t := &Type{
		kind:  et,
		width: BADWIDTH,
	}
	t.underlying = t
	// TODO(josharian): lazily initialize some of these?
	switch t.kind {
	case TMAP:
		t.extra = new(Map)
	case TFORW:
		t.extra = new(Forward)
	case TFUNC:
		t.extra = new(Func)
	case TSTRUCT:
		t.extra = new(Struct)
	case TINTER:
		t.extra = new(Interface)
	case TPTR:
		t.extra = Ptr{}
	case TCHANARGS:
		t.extra = ChanArgs{}
	case TFUNCARGS:
		t.extra = FuncArgs{}
	case TCHAN:
		t.extra = new(Chan)
	case TTUPLE:
		t.extra = new(Tuple)
	case TRESULTS:
		t.extra = new(Results)
	}
	return t
}

// NewArray returns a new fixed-length array Type.
func NewArray(elem *Type, bound int64) *Type {
	if bound < 0 {
		base.Fatalf("NewArray: invalid bound %v", bound)
	}
	t := newType(TARRAY)
	t.extra = &Array{Elem: elem, Bound: bound}
	if elem.HasShape() {
		t.SetHasShape(true)
	}
	if elem.NotInHeap() {
		t.SetNotInHeap(true)
	}
	return t
}

// NewSlice returns the slice Type with element type elem.
func NewSlice(elem *Type) *Type {
	if t := elem.cache.slice; t != nil {
		if t.Elem() != elem {
			base.Fatalf("elem mismatch")
		}
		if elem.HasShape() != t.HasShape() {
			base.Fatalf("Incorrect HasShape flag for cached slice type")
		}
		return t
	}

	t := newType(TSLICE)
	t.extra = Slice{Elem: elem}
	elem.cache.slice = t
	if elem.HasShape() {
		t.SetHasShape(true)
	}
	return t
}

// NewChan returns a new chan Type with direction dir.
func NewChan(elem *Type, dir ChanDir) *Type {
	t := newType(TCHAN)
	ct := t.chanType()
	ct.Elem = elem
	ct.Dir = dir
	if elem.HasShape() {
		t.SetHasShape(true)
	}
	return t
}

func NewTuple(t1, t2 *Type) *Type {
	t := newType(TTUPLE)
	t.extra.(*Tuple).first = t1
	t.extra.(*Tuple).second = t2
	if t1.HasShape() || t2.HasShape() {
		t.SetHasShape(true)
	}
	return t
}

func newResults(types []*Type) *Type {
	t := newType(TRESULTS)
	t.extra.(*Results).Types = types
	return t
}

func NewResults(types []*Type) *Type {
	if len(types) == 1 && types[0] == TypeMem {
		return TypeResultMem
	}
	return newResults(types)
}

func newSSA(name string) *Type {
	t := newType(TSSA)
	t.extra = name
	return t
}

// NewMap returns a new map Type with key type k and element (aka value) type v.
func NewMap(k, v *Type) *Type {
	t := newType(TMAP)
	mt := t.MapType()
	mt.Key = k
	mt.Elem = v
	if k.HasShape() || v.HasShape() {
		t.SetHasShape(true)
	}
	return t
}

// NewPtrCacheEnabled controls whether *T Types are cached in T.
// Caching is disabled just before starting the backend.
// This allows the backend to run concurrently.
var NewPtrCacheEnabled = true

// NewPtr returns the pointer type pointing to t.
func NewPtr(elem *Type) *Type {
	if elem == nil {
		base.Fatalf("NewPtr: pointer to elem Type is nil")
	}

	if t := elem.cache.ptr; t != nil {
		if t.Elem() != elem {
			base.Fatalf("NewPtr: elem mismatch")
		}
		if elem.HasShape() != t.HasShape() {
			base.Fatalf("Incorrect HasShape flag for cached pointer type")
		}
		return t
	}

	t := newType(TPTR)
	t.extra = Ptr{Elem: elem}
	t.width = int64(PtrSize)
	t.align = uint8(PtrSize)
	t.intRegs = 1
	if NewPtrCacheEnabled {
		elem.cache.ptr = t
	}
	if elem.HasShape() {
		t.SetHasShape(true)
	}
	t.alg = AMEM
	if elem.Noalg() {
		t.SetNoalg(true)
		t.alg = ANOALG
	}
	// Note: we can't check elem.NotInHeap here because it might
	// not be set yet. See size.go:PtrDataSize.
	t.ptrBytes = int64(PtrSize)
	return t
}

// NewChanArgs returns a new TCHANARGS type for channel type c.
func NewChanArgs(c *Type) *Type {
	t := newType(TCHANARGS)
	t.extra = ChanArgs{T: c}
	return t
}

// NewFuncArgs returns a new TFUNCARGS type for func type f.
func NewFuncArgs(f *Type) *Type {
	t := newType(TFUNCARGS)
	t.extra = FuncArgs{T: f}
	return t
}

func NewField(pos src.XPos, sym *Sym, typ *Type) *Field {
	f := &Field{
		Pos:    pos,
		Sym:    sym,
		Type:   typ,
		Offset: BADWIDTH,
	}
	if typ == nil {
		base.Fatalf("typ is nil")
	}
	return f
}

// SubstAny walks t, replacing instances of "any" with successive
// elements removed from types.  It returns the substituted type.
func SubstAny(t *Type, types *[]*Type) *Type {
	if t == nil {
		return nil
	}

	switch t.kind {
	default:
		// Leave the type unchanged.

	case TANY:
		if len(*types) == 0 {
			base.Fatalf("SubstArgTypes: not enough argument types")
		}
		t = (*types)[0]
		*types = (*types)[1:]

	case TPTR:
		elem := SubstAny(t.Elem(), types)
		if elem != t.Elem() {
			t = t.copy()
			t.extra = Ptr{Elem: elem}
		}

	case TARRAY:
		elem := SubstAny(t.Elem(), types)
		if elem != t.Elem() {
			t = t.copy()
			t.extra.(*Array).Elem = elem
		}

	case TSLICE:
		elem := SubstAny(t.Elem(), types)
		if elem != t.Elem() {
			t = t.copy()
			t.extra = Slice{Elem: elem}
		}

	case TCHAN:
		elem := SubstAny(t.Elem(), types)
		if elem != t.Elem() {
			t = t.copy()
			t.extra.(*Chan).Elem = elem
		}

	case TMAP:
		key := SubstAny(t.Key(), types)
		elem := SubstAny(t.Elem(), types)
		if key != t.Key() || elem != t.Elem() {
			t = t.copy()
			t.extra.(*Map).Key = key
			t.extra.(*Map).Elem = elem
		}

	case TFUNC:
		ft := t.funcType()
		allParams := substFields(ft.allParams, types)

		t = t.copy()
		ft = t.funcType()
		ft.allParams = allParams

		rt := ft.resultsTuple
		rt = rt.copy()
		ft.resultsTuple = rt
		rt.setFields(t.Results())

	case TSTRUCT:
		// Make a copy of all fields, including ones whose type does not change.
		// This prevents aliasing across functions, which can lead to later
		// fields getting their Offset incorrectly overwritten.
		nfs := substFields(t.Fields(), types)
		t = t.copy()
		t.setFields(nfs)
	}

	return t
}

func substFields(fields []*Field, types *[]*Type) []*Field {
	nfs := make([]*Field, len(fields))
	for i, f := range fields {
		nft := SubstAny(f.Type, types)
		nfs[i] = f.Copy()
		nfs[i].Type = nft
	}
	return nfs
}

// copy returns a shallow copy of the Type.
func (t *Type) copy() *Type {
	if t == nil {
		return nil
	}
	nt := *t
	// copy any *T Extra fields, to avoid aliasing
	switch t.kind {
	case TMAP:
		x := *t.extra.(*Map)
		nt.extra = &x
	case TFORW:
		x := *t.extra.(*Forward)
		nt.extra = &x
	case TFUNC:
		x := *t.extra.(*Func)
		nt.extra = &x
	case TSTRUCT:
		x := *t.extra.(*Struct)
		nt.extra = &x
	case TINTER:
		x := *t.extra.(*Interface)
		nt.extra = &x
	case TCHAN:
		x := *t.extra.(*Chan)
		nt.extra = &x
	case TARRAY:
		x := *t.extra.(*Array)
		nt.extra = &x
	case TTUPLE, TSSA, TRESULTS:
		base.Fatalf("ssa types cannot be copied")
	}
	// TODO(mdempsky): Find out why this is necessary and explain.
	if t.underlying == t {
		nt.underlying = &nt
	}
	return &nt
}

func (f *Field) Copy() *Field {
	nf := *f
	return &nf
}

func (t *Type) wantEtype(et Kind) {
	if t.kind != et {
		base.Fatalf("want %v, but have %v", et, t)
	}
}

// ResultsTuple returns the result type of signature type t as a tuple.
// This can be used as the type of multi-valued call expressions.
func (t *Type) ResultsTuple() *Type { return t.funcType().resultsTuple }

// Recvs returns a slice of receiver parameters of signature type t.
// The returned slice always has length 0 or 1.
func (t *Type) Recvs() []*Field { return t.funcType().recvs() }

// Params returns a slice of regular parameters of signature type t.
func (t *Type) Params() []*Field { return t.funcType().params() }

// Results returns a slice of result parameters of signature type t.
func (t *Type) Results() []*Field { return t.funcType().results() }

// RecvParamsResults returns a slice containing all of the
// signature's parameters in receiver (if any), (normal) parameters,
// and then results.
func (t *Type) RecvParamsResults() []*Field { return t.funcType().allParams }

// RecvParams returns a slice containing the signature's receiver (if
// any) followed by its (normal) parameters.
func (t *Type) RecvParams() []*Field { return t.funcType().recvParams() }

// ParamsResults returns a slice containing the signature's (normal)
// parameters followed by its results.
func (t *Type) ParamsResults() []*Field { return t.funcType().paramsResults() }

func (t *Type) NumRecvs() int   { return len(t.Recvs()) }
func (t *Type) NumParams() int  { return len(t.Params()) }
func (t *Type) NumResults() int { return len(t.Results()) }

// IsVariadic reports whether function type t is variadic.
func (t *Type) IsVariadic() bool {
	n := t.NumParams()
	return n > 0 && t.Param(n-1).IsDDD()
}

// Recv returns the receiver of function type t, if any.
func (t *Type) Recv() *Field {
	if s := t.Recvs(); len(s) == 1 {
		return s[0]
	}
	return nil
}

// Param returns the i'th parameter of signature type t.
func (t *Type) Param(i int) *Field { return t.Params()[i] }

// Result returns the i'th result of signature type t.
func (t *Type) Result(i int) *Field { return t.Results()[i] }

// Key returns the key type of map type t.
func (t *Type) Key() *Type {
	t.wantEtype(TMAP)
	return t.extra.(*Map).Key
}

// Elem returns the type of elements of t.
// Usable with pointers, channels, arrays, slices, and maps.
func (t *Type) Elem() *Type {
	switch t.kind {
	case TPTR:
		return t.extra.(Ptr).Elem
	case TARRAY:
		return t.extra.(*Array).Elem
	case TSLICE:
		return t.extra.(Slice).Elem
	case TCHAN:
		return t.extra.(*Chan).Elem
	case TMAP:
		return t.extra.(*Map).Elem
	}
	base.Fatalf("Type.Elem %s", t.kind)
	return nil
}

// ChanArgs returns the channel type for TCHANARGS type t.
func (t *Type) ChanArgs() *Type {
	t.wantEtype(TCHANARGS)
	return t.extra.(ChanArgs).T
}

// FuncArgs returns the func type for TFUNCARGS type t.
func (t *Type) FuncArgs() *Type {
	t.wantEtype(TFUNCARGS)
	return t.extra.(FuncArgs).T
}

// IsFuncArgStruct reports whether t is a struct representing function parameters or results.
func (t *Type) IsFuncArgStruct() bool {
	return t.kind == TSTRUCT && t.extra.(*Struct).ParamTuple
}

// Methods returns a pointer to the base methods (excluding embedding) for type t.
// These can either be concrete methods (for non-interface types) or interface
// methods (for interface types).
func (t *Type) Methods() []*Field {
	return t.methods.Slice()
}

// AllMethods returns a pointer to all the methods (including embedding) for type t.
// For an interface type, this is the set of methods that are typically iterated
// over. For non-interface types, AllMethods() only returns a valid result after
// CalcMethods() has been called at least once.
func (t *Type) AllMethods() []*Field {
	if t.kind == TINTER {
		// Calculate the full method set of an interface type on the fly
		// now, if not done yet.
		CalcSize(t)
	}
	return t.allMethods.Slice()
}

// SetMethods sets the direct method set for type t (i.e., *not*
// including promoted methods from embedded types).
func (t *Type) SetMethods(fs []*Field) {
	t.methods.Set(fs)
}

// SetAllMethods sets the set of all methods for type t (i.e.,
// including promoted methods from embedded types).
func (t *Type) SetAllMethods(fs []*Field) {
	t.allMethods.Set(fs)
}

// fields returns the fields of struct type t.
func (t *Type) fields() *fields {
	t.wantEtype(TSTRUCT)
	return &t.extra.(*Struct).fields
}

// Field returns the i'th field of struct type t.
func (t *Type) Field(i int) *Field { return t.Fields()[i] }

// Fields returns a slice of containing all fields of
// a struct type t.
func (t *Type) Fields() []*Field { return t.fields().Slice() }

// setFields sets struct type t's fields to fields.
func (t *Type) setFields(fields []*Field) {
	// If we've calculated the width of t before,
	// then some other type such as a function signature
	// might now have the wrong type.
	// Rather than try to track and invalidate those,
	// enforce that SetFields cannot be called once
	// t's width has been calculated.
	if t.widthCalculated() {
		base.Fatalf("SetFields of %v: width previously calculated", t)
	}
	t.wantEtype(TSTRUCT)
	t.fields().Set(fields)
}

// SetInterface sets the base methods of an interface type t.
func (t *Type) SetInterface(methods []*Field) {
	t.wantEtype(TINTER)
	t.methods.Set(methods)
}

// ArgWidth returns the total aligned argument size for a function.
// It includes the receiver, parameters, and results.
func (t *Type) ArgWidth() int64 {
	t.wantEtype(TFUNC)
	return t.extra.(*Func).Argwid
}

func (t *Type) Size() int64 {
	if t.kind == TSSA {
		if t == TypeInt128 {
			return 16
		}
		return 0
	}
	CalcSize(t)
	return t.width
}

func (t *Type) Alignment() int64 {
	CalcSize(t)
	return int64(t.align)
}

func (t *Type) SimpleString() string {
	return t.kind.String()
}

// Cmp is a comparison between values a and b.
//
//	-1 if a < b
//	 0 if a == b
//	 1 if a > b
type Cmp int8

const (
	CMPlt = Cmp(-1)
	CMPeq = Cmp(0)
	CMPgt = Cmp(1)
)

// Compare compares types for purposes of the SSA back
// end, returning a Cmp (one of CMPlt, CMPeq, CMPgt).
// The answers are correct for an optimizer
// or code generator, but not necessarily typechecking.
// The order chosen is arbitrary, only consistency and division
// into equivalence classes (Types that compare CMPeq) matters.
func (t *Type) Compare(x *Type) Cmp {
	if x == t {
		return CMPeq
	}
	return t.cmp(x)
}

func cmpForNe(x bool) Cmp {
	if x {
		return CMPlt
	}
	return CMPgt
}

func (r *Sym) cmpsym(s *Sym) Cmp {
	if r == s {
		return CMPeq
	}
	if r == nil {
		return CMPlt
	}
	if s == nil {
		return CMPgt
	}
	// Fast sort, not pretty sort
	if len(r.Name) != len(s.Name) {
		return cmpForNe(len(r.Name) < len(s.Name))
	}
	if r.Pkg != s.Pkg {
		if len(r.Pkg.Prefix) != len(s.Pkg.Prefix) {
			return cmpForNe(len(r.Pkg.Prefix) < len(s.Pkg.Prefix))
		}
		if r.Pkg.Prefix != s.Pkg.Prefix {
			return cmpForNe(r.Pkg.Prefix < s.Pkg.Prefix)
		}
	}
	if r.Name != s.Name {
		return cmpForNe(r.Name < s.Name)
	}
	return CMPeq
}

// cmp compares two *Types t and x, returning CMPlt,
// CMPeq, CMPgt as t<x, t==x, t>x, for an arbitrary
// and optimizer-centric notion of comparison.
// TODO(josharian): make this safe for recursive interface types
// and use in signatlist sorting. See issue 19869.
func (t *Type) cmp(x *Type) Cmp {
	// This follows the structure of function identical in identity.go
	// with two exceptions.
	// 1. Symbols are compared more carefully because a <,=,> result is desired.
	// 2. Maps are treated specially to avoid endless recursion -- maps
	//    contain an internal data type not expressible in Go source code.
	if t == x {
		return CMPeq
	}
	if t == nil {
		return CMPlt
	}
	if x == nil {
		return CMPgt
	}

	if t.kind != x.kind {
		return cmpForNe(t.kind < x.kind)
	}

	if t.obj != nil || x.obj != nil {
		// Special case: we keep byte and uint8 separate
		// for error messages. Treat them as equal.
		switch t.kind {
		case TUINT8:
			if (t == Types[TUINT8] || t == ByteType) && (x == Types[TUINT8] || x == ByteType) {
				return CMPeq
			}

		case TINT32:
			if (t == Types[RuneType.kind] || t == RuneType) && (x == Types[RuneType.kind] || x == RuneType) {
				return CMPeq
			}

		case TINTER:
			// Make sure named any type matches any empty interface.
			if t == AnyType && x.IsEmptyInterface() || x == AnyType && t.IsEmptyInterface() {
				return CMPeq
			}
		}
	}

	if c := t.Sym().cmpsym(x.Sym()); c != CMPeq {
		return c
	}

	if x.obj != nil {
		return CMPeq
	}
	// both syms nil, look at structure below.

	switch t.kind {
	case TBOOL, TFLOAT32, TFLOAT64, TCOMPLEX64, TCOMPLEX128, TUNSAFEPTR, TUINTPTR,
		TINT8, TINT16, TINT32, TINT64, TINT, TUINT8, TUINT16, TUINT32, TUINT64, TUINT:
		return CMPeq

	case TSSA:
		tname := t.extra.(string)
		xname := x.extra.(string)
		// desire fast sorting, not pretty sorting.
		if len(tname) == len(xname) {
			if tname == xname {
				return CMPeq
			}
			if tname < xname {
				return CMPlt
			}
			return CMPgt
		}
		if len(tname) > len(xname) {
			return CMPgt
		}
		return CMPlt

	case TTUPLE:
		xtup := x.extra.(*Tuple)
		ttup := t.extra.(*Tuple)
		if c := ttup.first.Compare(xtup.first); c != CMPeq {
			return c
		}
		return ttup.second.Compare(xtup.second)

	case TRESULTS:
		xResults := x.extra.(*Results)
		tResults := t.extra.(*Results)
		xl, tl := len(xResults.Types), len(tResults.Types)
		if tl != xl {
			if tl < xl {
				return CMPlt
			}
			return CMPgt
		}
		for i := 0; i < tl; i++ {
			if c := tResults.Types[i].Compare(xResults.Types[i]); c != CMPeq {
				return c
			}
		}
		return CMPeq

	case TMAP:
		if c := t.Key().cmp(x.Key()); c != CMPeq {
			return c
		}
		return t.Elem().cmp(x.Elem())

	case TPTR, TSLICE:
		// No special cases for these, they are handled
		// by the general code after the switch.

	case TSTRUCT:
		if buildcfg.Experiment.SwissMap {
			// Is this a map group type?
			if t.StructType().Map == nil {
				if x.StructType().Map != nil {
					return CMPlt // nil < non-nil
				}
				// to the fallthrough
			} else if x.StructType().Map == nil {
				return CMPgt // nil > non-nil
			}
			// Both have non-nil Map, fallthrough to the general
			// case. Note that the map type does not directly refer
			// to the group type (it uses unsafe.Pointer). If it
			// did, this would need special handling to avoid
			// infinite recursion.
		} else {
			// Is this a map bucket type?
			if t.StructType().Map == nil {
				if x.StructType().Map != nil {
					return CMPlt // nil < non-nil
				}
				// to the fallthrough
			} else if x.StructType().Map == nil {
				return CMPgt // nil > non-nil
			}
			// Both have non-nil Map, fallthrough to the general
			// case. Note that the map type does not directly refer
			// to the bucket type (it uses unsafe.Pointer). If it
			// did, this would need special handling to avoid
			// infinite recursion.
		}

		tfs := t.Fields()
		xfs := x.Fields()
		for i := 0; i < len(tfs) && i < len(xfs); i++ {
			t1, x1 := tfs[i], xfs[i]
			if t1.Embedded != x1.Embedded {
				return cmpForNe(t1.Embedded < x1.Embedded)
			}
			if t1.Note != x1.Note {
				return cmpForNe(t1.Note < x1.Note)
			}
			if c := t1.Sym.cmpsym(x1.Sym); c != CMPeq {
				return c
			}
			if c := t1.Type.cmp(x1.Type); c != CMPeq {
				return c
			}
		}
		if len(tfs) != len(xfs) {
			return cmpForNe(len(tfs) < len(xfs))
		}
		return CMPeq

	case TINTER:
		tfs := t.AllMethods()
		xfs := x.AllMethods()
		for i := 0; i < len(tfs) && i < len(xfs); i++ {
			t1, x1 := tfs[i], xfs[i]
			if c := t1.Sym.cmpsym(x1.Sym); c != CMPeq {
				return c
			}
			if c := t1.Type.cmp(x1.Type); c != CMPeq {
				return c
			}
		}
		if len(tfs) != len(xfs) {
			return cmpForNe(len(tfs) < len(xfs))
		}
		return CMPeq

	case TFUNC:
		if tn, xn := t.NumRecvs(), x.NumRecvs(); tn != xn {
			return cmpForNe(tn < xn)
		}
		if tn, xn := t.NumParams(), x.NumParams(); tn != xn {
			return cmpForNe(tn < xn)
		}
		if tn, xn := t.NumResults(), x.NumResults(); tn != xn {
			return cmpForNe(tn < xn)
		}
		if tv, xv := t.IsVariadic(), x.IsVariadic(); tv != xv {
			return cmpForNe(!tv)
		}

		tfs := t.RecvParamsResults()
		xfs := x.RecvParamsResults()
		for i, tf := range tfs {
			if c := tf.Type.cmp(xfs[i].Type); c != CMPeq {
				return c
			}
		}
		return CMPeq

	case TARRAY:
		if t.NumElem() != x.NumElem() {
			return cmpForNe(t.NumElem() < x.NumElem())
		}

	case TCHAN:
		if t.ChanDir() != x.ChanDir() {
			return cmpForNe(t.ChanDir() < x.ChanDir())
		}

	default:
		e := fmt.Sprintf("Do not know how to compare %v with %v", t, x)
		panic(e)
	}

	// Common element type comparison for TARRAY, TCHAN, TPTR, and TSLICE.
	return t.Elem().cmp(x.Elem())
}

// IsKind reports whether t is a Type of the specified kind.
func (t *Type) IsKind(et Kind) bool {
	return t != nil && t.kind == et
}

func (t *Type) IsBoolean() bool {
	return t.kind == TBOOL
}

var unsignedEType = [...]Kind{
	TINT8:    TUINT8,
	TUINT8:   TUINT8,
	TINT16:   TUINT16,
	TUINT16:  TUINT16,
	TINT32:   TUINT32,
	TUINT32:  TUINT32,
	TINT64:   TUINT64,
	TUINT64:  TUINT64,
	TINT:     TUINT,
	TUINT:    TUINT,
	TUINTPTR: TUINTPTR,
}

// ToUnsigned returns the unsigned equivalent of integer type t.
func (t *Type) ToUnsigned() *Type {
	if !t.IsInteger() {
		base.Fatalf("unsignedType(%v)", t)
	}
	return Types[unsignedEType[t.kind]]
}

func (t *Type) IsInteger() bool {
	switch t.kind {
	case TINT8, TUINT8, TINT16, TUINT16, TINT32, TUINT32, TINT64, TUINT64, TINT, TUINT, TUINTPTR:
		return true
	}
	return t == UntypedInt || t == UntypedRune
}

func (t *Type) IsSigned() bool {
	switch t.kind {
	case TINT8, TINT16, TINT32, TINT64, TINT:
		return true
	}
	return false
}

func (t *Type) IsUnsigned() bool {
	switch t.kind {
	case TUINT8, TUINT16, TUINT32, TUINT64, TUINT, TUINTPTR:
		return true
	}
	return false
}

func (t *Type) IsFloat() bool {
	return t.kind == TFLOAT32 || t.kind == TFLOAT64 || t == UntypedFloat
}

func (t *Type) IsComplex() bool {
	return t.kind == TCOMPLEX64 || t.kind == TCOMPLEX128 || t == UntypedComplex
}

// IsPtr reports whether t is a regular Go pointer type.
// This does not include unsafe.Pointer.
func (t *Type) IsPtr() bool {
	return t.kind == TPTR
}

// IsPtrElem reports whether t is the element of a pointer (to t).
func (t *Type) IsPtrElem() bool {
	return t.cache.ptr != nil
}

// IsUnsafePtr reports whether t is an unsafe pointer.
func (t *Type) IsUnsafePtr() bool {
	return t.kind == TUNSAFEPTR
}

// IsUintptr reports whether t is a uintptr.
func (t *Type) IsUintptr() bool {
	return t.kind == TUINTPTR
}

// IsPtrShaped reports whether t is represented by a single machine pointer.
// In addition to regular Go pointer types, this includes map, channel, and
// function types and unsafe.Pointer. It does not include array or struct types
// that consist of a single pointer shaped type.
// TODO(mdempsky): Should it? See golang.org/issue/15028.
func (t *Type) IsPtrShaped() bool {
	return t.kind == TPTR || t.kind == TUNSAFEPTR ||
		t.kind == TMAP || t.kind == TCHAN || t.kind == TFUNC
}

// HasNil reports whether the set of values determined by t includes nil.
func (t *Type) HasNil() bool {
	switch t.kind {
	case TCHAN, TFUNC, TINTER, TMAP, TNIL, TPTR, TSLICE, TUNSAFEPTR:
		return true
	}
	return false
}

func (t *Type) IsString() bool {
	return t.kind == TSTRING
}

func (t *Type) IsMap() bool {
	return t.kind == TMAP
}

func (t *Type) IsChan() bool {
	return t.kind == TCHAN
}

func (t *Type) IsSlice() bool {
	return t.kind == TSLICE
}

func (t *Type) IsArray() bool {
	return t.kind == TARRAY
}

func (t *Type) IsStruct() bool {
	return t.kind == TSTRUCT
}

func (t *Type) IsInterface() bool {
	return t.kind == TINTER
}

// IsEmptyInterface reports whether t is an empty interface type.
func (t *Type) IsEmptyInterface() bool {
	return t.IsInterface() && len(t.AllMethods()) == 0
}

// IsScalar reports whether 't' is a scalar Go type, e.g.
// bool/int/float/complex. Note that struct and array types consisting
// of a single scalar element are not considered scalar, likewise
// pointer types are also not considered scalar.
func (t *Type) IsScalar() bool {
	switch t.kind {
	case TBOOL, TINT8, TUINT8, TINT16, TUINT16, TINT32,
		TUINT32, TINT64, TUINT64, TINT, TUINT,
		TUINTPTR, TCOMPLEX64, TCOMPLEX128, TFLOAT32, TFLOAT64:
		return true
	}
	return false
}

func (t *Type) PtrTo() *Type {
	return NewPtr(t)
}

func (t *Type) NumFields() int {
	if t.kind == TRESULTS {
		return len(t.extra.(*Results).Types)
	}
	return len(t.Fields())
}
func (t *Type) FieldType(i int) *Type {
	if t.kind == TTUPLE {
		switch i {
		case 0:
			return t.extra.(*Tuple).first
		case 1:
			return t.extra.(*Tuple).second
		default:
			panic("bad tuple index")
		}
	}
	if t.kind == TRESULTS {
		return t.extra.(*Results).Types[i]
	}
	return t.Field(i).Type
}
func (t *Type) FieldOff(i int) int64 {
	return t.Field(i).Offset
}
func (t *Type) FieldName(i int) string {
	return t.Field(i).Sym.Name
}

// OffsetOf reports the offset of the field of a struct.
// The field is looked up by name.
func (t *Type) OffsetOf(name string) int64 {
	if t.kind != TSTRUCT {
		base.Fatalf("can't call OffsetOf on non-struct %v", t)
	}
	for _, f := range t.Fields() {
		if f.Sym.Name == name {
			return f.Offset
		}
	}
	base.Fatalf("couldn't find field %s in %v", name, t)
	return -1
}

func (t *Type) NumElem() int64 {
	t.wantEtype(TARRAY)
	return t.extra.(*Array).Bound
}

type componentsIncludeBlankFields bool

const (
	IgnoreBlankFields componentsIncludeBlankFields = false
	CountBlankFields  componentsIncludeBlankFields = true
)

// NumComponents returns the number of primitive elements that compose t.
// Struct and array types are flattened for the purpose of counting.
// All other types (including string, slice, and interface types) count as one element.
// If countBlank is IgnoreBlankFields, then blank struct fields
// (and their comprised elements) are excluded from the count.
// struct { x, y [3]int } has six components; [10]struct{ x, y string } has twenty.
func (t *Type) NumComponents(countBlank componentsIncludeBlankFields) int64 {
	switch t.kind {
	case TSTRUCT:
		if t.IsFuncArgStruct() {
			base.Fatalf("NumComponents func arg struct")
		}
		var n int64
		for _, f := range t.Fields() {
			if countBlank == IgnoreBlankFields && f.Sym.IsBlank() {
				continue
			}
			n += f.Type.NumComponents(countBlank)
		}
		return n
	case TARRAY:
		return t.NumElem() * t.Elem().NumComponents(countBlank)
	}
	return 1
}

// SoleComponent returns the only primitive component in t,
// if there is exactly one. Otherwise, it returns nil.
// Components are counted as in NumComponents, including blank fields.
// Keep in sync with cmd/compile/internal/walk/convert.go:soleComponent.
func (t *Type) SoleComponent() *Type {
	switch t.kind {
	case TSTRUCT:
		if t.IsFuncArgStruct() {
			base.Fatalf("SoleComponent func arg struct")
		}
		if t.NumFields() != 1 {
			return nil
		}
		return t.Field(0).Type.SoleComponent()
	case TARRAY:
		if t.NumElem() != 1 {
			return nil
		}
		return t.Elem().SoleComponent()
	}
	return t
}

// ChanDir returns the direction of a channel type t.
// The direction will be one of Crecv, Csend, or Cboth.
func (t *Type) ChanDir() ChanDir {
	t.wantEtype(TCHAN)
	return t.extra.(*Chan).Dir
}

func (t *Type) IsMemory() bool {
	if t == TypeMem || t.kind == TTUPLE && t.extra.(*Tuple).second == TypeMem {
		return true
	}
	if t.kind == TRESULTS {
		if types := t.extra.(*Results).Types; len(types) > 0 && types[len(types)-1] == TypeMem {
			return true
		}
	}
	return false
}
func (t *Type) IsFlags() bool   { return t == TypeFlags }
func (t *Type) IsVoid() bool    { return t == TypeVoid }
func (t *Type) IsTuple() bool   { return t.kind == TTUPLE }
func (t *Type) IsResults() bool { return t.kind == TRESULTS }

// IsUntyped reports whether t is an untyped type.
func (t *Type) IsUntyped() bool {
	if t == nil {
		return false
	}
	if t == UntypedString || t == UntypedBool {
		return true
	}
	switch t.kind {
	case TNIL, TIDEAL:
		return true
	}
	return false
}

// HasPointers reports whether t contains a heap pointer.
// Note that this function ignores pointers to not-in-heap types.
func (t *Type) HasPointers() bool {
	return PtrDataSize(t) > 0
}

var recvType *Type

// FakeRecvType returns the singleton type used for interface method receivers.
func FakeRecvType() *Type {
	if recvType == nil {
		recvType = NewPtr(newType(TSTRUCT))
	}
	return recvType
}

func FakeRecv() *Field {
	return NewField(base.AutogeneratedPos, nil, FakeRecvType())
}

var (
	// TSSA types. HasPointers assumes these are pointer-free.
	TypeInvalid   = newSSA("invalid")
	TypeMem       = newSSA("mem")
	TypeFlags     = newSSA("flags")
	TypeVoid      = newSSA("void")
	TypeInt128    = newSSA("int128")
	TypeResultMem = newResults([]*Type{TypeMem})
)

func init() {
	TypeInt128.width = 16
	TypeInt128.align = 8
}

// NewNamed returns a new named type for the given type name. obj should be an
// ir.Name. The new type is incomplete (marked as TFORW kind), and the underlying
// type should be set later via SetUnderlying(). References to the type are
// maintained until the type is filled in, so those references can be updated when
// the type is complete.
func NewNamed(obj Object) *Type {
	t := newType(TFORW)
	t.obj = obj
	sym := obj.Sym()
	if sym.Pkg == ShapePkg {
		t.SetIsShape(true)
		t.SetHasShape(true)
	}
	if sym.Pkg.Path == "internal/runtime/sys" && sym.Name == "nih" {
		// Recognize the special not-in-heap type. Any type including
		// this type will also be not-in-heap.
		// This logic is duplicated in go/types and
		// cmd/compile/internal/types2.
		t.SetNotInHeap(true)
	}
	return t
}

// Obj returns the canonical type name node for a named type t, nil for an unnamed type.
func (t *Type) Obj() Object {
	return t.obj
}

// SetUnderlying sets the underlying type of an incomplete type (i.e. type whose kind
// is currently TFORW). SetUnderlying automatically updates any types that were waiting
// for this type to be completed.
func (t *Type) SetUnderlying(underlying *Type) {
	if underlying.kind == TFORW {
		// This type isn't computed yet; when it is, update n.
		underlying.forwardType().Copyto = append(underlying.forwardType().Copyto, t)
		return
	}

	ft := t.forwardType()

	// TODO(mdempsky): Fix Type rekinding.
	t.kind = underlying.kind
	t.extra = underlying.extra
	t.width = underlying.width
	t.align = underlying.align
	t.alg = underlying.alg
	t.ptrBytes = underlying.ptrBytes
	t.intRegs = underlying.intRegs
	t.floatRegs = underlying.floatRegs
	t.underlying = underlying.underlying

	if underlying.NotInHeap() {
		t.SetNotInHeap(true)
	}
	if underlying.HasShape() {
		t.SetHasShape(true)
	}

	// spec: "The declared type does not inherit any methods bound
	// to the existing type, but the method set of an interface
	// type [...] remains unchanged."
	if t.IsInterface() {
		t.methods = underlying.methods
		t.allMethods = underlying.allMethods
	}

	// Update types waiting on this type.
	for _, w := range ft.Copyto {
		w.SetUnderlying(t)
	}

	// Double-check use of type as embedded type.
	if ft.Embedlineno.IsKnown() {
		if t.IsPtr() || t.IsUnsafePtr() {
			base.ErrorfAt(ft.Embedlineno, errors.InvalidPtrEmbed, "embedded type cannot be a pointer")
		}
	}
}

func fieldsHasShape(fields []*Field) bool {
	for _, f := range fields {
		if f.Type != nil && f.Type.HasShape() {
			return true
		}
	}
	return false
}

// newBasic returns a new basic type of the given kind.
func newBasic(kind Kind, obj Object) *Type {
	t := newType(kind)
	t.obj = obj
	return t
}

// NewInterface returns a new interface for the given methods and
// embedded types. Embedded types are specified as fields with no Sym.
func NewInterface(methods []*Field) *Type {
	t := newType(TINTER)
	t.SetInterface(methods)
	for _, f := range methods {
		// f.Type could be nil for a broken interface declaration
		if f.Type != nil && f.Type.HasShape() {
			t.SetHasShape(true)
			break
		}
	}
	return t
}

// NewSignature returns a new function type for the given receiver,
// parameters, and results, any of which may be nil.
func NewSignature(recv *Field, params, results []*Field) *Type {
	startParams := 0
	if recv != nil {
		startParams = 1
	}
	startResults := startParams + len(params)

	allParams := make([]*Field, startResults+len(results))
	if recv != nil {
		allParams[0] = recv
	}
	copy(allParams[startParams:], params)
	copy(allParams[startResults:], results)

	t := newType(TFUNC)
	ft := t.funcType()

	funargs := func(fields []*Field) *Type {
		s := NewStruct(fields)
		s.StructType().ParamTuple = true
		return s
	}

	ft.allParams = allParams
	ft.startParams = startParams
	ft.startResults = startResults

	ft.resultsTuple = funargs(allParams[startResults:])

	if fieldsHasShape(allParams) {
		t.SetHasShape(true)
	}

	return t
}

// NewStruct returns a new struct with the given fields.
func NewStruct(fields []*Field) *Type {
	t := newType(TSTRUCT)
	t.setFields(fields)
	if fieldsHasShape(fields) {
		t.SetHasShape(true)
	}
	for _, f := range fields {
		if f.Type.NotInHeap() {
			t.SetNotInHeap(true)
			break
		}
	}

	return t
}

var (
	IsInt     [NTYPE]bool
	IsFloat   [NTYPE]bool
	IsComplex [NTYPE]bool
	IsSimple  [NTYPE]bool
)

var IsOrdered [NTYPE]bool

// IsReflexive reports whether t has a reflexive equality operator.
// That is, if x==x for all x of type t.
func IsReflexive(t *Type) bool {
	switch t.Kind() {
	case TBOOL,
		TINT,
		TUINT,
		TINT8,
		TUINT8,
		TINT16,
		TUINT16,
		TINT32,
		TUINT32,
		TINT64,
		TUINT64,
		TUINTPTR,
		TPTR,
		TUNSAFEPTR,
		TSTRING,
		TCHAN:
		return true

	case TFLOAT32,
		TFLOAT64,
		TCOMPLEX64,
		TCOMPLEX128,
		TINTER:
		return false

	case TARRAY:
		return IsReflexive(t.Elem())

	case TSTRUCT:
		for _, t1 := range t.Fields() {
			if !IsReflexive(t1.Type) {
				return false
			}
		}
		return true

	default:
		base.Fatalf("bad type for map key: %v", t)
		return false
	}
}

// Can this type be stored directly in an interface word?
// Yes, if the representation is a single pointer.
func IsDirectIface(t *Type) bool {
	switch t.Kind() {
	case TPTR:
		// Pointers to notinheap types must be stored indirectly. See issue 42076.
		return !t.Elem().NotInHeap()
	case TCHAN,
		TMAP,
		TFUNC,
		TUNSAFEPTR:
		return true

	case TARRAY:
		// Array of 1 direct iface type can be direct.
		return t.NumElem() == 1 && IsDirectIface(t.Elem())

	case TSTRUCT:
		// Struct with 1 field of direct iface type can be direct.
		return t.NumFields() == 1 && IsDirectIface(t.Field(0).Type)
	}

	return false
}

// IsInterfaceMethod reports whether (field) m is
// an interface method. Such methods have the
// special receiver type types.FakeRecvType().
func IsInterfaceMethod(f *Type) bool {
	return f.Recv().Type == FakeRecvType()
}

// IsMethodApplicable reports whether method m can be called on a
// value of type t. This is necessary because we compute a single
// method set for both T and *T, but some *T methods are not
// applicable to T receivers.
func IsMethodApplicable(t *Type, m *Field) bool {
	return t.IsPtr() || !m.Type.Recv().Type.IsPtr() || IsInterfaceMethod(m.Type) || m.Embedded == 2
}

// RuntimeSymName returns the name of s if it's in package "runtime"; otherwise
// it returns "".
func RuntimeSymName(s *Sym) string {
	if s.Pkg.Path == "runtime" {
		return s.Name
	}
	return ""
}

// ReflectSymName returns the name of s if it's in package "reflect"; otherwise
// it returns "".
func ReflectSymName(s *Sym) string {
	if s.Pkg.Path == "reflect" {
		return s.Name
	}
	return ""
}

// IsNoInstrumentPkg reports whether p is a package that
// should not be instrumented.
func IsNoInstrumentPkg(p *Pkg) bool {
	return objabi.LookupPkgSpecial(p.Path).NoInstrument
}

// IsNoRacePkg reports whether p is a package that
// should not be race instrumented.
func IsNoRacePkg(p *Pkg) bool {
	return objabi.LookupPkgSpecial(p.Path).NoRaceFunc
}

// IsRuntimePkg reports whether p is a runtime package.
func IsRuntimePkg(p *Pkg) bool {
	return objabi.LookupPkgSpecial(p.Path).Runtime
}

// ReceiverBaseType returns the underlying type, if any,
// that owns methods with receiver parameter t.
// The result is either a named type or an anonymous struct.
func ReceiverBaseType(t *Type) *Type {
	if t == nil {
		return nil
	}

	// Strip away pointer if it's there.
	if t.IsPtr() {
		if t.Sym() != nil {
			return nil
		}
		t = t.Elem()
		if t == nil {
			return nil
		}
	}

	// Must be a named type or anonymous struct.
	if t.Sym() == nil && !t.IsStruct() {
		return nil
	}

	// Check types.
	if IsSimple[t.Kind()] {
		return t
	}
	switch t.Kind() {
	case TARRAY, TCHAN, TFUNC, TMAP, TSLICE, TSTRING, TSTRUCT:
		return t
	}
	return nil
}

func FloatForComplex(t *Type) *Type {
	switch t.Kind() {
	case TCOMPLEX64:
		return Types[TFLOAT32]
	case TCOMPLEX128:
		return Types[TFLOAT64]
	}
	base.Fatalf("unexpected type: %v", t)
	return nil
}

func ComplexForFloat(t *Type) *Type {
	switch t.Kind() {
	case TFLOAT32:
		return Types[TCOMPLEX64]
	case TFLOAT64:
		return Types[TCOMPLEX128]
	}
	base.Fatalf("unexpected type: %v", t)
	return nil
}

func TypeSym(t *Type) *Sym {
	return TypeSymLookup(TypeSymName(t))
}

func TypeSymLookup(name string) *Sym {
	typepkgmu.Lock()
	s := typepkg.Lookup(name)
	typepkgmu.Unlock()
	return s
}

func TypeSymName(t *Type) string {
	name := t.LinkString()
	// Use a separate symbol name for Noalg types for #17752.
	if TypeHasNoAlg(t) {
		name = "noalg." + name
	}
	return name
}

// Fake package for runtime type info (headers)
// Don't access directly, use typeLookup below.
var (
	typepkgmu sync.Mutex // protects typepkg lookups
	typepkg   = NewPkg("type", "type")
)

var SimType [NTYPE]Kind

// Fake package for shape types (see typecheck.Shapify()).
var ShapePkg = NewPkg("go.shape", "go.shape")
```