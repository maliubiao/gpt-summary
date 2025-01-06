Response:
The user wants a summary of the functionality of the provided Go code snippet. This code defines the `Type` struct and related methods for representing Go types within the `cmd/compile/internal/types` package.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the core entity:** The central element is the `Type` struct. The methods are clearly operating on instances of this struct.

2. **Understand the purpose of the package:** The path `go/src/cmd/compile/internal/types/type.go` indicates this code is part of the Go compiler. Therefore, the `Type` struct is used internally by the compiler to represent Go types during compilation.

3. **Categorize the methods:** Group the methods based on their apparent function. Looking through the code, some obvious categories emerge:

    * **Comparison:** The `cmp` method stands out for type comparison.
    * **Kind Checking:**  Methods like `IsKind`, `IsBoolean`, `IsInteger`, etc., are for determining the category or nature of a type.
    * **Type Conversion/Related Types:** Methods like `ToUnsigned`, `PtrTo`, `Elem`, `Key`, `Value` provide related types or perform conversions.
    * **Structure/Layout Information:** Methods like `NumFields`, `FieldType`, `FieldOff`, `FieldName`, `OffsetOf`, `NumElem`, `NumComponents` deal with the structure and memory layout of composite types.
    * **Properties:** Methods like `HasNil`, `HasPointers`, `IsReflexive`, `IsDirectIface` check for specific properties of the type.
    * **Function/Method Related:** Methods like `NumRecvs`, `NumParams`, `NumResults`, `IsVariadic`, `RecvParamsResults`, `IsInterfaceMethod`, `IsMethodApplicable`.
    * **Named Types:** Methods related to named types like `NewNamed`, `Obj`, `SetUnderlying`.
    * **New Type Constructors:** Functions starting with `New` (e.g., `NewInterface`, `NewSignature`, `NewStruct`, `NewPtr`, `NewArray`, `NewMap`, `NewChan`, `NewSlice`) are used to create new `Type` instances.
    * **Internal/SSA Related:**  Methods and variables prefixed with "Fake" or the `TypeMem`, `TypeFlags` etc. suggest internal compiler representations, likely related to Static Single Assignment (SSA).
    * **Package and Symbol Related:**  Functions like `RuntimeSymName`, `ReflectSymName`, `IsNoInstrumentPkg`, `IsNoRacePkg`, `IsRuntimePkg`, `TypeSym`, `TypeSymName` deal with the association of types with packages and symbols.

4. **Infer the purpose of the `cmp` method:**  The `cmp` method handles various type kinds and compares their properties. This is likely used for type equality checks or ordering, which is crucial for compiler optimizations and type system correctness. The handling of different type kinds (struct, func, array, chan) suggests it's a comprehensive comparison function.

5. **Infer the purpose of `IsKind` and related methods:** These are straightforward type introspection methods used throughout the compiler to make decisions based on the type's nature.

6. **Infer the purpose of `ToUnsigned`, `PtrTo`, etc.:** These are utility functions for easily obtaining related types, which is common in type manipulation within a compiler.

7. **Infer the purpose of structure/layout methods:** These are essential for code generation, memory allocation, and understanding the memory representation of data.

8. **Infer the purpose of `HasNil`, `HasPointers`, etc.:** These properties are important for various compiler analyses, such as escape analysis (for `HasPointers`) and determining valid operations.

9. **Infer the purpose of function/method related methods:** These are used to represent and analyze function signatures and method definitions, which is central to compiling function calls and method invocations.

10. **Infer the purpose of named type methods:**  Named types are fundamental in Go. These methods manage the creation and linking of named types. The `SetUnderlying` method is crucial for handling forward declarations.

11. **Infer the purpose of the `New*` functions:** These are the primary ways to instantiate `Type` objects for different kinds of types.

12. **Infer the purpose of internal/SSA related elements:** The "Fake" prefix and names like `TypeMem` suggest these are internal representations used during the compiler's intermediate stages.

13. **Infer the purpose of package and symbol related functions:** These connect the type system with the broader symbol table and package structure of the Go program.

14. **Synthesize the summary:**  Combine the insights from the categorized methods to produce a concise summary of the code's functionality. Emphasize the central role of the `Type` struct and its methods in representing and manipulating Go types within the compiler.

15. **Review and Refine:**  Read the generated summary to ensure accuracy and completeness. Check if it captures the key functionalities of the provided code. Make sure the language is clear and understandable.

This systematic approach of identifying the core entity, categorizing methods, and inferring purposes allows for a comprehensive understanding and effective summarization of the given code snippet.
这是 `go/src/cmd/compile/internal/types/type.go` 文件的一部分，主要负责定义和操作 Go 语言的类型系统。以下是对其功能的归纳：

**核心功能：表示和比较 Go 语言类型**

这段代码的核心目标是定义 `Type` 结构体，用于在 Go 编译器内部表示各种 Go 语言类型，例如基本类型（int、bool、string）、复合类型（数组、切片、结构体、函数、指针、Map、Channel、接口）以及一些特殊的内部类型。

该代码片段着重展示了 `Type` 结构体的比较功能，通过 `cmp` 方法实现了对不同类型进行深度比较，判断两个类型是否相同或存在某种顺序关系。

**具体功能点：**

1. **类型比较 (`cmp` 方法):**
   - 实现了对各种 Go 语言类型的比较逻辑。
   - 对于**命名类型 (TFORW)**，会递归比较其对应的符号。
   - 对于**结构体 (TSTRUCT)**，会比较字段的数量和每个字段的类型。
   - 对于**函数 (TFUNC)**，会比较接收者、参数和返回值的数量及类型，以及是否是变参函数。
   - 对于**数组 (TARRAY)**，会比较元素的数量。
   - 对于**通道 (TCHAN)**，会比较通道的方向。
   - 对于**指针、切片等类型**，会递归比较其元素类型。
   - 如果遇到未知的类型比较，会触发 panic。

2. **类型判断 (`IsKind` 及一系列 `Is...` 方法):**
   - 提供了一系列方法来判断一个 `Type` 对象是否属于特定的类型或类别，例如：
     - `IsKind(et Kind)`: 判断是否是指定的 Kind。
     - `IsBoolean()`: 判断是否是布尔类型。
     - `IsInteger()`, `IsSigned()`, `IsUnsigned()`: 判断是否是整数类型，以及是否是有符号或无符号。
     - `IsFloat()`, `IsComplex()`: 判断是否是浮点数或复数类型。
     - `IsPtr()`, `IsUnsafePtr()`, `IsUintptr()`: 判断是否是指针类型。
     - `IsString()`, `IsMap()`, `IsChan()`, `IsSlice()`, `IsArray()`, `IsStruct()`, `IsInterface()`: 判断是否是相应的复合类型。
     - `IsEmptyInterface()`: 判断是否是空接口。
     - `IsScalar()`: 判断是否是标量类型。
     - `IsUntyped()`: 判断是否是未确定类型。
     - `HasNil()`: 判断该类型的值是否可以为 nil。
     - `HasPointers()`: 判断该类型是否包含指针。

3. **获取相关类型的方法:**
   - `ToUnsigned()`: 获取整数类型对应的无符号类型。
   - `PtrTo()`: 获取指向该类型的指针类型。
   - `NumElem()`: 获取数组的元素数量。
   - `ChanDir()`: 获取通道的方向。
   - `FieldType(i int)`: 获取结构体或元组中第 i 个字段的类型。
   - `FieldName(i int)`: 获取结构体中第 i 个字段的名称。
   - `OffsetOf(name string)`: 获取结构体中指定名称字段的偏移量。
   - `NumComponents()`: 获取类型包含的原始元素数量（递归展开结构体和数组）。
   - `SoleComponent()`: 获取类型中唯一的原始元素类型（如果只有一个）。
   - `Recv()`: 获取函数类型的接收者。
   - `Params()`: 获取函数类型的参数列表。
   - `Results()`: 获取函数类型的返回值列表。

4. **创建新类型的方法 (`New...` 函数):**
   - 提供了一系列函数用于创建不同类型的 `Type` 对象，例如：
     - `NewNamed(obj Object)`: 创建一个命名类型。
     - `NewInterface(methods []*Field)`: 创建一个接口类型。
     - `NewSignature(recv *Field, params, results []*Field)`: 创建一个函数类型。
     - `NewStruct(fields []*Field)`: 创建一个结构体类型。
     - `NewPtr(elem *Type)`: 创建一个指针类型。
     - `NewArray(elem *Type, bound int64)`: 创建一个数组类型。
     - `NewSlice(elem *Type)`: 创建一个切片类型。
     - `NewMap(key, elem *Type)`: 创建一个 Map 类型。
     - `NewChan(elem *Type, dir ChanDir)`: 创建一个 Channel 类型。

5. **处理命名类型 (`TFORW`):**
   - 引入了 `TFORW` (forward) 类型，用于处理类型的前向声明。
   - `SetUnderlying(underlying *Type)`: 用于设置 `TFORW` 类型的实际底层类型，并更新所有依赖该类型的其他类型。

6. **与符号 (Symbol) 和包 (Package) 的关联:**
   - `Obj()`: 获取命名类型关联的 `Object`（通常是 `ir.Name`）。
   - `TypeSym(t *Type)` 和 `TypeSymLookup(name string)`: 用于获取或查找与类型关联的符号。
   - 提供了判断类型或符号是否属于特定包（如 "runtime", "reflect"）的方法。

7. **内部类型和常量:**
   - 定义了一些内部使用的特殊类型，例如 `TypeMem`, `TypeFlags`, `TypeVoid`, `TypeInt128`。
   - 定义了一些常量，例如 `IgnoreBlankFields`, `CountBlankFields` 用于控制某些操作的行为。

**总结 `cmp` 方法的功能：**

`cmp` 方法的核心功能是 **比较两个 `Type` 对象是否相等或存在顺序关系**。 它通过递归地比较两个类型的各个组成部分（例如，对于结构体比较字段，对于函数比较参数和返回值）来实现深度的类型比较。 这个方法是 Go 编译器内部类型系统的重要组成部分，用于类型检查、类型推断和代码优化等多个环节。

**代码示例 (假设输入与输出):**

```go
package main

import "fmt"
import "cmd/compile/internal/types"

func main() {
	// 假设已经创建了两个类型对象 type1 和 type2
	// 并且 type1 是 *types.Type, type2 也是 *types.Type

	// 假设 type1 代表 int 类型， type2 也代表 int 类型
	type1 := types.Types[types.TINT]
	type2 := types.Types[types.TINT]

	// 比较 type1 和 type2
	comparisonResult := type1.Cmp(type2)
	fmt.Println("比较结果 (CMPeq = 0):", comparisonResult) // 输出: 比较结果 (CMPeq = 0): 0

	// 假设 type3 代表 string 类型
	type3 := types.Types[types.TSTRING]

	// 比较 type1 和 type3
	comparisonResult = type1.Cmp(type3)
	fmt.Println("比较结果 (CMPne < 0 或 > 0):", comparisonResult) // 输出: 比较结果 (CMPne < 0 或 > 0): -1 (或 1，取决于比较顺序)

	// 假设 type4 代表一个包含一个 int 字段的结构体
	field := types.NewField(0, types.NewPkg("", ""), types.Types[types.TINT])
	field.Sym = types.NewSym(types.NewPkg("", ""), "Field1")
	type4 := types.NewStruct([]*types.Field{field})

	// 假设 type5 代表另一个包含一个 int 字段的结构体
	field2 := types.NewField(0, types.NewPkg("", ""), types.Types[types.TINT])
	field2.Sym = types.NewSym(types.NewPkg("", ""), "FieldA") // 不同的字段名
	type5 := types.NewStruct([]*types.Field{field2})

	comparisonResult = type4.Cmp(type5)
	fmt.Println("比较结构体结果 (字段名不同):", comparisonResult) // 输出: 比较结构体结果 (字段名不同): -1 (或 1)

	// 假设 type6 代表一个指向 int 的指针
	type6 := types.NewPtr(types.Types[types.TINT])

	comparisonResult = type1.Cmp(type6)
	fmt.Println("比较 int 和 *int:", comparisonResult) // 输出: 比较 int 和 *int: -1 (或 1)
}
```

**假设的输入与输出:**

上面代码示例中已经包含了假设的输入（创建不同的 `types.Type` 对象）和预期的输出（比较结果）。

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。命令行参数的处理通常发生在 `cmd/compile/internal/gc` 包或其他编译器的前端部分。`types` 包主要负责类型系统的表示和操作，供编译器的其他阶段使用。

**使用者易犯错的点 (不在此部分代码中体现):**

虽然这段代码本身是类型系统的核心实现，但开发者在使用 `cmd/compile/internal/types` 包时可能会犯一些错误，例如：

- **不正确地创建或初始化 `Type` 对象。**
- **在类型比较时，错误地理解类型的相等性 (例如，两个匿名结构体即使字段相同，在某些情况下也不被认为是同一个类型)。**
- **过度依赖内部类型系统的细节，而这些细节可能会在 Go 版本更新中发生变化。**

这段代码是 Go 编译器内部类型系统的基础，提供了类型表示、比较和操作的关键功能，为编译器的类型检查、代码生成和优化等环节提供了必要的支持。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/types/type.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

"""
 t1.Sym.cmpsym(x1.Sym); c != CMPeq {
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

"""




```