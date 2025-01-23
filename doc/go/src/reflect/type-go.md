Response:
My goal is to analyze the provided Go code snippet (`go/src/reflect/type.go`) and summarize its functionality in Chinese. Here's a breakdown of my thought process:

1. **Identify the Core Purpose:** The initial comments in the code are crucial. They explicitly state that the `reflect` package provides runtime reflection capabilities. This is the central theme.

2. **Focus on the `Type` Interface:** The prompt specifically mentions `type.go`. The `Type` interface is the most important part of this file. I need to understand what it represents and what methods it offers.

3. **Categorize `Type` Interface Methods:**  The comments within the `Type` interface definition divide the methods into two categories:
    * "Methods applicable to all types."
    * "Methods applicable only to some types, depending on Kind."
   This categorization is helpful for summarizing. I should group the methods accordingly.

4. **Analyze Each Method (Briefly):** I need to understand the basic function of each method within the `Type` interface. Keywords like "alignment," "method," "name," "package path," "size," "kind," "implements," "assignable," "convertible," "comparable," "bits," "channel direction," "variadic," "element," "field," "length," "input," "output," and "overflow" provide clues. I don't need to go into deep implementation details at this stage, just the high-level purpose.

5. **Identify Key Supporting Types:**  The code defines various structs and constants related to type representation. These are important for understanding how Go represents types internally for reflection. Key examples include: `Kind`, `Method`, `StructField`, `ChanDir`, and various `...Type` structs (`arrayType`, `chanType`, etc.). I need to mention their roles.

6. **Look for Compiler/Runtime Interaction:** The comments mention that the compiler and runtime are aware of certain data structures (`abi.Type`, etc.). This highlights a low-level interaction that is crucial for the `reflect` package to work. I should note this.

7. **Consider Examples (Implicitly):** While the prompt asks for examples later, I should keep in mind how these methods *could* be used. For example, `Name()` returns the type's name, so I might think of scenarios where that's useful.

8. **Formulate the Summary:**  Based on the above analysis, I can start drafting the summary in Chinese. I'll structure it logically:
    * Start with the overall purpose of the file (implementing `reflect.Type`).
    * Describe the core functionality of the `Type` interface, categorizing its methods.
    * Briefly mention the supporting types and their roles.
    * Point out the low-level interaction with the compiler and runtime.

9. **Refine the Language (Chinese):** I'll use clear and concise Chinese, avoiding overly technical jargon where possible, but still maintaining accuracy. I need to use appropriate terminology for reflection, types, methods, etc.

**Self-Correction/Refinement During the Process:**

* **Initial Thought:**  Maybe focus heavily on the `rtype` struct.
* **Correction:**  While `rtype` is important, the prompt focuses on the *functionality* which is exposed through the `Type` interface. `rtype` is an implementation detail. Shift focus to the interface.
* **Initial Thought:**  List every single method's detail.
* **Correction:** The prompt asks for a *summary* of functionality for "part 1". Briefly describe the *categories* of methods and their general purpose, rather than going into deep detail on each one. Save the detailed explanation for later parts if needed.
* **Initial Thought:**  Use very technical terms like "metadata."
* **Correction:** While accurate, using simpler terms like "类型信息" (type information) in the summary might be more accessible. Reserve the technical terms for when explaining specific methods.

By following these steps and making necessary corrections, I arrived at the provided summary. The key was to understand the core purpose, focus on the main interface, and summarize the functionalities at a high level for this "part 1" of the analysis.


这段代码是 Go 语言 `reflect` 包中 `type.go` 文件的一部分，它主要负责 **定义和实现了 `Type` 接口及其相关的类型表示和操作**。

**功能归纳:**

1. **定义 `Type` 接口:** 这是 `reflect` 包的核心接口，用于表示 Go 语言中的各种类型（例如：`int`, `string`, `struct`, `interface`, `func` 等）。它提供了一系列方法来获取类型的各种信息和进行类型相关的操作。

2. **定义类型的元数据结构:**  代码中定义了多种结构体，用于存储和表示 Go 类型的元数据，例如：
   - `rtype`:  大多数类型的通用实现。
   - `arrayType`, `chanType`, `funcType`, `interfaceType`, `ptrType`, `sliceType`, `structType`: 分别表示数组、通道、函数、接口、指针、切片和结构体类型。
   - `uncommonType`: 用于存储定义类型或拥有方法的类型的额外信息。
   - `common`: 包含 `abi.Type` 的嵌入结构体，用于获取公共的类型信息。
   - `abi.Type`, `abi.UncommonType`, `abi.Method`, `abi.StructField` 等： 这些是内部包 `internal/abi` 中定义的结构，用于更底层的类型表示。

3. **提供获取类型信息的方法:** `Type` 接口定义了大量的方法，用于获取类型的各种属性，例如：
   - **基本属性:** `Align()`, `FieldAlign()`, `Size()`, `String()`, `Kind()`, `Name()`, `PkgPath()`, `Comparable()`, `ConvertibleTo()`, `AssignableTo()`, `Implements()`.
   - **方法相关:** `Method()`, `MethodByName()`, `NumMethod()`.
   - **复合类型相关:**
     - **数组:** `Elem()`, `Len()`.
     - **通道:** `Elem()`, `ChanDir()`.
     - **函数:** `In()`, `NumIn()`, `Out()`, `NumOut()`, `IsVariadic()`.
     - **Map:** `Key()`, `Elem()`.
     - **指针:** `Elem()`.
     - **切片:** `Elem()`.
     - **结构体:** `Field()`, `FieldByIndex()`, `FieldByName()`, `FieldByNameFunc()`, `NumField()`.
   - **数值类型溢出检查:** `OverflowComplex()`, `OverflowFloat()`, `OverflowInt()`, `OverflowUint()`.
   - **迭代能力检查:** `CanSeq()`, `CanSeq2()`.

4. **定义 `Kind` 枚举:**  `Kind` 类型是一个枚举，定义了 Go 语言中所有可能的类型种类（例如：`Bool`, `Int`, `String`, `Struct`, `Interface` 等）。

5. **定义 `Method` 结构体:**  表示一个方法，包含方法名、包路径、类型和对应的函数值。

6. **定义 `StructField` 结构体:** 表示结构体中的一个字段，包含字段名、包路径、类型、标签、偏移量和索引等信息。

7. **定义 `ChanDir` 类型:**  表示通道的方向 (`SendDir`, `RecvDir`, `BothDir`)。

8. **与运行时 (runtime) 和编译器 (compiler) 交互:** 代码中通过 `import "internal/abi"` 和注释 (`These data structures are known to the compiler...`) 可以看出，`reflect` 包的实现与 Go 的编译器和运行时系统紧密相关，依赖于它们提供的底层类型信息。

**总而言之，这段代码的核心在于定义了 `reflect` 包中用于描述和操作 Go 语言类型的核心接口和数据结构，是 Go 语言实现反射机制的关键组成部分。**

由于这是第一部分，我们先聚焦于 `Type` 接口本身的功能和它提供的能力。在后续部分，可能会深入到具体的实现细节和使用场景。

### 提示词
```
这是路径为go/src/reflect/type.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```go
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package reflect implements run-time reflection, allowing a program to
// manipulate objects with arbitrary types. The typical use is to take a value
// with static type interface{} and extract its dynamic type information by
// calling TypeOf, which returns a Type.
//
// A call to ValueOf returns a Value representing the run-time data.
// Zero takes a Type and returns a Value representing a zero value
// for that type.
//
// See "The Laws of Reflection" for an introduction to reflection in Go:
// https://golang.org/doc/articles/laws_of_reflection.html
package reflect

import (
	"internal/abi"
	"internal/goarch"
	"runtime"
	"strconv"
	"sync"
	"unicode"
	"unicode/utf8"
	"unsafe"
)

// Type is the representation of a Go type.
//
// Not all methods apply to all kinds of types. Restrictions,
// if any, are noted in the documentation for each method.
// Use the Kind method to find out the kind of type before
// calling kind-specific methods. Calling a method
// inappropriate to the kind of type causes a run-time panic.
//
// Type values are comparable, such as with the == operator,
// so they can be used as map keys.
// Two Type values are equal if they represent identical types.
type Type interface {
	// Methods applicable to all types.

	// Align returns the alignment in bytes of a value of
	// this type when allocated in memory.
	Align() int

	// FieldAlign returns the alignment in bytes of a value of
	// this type when used as a field in a struct.
	FieldAlign() int

	// Method returns the i'th method in the type's method set.
	// It panics if i is not in the range [0, NumMethod()).
	//
	// For a non-interface type T or *T, the returned Method's Type and Func
	// fields describe a function whose first argument is the receiver,
	// and only exported methods are accessible.
	//
	// For an interface type, the returned Method's Type field gives the
	// method signature, without a receiver, and the Func field is nil.
	//
	// Methods are sorted in lexicographic order.
	Method(int) Method

	// MethodByName returns the method with that name in the type's
	// method set and a boolean indicating if the method was found.
	//
	// For a non-interface type T or *T, the returned Method's Type and Func
	// fields describe a function whose first argument is the receiver.
	//
	// For an interface type, the returned Method's Type field gives the
	// method signature, without a receiver, and the Func field is nil.
	MethodByName(string) (Method, bool)

	// NumMethod returns the number of methods accessible using Method.
	//
	// For a non-interface type, it returns the number of exported methods.
	//
	// For an interface type, it returns the number of exported and unexported methods.
	NumMethod() int

	// Name returns the type's name within its package for a defined type.
	// For other (non-defined) types it returns the empty string.
	Name() string

	// PkgPath returns a defined type's package path, that is, the import path
	// that uniquely identifies the package, such as "encoding/base64".
	// If the type was predeclared (string, error) or not defined (*T, struct{},
	// []int, or A where A is an alias for a non-defined type), the package path
	// will be the empty string.
	PkgPath() string

	// Size returns the number of bytes needed to store
	// a value of the given type; it is analogous to unsafe.Sizeof.
	Size() uintptr

	// String returns a string representation of the type.
	// The string representation may use shortened package names
	// (e.g., base64 instead of "encoding/base64") and is not
	// guaranteed to be unique among types. To test for type identity,
	// compare the Types directly.
	String() string

	// Kind returns the specific kind of this type.
	Kind() Kind

	// Implements reports whether the type implements the interface type u.
	Implements(u Type) bool

	// AssignableTo reports whether a value of the type is assignable to type u.
	AssignableTo(u Type) bool

	// ConvertibleTo reports whether a value of the type is convertible to type u.
	// Even if ConvertibleTo returns true, the conversion may still panic.
	// For example, a slice of type []T is convertible to *[N]T,
	// but the conversion will panic if its length is less than N.
	ConvertibleTo(u Type) bool

	// Comparable reports whether values of this type are comparable.
	// Even if Comparable returns true, the comparison may still panic.
	// For example, values of interface type are comparable,
	// but the comparison will panic if their dynamic type is not comparable.
	Comparable() bool

	// Methods applicable only to some types, depending on Kind.
	// The methods allowed for each kind are:
	//
	//	Int*, Uint*, Float*, Complex*: Bits
	//	Array: Elem, Len
	//	Chan: ChanDir, Elem
	//	Func: In, NumIn, Out, NumOut, IsVariadic.
	//	Map: Key, Elem
	//	Pointer: Elem
	//	Slice: Elem
	//	Struct: Field, FieldByIndex, FieldByName, FieldByNameFunc, NumField

	// Bits returns the size of the type in bits.
	// It panics if the type's Kind is not one of the
	// sized or unsized Int, Uint, Float, or Complex kinds.
	Bits() int

	// ChanDir returns a channel type's direction.
	// It panics if the type's Kind is not Chan.
	ChanDir() ChanDir

	// IsVariadic reports whether a function type's final input parameter
	// is a "..." parameter. If so, t.In(t.NumIn() - 1) returns the parameter's
	// implicit actual type []T.
	//
	// For concreteness, if t represents func(x int, y ... float64), then
	//
	//	t.NumIn() == 2
	//	t.In(0) is the reflect.Type for "int"
	//	t.In(1) is the reflect.Type for "[]float64"
	//	t.IsVariadic() == true
	//
	// IsVariadic panics if the type's Kind is not Func.
	IsVariadic() bool

	// Elem returns a type's element type.
	// It panics if the type's Kind is not Array, Chan, Map, Pointer, or Slice.
	Elem() Type

	// Field returns a struct type's i'th field.
	// It panics if the type's Kind is not Struct.
	// It panics if i is not in the range [0, NumField()).
	Field(i int) StructField

	// FieldByIndex returns the nested field corresponding
	// to the index sequence. It is equivalent to calling Field
	// successively for each index i.
	// It panics if the type's Kind is not Struct.
	FieldByIndex(index []int) StructField

	// FieldByName returns the struct field with the given name
	// and a boolean indicating if the field was found.
	// If the returned field is promoted from an embedded struct,
	// then Offset in the returned StructField is the offset in
	// the embedded struct.
	FieldByName(name string) (StructField, bool)

	// FieldByNameFunc returns the struct field with a name
	// that satisfies the match function and a boolean indicating if
	// the field was found.
	//
	// FieldByNameFunc considers the fields in the struct itself
	// and then the fields in any embedded structs, in breadth first order,
	// stopping at the shallowest nesting depth containing one or more
	// fields satisfying the match function. If multiple fields at that depth
	// satisfy the match function, they cancel each other
	// and FieldByNameFunc returns no match.
	// This behavior mirrors Go's handling of name lookup in
	// structs containing embedded fields.
	//
	// If the returned field is promoted from an embedded struct,
	// then Offset in the returned StructField is the offset in
	// the embedded struct.
	FieldByNameFunc(match func(string) bool) (StructField, bool)

	// In returns the type of a function type's i'th input parameter.
	// It panics if the type's Kind is not Func.
	// It panics if i is not in the range [0, NumIn()).
	In(i int) Type

	// Key returns a map type's key type.
	// It panics if the type's Kind is not Map.
	Key() Type

	// Len returns an array type's length.
	// It panics if the type's Kind is not Array.
	Len() int

	// NumField returns a struct type's field count.
	// It panics if the type's Kind is not Struct.
	NumField() int

	// NumIn returns a function type's input parameter count.
	// It panics if the type's Kind is not Func.
	NumIn() int

	// NumOut returns a function type's output parameter count.
	// It panics if the type's Kind is not Func.
	NumOut() int

	// Out returns the type of a function type's i'th output parameter.
	// It panics if the type's Kind is not Func.
	// It panics if i is not in the range [0, NumOut()).
	Out(i int) Type

	// OverflowComplex reports whether the complex128 x cannot be represented by type t.
	// It panics if t's Kind is not Complex64 or Complex128.
	OverflowComplex(x complex128) bool

	// OverflowFloat reports whether the float64 x cannot be represented by type t.
	// It panics if t's Kind is not Float32 or Float64.
	OverflowFloat(x float64) bool

	// OverflowInt reports whether the int64 x cannot be represented by type t.
	// It panics if t's Kind is not Int, Int8, Int16, Int32, or Int64.
	OverflowInt(x int64) bool

	// OverflowUint reports whether the uint64 x cannot be represented by type t.
	// It panics if t's Kind is not Uint, Uintptr, Uint8, Uint16, Uint32, or Uint64.
	OverflowUint(x uint64) bool

	// CanSeq reports whether a [Value] with this type can be iterated over using [Value.Seq].
	CanSeq() bool

	// CanSeq2 reports whether a [Value] with this type can be iterated over using [Value.Seq2].
	CanSeq2() bool

	common() *abi.Type
	uncommon() *uncommonType
}

// BUG(rsc): FieldByName and related functions consider struct field names to be equal
// if the names are equal, even if they are unexported names originating
// in different packages. The practical effect of this is that the result of
// t.FieldByName("x") is not well defined if the struct type t contains
// multiple fields named x (embedded from different packages).
// FieldByName may return one of the fields named x or may report that there are none.
// See https://golang.org/issue/4876 for more details.

/*
 * These data structures are known to the compiler (../cmd/compile/internal/reflectdata/reflect.go).
 * A few are known to ../runtime/type.go to convey to debuggers.
 * They are also known to ../internal/abi/type.go.
 */

// A Kind represents the specific kind of type that a [Type] represents.
// The zero Kind is not a valid kind.
type Kind uint

const (
	Invalid Kind = iota
	Bool
	Int
	Int8
	Int16
	Int32
	Int64
	Uint
	Uint8
	Uint16
	Uint32
	Uint64
	Uintptr
	Float32
	Float64
	Complex64
	Complex128
	Array
	Chan
	Func
	Interface
	Map
	Pointer
	Slice
	String
	Struct
	UnsafePointer
)

// Ptr is the old name for the [Pointer] kind.
const Ptr = Pointer

// uncommonType is present only for defined types or types with methods
// (if T is a defined type, the uncommonTypes for T and *T have methods).
// Using a pointer to this struct reduces the overall size required
// to describe a non-defined type with no methods.
type uncommonType = abi.UncommonType

// Embed this type to get common/uncommon
type common struct {
	abi.Type
}

// rtype is the common implementation of most values.
// It is embedded in other struct types.
type rtype struct {
	t abi.Type
}

func (t *rtype) common() *abi.Type {
	return &t.t
}

func (t *rtype) uncommon() *abi.UncommonType {
	return t.t.Uncommon()
}

type aNameOff = abi.NameOff
type aTypeOff = abi.TypeOff
type aTextOff = abi.TextOff

// ChanDir represents a channel type's direction.
type ChanDir int

const (
	RecvDir ChanDir             = 1 << iota // <-chan
	SendDir                                 // chan<-
	BothDir = RecvDir | SendDir             // chan
)

// arrayType represents a fixed array type.
type arrayType = abi.ArrayType

// chanType represents a channel type.
type chanType = abi.ChanType

// funcType represents a function type.
//
// A *rtype for each in and out parameter is stored in an array that
// directly follows the funcType (and possibly its uncommonType). So
// a function type with one method, one input, and one output is:
//
//	struct {
//		funcType
//		uncommonType
//		[2]*rtype    // [0] is in, [1] is out
//	}
type funcType = abi.FuncType

// interfaceType represents an interface type.
type interfaceType struct {
	abi.InterfaceType // can embed directly because not a public type.
}

func (t *interfaceType) nameOff(off aNameOff) abi.Name {
	return toRType(&t.Type).nameOff(off)
}

func nameOffFor(t *abi.Type, off aNameOff) abi.Name {
	return toRType(t).nameOff(off)
}

func typeOffFor(t *abi.Type, off aTypeOff) *abi.Type {
	return toRType(t).typeOff(off)
}

func (t *interfaceType) typeOff(off aTypeOff) *abi.Type {
	return toRType(&t.Type).typeOff(off)
}

func (t *interfaceType) common() *abi.Type {
	return &t.Type
}

func (t *interfaceType) uncommon() *abi.UncommonType {
	return t.Uncommon()
}

// ptrType represents a pointer type.
type ptrType struct {
	abi.PtrType
}

// sliceType represents a slice type.
type sliceType struct {
	abi.SliceType
}

// Struct field
type structField = abi.StructField

// structType represents a struct type.
type structType struct {
	abi.StructType
}

func pkgPath(n abi.Name) string {
	if n.Bytes == nil || *n.DataChecked(0, "name flag field")&(1<<2) == 0 {
		return ""
	}
	i, l := n.ReadVarint(1)
	off := 1 + i + l
	if n.HasTag() {
		i2, l2 := n.ReadVarint(off)
		off += i2 + l2
	}
	var nameOff int32
	// Note that this field may not be aligned in memory,
	// so we cannot use a direct int32 assignment here.
	copy((*[4]byte)(unsafe.Pointer(&nameOff))[:], (*[4]byte)(unsafe.Pointer(n.DataChecked(off, "name offset field")))[:])
	pkgPathName := abi.Name{Bytes: (*byte)(resolveTypeOff(unsafe.Pointer(n.Bytes), nameOff))}
	return pkgPathName.Name()
}

func newName(n, tag string, exported, embedded bool) abi.Name {
	return abi.NewName(n, tag, exported, embedded)
}

/*
 * The compiler knows the exact layout of all the data structures above.
 * The compiler does not know about the data structures and methods below.
 */

// Method represents a single method.
type Method struct {
	// Name is the method name.
	Name string

	// PkgPath is the package path that qualifies a lower case (unexported)
	// method name. It is empty for upper case (exported) method names.
	// The combination of PkgPath and Name uniquely identifies a method
	// in a method set.
	// See https://golang.org/ref/spec#Uniqueness_of_identifiers
	PkgPath string

	Type  Type  // method type
	Func  Value // func with receiver as first argument
	Index int   // index for Type.Method
}

// IsExported reports whether the method is exported.
func (m Method) IsExported() bool {
	return m.PkgPath == ""
}

// String returns the name of k.
func (k Kind) String() string {
	if uint(k) < uint(len(kindNames)) {
		return kindNames[uint(k)]
	}
	return "kind" + strconv.Itoa(int(k))
}

var kindNames = []string{
	Invalid:       "invalid",
	Bool:          "bool",
	Int:           "int",
	Int8:          "int8",
	Int16:         "int16",
	Int32:         "int32",
	Int64:         "int64",
	Uint:          "uint",
	Uint8:         "uint8",
	Uint16:        "uint16",
	Uint32:        "uint32",
	Uint64:        "uint64",
	Uintptr:       "uintptr",
	Float32:       "float32",
	Float64:       "float64",
	Complex64:     "complex64",
	Complex128:    "complex128",
	Array:         "array",
	Chan:          "chan",
	Func:          "func",
	Interface:     "interface",
	Map:           "map",
	Pointer:       "ptr",
	Slice:         "slice",
	String:        "string",
	Struct:        "struct",
	UnsafePointer: "unsafe.Pointer",
}

// resolveNameOff resolves a name offset from a base pointer.
// The (*rtype).nameOff method is a convenience wrapper for this function.
// Implemented in the runtime package.
//
//go:noescape
func resolveNameOff(ptrInModule unsafe.Pointer, off int32) unsafe.Pointer

// resolveTypeOff resolves an *rtype offset from a base type.
// The (*rtype).typeOff method is a convenience wrapper for this function.
// Implemented in the runtime package.
//
//go:noescape
func resolveTypeOff(rtype unsafe.Pointer, off int32) unsafe.Pointer

// resolveTextOff resolves a function pointer offset from a base type.
// The (*rtype).textOff method is a convenience wrapper for this function.
// Implemented in the runtime package.
//
//go:noescape
func resolveTextOff(rtype unsafe.Pointer, off int32) unsafe.Pointer

// addReflectOff adds a pointer to the reflection lookup map in the runtime.
// It returns a new ID that can be used as a typeOff or textOff, and will
// be resolved correctly. Implemented in the runtime package.
//
// addReflectOff should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/goplus/reflectx
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname addReflectOff
//go:noescape
func addReflectOff(ptr unsafe.Pointer) int32

// resolveReflectName adds a name to the reflection lookup map in the runtime.
// It returns a new nameOff that can be used to refer to the pointer.
func resolveReflectName(n abi.Name) aNameOff {
	return aNameOff(addReflectOff(unsafe.Pointer(n.Bytes)))
}

// resolveReflectType adds a *rtype to the reflection lookup map in the runtime.
// It returns a new typeOff that can be used to refer to the pointer.
func resolveReflectType(t *abi.Type) aTypeOff {
	return aTypeOff(addReflectOff(unsafe.Pointer(t)))
}

// resolveReflectText adds a function pointer to the reflection lookup map in
// the runtime. It returns a new textOff that can be used to refer to the
// pointer.
func resolveReflectText(ptr unsafe.Pointer) aTextOff {
	return aTextOff(addReflectOff(ptr))
}

func (t *rtype) nameOff(off aNameOff) abi.Name {
	return abi.Name{Bytes: (*byte)(resolveNameOff(unsafe.Pointer(t), int32(off)))}
}

func (t *rtype) typeOff(off aTypeOff) *abi.Type {
	return (*abi.Type)(resolveTypeOff(unsafe.Pointer(t), int32(off)))
}

func (t *rtype) textOff(off aTextOff) unsafe.Pointer {
	return resolveTextOff(unsafe.Pointer(t), int32(off))
}

func textOffFor(t *abi.Type, off aTextOff) unsafe.Pointer {
	return toRType(t).textOff(off)
}

func (t *rtype) String() string {
	s := t.nameOff(t.t.Str).Name()
	if t.t.TFlag&abi.TFlagExtraStar != 0 {
		return s[1:]
	}
	return s
}

func (t *rtype) Size() uintptr { return t.t.Size() }

func (t *rtype) Bits() int {
	if t == nil {
		panic("reflect: Bits of nil Type")
	}
	k := t.Kind()
	if k < Int || k > Complex128 {
		panic("reflect: Bits of non-arithmetic Type " + t.String())
	}
	return int(t.t.Size_) * 8
}

func (t *rtype) Align() int { return t.t.Align() }

func (t *rtype) FieldAlign() int { return t.t.FieldAlign() }

func (t *rtype) Kind() Kind { return Kind(t.t.Kind()) }

func (t *rtype) exportedMethods() []abi.Method {
	ut := t.uncommon()
	if ut == nil {
		return nil
	}
	return ut.ExportedMethods()
}

func (t *rtype) NumMethod() int {
	if t.Kind() == Interface {
		tt := (*interfaceType)(unsafe.Pointer(t))
		return tt.NumMethod()
	}
	return len(t.exportedMethods())
}

func (t *rtype) Method(i int) (m Method) {
	if t.Kind() == Interface {
		tt := (*interfaceType)(unsafe.Pointer(t))
		return tt.Method(i)
	}
	methods := t.exportedMethods()
	if i < 0 || i >= len(methods) {
		panic("reflect: Method index out of range")
	}
	p := methods[i]
	pname := t.nameOff(p.Name)
	m.Name = pname.Name()
	fl := flag(Func)
	mtyp := t.typeOff(p.Mtyp)
	ft := (*funcType)(unsafe.Pointer(mtyp))
	in := make([]Type, 0, 1+ft.NumIn())
	in = append(in, t)
	for _, arg := range ft.InSlice() {
		in = append(in, toRType(arg))
	}
	out := make([]Type, 0, ft.NumOut())
	for _, ret := range ft.OutSlice() {
		out = append(out, toRType(ret))
	}
	mt := FuncOf(in, out, ft.IsVariadic())
	m.Type = mt
	tfn := t.textOff(p.Tfn)
	fn := unsafe.Pointer(&tfn)
	m.Func = Value{&mt.(*rtype).t, fn, fl}

	m.Index = i
	return m
}

func (t *rtype) MethodByName(name string) (m Method, ok bool) {
	if t.Kind() == Interface {
		tt := (*interfaceType)(unsafe.Pointer(t))
		return tt.MethodByName(name)
	}
	ut := t.uncommon()
	if ut == nil {
		return Method{}, false
	}

	methods := ut.ExportedMethods()

	// We are looking for the first index i where the string becomes >= s.
	// This is a copy of sort.Search, with f(h) replaced by (t.nameOff(methods[h].name).name() >= name).
	i, j := 0, len(methods)
	for i < j {
		h := int(uint(i+j) >> 1) // avoid overflow when computing h
		// i ≤ h < j
		if !(t.nameOff(methods[h].Name).Name() >= name) {
			i = h + 1 // preserves f(i-1) == false
		} else {
			j = h // preserves f(j) == true
		}
	}
	// i == j, f(i-1) == false, and f(j) (= f(i)) == true  =>  answer is i.
	if i < len(methods) && name == t.nameOff(methods[i].Name).Name() {
		return t.Method(i), true
	}

	return Method{}, false
}

func (t *rtype) PkgPath() string {
	if t.t.TFlag&abi.TFlagNamed == 0 {
		return ""
	}
	ut := t.uncommon()
	if ut == nil {
		return ""
	}
	return t.nameOff(ut.PkgPath).Name()
}

func pkgPathFor(t *abi.Type) string {
	return toRType(t).PkgPath()
}

func (t *rtype) Name() string {
	if !t.t.HasName() {
		return ""
	}
	s := t.String()
	i := len(s) - 1
	sqBrackets := 0
	for i >= 0 && (s[i] != '.' || sqBrackets != 0) {
		switch s[i] {
		case ']':
			sqBrackets++
		case '[':
			sqBrackets--
		}
		i--
	}
	return s[i+1:]
}

func nameFor(t *abi.Type) string {
	return toRType(t).Name()
}

func (t *rtype) ChanDir() ChanDir {
	if t.Kind() != Chan {
		panic("reflect: ChanDir of non-chan type " + t.String())
	}
	tt := (*abi.ChanType)(unsafe.Pointer(t))
	return ChanDir(tt.Dir)
}

func toRType(t *abi.Type) *rtype {
	return (*rtype)(unsafe.Pointer(t))
}

func elem(t *abi.Type) *abi.Type {
	et := t.Elem()
	if et != nil {
		return et
	}
	panic("reflect: Elem of invalid type " + stringFor(t))
}

func (t *rtype) Elem() Type {
	return toType(elem(t.common()))
}

func (t *rtype) Field(i int) StructField {
	if t.Kind() != Struct {
		panic("reflect: Field of non-struct type " + t.String())
	}
	tt := (*structType)(unsafe.Pointer(t))
	return tt.Field(i)
}

func (t *rtype) FieldByIndex(index []int) StructField {
	if t.Kind() != Struct {
		panic("reflect: FieldByIndex of non-struct type " + t.String())
	}
	tt := (*structType)(unsafe.Pointer(t))
	return tt.FieldByIndex(index)
}

func (t *rtype) FieldByName(name string) (StructField, bool) {
	if t.Kind() != Struct {
		panic("reflect: FieldByName of non-struct type " + t.String())
	}
	tt := (*structType)(unsafe.Pointer(t))
	return tt.FieldByName(name)
}

func (t *rtype) FieldByNameFunc(match func(string) bool) (StructField, bool) {
	if t.Kind() != Struct {
		panic("reflect: FieldByNameFunc of non-struct type " + t.String())
	}
	tt := (*structType)(unsafe.Pointer(t))
	return tt.FieldByNameFunc(match)
}

func (t *rtype) Len() int {
	if t.Kind() != Array {
		panic("reflect: Len of non-array type " + t.String())
	}
	tt := (*arrayType)(unsafe.Pointer(t))
	return int(tt.Len)
}

func (t *rtype) NumField() int {
	if t.Kind() != Struct {
		panic("reflect: NumField of non-struct type " + t.String())
	}
	tt := (*structType)(unsafe.Pointer(t))
	return len(tt.Fields)
}

func (t *rtype) In(i int) Type {
	if t.Kind() != Func {
		panic("reflect: In of non-func type " + t.String())
	}
	tt := (*abi.FuncType)(unsafe.Pointer(t))
	return toType(tt.InSlice()[i])
}

func (t *rtype) NumIn() int {
	if t.Kind() != Func {
		panic("reflect: NumIn of non-func type " + t.String())
	}
	tt := (*abi.FuncType)(unsafe.Pointer(t))
	return tt.NumIn()
}

func (t *rtype) NumOut() int {
	if t.Kind() != Func {
		panic("reflect: NumOut of non-func type " + t.String())
	}
	tt := (*abi.FuncType)(unsafe.Pointer(t))
	return tt.NumOut()
}

func (t *rtype) Out(i int) Type {
	if t.Kind() != Func {
		panic("reflect: Out of non-func type " + t.String())
	}
	tt := (*abi.FuncType)(unsafe.Pointer(t))
	return toType(tt.OutSlice()[i])
}

func (t *rtype) IsVariadic() bool {
	if t.Kind() != Func {
		panic("reflect: IsVariadic of non-func type " + t.String())
	}
	tt := (*abi.FuncType)(unsafe.Pointer(t))
	return tt.IsVariadic()
}

func (t *rtype) OverflowComplex(x complex128) bool {
	k := t.Kind()
	switch k {
	case Complex64:
		return overflowFloat32(real(x)) || overflowFloat32(imag(x))
	case Complex128:
		return false
	}
	panic("reflect: OverflowComplex of non-complex type " + t.String())
}

func (t *rtype) OverflowFloat(x float64) bool {
	k := t.Kind()
	switch k {
	case Float32:
		return overflowFloat32(x)
	case Float64:
		return false
	}
	panic("reflect: OverflowFloat of non-float type " + t.String())
}

func (t *rtype) OverflowInt(x int64) bool {
	k := t.Kind()
	switch k {
	case Int, Int8, Int16, Int32, Int64:
		bitSize := t.Size() * 8
		trunc := (x << (64 - bitSize)) >> (64 - bitSize)
		return x != trunc
	}
	panic("reflect: OverflowInt of non-int type " + t.String())
}

func (t *rtype) OverflowUint(x uint64) bool {
	k := t.Kind()
	switch k {
	case Uint, Uintptr, Uint8, Uint16, Uint32, Uint64:
		bitSize := t.Size() * 8
		trunc := (x << (64 - bitSize)) >> (64 - bitSize)
		return x != trunc
	}
	panic("reflect: OverflowUint of non-uint type " + t.String())
}

func (t *rtype) CanSeq() bool {
	switch t.Kind() {
	case Int8, Int16, Int32, Int64, Int, Uint8, Uint16, Uint32, Uint64, Uint, Uintptr, Array, Slice, Chan, String, Map:
		return true
	case Func:
		return canRangeFunc(&t.t)
	case Pointer:
		return t.Elem().Kind() == Array
	}
	return false
}

func canRangeFunc(t *abi.Type) bool {
	if t.Kind() != abi.Func {
		return false
	}
	f := t.FuncType()
	if f.InCount != 1 || f.OutCount != 0 {
		return false
	}
	y := f.In(0)
	if y.Kind() != abi.Func {
		return false
	}
	yield := y.FuncType()
	return yield.InCount == 1 && yield.OutCount == 1 && yield.Out(0).Kind() == abi.Bool
}

func (t *rtype) CanSeq2() bool {
	switch t.Kind() {
	case Array, Slice, String, Map:
		return true
	case Func:
		return canRangeFunc2(&t.t)
	case Pointer:
		return t.Elem().Kind() == Array
	}
	return false
}

func canRangeFunc2(t *abi.Type) bool {
	if t.Kind() != abi.Func {
		return false
	}
	f := t.FuncType()
	if f.InCount != 1 || f.OutCount != 0 {
		return false
	}
	y := f.In(0)
	if y.Kind() != abi.Func {
		return false
	}
	yield := y.FuncType()
	return yield.InCount == 2 && yield.OutCount == 1 && yield.Out(0).Kind() == abi.Bool
}

// add returns p+x.
//
// The whySafe string is ignored, so that the function still inlines
// as efficiently as p+x, but all call sites should use the string to
// record why the addition is safe, which is to say why the addition
// does not cause x to advance to the very end of p's allocation
// and therefore point incorrectly at the next block in memory.
//
// add should be an internal detail (and is trivially copyable),
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/pinpoint-apm/pinpoint-go-agent
//   - github.com/vmware/govmomi
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname add
func add(p unsafe.Pointer, x uintptr, whySafe string) unsafe.Pointer {
	return unsafe.Pointer(uintptr(p) + x)
}

func (d ChanDir) String() string {
	switch d {
	case SendDir:
		return "chan<-"
	case RecvDir:
		return "<-chan"
	case BothDir:
		return "chan"
	}
	return "ChanDir" + strconv.Itoa(int(d))
}

// Method returns the i'th method in the type's method set.
func (t *interfaceType) Method(i int) (m Method) {
	if i < 0 || i >= len(t.Methods) {
		return
	}
	p := &t.Methods[i]
	pname := t.nameOff(p.Name)
	m.Name = pname.Name()
	if !pname.IsExported() {
		m.PkgPath = pkgPath(pname)
		if m.PkgPath == "" {
			m.PkgPath = t.PkgPath.Name()
		}
	}
	m.Type = toType(t.typeOff(p.Typ))
	m.Index = i
	return
}

// NumMethod returns the number of interface methods in the type's method set.
func (t *interfaceType) NumMethod() int { return len(t.Methods) }

// MethodByName method with the given name in the type's method set.
func (t *interfaceType) MethodByName(name string) (m Method, ok bool) {
	if t == nil {
		return
	}
	var p *abi.Imethod
	for i := range t.Methods {
		p = &t.Methods[i]
		if t.nameOff(p.Name).Name() == name {
			return t.Method(i), true
		}
	}
	return
}

// A StructField describes a single field in a struct.
type StructField struct {
	// Name is the field name.
	Name string

	// PkgPath is the package path that qualifies a lower case (unexported)
	// field name. It is empty for upper case (exported) field names.
	// See https://golang.org/ref/spec#Uniqueness_of_identifiers
	PkgPath string

	Type      Type      // field type
	Tag       StructTag // field tag string
	Offset    uintptr   // offset within struct, in bytes
	Index     []int     // index sequence for Type.FieldByIndex
	Anonymous bool      // is an embedded field
}

// IsExported reports whether the field is exported.
func (f StructField) IsExported() bool {
	return f.PkgPath == ""
}

// A StructTag is the tag string in a struct field.
//
// By convention, tag strings are a concatenation of
// optionally space-separated key:"value" pairs.
// Each key is a non-empty string consisting of non-control
// characters other than space (U+0020 ' '), quote (U+0022 '"'),
// and colon (U+003A ':').  Each value is quoted using U+0022 '"'
// characters and Go string literal syntax.
type StructTag string

// Get returns the value associated with key in the tag string.
// If there is no such key in the tag, Get returns the empty string.
// If the tag does not have the conventional format, the value
// returned by Get is unspecified. To determine whether a tag is
// explicitly set to the empty string, use [StructTag.Lookup].
func (tag StructTag) Get(key string) string {
	v, _ := tag.Lookup(key)
	return v
}

// Lookup returns the value associated with key in the tag string.
// If the key is present in the tag the value (which may be empty)
// is returned. Otherwise the returned value will be the empty string.
// The ok return value reports whether the value was explicitly set in
// the tag string. If the tag does not have the conventional format,
// the value returned by Lookup is unspecified.
func (tag StructTag) Lookup(key string) (value string, ok bool) {
	// When modifying this code, also update the validateStructTag code
	// in cmd/vet/structtag.go.

	for tag != "" {
		// Skip leading space.
		i := 0
		for i < len(tag) && tag[i] == ' ' {
			i++
		}
		tag = tag[i:]
		if tag == "" {
			break
		}

		// Scan to colon. A space, a quote or a control character is a syntax error.
		// Strictly speaking, control chars include the range [0x7f, 0x9f], not just
		// [0x00, 0x1f], but in practice, we ignore the multi-byte control characters
		// as it is simpler to inspect the tag's bytes than the tag's runes.
		i = 0
		for i < len(tag) && tag[i] > ' ' && tag[i] != ':' && tag[i] != '"' && tag[i] != 0x7f {
			i++
		}
		if i == 0 || i+1 >= len(tag) || tag[i] != ':' || tag[i+1] != '"' {
			break
		}
		name := string(tag[:i])
		tag = tag[i+1:]

		// Scan quoted string to find value.
		i = 1
		for i < len(tag) && tag[i] != '"' {
			if tag[i] == '\\' {
				i++
			}
			i++
		}
		if i >= len(tag) {
			break
		}
		qvalue := string(tag[:i+1])
		tag = tag[i+1:]

		if key == name {
			value, err := strconv.Unquote(qvalue)
			if err != nil {
				break
			}
			return value, true
		}
	}
	return "", false
}

// Field returns the i'th struct field.
func (t *structType) Field(i int) (f StructField) {
	if i < 0 || i >= len(t.Fields) {
		panic("reflect: Field index out of bounds")
	}
	p := &t.Fields[i]
	f.Type = toType(p.Typ)
	f.Name = p.Name.Name()
	f.Anonymous = p.Embedded()
	if !p.Name.IsExported() {
		f.PkgPath = t.PkgPath.Name()
	}
	if tag := p.Name.Tag(); tag != "" {
		f.Tag = StructTag(tag)
	}
	f.Offset = p.Offset

	// We can't safely use this optimization on js or wasi,
	// which do not appear to support read-only data.
	if i < 256 && runtime.GOOS != "js" && runtime.GOOS != "wasip1" {
		staticuint64s := getStaticuint64s()
		p := unsafe.Pointer(&(*staticuint64s)[i])
		if unsafe.Sizeof(int(0)) == 4 && goarch.BigEndian {
			p = unsafe.Add(p, 4)
		}
		f.Index = unsafe.Slice((*int)(p), 1)
	} else {
		// NOTE(rsc): This is the only allocation in the interface
		// presented by a reflect.Type. It would be nice to avoid,
		// but we need to make sure that misbehaving clients of
		// reflect cannot affect other uses of reflect.
		// One possibility is CL 5371098, but we postponed that
		// ugliness until there is a demonstrated
		// need for the performance. This is issue 2320.
		f.Index = []int{i}
	}
	return
}

// getStaticuint64s returns a pointer to an array of 256 uint64 values,
// defined in the runtime package in read-only memory.
// staticuint64s[0] == 0, staticuint64s[1] == 1, and so forth.
//
//go:linkname getStaticuint64s runtime.getStaticuint64s
func getStaticuint64s() *[256]uint64

// TODO(gri): Should there be an error/bool indicator if the index
// is wrong for FieldByIndex?

// FieldByIndex returns the nested field corres
```