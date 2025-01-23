Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Understanding the Goal:**

The request asks for a functional breakdown of the `go/src/internal/reflectlite/type.go` file. Key aspects to cover include:

* **Functionality:** What does the code *do*?
* **Underlying Go Feature:** What larger Go feature does this contribute to?
* **Code Examples:** How can the functionality be demonstrated in Go code?
* **Assumptions and I/O:**  If providing code examples, what are the inputs and expected outputs?
* **Command-line Arguments:**  Does it involve command-line processing (unlikely given the file path and content)?
* **Common Mistakes:** What are potential pitfalls for users?
* **Language:** Use Chinese.

**2. Initial Code Scan and High-Level Interpretation:**

* **Package Name:** `reflectlite` immediately suggests a lightweight version of the `reflect` package. This means it likely provides similar functionality but with fewer features or optimizations for size/speed in specific contexts.
* **Imports:**  The imports `internal/abi`, `runtime`, and `unsafe` are crucial.
    * `internal/abi`:  This strongly indicates that `reflectlite` directly works with the low-level representation of Go types. The "abi" likely refers to the Application Binary Interface, defining how data is laid out in memory.
    * `runtime`: This confirms a tight integration with the Go runtime system, responsible for memory management, goroutines, etc.
    * `unsafe`:  This signals direct memory manipulation, which is necessary for reflection but also carries risks.
* **`Type` Interface:** The definition of the `Type` interface is central. It lists core methods like `Name()`, `PkgPath()`, `Size()`, `Kind()`, `Implements()`, etc. These are all familiar concepts from the standard `reflect` package.
* **`Kind` Type:**  The `Kind` type, aliased from `abi.Kind`, signifies the different categories of Go types (struct, slice, pointer, etc.).
* **Struct Definitions:**  The code defines various structs like `rtype`, `uncommonType`, `arrayType`, `chanType`, etc. These mirror the internal representations of different Go type structures. The comments mentioning "known to the compiler" reinforce this low-level nature.
* **Helper Functions:**  Functions like `resolveNameOff`, `resolveTypeOff`, `add`, `TypeOf`, `implements`, and `directlyAssignable` appear to be the core logic for manipulating and comparing type information.

**3. Deep Dive into Key Components:**

* **`Type` Interface Methods:**  Analyze the purpose of each method in the `Type` interface. Connect them to their counterparts in the standard `reflect` package.
* **`rtype` Struct:** Understand this as the core implementation of the `Type` interface in `reflectlite`. Its fields likely hold the underlying type information.
* **`name` Struct:**  Notice the complex encoding of type names, including flags for export status, tags, and package paths. The `readVarint` function suggests a compact encoding scheme.
* **`implements` and `directlyAssignable`:** These functions implement the core logic for type compatibility, which is fundamental to Go's type system.

**4. Connecting to the `reflect` Package:**

Realize that `reflectlite` is a subset of the standard `reflect` package. Its purpose is likely to provide reflection capabilities in situations where the full `reflect` package is too large or has too many dependencies. This might be for resource-constrained environments or internal runtime usage.

**5. Generating Examples and Explanations:**

* **Functionality Listing:**  Based on the analysis, create a clear list of the functionalities provided by `reflectlite`.
* **Underlying Go Feature:**  Explicitly state that it's a lightweight version of reflection and explain its purpose.
* **Code Examples:**  Choose a few common reflection operations (getting type information, checking assignability, checking interface implementation) and demonstrate them using `reflectlite` functions. Crucially, provide the *expected output* for each example. This requires understanding how the `reflectlite` functions work.
* **Assumptions and I/O:**  For the code examples, clearly state the input Go code and the resulting output from the `reflectlite` operations.
* **Command-line Arguments:**  Recognize that this file is a library component and doesn't directly involve command-line arguments.
* **Common Mistakes:** Think about typical errors developers make when using reflection (e.g., calling methods on incorrect `Kind` of types). Provide concrete code examples of such mistakes and explain the resulting panic.

**6. Structuring the Answer:**

Organize the information logically with clear headings and subheadings as requested in the prompt. Use clear and concise Chinese.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Perhaps this is used for very specific internal optimizations.
* **Refinement:** While likely used internally, the core purpose is a *lightweight* alternative to the full `reflect` package.
* **Initial thought:**  Focus heavily on the low-level struct definitions.
* **Refinement:**  Balance the explanation of the low-level structures with a higher-level explanation of the functionalities they enable. The user needs to understand *what* it does, not just *how* it's structured internally.
* **Ensuring Clarity of Examples:**  Make sure the code examples are self-contained and easy to understand. The output should be precise.

By following these steps, the detailed and accurate analysis of `go/src/internal/reflectlite/type.go` can be generated, addressing all aspects of the original request.
这段代码是 Go 语言 `reflectlite` 包中关于类型表示的核心部分。`reflectlite` 是 `reflect` 包的轻量级版本，它不依赖于其他包，仅使用了 `runtime`、`unsafe` 和 `internal/abi` 包。其主要目的是在一些对性能和包依赖有严格要求的场景下提供基本的反射能力。

以下是代码中定义的主要功能：

**1. `Type` 接口:**

   -  **核心抽象:** `Type` 接口是 `reflectlite` 中类型表示的核心抽象。它定义了一系列方法，用于获取和操作 Go 语言的类型信息。
   -  **类型元数据访问:**  接口中的方法允许访问类型的名称 (`Name`)、包路径 (`PkgPath`)、大小 (`Size`)、种类 (`Kind`) 等基本元数据。
   -  **类型关系判断:**  `Implements` 方法用于判断一个类型是否实现了某个接口，`AssignableTo` 方法用于判断一个类型的值是否可以赋值给另一个类型。
   -  **可比较性:** `Comparable` 方法判断类型的值是否可以进行比较。
   -  **字符串表示:** `String` 方法返回类型的字符串表示。
   -  **元素类型获取:** `Elem` 方法用于获取指针、数组、切片或通道类型的元素类型。
   -  **内部访问:** `common()` 和 `uncommon()` 方法提供了访问底层类型表示的途径。

**2. `Kind` 类型:**

   -  **枚举类型种类:** `Kind` 是一个枚举类型，定义了 Go 语言中各种类型的种类，如 `Ptr`（指针）、`Interface`（接口）、`Slice`（切片）、`String`（字符串）、`Struct`（结构体）等。它直接使用了 `internal/abi` 包中的 `Kind` 定义。

**3. 底层类型表示结构体:**

   -  **`rtype`:**  表示 Go 语言的类型，它内嵌了 `abi.Type`。这是 `reflectlite` 中最核心的类型表示结构。
   -  **`uncommonType`:**  用于存储定义类型或带有方法的类型的额外信息，通过指针使用可以减少非定义且无方法类型的大小。
   -  **`arrayType`，`chanType`，`funcType`，`interfaceType`，`ptrType`，`sliceType`，`structType`:**  分别表示数组、通道、函数、接口、指针、切片和结构体类型的具体信息，这些结构体也直接使用了 `internal/abi` 包中的定义。

**4. `name` 结构体:**

   -  **类型名称编码:** `name` 结构体用于表示编码后的类型名称，其中包含类型的导出信息、标签数据以及包路径等。
   -  **数据访问方法:** 提供了 `data` 方法用于安全地访问编码数据，以及 `isExported`、`hasTag`、`embedded` 等方法用于解析编码信息。
   -  **变长整数读取:** `readVarint` 方法用于读取编码名称中的变长整数，用于表示长度等信息。
   -  **名称和标签获取:** `name()` 和 `tag()` 方法用于解码并获取类型的名称和标签。
   -  **包路径获取:** `pkgPath` 函数用于获取类型的包路径。

**5. 辅助函数:**

   -  **`resolveNameOff` 和 `resolveTypeOff`:**  这两个是标记为 `//go:noescape` 的函数，意味着它们不会发生栈逃逸，并且是在 `runtime` 包中实现的。它们用于解析类型元数据中存储的偏移量，将其转换为指向实际 `name` 或 `abi.Type` 的指针。
   -  **`nameOff` 和 `typeOff`:**  作为 `rtype` 的方法，是对 `resolveNameOff` 和 `resolveTypeOff` 的便捷封装。
   -  **`uncommon`，`String`，`common`，`exportedMethods`，`NumMethod`，`PkgPath`，`Name`:**  这些是 `rtype` 的方法，实现了 `Type` 接口中定义的方法，用于获取类型的各种属性。
   -  **`toRType` 和 `toType`:**  用于在 `abi.Type` 和 `reflectlite.Type` 之间进行转换。
   -  **`elem`，`In`，`Key`，`Len`，`NumField`，`NumIn`，`NumOut`，`Out`:**  这些是 `rtype` 的方法，用于获取复合类型的组成部分信息，例如切片的元素类型、函数的参数和返回值类型等。
   -  **`add`:**  一个内联的指针加法函数，用于进行内存地址计算。
   -  **`TypeOf`:**  返回给定接口值的动态类型的 `reflectlite.Type`。
   -  **`Implements`，`AssignableTo`，`Comparable`:**  实现了 `Type` 接口中定义的类型关系判断方法。
   -  **`implements` 和 `directlyAssignable`:**  实现了类型是否实现接口以及是否可以直接赋值的底层逻辑。
   -  **`haveIdenticalType` 和 `haveIdenticalUnderlyingType`:**  用于判断两个类型是否相同或具有相同的底层类型。

**它是什么Go语言功能的实现？**

`go/src/internal/reflectlite/type.go` 是 **Go 语言反射功能的一个轻量级实现**。它提供了在运行时检查变量类型和结构的能力，但相比于标准的 `reflect` 包，它更加精简，减少了依赖，可能牺牲了一些高级特性或性能优化，以适应特定的内部使用场景。

**Go 代码示例:**

假设我们有以下 Go 代码：

```go
package main

import (
	"fmt"
	"internal/reflectlite"
)

type MyInt int
type MyString string

type MyStruct struct {
	A int
	B string
}

func main() {
	var i int = 10
	var mi MyInt = 20
	var s string = "hello"
	var ms MyString = "world"
	var st MyStruct = MyStruct{A: 1, B: "test"}

	fmt.Println("Type of i:", reflectlite.TypeOf(i))
	fmt.Println("Type of mi:", reflectlite.TypeOf(mi))
	fmt.Println("Type of s:", reflectlite.TypeOf(s))
	fmt.Println("Type of ms:", reflectlite.TypeOf(ms))
	fmt.Println("Type of st:", reflectlite.TypeOf(st))

	fmt.Println("Kind of i:", reflectlite.TypeOf(i).Kind())
	fmt.Println("Kind of mi:", reflectlite.TypeOf(mi).Kind())
	fmt.Println("Kind of st:", reflectlite.TypeOf(st).Kind())

	fmt.Println("Name of mi:", reflectlite.TypeOf(mi).Name())
	fmt.Println("Name of st:", reflectlite.TypeOf(st).Name())

	fmt.Println("PkgPath of mi:", reflectlite.TypeOf(mi).PkgPath())
	fmt.Println("PkgPath of st:", reflectlite.TypeOf(st).PkgPath())
}
```

**假设的输出:**

```
Type of i: int
Type of mi: main.MyInt
Type of s: string
Type of ms: main.MyString
Type of st: main.MyStruct
Kind of i: int
Kind of mi: int
Kind of st: struct
Name of mi: MyInt
Name of st: MyStruct
PkgPath of mi: main
PkgPath of st: main
```

**代码推理:**

- `reflectlite.TypeOf(i)` 会返回 `int` 类型的 `reflectlite.Type` 实例。
- `reflectlite.TypeOf(mi)` 会返回 `main.MyInt` 类型的 `reflectlite.Type` 实例。注意，`MyInt` 是一个自定义类型。
- `reflectlite.TypeOf(st).Kind()` 会返回 `reflectlite.Struct`，因为 `MyStruct` 是一个结构体。
- `reflectlite.TypeOf(mi).Name()` 会返回 "MyInt"，即自定义类型的名称。
- `reflectlite.TypeOf(mi).PkgPath()` 会返回 "main"，即 `MyInt` 类型所在的包的路径。

**命令行参数的具体处理:**

这段代码本身是 Go 语言的内部库实现，不直接处理命令行参数。它提供的功能是通过 Go 语言的 API 调用的方式被使用的。

**使用者易犯错的点:**

使用 `reflectlite` 和使用标准的 `reflect` 包类似，一个常见的错误是 **在类型不匹配的情况下调用类型特定的方法**，这会导致运行时 panic。

**示例:**

```go
package main

import (
	"fmt"
	"internal/reflectlite"
)

func main() {
	var i int = 10
	t := reflectlite.TypeOf(i)

	// 错误：尝试在 int 类型上调用 Elem() 方法，而 int 不是指针、数组、切片或通道类型
	// 这会触发 panic: reflect: Elem of invalid type int
	elemType := t.Elem()
	fmt.Println(elemType)
}
```

在这个例子中，`reflectlite.TypeOf(i)` 返回的 `t` 是 `int` 类型的表示。`int` 类型没有元素类型，因此调用 `t.Elem()` 会导致运行时 panic。使用者需要在使用类型特定的方法前，先使用 `Kind()` 方法检查类型，以避免这类错误。

总而言之，`go/src/internal/reflectlite/type.go` 提供了一套精简的反射机制，用于在运行时检查和操作 Go 语言的类型信息，主要服务于 Go 语言内部或对包依赖有严格要求的场景。使用者需要注意类型匹配，避免在不适用的类型上调用特定方法。

### 提示词
```
这是路径为go/src/internal/reflectlite/type.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package reflectlite implements lightweight version of reflect, not using
// any package except for "runtime", "unsafe", and "internal/abi"
package reflectlite

import (
	"internal/abi"
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

	// Kind returns the specific kind of this type.
	Kind() Kind

	// Implements reports whether the type implements the interface type u.
	Implements(u Type) bool

	// AssignableTo reports whether a value of the type is assignable to type u.
	AssignableTo(u Type) bool

	// Comparable reports whether values of this type are comparable.
	Comparable() bool

	// String returns a string representation of the type.
	// The string representation may use shortened package names
	// (e.g., base64 instead of "encoding/base64") and is not
	// guaranteed to be unique among types. To test for type identity,
	// compare the Types directly.
	String() string

	// Elem returns a type's element type.
	// It panics if the type's Kind is not Ptr.
	Elem() Type

	common() *abi.Type
	uncommon() *uncommonType
}

/*
 * These data structures are known to the compiler (../../cmd/internal/reflectdata/reflect.go).
 * A few are known to ../runtime/type.go to convey to debuggers.
 * They are also known to ../runtime/type.go.
 */

// A Kind represents the specific kind of type that a Type represents.
// The zero Kind is not a valid kind.
type Kind = abi.Kind

const Ptr = abi.Pointer

const (
	// Import-and-export these constants as necessary
	Interface = abi.Interface
	Slice     = abi.Slice
	String    = abi.String
	Struct    = abi.Struct
)

type nameOff = abi.NameOff
type typeOff = abi.TypeOff
type textOff = abi.TextOff

type rtype struct {
	*abi.Type
}

// uncommonType is present only for defined types or types with methods
// (if T is a defined type, the uncommonTypes for T and *T have methods).
// Using a pointer to this struct reduces the overall size required
// to describe a non-defined type with no methods.
type uncommonType = abi.UncommonType

// arrayType represents a fixed array type.
type arrayType = abi.ArrayType

// chanType represents a channel type.
type chanType = abi.ChanType

type funcType = abi.FuncType

type interfaceType = abi.InterfaceType

// ptrType represents a pointer type.
type ptrType = abi.PtrType

// sliceType represents a slice type.
type sliceType = abi.SliceType

// structType represents a struct type.
type structType = abi.StructType

// name is an encoded type name with optional extra data.
//
// The first byte is a bit field containing:
//
//	1<<0 the name is exported
//	1<<1 tag data follows the name
//	1<<2 pkgPath nameOff follows the name and tag
//
// The next two bytes are the data length:
//
//	l := uint16(data[1])<<8 | uint16(data[2])
//
// Bytes [3:3+l] are the string data.
//
// If tag data follows then bytes 3+l and 3+l+1 are the tag length,
// with the data following.
//
// If the import path follows, then 4 bytes at the end of
// the data form a nameOff. The import path is only set for concrete
// methods that are defined in a different package than their type.
//
// If a name starts with "*", then the exported bit represents
// whether the pointed to type is exported.
type name struct {
	bytes *byte
}

func (n name) data(off int, whySafe string) *byte {
	return (*byte)(add(unsafe.Pointer(n.bytes), uintptr(off), whySafe))
}

func (n name) isExported() bool {
	return (*n.bytes)&(1<<0) != 0
}

func (n name) hasTag() bool {
	return (*n.bytes)&(1<<1) != 0
}

func (n name) embedded() bool {
	return (*n.bytes)&(1<<3) != 0
}

// readVarint parses a varint as encoded by encoding/binary.
// It returns the number of encoded bytes and the encoded value.
func (n name) readVarint(off int) (int, int) {
	v := 0
	for i := 0; ; i++ {
		x := *n.data(off+i, "read varint")
		v += int(x&0x7f) << (7 * i)
		if x&0x80 == 0 {
			return i + 1, v
		}
	}
}

func (n name) name() string {
	if n.bytes == nil {
		return ""
	}
	i, l := n.readVarint(1)
	return unsafe.String(n.data(1+i, "non-empty string"), l)
}

func (n name) tag() string {
	if !n.hasTag() {
		return ""
	}
	i, l := n.readVarint(1)
	i2, l2 := n.readVarint(1 + i + l)
	return unsafe.String(n.data(1+i+l+i2, "non-empty string"), l2)
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
	pkgPathName := name{(*byte)(resolveTypeOff(unsafe.Pointer(n.Bytes), nameOff))}
	return pkgPathName.name()
}

/*
 * The compiler knows the exact layout of all the data structures above.
 * The compiler does not know about the data structures and methods below.
 */

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

func (t rtype) nameOff(off nameOff) abi.Name {
	return abi.Name{Bytes: (*byte)(resolveNameOff(unsafe.Pointer(t.Type), int32(off)))}
}

func (t rtype) typeOff(off typeOff) *abi.Type {
	return (*abi.Type)(resolveTypeOff(unsafe.Pointer(t.Type), int32(off)))
}

func (t rtype) uncommon() *uncommonType {
	return t.Uncommon()
}

func (t rtype) String() string {
	s := t.nameOff(t.Str).Name()
	if t.TFlag&abi.TFlagExtraStar != 0 {
		return s[1:]
	}
	return s
}

func (t rtype) common() *abi.Type { return t.Type }

func (t rtype) exportedMethods() []abi.Method {
	ut := t.uncommon()
	if ut == nil {
		return nil
	}
	return ut.ExportedMethods()
}

func (t rtype) NumMethod() int {
	tt := t.Type.InterfaceType()
	if tt != nil {
		return tt.NumMethod()
	}
	return len(t.exportedMethods())
}

func (t rtype) PkgPath() string {
	if t.TFlag&abi.TFlagNamed == 0 {
		return ""
	}
	ut := t.uncommon()
	if ut == nil {
		return ""
	}
	return t.nameOff(ut.PkgPath).Name()
}

func (t rtype) Name() string {
	if !t.HasName() {
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

func toRType(t *abi.Type) rtype {
	return rtype{t}
}

func elem(t *abi.Type) *abi.Type {
	et := t.Elem()
	if et != nil {
		return et
	}
	panic("reflect: Elem of invalid type " + toRType(t).String())
}

func (t rtype) Elem() Type {
	return toType(elem(t.common()))
}

func (t rtype) In(i int) Type {
	tt := t.Type.FuncType()
	if tt == nil {
		panic("reflect: In of non-func type")
	}
	return toType(tt.InSlice()[i])
}

func (t rtype) Key() Type {
	tt := t.Type.MapType()
	if tt == nil {
		panic("reflect: Key of non-map type")
	}
	return toType(tt.Key)
}

func (t rtype) Len() int {
	tt := t.Type.ArrayType()
	if tt == nil {
		panic("reflect: Len of non-array type")
	}
	return int(tt.Len)
}

func (t rtype) NumField() int {
	tt := t.Type.StructType()
	if tt == nil {
		panic("reflect: NumField of non-struct type")
	}
	return len(tt.Fields)
}

func (t rtype) NumIn() int {
	tt := t.Type.FuncType()
	if tt == nil {
		panic("reflect: NumIn of non-func type")
	}
	return int(tt.InCount)
}

func (t rtype) NumOut() int {
	tt := t.Type.FuncType()
	if tt == nil {
		panic("reflect: NumOut of non-func type")
	}
	return tt.NumOut()
}

func (t rtype) Out(i int) Type {
	tt := t.Type.FuncType()
	if tt == nil {
		panic("reflect: Out of non-func type")
	}
	return toType(tt.OutSlice()[i])
}

// add returns p+x.
//
// The whySafe string is ignored, so that the function still inlines
// as efficiently as p+x, but all call sites should use the string to
// record why the addition is safe, which is to say why the addition
// does not cause x to advance to the very end of p's allocation
// and therefore point incorrectly at the next block in memory.
func add(p unsafe.Pointer, x uintptr, whySafe string) unsafe.Pointer {
	return unsafe.Pointer(uintptr(p) + x)
}

// TypeOf returns the reflection Type that represents the dynamic type of i.
// If i is a nil interface value, TypeOf returns nil.
func TypeOf(i any) Type {
	return toType(abi.TypeOf(i))
}

func (t rtype) Implements(u Type) bool {
	if u == nil {
		panic("reflect: nil type passed to Type.Implements")
	}
	if u.Kind() != Interface {
		panic("reflect: non-interface type passed to Type.Implements")
	}
	return implements(u.common(), t.common())
}

func (t rtype) AssignableTo(u Type) bool {
	if u == nil {
		panic("reflect: nil type passed to Type.AssignableTo")
	}
	uu := u.common()
	tt := t.common()
	return directlyAssignable(uu, tt) || implements(uu, tt)
}

func (t rtype) Comparable() bool {
	return t.Equal != nil
}

// implements reports whether the type V implements the interface type T.
func implements(T, V *abi.Type) bool {
	t := T.InterfaceType()
	if t == nil {
		return false
	}
	if len(t.Methods) == 0 {
		return true
	}
	rT := toRType(T)
	rV := toRType(V)

	// The same algorithm applies in both cases, but the
	// method tables for an interface type and a concrete type
	// are different, so the code is duplicated.
	// In both cases the algorithm is a linear scan over the two
	// lists - T's methods and V's methods - simultaneously.
	// Since method tables are stored in a unique sorted order
	// (alphabetical, with no duplicate method names), the scan
	// through V's methods must hit a match for each of T's
	// methods along the way, or else V does not implement T.
	// This lets us run the scan in overall linear time instead of
	// the quadratic time  a naive search would require.
	// See also ../runtime/iface.go.
	if V.Kind() == Interface {
		v := (*interfaceType)(unsafe.Pointer(V))
		i := 0
		for j := 0; j < len(v.Methods); j++ {
			tm := &t.Methods[i]
			tmName := rT.nameOff(tm.Name)
			vm := &v.Methods[j]
			vmName := rV.nameOff(vm.Name)
			if vmName.Name() == tmName.Name() && rV.typeOff(vm.Typ) == rT.typeOff(tm.Typ) {
				if !tmName.IsExported() {
					tmPkgPath := pkgPath(tmName)
					if tmPkgPath == "" {
						tmPkgPath = t.PkgPath.Name()
					}
					vmPkgPath := pkgPath(vmName)
					if vmPkgPath == "" {
						vmPkgPath = v.PkgPath.Name()
					}
					if tmPkgPath != vmPkgPath {
						continue
					}
				}
				if i++; i >= len(t.Methods) {
					return true
				}
			}
		}
		return false
	}

	v := V.Uncommon()
	if v == nil {
		return false
	}
	i := 0
	vmethods := v.Methods()
	for j := 0; j < int(v.Mcount); j++ {
		tm := &t.Methods[i]
		tmName := rT.nameOff(tm.Name)
		vm := vmethods[j]
		vmName := rV.nameOff(vm.Name)
		if vmName.Name() == tmName.Name() && rV.typeOff(vm.Mtyp) == rT.typeOff(tm.Typ) {
			if !tmName.IsExported() {
				tmPkgPath := pkgPath(tmName)
				if tmPkgPath == "" {
					tmPkgPath = t.PkgPath.Name()
				}
				vmPkgPath := pkgPath(vmName)
				if vmPkgPath == "" {
					vmPkgPath = rV.nameOff(v.PkgPath).Name()
				}
				if tmPkgPath != vmPkgPath {
					continue
				}
			}
			if i++; i >= len(t.Methods) {
				return true
			}
		}
	}
	return false
}

// directlyAssignable reports whether a value x of type V can be directly
// assigned (using memmove) to a value of type T.
// https://golang.org/doc/go_spec.html#Assignability
// Ignoring the interface rules (implemented elsewhere)
// and the ideal constant rules (no ideal constants at run time).
func directlyAssignable(T, V *abi.Type) bool {
	// x's type V is identical to T?
	if T == V {
		return true
	}

	// Otherwise at least one of T and V must not be defined
	// and they must have the same kind.
	if T.HasName() && V.HasName() || T.Kind() != V.Kind() {
		return false
	}

	// x's type T and V must  have identical underlying types.
	return haveIdenticalUnderlyingType(T, V, true)
}

func haveIdenticalType(T, V *abi.Type, cmpTags bool) bool {
	if cmpTags {
		return T == V
	}

	if toRType(T).Name() != toRType(V).Name() || T.Kind() != V.Kind() {
		return false
	}

	return haveIdenticalUnderlyingType(T, V, false)
}

func haveIdenticalUnderlyingType(T, V *abi.Type, cmpTags bool) bool {
	if T == V {
		return true
	}

	kind := T.Kind()
	if kind != V.Kind() {
		return false
	}

	// Non-composite types of equal kind have same underlying type
	// (the predefined instance of the type).
	if abi.Bool <= kind && kind <= abi.Complex128 || kind == abi.String || kind == abi.UnsafePointer {
		return true
	}

	// Composite types.
	switch kind {
	case abi.Array:
		return T.Len() == V.Len() && haveIdenticalType(T.Elem(), V.Elem(), cmpTags)

	case abi.Chan:
		// Special case:
		// x is a bidirectional channel value, T is a channel type,
		// and x's type V and T have identical element types.
		if V.ChanDir() == abi.BothDir && haveIdenticalType(T.Elem(), V.Elem(), cmpTags) {
			return true
		}

		// Otherwise continue test for identical underlying type.
		return V.ChanDir() == T.ChanDir() && haveIdenticalType(T.Elem(), V.Elem(), cmpTags)

	case abi.Func:
		t := (*funcType)(unsafe.Pointer(T))
		v := (*funcType)(unsafe.Pointer(V))
		if t.OutCount != v.OutCount || t.InCount != v.InCount {
			return false
		}
		for i := 0; i < t.NumIn(); i++ {
			if !haveIdenticalType(t.In(i), v.In(i), cmpTags) {
				return false
			}
		}
		for i := 0; i < t.NumOut(); i++ {
			if !haveIdenticalType(t.Out(i), v.Out(i), cmpTags) {
				return false
			}
		}
		return true

	case Interface:
		t := (*interfaceType)(unsafe.Pointer(T))
		v := (*interfaceType)(unsafe.Pointer(V))
		if len(t.Methods) == 0 && len(v.Methods) == 0 {
			return true
		}
		// Might have the same methods but still
		// need a run time conversion.
		return false

	case abi.Map:
		return haveIdenticalType(T.Key(), V.Key(), cmpTags) && haveIdenticalType(T.Elem(), V.Elem(), cmpTags)

	case Ptr, abi.Slice:
		return haveIdenticalType(T.Elem(), V.Elem(), cmpTags)

	case abi.Struct:
		t := (*structType)(unsafe.Pointer(T))
		v := (*structType)(unsafe.Pointer(V))
		if len(t.Fields) != len(v.Fields) {
			return false
		}
		if t.PkgPath.Name() != v.PkgPath.Name() {
			return false
		}
		for i := range t.Fields {
			tf := &t.Fields[i]
			vf := &v.Fields[i]
			if tf.Name.Name() != vf.Name.Name() {
				return false
			}
			if !haveIdenticalType(tf.Typ, vf.Typ, cmpTags) {
				return false
			}
			if cmpTags && tf.Name.Tag() != vf.Name.Tag() {
				return false
			}
			if tf.Offset != vf.Offset {
				return false
			}
			if tf.Embedded() != vf.Embedded() {
				return false
			}
		}
		return true
	}

	return false
}

// toType converts from a *rtype to a Type that can be returned
// to the client of package reflect. In gc, the only concern is that
// a nil *rtype must be replaced by a nil Type, but in gccgo this
// function takes care of ensuring that multiple *rtype for the same
// type are coalesced into a single Type.
func toType(t *abi.Type) Type {
	if t == nil {
		return nil
	}
	return toRType(t)
}
```