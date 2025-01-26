Response:
Let's break down the thought process for analyzing the provided Go code snippet.

1. **Understanding the Goal:** The request asks for an explanation of the Go code in `go/src/debug/dwarf/type.go`. Specifically, it wants to know the functionality, the Go feature it implements, example usage, handling of command-line arguments (if any), and common pitfalls.

2. **Initial Scan and Keyword Identification:**  A quick scan reveals keywords like `dwarf`, `type`, `debug`, `struct`, `interface`, `pointer`, `array`, `enum`, `func`, `typedef`. This immediately suggests the code deals with debugging information, specifically type representation in the DWARF debugging format.

3. **Core Data Structures:** The code defines several `struct` types (e.g., `BasicType`, `CharType`, `StructType`, `ArrayType`). These likely represent different kinds of data types found in programming languages (integers, characters, structures, arrays, etc.). The `Type` interface suggests a polymorphic way to handle these different type representations.

4. **Key Methods:** The presence of `String()` methods on most of the type structs is a strong indicator of how these types are represented textually, likely for debugging or informational purposes. Methods like `Size()` suggest calculating the memory footprint of these types.

5. **Connecting to DWARF:** The package name `dwarf` and the comments referring to "DWARF v2 §5.x" directly link this code to the DWARF debugging standard. Comments like "The format is heavily biased toward C" further reinforce this. The presence of attributes like `AttrType`, `AttrName`, `AttrByteSize` directly correspond to DWARF attributes.

6. **Inferring Functionality:** Based on the data structures and methods, the primary function of this code is to:
    * **Parse DWARF type information:**  The `readType` function is central to this, taking a `typeReader` and an `Offset` as input, clearly suggesting it's reading DWARF data.
    * **Represent Go types from DWARF:**  The various `struct` types act as Go representations of DWARF type entries.
    * **Provide textual representations:** The `String()` methods allow for a human-readable output of the parsed type information.
    * **Calculate type sizes:** The `Size()` methods determine the memory size of the represented types.

7. **Identifying the Go Feature:** The code implements the reading and interpretation of DWARF type information. This is a core part of debugging Go programs, allowing debuggers (like `gdb` or delve) to understand the structure of variables and data. The `debug/dwarf` package is the specific Go feature being implemented.

8. **Developing a Code Example:** To illustrate usage, a scenario where DWARF information is read and a type is inspected is necessary. This requires:
    * Opening an executable with DWARF information.
    * Creating a `dwarf.Data` instance.
    * Finding the offset of a specific type (this requires some prior knowledge of DWARF structure or using tools to find the offset).
    * Calling the `Type()` method to retrieve the `Type` interface.
    * Using a type assertion to get the concrete type.
    * Printing relevant information like `String()` and `Size()`.

9. **Considering Command-Line Arguments:** The code itself doesn't directly process command-line arguments. However, the *package* `debug/dwarf` is used by tools that *do* process command-line arguments (like debuggers which take the executable path as an argument). The key is to differentiate between the functionality of this specific file and the broader usage of the package.

10. **Identifying Potential Pitfalls:** Common errors usually arise from misunderstandings or limitations of the DWARF format or the `debug/dwarf` package.
    * **Incomplete DWARF information:**  If the executable isn't compiled with sufficient debug information, the parsed types might be incomplete or inaccurate.
    * **Complex C++ constructs:** The code itself acknowledges limitations in handling complex C++ features.
    * **Assumption about DWARF versions:**  Different DWARF versions might have slightly different structures, which could lead to parsing issues (though this code seems designed to handle some variations).
    * **Manual offset retrieval:**  Manually determining the offset of a type is error-prone and requires knowledge of DWARF structures.

11. **Structuring the Answer:**  Organize the information logically with clear headings: 功能, 实现的Go语言功能, 代码示例, 命令行参数处理, 易犯错的点. Use code blocks for Go examples and format output clearly.

12. **Refining and Reviewing:**  Read through the answer to ensure clarity, accuracy, and completeness. Check for any missing details or potential misunderstandings. For instance, initially, I might have focused too much on the individual type structures. The key is to connect them to the overall goal of representing DWARF type information. Also, ensure the language is natural and easy to understand (as requested by "请用中文回答").
这段Go语言代码是 `go/src/debug/dwarf/type.go` 文件的一部分，它定义了用于表示 DWARF (Debugging With Attributed Records Format) 调试信息的类型结构。DWARF 是一种通用的调试数据格式，编译器和链接器使用它来将源代码级别的调试信息嵌入到可执行文件中。

**主要功能:**

1. **定义了表示各种数据类型的结构体:**  这段代码定义了一系列 Go 结构体，用于映射 DWARF 标准中定义的各种数据类型。这些结构体包括：
    * `BasicType`:  基本类型 (如 int, float, char)。
    * `CharType`, `UcharType`, `IntType`, `UintType`, `FloatType`, `ComplexType`, `BoolType`, `AddrType`, `UnspecifiedType`:  各种具体的基本类型。
    * `QualType`:  带有类型修饰符 (如 const, volatile) 的类型。
    * `ArrayType`:  数组类型。
    * `VoidType`:  void 类型。
    * `PtrType`:  指针类型。
    * `StructType`:  结构体、联合体或类类型。
    * `StructField`:  结构体、联合体或类的成员。
    * `EnumType`:  枚举类型。
    * `EnumValue`:  枚举类型的值。
    * `FuncType`:  函数类型。
    * `DotDotDotType`:  可变参数 `...` 类型。
    * `TypedefType`:  类型别名。
    * `UnsupportedType`:  表示不支持的 DWARF 类型。

2. **实现了 `Type` 接口:**  定义了一个 `Type` 接口，所有表示 DWARF 类型的结构体都实现了这个接口。这个接口包含以下方法：
    * `Common() *CommonType`: 返回通用的类型信息。
    * `String() string`: 返回类型的字符串表示形式 (类似 Go 语法)。
    * `Size() int64`: 返回类型的大小 (字节)。

3. **提供类型信息的通用部分:**  定义了 `CommonType` 结构体，用于存储各种类型共有的信息，如大小和名称。

4. **实现了类型信息的字符串表示:**  每个具体的类型结构体都实现了 `String()` 方法，以便以一种可读的方式打印出类型信息。例如，`PtrType` 的 `String()` 方法会返回类似 `*int` 的字符串。

5. **实现了类型大小的计算:**  部分类型结构体实现了 `Size()` 方法来计算类型的大小。对于复合类型 (如数组和指针)，它们的大小依赖于其包含的类型。

6. **支持读取 DWARF 类型信息:**  `Data` 结构体 (未在此代码段中完整展示，但通过 `d *Data`) 和相关方法 (如 `Type(off Offset)`) 用于从 DWARF 数据中读取和解析类型信息。`readType` 函数是核心的解析函数。

**它是什么Go语言功能的实现:**

这段代码是 Go 语言 `debug/dwarf` 标准库中用于处理 DWARF 调试信息的一部分。具体来说，它负责解析和表示 DWARF 中描述的类型信息。这对于构建调试器、性能分析工具以及其他需要理解程序内部数据结构的工具至关重要。

**Go 代码示例:**

以下示例演示了如何使用 `debug/dwarf` 包来读取 DWARF 信息并获取类型信息。

```go
package main

import (
	"debug/dwarf"
	"debug/elf"
	"fmt"
	"log"
)

func main() {
	// 假设有一个已编译的 ELF 文件 "myprogram" 带有 DWARF 调试信息
	f, err := elf.Open("myprogram")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	dwarfData, err := f.DWARF()
	if err != nil {
		log.Fatal(err)
	}

	// 假设我们知道某个类型的偏移量 (实际使用中需要遍历 DWARF 条目来查找)
	// 这里假设偏移量为 0x4b
	typeOffset := dwarf.Offset(0x4b)

	// 获取类型信息
	dwarfType, err := dwarfData.Type(typeOffset)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Type: %s\n", dwarfType.String())
	fmt.Printf("Size: %d bytes\n", dwarfType.Size())

	// 根据实际类型进行类型断言
	if ptrType, ok := dwarfType.(*dwarf.PtrType); ok {
		fmt.Printf("Is a pointer to: %s\n", ptrType.Type.String())
	} else if structType, ok := dwarfType.(*dwarf.StructType); ok {
		fmt.Printf("Is a struct named: %s\n", structType.StructName)
		for _, field := range structType.Field {
			fmt.Printf("  Field: %s, Type: %s, Offset: %d\n", field.Name, field.Type.String(), field.ByteOffset)
		}
	}
}
```

**假设的输入与输出:**

假设 `myprogram` 的 DWARF 信息中，偏移量 `0x4b` 处描述的是一个指向 `int` 类型的指针。

**输入 (DWARF 数据):**  在 `myprogram` 的 DWARF 数据中，偏移量 `0x4b` 对应的条目描述了一个 `DW_TAG_pointer_type`，其 `DW_AT_type` 属性指向描述 `int` 类型的另一个条目。

**输出:**

```
Type: *int
Size: 8 bytes  // 假设是 64 位系统
Is a pointer to: int
```

如果偏移量 `0x4b` 处描述的是一个结构体：

**输入 (DWARF 数据):** 在 `myprogram` 的 DWARF 数据中，偏移量 `0x4b` 对应的条目描述了一个 `DW_TAG_structure_type`，其包含若干 `DW_TAG_member` 条目描述结构体的字段。

**输出:**

```
Type: struct MyStruct
Size: 16 bytes // 假设结构体大小
Is a struct named: MyStruct
  Field: field1, Type: int, Offset: 0
  Field: field2, Type: bool, Offset: 8
```

**命令行参数的具体处理:**

这段代码本身不直接处理命令行参数。`debug/dwarf` 包通常被其他工具使用，这些工具会接收命令行参数来指定要调试的可执行文件。例如，调试器 `dlv` 或 `gdb` 会接收可执行文件的路径作为参数，然后使用 `debug/dwarf` 包来读取该文件的调试信息。

**使用者易犯错的点:**

1. **假设 DWARF 信息存在且完整:**  如果被调试的程序在编译时没有包含 DWARF 调试信息，或者信息被剥离，那么 `f.DWARF()` 可能会返回错误，或者解析出的类型信息不完整。
2. **手动计算或猜测偏移量:**  示例代码中使用了硬编码的偏移量 `0x4b`，这在实际应用中是不可行的。使用者需要通过遍历 DWARF 条目，根据标签 (Tag) 和属性 (Attribute) 来找到目标类型的偏移量。`debug/dwarf` 包提供了 `Reader` 和 `Entry` 等结构体来帮助遍历。
3. **未进行充分的类型断言:**  `dwarfData.Type()` 方法返回的是 `Type` 接口，需要根据实际的 DWARF 条目类型进行类型断言，才能访问特定类型结构体的字段 (如 `ptrType.Type` 或 `structType.Field`)。如果断言错误，会导致程序 panic。
4. **忽略错误处理:**  在调用 `debug/dwarf` 包的函数时，务必检查返回的错误，以便及时发现和处理问题。

总而言之，这段 `type.go` 文件是 Go 语言 `debug/dwarf` 包中用于表示 DWARF 类型信息的核心部分，它为解析和理解程序调试信息提供了基础的数据结构。使用者需要结合 `debug/elf` 包或其他方式加载可执行文件，并遍历 DWARF 数据来获取具体的类型信息。

Prompt: 
```
这是路径为go/src/debug/dwarf/type.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// DWARF type information structures.
// The format is heavily biased toward C, but for simplicity
// the String methods use a pseudo-Go syntax.

package dwarf

import "strconv"

// A Type conventionally represents a pointer to any of the
// specific Type structures ([CharType], [StructType], etc.).
type Type interface {
	Common() *CommonType
	String() string
	Size() int64
}

// A CommonType holds fields common to multiple types.
// If a field is not known or not applicable for a given type,
// the zero value is used.
type CommonType struct {
	ByteSize int64  // size of value of this type, in bytes
	Name     string // name that can be used to refer to type
}

func (c *CommonType) Common() *CommonType { return c }

func (c *CommonType) Size() int64 { return c.ByteSize }

// Basic types

// A BasicType holds fields common to all basic types.
//
// See the documentation for [StructField] for more info on the interpretation of
// the BitSize/BitOffset/DataBitOffset fields.
type BasicType struct {
	CommonType
	BitSize       int64
	BitOffset     int64
	DataBitOffset int64
}

func (b *BasicType) Basic() *BasicType { return b }

func (t *BasicType) String() string {
	if t.Name != "" {
		return t.Name
	}
	return "?"
}

// A CharType represents a signed character type.
type CharType struct {
	BasicType
}

// A UcharType represents an unsigned character type.
type UcharType struct {
	BasicType
}

// An IntType represents a signed integer type.
type IntType struct {
	BasicType
}

// A UintType represents an unsigned integer type.
type UintType struct {
	BasicType
}

// A FloatType represents a floating point type.
type FloatType struct {
	BasicType
}

// A ComplexType represents a complex floating point type.
type ComplexType struct {
	BasicType
}

// A BoolType represents a boolean type.
type BoolType struct {
	BasicType
}

// An AddrType represents a machine address type.
type AddrType struct {
	BasicType
}

// An UnspecifiedType represents an implicit, unknown, ambiguous or nonexistent type.
type UnspecifiedType struct {
	BasicType
}

// qualifiers

// A QualType represents a type that has the C/C++ "const", "restrict", or "volatile" qualifier.
type QualType struct {
	CommonType
	Qual string
	Type Type
}

func (t *QualType) String() string { return t.Qual + " " + t.Type.String() }

func (t *QualType) Size() int64 { return t.Type.Size() }

// An ArrayType represents a fixed size array type.
type ArrayType struct {
	CommonType
	Type          Type
	StrideBitSize int64 // if > 0, number of bits to hold each element
	Count         int64 // if == -1, an incomplete array, like char x[].
}

func (t *ArrayType) String() string {
	return "[" + strconv.FormatInt(t.Count, 10) + "]" + t.Type.String()
}

func (t *ArrayType) Size() int64 {
	if t.Count == -1 {
		return 0
	}
	return t.Count * t.Type.Size()
}

// A VoidType represents the C void type.
type VoidType struct {
	CommonType
}

func (t *VoidType) String() string { return "void" }

// A PtrType represents a pointer type.
type PtrType struct {
	CommonType
	Type Type
}

func (t *PtrType) String() string { return "*" + t.Type.String() }

// A StructType represents a struct, union, or C++ class type.
type StructType struct {
	CommonType
	StructName string
	Kind       string // "struct", "union", or "class".
	Field      []*StructField
	Incomplete bool // if true, struct, union, class is declared but not defined
}

// A StructField represents a field in a struct, union, or C++ class type.
//
// # Bit Fields
//
// The BitSize, BitOffset, and DataBitOffset fields describe the bit
// size and offset of data members declared as bit fields in C/C++
// struct/union/class types.
//
// BitSize is the number of bits in the bit field.
//
// DataBitOffset, if non-zero, is the number of bits from the start of
// the enclosing entity (e.g. containing struct/class/union) to the
// start of the bit field. This corresponds to the DW_AT_data_bit_offset
// DWARF attribute that was introduced in DWARF 4.
//
// BitOffset, if non-zero, is the number of bits between the most
// significant bit of the storage unit holding the bit field to the
// most significant bit of the bit field. Here "storage unit" is the
// type name before the bit field (for a field "unsigned x:17", the
// storage unit is "unsigned"). BitOffset values can vary depending on
// the endianness of the system. BitOffset corresponds to the
// DW_AT_bit_offset DWARF attribute that was deprecated in DWARF 4 and
// removed in DWARF 5.
//
// At most one of DataBitOffset and BitOffset will be non-zero;
// DataBitOffset/BitOffset will only be non-zero if BitSize is
// non-zero. Whether a C compiler uses one or the other
// will depend on compiler vintage and command line options.
//
// Here is an example of C/C++ bit field use, along with what to
// expect in terms of DWARF bit offset info. Consider this code:
//
//	struct S {
//		int q;
//		int j:5;
//		int k:6;
//		int m:5;
//		int n:8;
//	} s;
//
// For the code above, one would expect to see the following for
// DW_AT_bit_offset values (using GCC 8):
//
//	       Little   |     Big
//	       Endian   |    Endian
//	                |
//	"j":     27     |     0
//	"k":     21     |     5
//	"m":     16     |     11
//	"n":     8      |     16
//
// Note that in the above the offsets are purely with respect to the
// containing storage unit for j/k/m/n -- these values won't vary based
// on the size of prior data members in the containing struct.
//
// If the compiler emits DW_AT_data_bit_offset, the expected values
// would be:
//
//	"j":     32
//	"k":     37
//	"m":     43
//	"n":     48
//
// Here the value 32 for "j" reflects the fact that the bit field is
// preceded by other data members (recall that DW_AT_data_bit_offset
// values are relative to the start of the containing struct). Hence
// DW_AT_data_bit_offset values can be quite large for structs with
// many fields.
//
// DWARF also allow for the possibility of base types that have
// non-zero bit size and bit offset, so this information is also
// captured for base types, but it is worth noting that it is not
// possible to trigger this behavior using mainstream languages.
type StructField struct {
	Name          string
	Type          Type
	ByteOffset    int64
	ByteSize      int64 // usually zero; use Type.Size() for normal fields
	BitOffset     int64
	DataBitOffset int64
	BitSize       int64 // zero if not a bit field
}

func (t *StructType) String() string {
	if t.StructName != "" {
		return t.Kind + " " + t.StructName
	}
	return t.Defn()
}

func (f *StructField) bitOffset() int64 {
	if f.BitOffset != 0 {
		return f.BitOffset
	}
	return f.DataBitOffset
}

func (t *StructType) Defn() string {
	s := t.Kind
	if t.StructName != "" {
		s += " " + t.StructName
	}
	if t.Incomplete {
		s += " /*incomplete*/"
		return s
	}
	s += " {"
	for i, f := range t.Field {
		if i > 0 {
			s += "; "
		}
		s += f.Name + " " + f.Type.String()
		s += "@" + strconv.FormatInt(f.ByteOffset, 10)
		if f.BitSize > 0 {
			s += " : " + strconv.FormatInt(f.BitSize, 10)
			s += "@" + strconv.FormatInt(f.bitOffset(), 10)
		}
	}
	s += "}"
	return s
}

// An EnumType represents an enumerated type.
// The only indication of its native integer type is its ByteSize
// (inside [CommonType]).
type EnumType struct {
	CommonType
	EnumName string
	Val      []*EnumValue
}

// An EnumValue represents a single enumeration value.
type EnumValue struct {
	Name string
	Val  int64
}

func (t *EnumType) String() string {
	s := "enum"
	if t.EnumName != "" {
		s += " " + t.EnumName
	}
	s += " {"
	for i, v := range t.Val {
		if i > 0 {
			s += "; "
		}
		s += v.Name + "=" + strconv.FormatInt(v.Val, 10)
	}
	s += "}"
	return s
}

// A FuncType represents a function type.
type FuncType struct {
	CommonType
	ReturnType Type
	ParamType  []Type
}

func (t *FuncType) String() string {
	s := "func("
	for i, t := range t.ParamType {
		if i > 0 {
			s += ", "
		}
		s += t.String()
	}
	s += ")"
	if t.ReturnType != nil {
		s += " " + t.ReturnType.String()
	}
	return s
}

// A DotDotDotType represents the variadic ... function parameter.
type DotDotDotType struct {
	CommonType
}

func (t *DotDotDotType) String() string { return "..." }

// A TypedefType represents a named type.
type TypedefType struct {
	CommonType
	Type Type
}

func (t *TypedefType) String() string { return t.Name }

func (t *TypedefType) Size() int64 { return t.Type.Size() }

// An UnsupportedType is a placeholder returned in situations where we
// encounter a type that isn't supported.
type UnsupportedType struct {
	CommonType
	Tag Tag
}

func (t *UnsupportedType) String() string {
	if t.Name != "" {
		return t.Name
	}
	return t.Name + "(unsupported type " + t.Tag.String() + ")"
}

// typeReader is used to read from either the info section or the
// types section.
type typeReader interface {
	Seek(Offset)
	Next() (*Entry, error)
	clone() typeReader
	offset() Offset
	// AddressSize returns the size in bytes of addresses in the current
	// compilation unit.
	AddressSize() int
}

// Type reads the type at off in the DWARF “info” section.
func (d *Data) Type(off Offset) (Type, error) {
	return d.readType("info", d.Reader(), off, d.typeCache, nil)
}

type typeFixer struct {
	typedefs   []*TypedefType
	arraytypes []*Type
}

func (tf *typeFixer) recordArrayType(t *Type) {
	if t == nil {
		return
	}
	_, ok := (*t).(*ArrayType)
	if ok {
		tf.arraytypes = append(tf.arraytypes, t)
	}
}

func (tf *typeFixer) apply() {
	for _, t := range tf.typedefs {
		t.Common().ByteSize = t.Type.Size()
	}
	for _, t := range tf.arraytypes {
		zeroArray(t)
	}
}

// readType reads a type from r at off of name. It adds types to the
// type cache, appends new typedef types to typedefs, and computes the
// sizes of types. Callers should pass nil for typedefs; this is used
// for internal recursion.
func (d *Data) readType(name string, r typeReader, off Offset, typeCache map[Offset]Type, fixups *typeFixer) (Type, error) {
	if t, ok := typeCache[off]; ok {
		return t, nil
	}
	r.Seek(off)
	e, err := r.Next()
	if err != nil {
		return nil, err
	}
	addressSize := r.AddressSize()
	if e == nil || e.Offset != off {
		return nil, DecodeError{name, off, "no type at offset"}
	}

	// If this is the root of the recursion, prepare to resolve
	// typedef sizes and perform other fixups once the recursion is
	// done. This must be done after the type graph is constructed
	// because it may need to resolve cycles in a different order than
	// readType encounters them.
	if fixups == nil {
		var fixer typeFixer
		defer func() {
			fixer.apply()
		}()
		fixups = &fixer
	}

	// Parse type from Entry.
	// Must always set typeCache[off] before calling
	// d.readType recursively, to handle circular types correctly.
	var typ Type

	nextDepth := 0

	// Get next child; set err if error happens.
	next := func() *Entry {
		if !e.Children {
			return nil
		}
		// Only return direct children.
		// Skip over composite entries that happen to be nested
		// inside this one. Most DWARF generators wouldn't generate
		// such a thing, but clang does.
		// See golang.org/issue/6472.
		for {
			kid, err1 := r.Next()
			if err1 != nil {
				err = err1
				return nil
			}
			if kid == nil {
				err = DecodeError{name, r.offset(), "unexpected end of DWARF entries"}
				return nil
			}
			if kid.Tag == 0 {
				if nextDepth > 0 {
					nextDepth--
					continue
				}
				return nil
			}
			if kid.Children {
				nextDepth++
			}
			if nextDepth > 0 {
				continue
			}
			return kid
		}
	}

	// Get Type referred to by Entry's AttrType field.
	// Set err if error happens. Not having a type is an error.
	typeOf := func(e *Entry) Type {
		tval := e.Val(AttrType)
		var t Type
		switch toff := tval.(type) {
		case Offset:
			if t, err = d.readType(name, r.clone(), toff, typeCache, fixups); err != nil {
				return nil
			}
		case uint64:
			if t, err = d.sigToType(toff); err != nil {
				return nil
			}
		default:
			// It appears that no Type means "void".
			return new(VoidType)
		}
		return t
	}

	switch e.Tag {
	case TagArrayType:
		// Multi-dimensional array.  (DWARF v2 §5.4)
		// Attributes:
		//	AttrType:subtype [required]
		//	AttrStrideSize: size in bits of each element of the array
		//	AttrByteSize: size of entire array
		// Children:
		//	TagSubrangeType or TagEnumerationType giving one dimension.
		//	dimensions are in left to right order.
		t := new(ArrayType)
		typ = t
		typeCache[off] = t
		if t.Type = typeOf(e); err != nil {
			goto Error
		}
		t.StrideBitSize, _ = e.Val(AttrStrideSize).(int64)

		// Accumulate dimensions,
		var dims []int64
		for kid := next(); kid != nil; kid = next() {
			// TODO(rsc): Can also be TagEnumerationType
			// but haven't seen that in the wild yet.
			switch kid.Tag {
			case TagSubrangeType:
				count, ok := kid.Val(AttrCount).(int64)
				if !ok {
					// Old binaries may have an upper bound instead.
					count, ok = kid.Val(AttrUpperBound).(int64)
					if ok {
						count++ // Length is one more than upper bound.
					} else if len(dims) == 0 {
						count = -1 // As in x[].
					}
				}
				dims = append(dims, count)
			case TagEnumerationType:
				err = DecodeError{name, kid.Offset, "cannot handle enumeration type as array bound"}
				goto Error
			}
		}
		if len(dims) == 0 {
			// LLVM generates this for x[].
			dims = []int64{-1}
		}

		t.Count = dims[0]
		for i := len(dims) - 1; i >= 1; i-- {
			t.Type = &ArrayType{Type: t.Type, Count: dims[i]}
		}

	case TagBaseType:
		// Basic type.  (DWARF v2 §5.1)
		// Attributes:
		//	AttrName: name of base type in programming language of the compilation unit [required]
		//	AttrEncoding: encoding value for type (encFloat etc) [required]
		//	AttrByteSize: size of type in bytes [required]
		//	AttrBitOffset: bit offset of value within containing storage unit
		//	AttrDataBitOffset: bit offset of value within containing storage unit
		//	AttrBitSize: size in bits
		//
		// For most languages BitOffset/DataBitOffset/BitSize will not be present
		// for base types.
		name, _ := e.Val(AttrName).(string)
		enc, ok := e.Val(AttrEncoding).(int64)
		if !ok {
			err = DecodeError{name, e.Offset, "missing encoding attribute for " + name}
			goto Error
		}
		switch enc {
		default:
			err = DecodeError{name, e.Offset, "unrecognized encoding attribute value"}
			goto Error

		case encAddress:
			typ = new(AddrType)
		case encBoolean:
			typ = new(BoolType)
		case encComplexFloat:
			typ = new(ComplexType)
			if name == "complex" {
				// clang writes out 'complex' instead of 'complex float' or 'complex double'.
				// clang also writes out a byte size that we can use to distinguish.
				// See issue 8694.
				switch byteSize, _ := e.Val(AttrByteSize).(int64); byteSize {
				case 8:
					name = "complex float"
				case 16:
					name = "complex double"
				}
			}
		case encFloat:
			typ = new(FloatType)
		case encSigned:
			typ = new(IntType)
		case encUnsigned:
			typ = new(UintType)
		case encSignedChar:
			typ = new(CharType)
		case encUnsignedChar:
			typ = new(UcharType)
		}
		typeCache[off] = typ
		t := typ.(interface {
			Basic() *BasicType
		}).Basic()
		t.Name = name
		t.BitSize, _ = e.Val(AttrBitSize).(int64)
		haveBitOffset := false
		haveDataBitOffset := false
		t.BitOffset, haveBitOffset = e.Val(AttrBitOffset).(int64)
		t.DataBitOffset, haveDataBitOffset = e.Val(AttrDataBitOffset).(int64)
		if haveBitOffset && haveDataBitOffset {
			err = DecodeError{name, e.Offset, "duplicate bit offset attributes"}
			goto Error
		}

	case TagClassType, TagStructType, TagUnionType:
		// Structure, union, or class type.  (DWARF v2 §5.5)
		// Attributes:
		//	AttrName: name of struct, union, or class
		//	AttrByteSize: byte size [required]
		//	AttrDeclaration: if true, struct/union/class is incomplete
		// Children:
		//	TagMember to describe one member.
		//		AttrName: name of member [required]
		//		AttrType: type of member [required]
		//		AttrByteSize: size in bytes
		//		AttrBitOffset: bit offset within bytes for bit fields
		//		AttrDataBitOffset: field bit offset relative to struct start
		//		AttrBitSize: bit size for bit fields
		//		AttrDataMemberLoc: location within struct [required for struct, class]
		// There is much more to handle C++, all ignored for now.
		t := new(StructType)
		typ = t
		typeCache[off] = t
		switch e.Tag {
		case TagClassType:
			t.Kind = "class"
		case TagStructType:
			t.Kind = "struct"
		case TagUnionType:
			t.Kind = "union"
		}
		t.StructName, _ = e.Val(AttrName).(string)
		t.Incomplete = e.Val(AttrDeclaration) != nil
		t.Field = make([]*StructField, 0, 8)
		var lastFieldType *Type
		var lastFieldBitSize int64
		var lastFieldByteOffset int64
		for kid := next(); kid != nil; kid = next() {
			if kid.Tag != TagMember {
				continue
			}
			f := new(StructField)
			if f.Type = typeOf(kid); err != nil {
				goto Error
			}
			switch loc := kid.Val(AttrDataMemberLoc).(type) {
			case []byte:
				// TODO: Should have original compilation
				// unit here, not unknownFormat.
				b := makeBuf(d, unknownFormat{}, "location", 0, loc)
				if b.uint8() != opPlusUconst {
					err = DecodeError{name, kid.Offset, "unexpected opcode"}
					goto Error
				}
				f.ByteOffset = int64(b.uint())
				if b.err != nil {
					err = b.err
					goto Error
				}
			case int64:
				f.ByteOffset = loc
			}

			f.Name, _ = kid.Val(AttrName).(string)
			f.ByteSize, _ = kid.Val(AttrByteSize).(int64)
			haveBitOffset := false
			haveDataBitOffset := false
			f.BitOffset, haveBitOffset = kid.Val(AttrBitOffset).(int64)
			f.DataBitOffset, haveDataBitOffset = kid.Val(AttrDataBitOffset).(int64)
			if haveBitOffset && haveDataBitOffset {
				err = DecodeError{name, e.Offset, "duplicate bit offset attributes"}
				goto Error
			}
			f.BitSize, _ = kid.Val(AttrBitSize).(int64)
			t.Field = append(t.Field, f)

			if lastFieldBitSize == 0 && lastFieldByteOffset == f.ByteOffset && t.Kind != "union" {
				// Last field was zero width. Fix array length.
				// (DWARF writes out 0-length arrays as if they were 1-length arrays.)
				fixups.recordArrayType(lastFieldType)
			}
			lastFieldType = &f.Type
			lastFieldByteOffset = f.ByteOffset
			lastFieldBitSize = f.BitSize
		}
		if t.Kind != "union" {
			b, ok := e.Val(AttrByteSize).(int64)
			if ok && b == lastFieldByteOffset {
				// Final field must be zero width. Fix array length.
				fixups.recordArrayType(lastFieldType)
			}
		}

	case TagConstType, TagVolatileType, TagRestrictType:
		// Type modifier (DWARF v2 §5.2)
		// Attributes:
		//	AttrType: subtype
		t := new(QualType)
		typ = t
		typeCache[off] = t
		if t.Type = typeOf(e); err != nil {
			goto Error
		}
		switch e.Tag {
		case TagConstType:
			t.Qual = "const"
		case TagRestrictType:
			t.Qual = "restrict"
		case TagVolatileType:
			t.Qual = "volatile"
		}

	case TagEnumerationType:
		// Enumeration type (DWARF v2 §5.6)
		// Attributes:
		//	AttrName: enum name if any
		//	AttrByteSize: bytes required to represent largest value
		// Children:
		//	TagEnumerator:
		//		AttrName: name of constant
		//		AttrConstValue: value of constant
		t := new(EnumType)
		typ = t
		typeCache[off] = t
		t.EnumName, _ = e.Val(AttrName).(string)
		t.Val = make([]*EnumValue, 0, 8)
		for kid := next(); kid != nil; kid = next() {
			if kid.Tag == TagEnumerator {
				f := new(EnumValue)
				f.Name, _ = kid.Val(AttrName).(string)
				f.Val, _ = kid.Val(AttrConstValue).(int64)
				n := len(t.Val)
				if n >= cap(t.Val) {
					val := make([]*EnumValue, n, n*2)
					copy(val, t.Val)
					t.Val = val
				}
				t.Val = t.Val[0 : n+1]
				t.Val[n] = f
			}
		}

	case TagPointerType:
		// Type modifier (DWARF v2 §5.2)
		// Attributes:
		//	AttrType: subtype [not required!  void* has no AttrType]
		//	AttrAddrClass: address class [ignored]
		t := new(PtrType)
		typ = t
		typeCache[off] = t
		if e.Val(AttrType) == nil {
			t.Type = &VoidType{}
			break
		}
		t.Type = typeOf(e)

	case TagSubroutineType:
		// Subroutine type.  (DWARF v2 §5.7)
		// Attributes:
		//	AttrType: type of return value if any
		//	AttrName: possible name of type [ignored]
		//	AttrPrototyped: whether used ANSI C prototype [ignored]
		// Children:
		//	TagFormalParameter: typed parameter
		//		AttrType: type of parameter
		//	TagUnspecifiedParameter: final ...
		t := new(FuncType)
		typ = t
		typeCache[off] = t
		if t.ReturnType = typeOf(e); err != nil {
			goto Error
		}
		t.ParamType = make([]Type, 0, 8)
		for kid := next(); kid != nil; kid = next() {
			var tkid Type
			switch kid.Tag {
			default:
				continue
			case TagFormalParameter:
				if tkid = typeOf(kid); err != nil {
					goto Error
				}
			case TagUnspecifiedParameters:
				tkid = &DotDotDotType{}
			}
			t.ParamType = append(t.ParamType, tkid)
		}

	case TagTypedef:
		// Typedef (DWARF v2 §5.3)
		// Attributes:
		//	AttrName: name [required]
		//	AttrType: type definition [required]
		t := new(TypedefType)
		typ = t
		typeCache[off] = t
		t.Name, _ = e.Val(AttrName).(string)
		t.Type = typeOf(e)

	case TagUnspecifiedType:
		// Unspecified type (DWARF v3 §5.2)
		// Attributes:
		//	AttrName: name
		t := new(UnspecifiedType)
		typ = t
		typeCache[off] = t
		t.Name, _ = e.Val(AttrName).(string)

	default:
		// This is some other type DIE that we're currently not
		// equipped to handle. Return an abstract "unsupported type"
		// object in such cases.
		t := new(UnsupportedType)
		typ = t
		typeCache[off] = t
		t.Tag = e.Tag
		t.Name, _ = e.Val(AttrName).(string)
	}

	if err != nil {
		goto Error
	}

	{
		b, ok := e.Val(AttrByteSize).(int64)
		if !ok {
			b = -1
			switch t := typ.(type) {
			case *TypedefType:
				// Record that we need to resolve this
				// type's size once the type graph is
				// constructed.
				fixups.typedefs = append(fixups.typedefs, t)
			case *PtrType:
				b = int64(addressSize)
			}
		}
		typ.Common().ByteSize = b
	}
	return typ, nil

Error:
	// If the parse fails, take the type out of the cache
	// so that the next call with this offset doesn't hit
	// the cache and return success.
	delete(typeCache, off)
	return nil, err
}

func zeroArray(t *Type) {
	at := (*t).(*ArrayType)
	if at.Type.Size() == 0 {
		return
	}
	// Make a copy to avoid invalidating typeCache.
	tt := *at
	tt.Count = 0
	*t = &tt
}

"""



```