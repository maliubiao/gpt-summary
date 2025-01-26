Response:
Let's break down the thought process to arrive at the answer.

1. **Understand the Goal:** The request asks for the functionality of the Go code snippet, examples, and potential pitfalls. The core is the `go/src/debug/dwarf/const.go` file.

2. **Initial Scan and Keywords:** Quickly scan the code for keywords. "Constants" in the file path and the comment `// Constants` are strong indicators. The `const` keyword appears repeatedly. Types like `Attr`, `format`, `Tag` are defined as `uint32` and associated with a set of named constants. The `//go:generate stringer` directives suggest code generation for string representations.

3. **Identify Core Data Structures:** The key data structures are `Attr`, `format`, and `Tag`. Recognize that these are enumerations (or similar concepts) used to represent different kinds of attributes, data formats, and entry types within the DWARF debugging information format.

4. **Infer Purpose - DWARF Debugging Information:**  The package name `dwarf` immediately suggests this code is related to the DWARF debugging format. The names of the constants (e.g., `AttrLocation`, `AttrByteSize`, `TagCompileUnit`, `formAddr`) strongly align with concepts in debugging and binary formats. Think about what kind of information a debugger needs: locations, sizes, types, etc.

5. **Functionality - Listing Constants:** The most obvious functionality is simply *defining* a large set of named constants. These constants are categorized into attributes, data formats, and tags, suggesting distinct roles within the DWARF structure.

6. **Deduce Usage - Interpreting DWARF Data:**  Reason about how these constants would be used. If you are parsing DWARF data, you'd encounter numerical codes representing attributes, formats, and tags. These constants provide a way to map those numerical codes to meaningful names. This leads to the core function: *representing elements of the DWARF debugging format*.

7. **Go Example - Reading DWARF Information (Hypothetical):**  To illustrate, create a simplified Go example that demonstrates the *intended use* of these constants. Since the code itself doesn't *use* these constants, the example needs to show how another part of the `dwarf` package (or a user of the package) would use them. This involves:
    * **Assumption:**  Assume a hypothetical function `ReadAttributeCode()` that reads a raw integer from DWARF data.
    * **Mapping:** Show how this raw integer can be cast to `dwarf.Attr` and then compared to the defined constants to determine the attribute type. Include an example with `AttrLocation`.
    * **Output:** Show how the string representation (`attr.String()`) would be used to print the human-readable name of the attribute.

8. **Go Example - Stringer:** Explain the `//go:generate stringer` directive. Show how it automatically generates the `String()` method, making the constants more user-friendly.

9. **Command-Line Arguments:**  Realize that this specific file doesn't handle command-line arguments. State this explicitly. The `stringer` tool itself *does* use command-line arguments, so briefly mention that.

10. **Potential Pitfalls - Incorrect Integer Values:** The most likely mistake is using the raw integer values directly without using the defined constants. This would make the code less readable and prone to errors if the constant values change. Provide a concrete example of this incorrect usage.

11. **Structure and Language:** Organize the answer logically with clear headings. Use precise and understandable Chinese. Explain DWARF and its purpose concisely.

12. **Refinement:** Review the answer for clarity, accuracy, and completeness. Ensure the examples are easy to follow and the explanations are clear. For example, initially, I might have focused too much on the internal workings of the `dwarf` package. The refinement step is about making the answer understandable to someone who might not be a DWARF expert. Highlighting that these are *representations* of DWARF elements is important.

By following this process of analysis, inference, and example creation, we arrive at the comprehensive answer provided earlier. The key is to move from the specific code to its broader purpose and how it would be used in a larger context.
这个Go语言源文件 `go/src/debug/dwarf/const.go` 的主要功能是**定义了用于表示 DWARF (Debugging With Attributed Records Format) 调试信息的各种常量**。DWARF 是一种被广泛使用的调试数据格式，编译器和链接器使用它来描述程序的类型、变量、函数以及源代码和目标代码之间的映射关系，以便调试器能够理解程序的结构和执行状态。

具体来说，这个文件定义了以下几种类型的常量：

1. **`Attr` (Attribute)**：表示 DWARF 调试信息条目 (Entry) 中字段的属性类型。每个 `Attr` 常量都对应 DWARF 标准中定义的一个属性，例如 `AttrLocation` 表示变量或函数的内存位置，`AttrName` 表示名称，`AttrType` 表示类型等等。

2. **`format` (Format)**：表示 DWARF 调试信息中数据的编码格式。例如 `formAddr` 表示地址，`formUdata` 表示无符号数据，`formString` 表示字符串等等。这些常量定义了如何解析和理解调试信息中的值。

3. **`Tag` (Tag)**：表示 DWARF 调试信息条目的分类或类型。每个 `Tag` 常量都对应 DWARF 标准中定义的一个标签，例如 `TagCompileUnit` 表示编译单元，`TagSubprogram` 表示子程序（函数），`TagVariable` 表示变量等等。

4. **Location Expression Operators (以 `op` 开头的常量)**：定义了用于表示变量或数据位置的表达式中的操作码。这些操作码用于构建复杂的表达式，描述如何在内存或寄存器中找到变量的值。

5. **Basic Type Encodings (以 `enc` 开头的常量)**：定义了基本数据类型的编码方式，例如 `encSigned` 表示有符号整数，`encFloat` 表示浮点数等等。

6. **Statement Program Opcodes (以 `lns` 和 `lne` 开头的常量)**：定义了 DWARF 行号信息状态机中的操作码，用于将目标代码指令映射回源代码行号。`lns` 开头的是标准操作码，`lne` 开头的是扩展操作码。

7. **Line Table Directory and File Name Entry Formats (以 `lnct` 开头的常量)**：定义了 DWARF 5 中用于描述源文件和目录信息的格式。

8. **Location List Entry Codes (以 `lle` 开头的常量)**：定义了 DWARF 5 中用于描述变量生命周期和位置变化的列表条目代码。

9. **Unit Header Unit Type Encodings (以 `ut` 开头的常量)**：定义了 DWARF 5 中编译单元头部的单元类型编码。

10. **Opcodes for DWARFv5 debug_rnglists section (以 `rle` 开头的常量)**：定义了 DWARF 5 中用于表示地址范围列表的操作码。

**这个文件本身并不实现任何具体的 Go 语言功能，它只是提供了一组常量定义，供 `debug/dwarf` 包的其他部分使用，以便解析和处理 DWARF 调试信息。**

**推理它是什么 Go 语言功能的实现：**

根据文件路径 `go/src/debug/dwarf/const.go` 和文件中定义的常量，可以推断出这个文件是 Go 语言 `debug/dwarf` 包的一部分。`debug/dwarf` 包是 Go 语言标准库中用于读取和解析 DWARF 调试信息的包。这个包允许 Go 程序（例如调试器或性能分析工具）理解由 Go 编译器生成的 DWARF 数据。

**Go 代码举例说明：**

虽然 `const.go` 本身不包含可执行代码，但我们可以展示 `debug/dwarf` 包的其他部分如何使用这些常量。以下是一个简单的例子，假设我们正在解析一个 DWARF 信息中的 Entry：

```go
package main

import (
	"debug/dwarf"
	"fmt"
	"os"
)

func main() {
	// 假设我们已经打开了一个包含 DWARF 信息的二进制文件
	f, err := os.Open("your_executable_file") // 将 "your_executable_file" 替换为你的可执行文件
	if err != nil {
		fmt.Println(err)
		return
	}
	defer f.Close()

	// 创建一个 DWARF 读取器
	r, err := dwarf.NewReader(f)
	if err != nil {
		fmt.Println(err)
		return
	}

	// 遍历所有的 Entry
	for {
		entry, err := r.Next()
		if err != nil {
			fmt.Println(err)
			return
		}
		if entry == nil {
			break // End of DWARF information
		}

		// 检查 Entry 的 Tag
		if entry.Tag == dwarf.TagSubprogram {
			fmt.Println("Found a Subprogram:")
			// 遍历 Entry 的所有字段
			for _, field := range entry.Field {
				// 使用 const.go 中定义的常量来判断属性类型
				switch field.Attr {
				case dwarf.AttrName:
					fmt.Printf("  Name: %v\n", field.Val)
				case dwarf.AttrLowpc:
					fmt.Printf("  LowPC: 0x%X\n", field.Val)
				case dwarf.AttrHighpc:
					fmt.Printf("  HighPC: 0x%X\n", field.Val)
				// ... 可以处理其他的属性
				}
			}
		}
	}
}
```

**假设的输入与输出：**

假设 `your_executable_file` 是一个用 Go 编译的可执行文件，其 DWARF 信息中包含一个名为 `main.main` 的函数。

**假设的输出：**

```
Found a Subprogram:
  Name: main.main
  LowPC: 0x12345
  HighPC: 0x12378
```

在这个例子中，`dwarf.TagSubprogram` 和 `dwarf.AttrName`、`dwarf.AttrLowpc`、`dwarf.AttrHighpc` 这些常量就是从 `const.go` 文件中定义的。`debug/dwarf` 包的其他部分会使用这些常量来解析 DWARF 数据，并将其呈现给用户。

**命令行参数的具体处理：**

`const.go` 文件本身不涉及命令行参数的处理。它只是定义常量。`debug/dwarf` 包的其他部分在具体使用时，可能会根据需要处理命令行参数，例如指定要读取 DWARF 信息的二进制文件路径等。但这部分逻辑不在 `const.go` 中。

**使用者易犯错的点：**

对于使用 `debug/dwarf` 包的开发者来说，一个常见的错误是**直接使用整数值而不是使用 `const.go` 中定义的常量来比较或设置 DWARF 属性、格式或标签**。

**错误示例：**

```go
// 错误的示例：直接使用整数值
if entry.Tag == 0x2E { // 0x2E 是 TagSubprogram 的值
    fmt.Println("Found a Subprogram")
}
```

**正确示例：**

```go
// 正确的示例：使用常量
if entry.Tag == dwarf.TagSubprogram {
    fmt.Println("Found a Subprogram")
}
```

直接使用整数值会降低代码的可读性和可维护性。如果 DWARF 标准发生变化，常量的值可能会改变，使用常量可以确保代码的正确性。此外，使用常量可以使代码意图更清晰，更容易理解。

总而言之，`go/src/debug/dwarf/const.go` 文件是 `debug/dwarf` 包的基础，它提供了用于描述 DWARF 调试信息的词汇表，使得 Go 语言能够有效地解析和利用这些调试信息。

Prompt: 
```
这是路径为go/src/debug/dwarf/const.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Constants

package dwarf

//go:generate stringer -type Attr -trimprefix=Attr

// An Attr identifies the attribute type in a DWARF [Entry.Field].
type Attr uint32

const (
	AttrSibling        Attr = 0x01
	AttrLocation       Attr = 0x02
	AttrName           Attr = 0x03
	AttrOrdering       Attr = 0x09
	AttrByteSize       Attr = 0x0B
	AttrBitOffset      Attr = 0x0C
	AttrBitSize        Attr = 0x0D
	AttrStmtList       Attr = 0x10
	AttrLowpc          Attr = 0x11
	AttrHighpc         Attr = 0x12
	AttrLanguage       Attr = 0x13
	AttrDiscr          Attr = 0x15
	AttrDiscrValue     Attr = 0x16
	AttrVisibility     Attr = 0x17
	AttrImport         Attr = 0x18
	AttrStringLength   Attr = 0x19
	AttrCommonRef      Attr = 0x1A
	AttrCompDir        Attr = 0x1B
	AttrConstValue     Attr = 0x1C
	AttrContainingType Attr = 0x1D
	AttrDefaultValue   Attr = 0x1E
	AttrInline         Attr = 0x20
	AttrIsOptional     Attr = 0x21
	AttrLowerBound     Attr = 0x22
	AttrProducer       Attr = 0x25
	AttrPrototyped     Attr = 0x27
	AttrReturnAddr     Attr = 0x2A
	AttrStartScope     Attr = 0x2C
	AttrStrideSize     Attr = 0x2E
	AttrUpperBound     Attr = 0x2F
	AttrAbstractOrigin Attr = 0x31
	AttrAccessibility  Attr = 0x32
	AttrAddrClass      Attr = 0x33
	AttrArtificial     Attr = 0x34
	AttrBaseTypes      Attr = 0x35
	AttrCalling        Attr = 0x36
	AttrCount          Attr = 0x37
	AttrDataMemberLoc  Attr = 0x38
	AttrDeclColumn     Attr = 0x39
	AttrDeclFile       Attr = 0x3A
	AttrDeclLine       Attr = 0x3B
	AttrDeclaration    Attr = 0x3C
	AttrDiscrList      Attr = 0x3D
	AttrEncoding       Attr = 0x3E
	AttrExternal       Attr = 0x3F
	AttrFrameBase      Attr = 0x40
	AttrFriend         Attr = 0x41
	AttrIdentifierCase Attr = 0x42
	AttrMacroInfo      Attr = 0x43
	AttrNamelistItem   Attr = 0x44
	AttrPriority       Attr = 0x45
	AttrSegment        Attr = 0x46
	AttrSpecification  Attr = 0x47
	AttrStaticLink     Attr = 0x48
	AttrType           Attr = 0x49
	AttrUseLocation    Attr = 0x4A
	AttrVarParam       Attr = 0x4B
	AttrVirtuality     Attr = 0x4C
	AttrVtableElemLoc  Attr = 0x4D
	// The following are new in DWARF 3.
	AttrAllocated     Attr = 0x4E
	AttrAssociated    Attr = 0x4F
	AttrDataLocation  Attr = 0x50
	AttrStride        Attr = 0x51
	AttrEntrypc       Attr = 0x52
	AttrUseUTF8       Attr = 0x53
	AttrExtension     Attr = 0x54
	AttrRanges        Attr = 0x55
	AttrTrampoline    Attr = 0x56
	AttrCallColumn    Attr = 0x57
	AttrCallFile      Attr = 0x58
	AttrCallLine      Attr = 0x59
	AttrDescription   Attr = 0x5A
	AttrBinaryScale   Attr = 0x5B
	AttrDecimalScale  Attr = 0x5C
	AttrSmall         Attr = 0x5D
	AttrDecimalSign   Attr = 0x5E
	AttrDigitCount    Attr = 0x5F
	AttrPictureString Attr = 0x60
	AttrMutable       Attr = 0x61
	AttrThreadsScaled Attr = 0x62
	AttrExplicit      Attr = 0x63
	AttrObjectPointer Attr = 0x64
	AttrEndianity     Attr = 0x65
	AttrElemental     Attr = 0x66
	AttrPure          Attr = 0x67
	AttrRecursive     Attr = 0x68
	// The following are new in DWARF 4.
	AttrSignature      Attr = 0x69
	AttrMainSubprogram Attr = 0x6A
	AttrDataBitOffset  Attr = 0x6B
	AttrConstExpr      Attr = 0x6C
	AttrEnumClass      Attr = 0x6D
	AttrLinkageName    Attr = 0x6E
	// The following are new in DWARF 5.
	AttrStringLengthBitSize  Attr = 0x6F
	AttrStringLengthByteSize Attr = 0x70
	AttrRank                 Attr = 0x71
	AttrStrOffsetsBase       Attr = 0x72
	AttrAddrBase             Attr = 0x73
	AttrRnglistsBase         Attr = 0x74
	AttrDwoName              Attr = 0x76
	AttrReference            Attr = 0x77
	AttrRvalueReference      Attr = 0x78
	AttrMacros               Attr = 0x79
	AttrCallAllCalls         Attr = 0x7A
	AttrCallAllSourceCalls   Attr = 0x7B
	AttrCallAllTailCalls     Attr = 0x7C
	AttrCallReturnPC         Attr = 0x7D
	AttrCallValue            Attr = 0x7E
	AttrCallOrigin           Attr = 0x7F
	AttrCallParameter        Attr = 0x80
	AttrCallPC               Attr = 0x81
	AttrCallTailCall         Attr = 0x82
	AttrCallTarget           Attr = 0x83
	AttrCallTargetClobbered  Attr = 0x84
	AttrCallDataLocation     Attr = 0x85
	AttrCallDataValue        Attr = 0x86
	AttrNoreturn             Attr = 0x87
	AttrAlignment            Attr = 0x88
	AttrExportSymbols        Attr = 0x89
	AttrDeleted              Attr = 0x8A
	AttrDefaulted            Attr = 0x8B
	AttrLoclistsBase         Attr = 0x8C
)

func (a Attr) GoString() string {
	if str, ok := _Attr_map[a]; ok {
		return "dwarf.Attr" + str
	}
	return "dwarf." + a.String()
}

// A format is a DWARF data encoding format.
type format uint32

const (
	// value formats
	formAddr        format = 0x01
	formDwarfBlock2 format = 0x03
	formDwarfBlock4 format = 0x04
	formData2       format = 0x05
	formData4       format = 0x06
	formData8       format = 0x07
	formString      format = 0x08
	formDwarfBlock  format = 0x09
	formDwarfBlock1 format = 0x0A
	formData1       format = 0x0B
	formFlag        format = 0x0C
	formSdata       format = 0x0D
	formStrp        format = 0x0E
	formUdata       format = 0x0F
	formRefAddr     format = 0x10
	formRef1        format = 0x11
	formRef2        format = 0x12
	formRef4        format = 0x13
	formRef8        format = 0x14
	formRefUdata    format = 0x15
	formIndirect    format = 0x16
	// The following are new in DWARF 4.
	formSecOffset   format = 0x17
	formExprloc     format = 0x18
	formFlagPresent format = 0x19
	formRefSig8     format = 0x20
	// The following are new in DWARF 5.
	formStrx          format = 0x1A
	formAddrx         format = 0x1B
	formRefSup4       format = 0x1C
	formStrpSup       format = 0x1D
	formData16        format = 0x1E
	formLineStrp      format = 0x1F
	formImplicitConst format = 0x21
	formLoclistx      format = 0x22
	formRnglistx      format = 0x23
	formRefSup8       format = 0x24
	formStrx1         format = 0x25
	formStrx2         format = 0x26
	formStrx3         format = 0x27
	formStrx4         format = 0x28
	formAddrx1        format = 0x29
	formAddrx2        format = 0x2A
	formAddrx3        format = 0x2B
	formAddrx4        format = 0x2C
	// Extensions for multi-file compression (.dwz)
	// http://www.dwarfstd.org/ShowIssue.php?issue=120604.1
	formGnuRefAlt  format = 0x1f20
	formGnuStrpAlt format = 0x1f21
)

//go:generate stringer -type Tag -trimprefix=Tag

// A Tag is the classification (the type) of an [Entry].
type Tag uint32

const (
	TagArrayType              Tag = 0x01
	TagClassType              Tag = 0x02
	TagEntryPoint             Tag = 0x03
	TagEnumerationType        Tag = 0x04
	TagFormalParameter        Tag = 0x05
	TagImportedDeclaration    Tag = 0x08
	TagLabel                  Tag = 0x0A
	TagLexDwarfBlock          Tag = 0x0B
	TagMember                 Tag = 0x0D
	TagPointerType            Tag = 0x0F
	TagReferenceType          Tag = 0x10
	TagCompileUnit            Tag = 0x11
	TagStringType             Tag = 0x12
	TagStructType             Tag = 0x13
	TagSubroutineType         Tag = 0x15
	TagTypedef                Tag = 0x16
	TagUnionType              Tag = 0x17
	TagUnspecifiedParameters  Tag = 0x18
	TagVariant                Tag = 0x19
	TagCommonDwarfBlock       Tag = 0x1A
	TagCommonInclusion        Tag = 0x1B
	TagInheritance            Tag = 0x1C
	TagInlinedSubroutine      Tag = 0x1D
	TagModule                 Tag = 0x1E
	TagPtrToMemberType        Tag = 0x1F
	TagSetType                Tag = 0x20
	TagSubrangeType           Tag = 0x21
	TagWithStmt               Tag = 0x22
	TagAccessDeclaration      Tag = 0x23
	TagBaseType               Tag = 0x24
	TagCatchDwarfBlock        Tag = 0x25
	TagConstType              Tag = 0x26
	TagConstant               Tag = 0x27
	TagEnumerator             Tag = 0x28
	TagFileType               Tag = 0x29
	TagFriend                 Tag = 0x2A
	TagNamelist               Tag = 0x2B
	TagNamelistItem           Tag = 0x2C
	TagPackedType             Tag = 0x2D
	TagSubprogram             Tag = 0x2E
	TagTemplateTypeParameter  Tag = 0x2F
	TagTemplateValueParameter Tag = 0x30
	TagThrownType             Tag = 0x31
	TagTryDwarfBlock          Tag = 0x32
	TagVariantPart            Tag = 0x33
	TagVariable               Tag = 0x34
	TagVolatileType           Tag = 0x35
	// The following are new in DWARF 3.
	TagDwarfProcedure  Tag = 0x36
	TagRestrictType    Tag = 0x37
	TagInterfaceType   Tag = 0x38
	TagNamespace       Tag = 0x39
	TagImportedModule  Tag = 0x3A
	TagUnspecifiedType Tag = 0x3B
	TagPartialUnit     Tag = 0x3C
	TagImportedUnit    Tag = 0x3D
	TagMutableType     Tag = 0x3E // Later removed from DWARF.
	TagCondition       Tag = 0x3F
	TagSharedType      Tag = 0x40
	// The following are new in DWARF 4.
	TagTypeUnit            Tag = 0x41
	TagRvalueReferenceType Tag = 0x42
	TagTemplateAlias       Tag = 0x43
	// The following are new in DWARF 5.
	TagCoarrayType       Tag = 0x44
	TagGenericSubrange   Tag = 0x45
	TagDynamicType       Tag = 0x46
	TagAtomicType        Tag = 0x47
	TagCallSite          Tag = 0x48
	TagCallSiteParameter Tag = 0x49
	TagSkeletonUnit      Tag = 0x4A
	TagImmutableType     Tag = 0x4B
)

func (t Tag) GoString() string {
	if t <= TagTemplateAlias {
		return "dwarf.Tag" + t.String()
	}
	return "dwarf." + t.String()
}

// Location expression operators.
// The debug info encodes value locations like 8(R3)
// as a sequence of these op codes.
// This package does not implement full expressions;
// the opPlusUconst operator is expected by the type parser.
const (
	opAddr       = 0x03 /* 1 op, const addr */
	opDeref      = 0x06
	opConst1u    = 0x08 /* 1 op, 1 byte const */
	opConst1s    = 0x09 /*	" signed */
	opConst2u    = 0x0A /* 1 op, 2 byte const  */
	opConst2s    = 0x0B /*	" signed */
	opConst4u    = 0x0C /* 1 op, 4 byte const */
	opConst4s    = 0x0D /*	" signed */
	opConst8u    = 0x0E /* 1 op, 8 byte const */
	opConst8s    = 0x0F /*	" signed */
	opConstu     = 0x10 /* 1 op, LEB128 const */
	opConsts     = 0x11 /*	" signed */
	opDup        = 0x12
	opDrop       = 0x13
	opOver       = 0x14
	opPick       = 0x15 /* 1 op, 1 byte stack index */
	opSwap       = 0x16
	opRot        = 0x17
	opXderef     = 0x18
	opAbs        = 0x19
	opAnd        = 0x1A
	opDiv        = 0x1B
	opMinus      = 0x1C
	opMod        = 0x1D
	opMul        = 0x1E
	opNeg        = 0x1F
	opNot        = 0x20
	opOr         = 0x21
	opPlus       = 0x22
	opPlusUconst = 0x23 /* 1 op, ULEB128 addend */
	opShl        = 0x24
	opShr        = 0x25
	opShra       = 0x26
	opXor        = 0x27
	opSkip       = 0x2F /* 1 op, signed 2-byte constant */
	opBra        = 0x28 /* 1 op, signed 2-byte constant */
	opEq         = 0x29
	opGe         = 0x2A
	opGt         = 0x2B
	opLe         = 0x2C
	opLt         = 0x2D
	opNe         = 0x2E
	opLit0       = 0x30
	/* OpLitN = OpLit0 + N for N = 0..31 */
	opReg0 = 0x50
	/* OpRegN = OpReg0 + N for N = 0..31 */
	opBreg0 = 0x70 /* 1 op, signed LEB128 constant */
	/* OpBregN = OpBreg0 + N for N = 0..31 */
	opRegx       = 0x90 /* 1 op, ULEB128 register */
	opFbreg      = 0x91 /* 1 op, SLEB128 offset */
	opBregx      = 0x92 /* 2 op, ULEB128 reg; SLEB128 off */
	opPiece      = 0x93 /* 1 op, ULEB128 size of piece */
	opDerefSize  = 0x94 /* 1-byte size of data retrieved */
	opXderefSize = 0x95 /* 1-byte size of data retrieved */
	opNop        = 0x96
	// The following are new in DWARF 3.
	opPushObjAddr    = 0x97
	opCall2          = 0x98 /* 2-byte offset of DIE */
	opCall4          = 0x99 /* 4-byte offset of DIE */
	opCallRef        = 0x9A /* 4- or 8- byte offset of DIE */
	opFormTLSAddress = 0x9B
	opCallFrameCFA   = 0x9C
	opBitPiece       = 0x9D
	// The following are new in DWARF 4.
	opImplicitValue = 0x9E
	opStackValue    = 0x9F
	// The following a new in DWARF 5.
	opImplicitPointer = 0xA0
	opAddrx           = 0xA1
	opConstx          = 0xA2
	opEntryValue      = 0xA3
	opConstType       = 0xA4
	opRegvalType      = 0xA5
	opDerefType       = 0xA6
	opXderefType      = 0xA7
	opConvert         = 0xA8
	opReinterpret     = 0xA9
	/* 0xE0-0xFF reserved for user-specific */
)

// Basic type encodings -- the value for AttrEncoding in a TagBaseType Entry.
const (
	encAddress      = 0x01
	encBoolean      = 0x02
	encComplexFloat = 0x03
	encFloat        = 0x04
	encSigned       = 0x05
	encSignedChar   = 0x06
	encUnsigned     = 0x07
	encUnsignedChar = 0x08
	// The following are new in DWARF 3.
	encImaginaryFloat = 0x09
	encPackedDecimal  = 0x0A
	encNumericString  = 0x0B
	encEdited         = 0x0C
	encSignedFixed    = 0x0D
	encUnsignedFixed  = 0x0E
	encDecimalFloat   = 0x0F
	// The following are new in DWARF 4.
	encUTF = 0x10
	// The following are new in DWARF 5.
	encUCS   = 0x11
	encASCII = 0x12
)

// Statement program standard opcode encodings.
const (
	lnsCopy           = 1
	lnsAdvancePC      = 2
	lnsAdvanceLine    = 3
	lnsSetFile        = 4
	lnsSetColumn      = 5
	lnsNegateStmt     = 6
	lnsSetBasicBlock  = 7
	lnsConstAddPC     = 8
	lnsFixedAdvancePC = 9

	// DWARF 3
	lnsSetPrologueEnd   = 10
	lnsSetEpilogueBegin = 11
	lnsSetISA           = 12
)

// Statement program extended opcode encodings.
const (
	lneEndSequence = 1
	lneSetAddress  = 2
	lneDefineFile  = 3

	// DWARF 4
	lneSetDiscriminator = 4
)

// Line table directory and file name entry formats.
// These are new in DWARF 5.
const (
	lnctPath           = 0x01
	lnctDirectoryIndex = 0x02
	lnctTimestamp      = 0x03
	lnctSize           = 0x04
	lnctMD5            = 0x05
)

// Location list entry codes.
// These are new in DWARF 5.
const (
	lleEndOfList       = 0x00
	lleBaseAddressx    = 0x01
	lleStartxEndx      = 0x02
	lleStartxLength    = 0x03
	lleOffsetPair      = 0x04
	lleDefaultLocation = 0x05
	lleBaseAddress     = 0x06
	lleStartEnd        = 0x07
	lleStartLength     = 0x08
)

// Unit header unit type encodings.
// These are new in DWARF 5.
const (
	utCompile      = 0x01
	utType         = 0x02
	utPartial      = 0x03
	utSkeleton     = 0x04
	utSplitCompile = 0x05
	utSplitType    = 0x06
)

// Opcodes for DWARFv5 debug_rnglists section.
const (
	rleEndOfList    = 0x0
	rleBaseAddressx = 0x1
	rleStartxEndx   = 0x2
	rleStartxLength = 0x3
	rleOffsetPair   = 0x4
	rleBaseAddress  = 0x5
	rleStartEnd     = 0x6
	rleStartLength  = 0x7
)

"""



```